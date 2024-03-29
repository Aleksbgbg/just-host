use crate::controllers::errors::{HandlerError, ValidatedJson};
use crate::models::id::Id;
use crate::models::user::{self, Authority, CreateUser, User};
use crate::secure::Bytes;
use crate::{secure, AppState, API_PREFIX, SECRET_LEN};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::{Extension, Json};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use validator::Validate;

const AUTH_COOKIE_KEY: &str = "Authorization";

lazy_static! {
  static ref AUTH_DURATION: Duration = Duration::try_weeks(52).unwrap();
}

fn interleave(left: &[u8], right: &[u8]) -> Vec<u8> {
  assert!(
    left.len() == right.len(),
    "assymetric length interleave not implemented"
  );

  let mut interleaved = vec![0; left.len() + right.len()];

  for index in 0..left.len() {
    let offset = index * 2;
    interleaved[offset] = left[index];
    interleaved[offset + 1] = right[index];
  }

  interleaved
}

#[derive(Serialize, Deserialize)]
struct Claims {
  exp: usize,
}

fn authenticate(
  state: &AppState,
  cookies: CookieJar,
  user: &User,
  lifespan: Duration,
) -> Result<CookieJar, HandlerError> {
  let token = jsonwebtoken::encode(
    &Header {
      kid: Some(user.id.to_string()),
      ..Default::default()
    },
    &Claims {
      exp: (Utc::now() + lifespan).timestamp().try_into()?,
    },
    &EncodingKey::from_secret(&interleave(&state.auth_secret, &user.auth_secret)),
  )?;
  let cookie = Cookie::build((AUTH_COOKIE_KEY, token))
    .max_age(time::Duration::seconds(lifespan.num_seconds()))
    .path(API_PREFIX)
    .secure(cfg!(not(debug_assertions)))
    .http_only(true)
    .same_site(SameSite::Strict)
    .build();

  Ok(cookies.add(cookie))
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RegisterUser {
  #[validate(length(min = 2, max = 32))]
  username: String,
  #[validate(email)]
  email_address: String,
  #[validate(length(min = 6, max = 128))]
  password: String,
  #[validate(must_match(other = "password", message = "Password"))]
  repeat_password: String,
}

pub async fn register(
  State(state): State<AppState>,
  cookies: CookieJar,
  ValidatedJson(input): ValidatedJson<RegisterUser>,
) -> Result<(StatusCode, CookieJar), HandlerError> {
  if user::name_exists(&state.connection_pool, &input.username).await? {
    return Err(HandlerError::NameExists);
  }
  if user::email_exists(&state.connection_pool, &input.email_address).await? {
    return Err(HandlerError::EmailExists);
  }

  let password_hash = Argon2::default()
    .hash_password(input.password.as_bytes(), &SaltString::generate(&mut OsRng))
    .map_err(HandlerError::HashPassword)?
    .to_string();
  let auth_secret = secure::random_bytes(Bytes(SECRET_LEN))?;
  let user = user::create(
    &state.connection_pool,
    &state.user_snowflake,
    CreateUser {
      username: &input.username,
      email: &input.email_address,
      password_hash: &password_hash,
      auth_secret,
      authority: Authority::None,
    },
  )
  .await?;

  let cookies = authenticate(&state, cookies, &user, *AUTH_DURATION)?;

  Ok((StatusCode::CREATED, cookies))
}

#[derive(Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct LoginUser {
  #[validate(length(min = 2, max = 32))]
  username: String,
  #[validate(length(min = 6, max = 128))]
  password: String,
}

pub async fn login(
  State(state): State<AppState>,
  cookies: CookieJar,
  ValidatedJson(input): ValidatedJson<LoginUser>,
) -> Result<(StatusCode, CookieJar), HandlerError> {
  let user = user::find_by_username(&state.connection_pool, &input.username)
    .await?
    .ok_or(HandlerError::NoUser)?;

  let parsed_hash = PasswordHash::new(&user.password_hash).map_err(HandlerError::ParseHash)?;
  Argon2::default()
    .verify_password(input.password.as_bytes(), &parsed_hash)
    .map_err(HandlerError::ValidateCredentials)?;

  let cookies = authenticate(&state, cookies, &user, *AUTH_DURATION)?;

  Ok((StatusCode::OK, cookies))
}

pub async fn logout(cookies: CookieJar) -> CookieJar {
  cookies.remove(AUTH_COOKIE_KEY)
}

#[derive(Error, Debug)]
pub enum AuthError {
  #[error("no authorization cookie set")]
  NoAuthCookie,
  #[error("could not decode header")]
  DecodeHeader(jsonwebtoken::errors::Error),
  #[error("user ID was not present")]
  NoKid,
  #[error("could not decode user ID")]
  DecodeId(bs58::decode::Error),
  #[error("user ID was not found")]
  UserNotFound,
  #[error("could not decode authentication token")]
  DecodeJwt(jsonwebtoken::errors::Error),
}

pub async fn extract(
  State(state): State<AppState>,
  cookies: CookieJar,
  mut req: Request,
  next: Next,
) -> Result<Response, HandlerError> {
  let token = cookies
    .get(AUTH_COOKIE_KEY)
    .ok_or(AuthError::NoAuthCookie)?
    .value();

  let id = jsonwebtoken::decode_header(token)
    .map_err(AuthError::DecodeHeader)?
    .kid
    .ok_or(AuthError::NoKid)?;

  let user = user::find_by_id(
    &state.connection_pool,
    Id::from_str(&id).map_err(AuthError::DecodeId)?,
  )
  .await?
  .ok_or(AuthError::UserNotFound)?;

  let _claims = jsonwebtoken::decode::<Claims>(
    token,
    &DecodingKey::from_secret(&interleave(&state.auth_secret, &user.auth_secret)),
    &Validation::default(),
  )
  .map_err(AuthError::DecodeJwt)?
  .claims;

  req.extensions_mut().insert(Arc::new(user));

  Ok(next.run(req).await)
}

#[derive(Serialize)]
pub struct UserDetails {
  id: Id,
  username: String,
}

pub async fn get(Extension(user): Extension<Arc<User>>) -> Json<UserDetails> {
  Json(UserDetails {
    id: user.id,
    username: user.username.clone(),
  })
}
