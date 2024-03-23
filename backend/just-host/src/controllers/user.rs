use crate::controllers::errors::{HandlerError, ValidatedJson};
use crate::models::user::{self, Authority, CreateUser, User};
use crate::{AppState, API_PREFIX};
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use validator::Validate;

const AUTH_COOKIE_KEY: &str = "Authorization";

lazy_static! {
  static ref AUTH_DURATION: Duration = Duration::try_weeks(52).unwrap();
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
      exp: (Utc::now() + lifespan)
        .timestamp()
        .try_into()
        .map_err(HandlerError::ConvertIntegerToTimestamp)?,
    },
    &EncodingKey::from_secret((state.auth_secret.clone() + &user.password).as_bytes()),
  )
  .map_err(HandlerError::EncodeJwt)?;
  let cookie = Cookie::build((AUTH_COOKIE_KEY, token))
    .max_age(time::Duration::seconds(lifespan.num_seconds()))
    .path(API_PREFIX)
    .secure(true)
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
  #[validate(length(min = 6, max = 72))]
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

  let user = user::create(
    &state.connection_pool,
    &state.user_snowflake,
    CreateUser {
      username: &input.username,
      email: &input.email_address,
      password: &input.password,
      authority: Authority::None,
    },
  )
  .await?;
  let cookies = authenticate(&state, cookies, &user, *AUTH_DURATION)?;

  Ok((StatusCode::CREATED, cookies))
}
