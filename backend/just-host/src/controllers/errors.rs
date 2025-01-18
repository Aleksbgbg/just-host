use super::user::AuthError;
use crate::models::user::DatabaseError;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use convert_case::{Case, Casing};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Display;
use std::num::TryFromIntError;
use strum::AsRefStr;
use thiserror::Error;
use tracing::error;
use validator::{Validate, ValidationErrors, ValidationErrorsKind};

#[derive(Clone, Default, Serialize)]
struct Errors {
  generic: Vec<String>,
  specific: HashMap<String, Vec<String>>,
}

impl Errors {
  fn generic(value: String) -> Self {
    let mut errors = Self::default();
    errors.add_generic(value);
    errors
  }

  fn add_generic(&mut self, value: String) {
    self.generic.push(value);
  }

  fn add_specific(&mut self, key: String, value: Vec<String>) {
    self.specific.insert(key, value);
  }

  fn add_one_specific(&mut self, key: String, value: String) {
    self.specific.insert(key, vec![value]);
  }
}

impl IntoResponse for Errors {
  fn into_response(self) -> Response {
    Json(json!({"errors": &self})).into_response()
  }
}

#[derive(Error, Debug, AsRefStr)]
pub enum HandlerError {
  #[error("{0}.")]
  JsonRejection(#[from] JsonRejection),
  #[error(transparent)]
  Validation(#[from] ValidationErrors),
  #[error("Username is already registered.")]
  NameExists,
  #[error("Email Address is already registered.")]
  EmailExists,
  #[error("Invalid credentials.")]
  NoUser,
  #[error("Invalid credentials.")]
  ValidateCredentials(argon2::password_hash::errors::Error),

  #[error("A user is required but the authentication token could not be verified: {0}.")]
  UserRequired(#[from] AuthError),

  #[error("A user is already logged in.")]
  UserAlreadyPresent,

  #[error("Database transaction failed.")]
  Database(#[from] DatabaseError),
  #[error("Could not hash password.")]
  HashPassword(argon2::password_hash::errors::Error),
  #[error("Could not generate user secret.")]
  GenerateSecret(#[from] rand_core::Error),
  #[error("Could not convert integer to timestamp.")]
  ConvertIntegerToTimestamp(#[from] TryFromIntError),
  #[error("Could not encode JWT.")]
  EncodeJwt(#[from] jsonwebtoken::errors::Error),
  #[error("Could not parse password hash.")]
  ParseHash(argon2::password_hash::errors::Error),
}

impl HandlerError {
  fn as_generic(&self, code: StatusCode) -> (StatusCode, Errors) {
    (code, Errors::generic(self.to_string()))
  }

  fn log_server_error(&self, message: impl Display) -> (StatusCode, Errors) {
    error!("{}: {}", self.as_ref(), message);
    self.as_generic(StatusCode::INTERNAL_SERVER_ERROR)
  }
}

fn failed_validation() -> Errors {
  Errors::generic("Some inputs failed validation.".into())
}

fn format_error_messages(field: &str, errors: ValidationErrorsKind) -> Vec<String> {
  let title = field.to_case(Case::Title);

  match errors {
    ValidationErrorsKind::Field(errors) => errors
      .into_iter()
      .map(|e| match e.code.as_ref() {
        "email" => format!("{} must be a valid email address.", title),
        "must_match" => format!("{} must be identical to {}.", title, e.message.unwrap()),
        "length" => format!(
          "{} must be between {} and {} characters long (currently {}).",
          title,
          e.params.get("min").unwrap(),
          e.params.get("max").unwrap(),
          e.params.get("value").unwrap().as_str().unwrap().len(),
        ),
        code => unimplemented!(
          "error message is not implemented for message code '{}'",
          code
        ),
      })
      .collect(),
    ValidationErrorsKind::Struct(_) | ValidationErrorsKind::List(_) => {
      panic!("unexpected error type")
    }
  }
}

impl IntoResponse for HandlerError {
  fn into_response(self) -> Response {
    match self {
      HandlerError::JsonRejection(_) => self.as_generic(StatusCode::BAD_REQUEST),
      HandlerError::Validation(validation_errors) => (StatusCode::BAD_REQUEST, {
        let mut errors = failed_validation();
        for (k, v) in validation_errors.into_errors() {
          errors.add_specific(k.to_case(Case::Camel), format_error_messages(k, v));
        }
        errors
      }),
      HandlerError::NameExists => (StatusCode::BAD_REQUEST, {
        let mut errors = failed_validation();
        errors.add_one_specific("username".into(), self.to_string());
        errors
      }),
      HandlerError::EmailExists => (StatusCode::BAD_REQUEST, {
        let mut errors = failed_validation();
        errors.add_one_specific("emailAddress".into(), self.to_string());
        errors
      }),
      HandlerError::NoUser => self.as_generic(StatusCode::BAD_REQUEST),
      HandlerError::ValidateCredentials(_) => self.as_generic(StatusCode::BAD_REQUEST),

      HandlerError::UserRequired(_) => self.as_generic(StatusCode::UNAUTHORIZED),

      HandlerError::UserAlreadyPresent => self.as_generic(StatusCode::FORBIDDEN),

      HandlerError::Database(ref inner) => self.log_server_error(inner),
      HandlerError::HashPassword(ref inner) => self.log_server_error(inner),
      HandlerError::GenerateSecret(ref inner) => self.log_server_error(inner),
      HandlerError::ConvertIntegerToTimestamp(ref inner) => self.log_server_error(inner),
      HandlerError::EncodeJwt(ref inner) => self.log_server_error(inner),
      HandlerError::ParseHash(ref inner) => self.log_server_error(inner),
    }
    .into_response()
  }
}

pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
  T: DeserializeOwned + Validate,
  S: Send + Sync,
  Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
  type Rejection = HandlerError;

  async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
    let Json(value) = Json::from_request(req, state).await?;
    value.validate()?;
    Ok(ValidatedJson(value))
  }
}
