use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use thiserror::Error;

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
}

impl IntoResponse for Errors {
  fn into_response(self) -> Response {
    json!({"errors": &self}).to_string().into_response()
  }
}

#[derive(Error, Debug)]
pub enum HandlerError {
  #[error("An empty error occurred.")]
  Empty,
}

impl HandlerError {
  fn into_generic(self, code: StatusCode) -> (StatusCode, Errors) {
    (code, Errors::generic(self.to_string()))
  }
}

impl IntoResponse for HandlerError {
  fn into_response(self) -> Response {
    match self {
      HandlerError::Empty => self.into_generic(StatusCode::BAD_REQUEST),
    }
    .into_response()
  }
}
