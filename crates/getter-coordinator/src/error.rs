//! HTTP error mapping that never exposes internal storage details.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use getter_core::ValidationError;
use getter_protocol::ApiErrorBody;
use getter_storage::StoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    pub fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, context, "internal coordinator error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the coordinator could not complete the request",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code.to_owned(),
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(kind) => Self::not_found(format!("{kind} not found")),
            StoreError::Conflict(message) => Self::conflict(message),
            StoreError::Forbidden(message) => Self::forbidden(message),
            StoreError::Enrollment(message) => Self::unauthorized(message),
            StoreError::InvalidData(message) => {
                tracing::error!(error = %message, "invalid stored data");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_stored_data",
                    "persisted coordinator state is invalid",
                )
            }
            StoreError::Database(error) => {
                tracing::error!(error = %error, "database operation failed");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "the coordinator database operation failed",
                )
            }
            StoreError::Poisoned => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "the coordinator storage lock is unavailable",
            ),
        }
    }
}

impl From<ValidationError> for ApiError {
    fn from(error: ValidationError) -> Self {
        Self::unprocessable("invalid_submission", error.to_string())
    }
}
