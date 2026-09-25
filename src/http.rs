//! Optional axum handler (feature `http`).
//!
//! * `POST /payments` body [`CreatePayment`] -> 201 [`PaymentRequest`](crate::PaymentRequest)
//! * `GET /payments/{id}` -> [`PaymentStatus`](crate::PaymentStatus)
//! * `GET /health` -> `ok`
//!
//! No authentication is built in: mount it behind your own auth layer / private network.

use crate::Error;
use crate::engine::{CreatePayment, Engine};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/payments", post(create))
        .route("/payments/{id}", get(status))
        .route("/health", get(|| async { "ok" }))
        .with_state(engine)
}

async fn create(State(e): State<Arc<Engine>>, body: Option<Json<CreatePayment>>) -> Response {
    let opts = body.map(|Json(b)| b).unwrap_or_default();
    match e.create_payment(opts) {
        Ok(req) => (StatusCode::CREATED, Json(req)).into_response(),
        Err(err) => error(err),
    }
}

async fn status(State(e): State<Arc<Engine>>, Path(id): Path<String>) -> Response {
    match e.status(&id) {
        Ok(s) => Json(s).into_response(),
        Err(err) => error(err),
    }
}

fn error(err: Error) -> Response {
    let code = match err {
        Error::NotFound(_) => StatusCode::NOT_FOUND,
        Error::Config(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    // Internal errors are logged, not echoed.
    if code == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::error!(error = %err, "http handler");
        return (code, "internal error").into_response();
    }
    (code, err.to_string()).into_response()
}
