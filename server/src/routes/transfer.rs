use crate::handlers::transfer_handler;
use axum::{routing::post, Router};

pub fn router() -> Router {
    Router::new().route(
        "/transfer",
        post(transfer_handler::transfer_request_handler),
    )
}
