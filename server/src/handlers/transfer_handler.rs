use crate::services::{sol_transfer, spl_confidential_transfer, spl_token_transfer};
use anyhow::{Context, Result};
use axum::{extract::Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::Signer;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::str::FromStr;

#[derive(Deserialize)]
pub struct TransferRequest {
    pub from_keypair: String,
    pub to: String,
    pub amount: f64,
    pub mint: Option<String>,
    pub confidential: Option<bool>,
}

#[derive(Serialize)]
pub struct TransferResponse {
    pub message: String,
    pub transaction_signature: String,
}

pub async fn transfer_request_handler(
    Json(payload): Json<TransferRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let result = handle_transfer(payload).await;
    match result {
        Ok(response) => Ok(Json(response)),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": err.to_string()})),
        )),
    }
}

async fn handle_transfer(payload: TransferRequest) -> Result<TransferResponse> {
    let decoded_secret_key: Vec<u8> =
        serde_json::from_str(&payload.from_keypair).context("Invalid 'from' keypair provided")?;
    let from_keypair =
        Keypair::from_bytes(&decoded_secret_key).context("Invalid 'from' keypair provided")?;
    let to_pubkey = Pubkey::from_str(&payload.to).context("Invalid 'to' address provided")?;
    let token_type = payload.mint.as_deref().unwrap_or("SOL");

    let signature = match (&payload.mint, payload.confidential) {
        (None, _) => sol_transfer::transfer_sol(&from_keypair, &to_pubkey, payload.amount).await?,
        (Some(mint_str), Some(true)) => {
            let mint = Pubkey::from_str(mint_str).context("Invalid 'mint' address provided")?;
            spl_confidential_transfer::confidential_transfer(
                &from_keypair,
                &to_pubkey,
                &mint,
                payload.amount,
            )
            .await?
        }
        (Some(mint_str), _) => {
            let mint = Pubkey::from_str(mint_str).context("Invalid 'mint' address provided")?;
            spl_token_transfer::transfer_token(&from_keypair, &to_pubkey, &mint, payload.amount)
                .await?
        }
    };

    Ok(TransferResponse {
        message: format!(
            "Transferred {} {} from {} to {}",
            payload.amount,
            token_type,
            from_keypair.pubkey(),
            to_pubkey
        ),
        transaction_signature: signature.to_string(),
    })
}
