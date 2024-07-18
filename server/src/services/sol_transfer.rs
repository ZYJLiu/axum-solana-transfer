use crate::config::RPC_URL;
use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::Signer;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    system_instruction,
    transaction::Transaction,
};

pub async fn transfer_sol(
    from_keypair: &Keypair,
    to_pubkey: &Pubkey,
    amount: f64,
) -> Result<Signature> {
    let rpc_client =
        RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

    let lamports = (amount * LAMPORTS_PER_SOL as f64) as u64;
    let instruction = system_instruction::transfer(&from_keypair.pubkey(), to_pubkey, lamports);

    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .context("Failed to get latest blockhash")?;

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&from_keypair.pubkey()),
        &[from_keypair],
        recent_blockhash,
    );

    rpc_client
        .send_and_confirm_transaction(&transaction)
        .context("Failed to send SOL transfer transaction")
}
