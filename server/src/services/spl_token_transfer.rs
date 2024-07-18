use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::Signer;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction as associated_token_instruction,
};
use spl_token_2022::{
    extension::{transfer_hook, BaseStateWithExtensions, StateWithExtensions},
    instruction,
    state::Mint,
};
use spl_transfer_hook_interface::offchain::add_extra_account_metas_for_execute;

use crate::config::RPC_URL;

pub async fn transfer_token(
    from_keypair: &Keypair,
    to_pubkey: &Pubkey,
    mint: &Pubkey,
    amount: f64,
) -> Result<Signature> {
    let rpc_client =
        RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

    let account = rpc_client
        .get_account(mint)
        .context("Failed to get mint account")?;
    let mint_data =
        StateWithExtensions::<Mint>::unpack(&account.data).context("Failed to unpack mint data")?;
    // let extension_types = mint_data.get_extension_types().unwrap();

    let from_ata =
        get_associated_token_address_with_program_id(&from_keypair.pubkey(), mint, &account.owner);
    let to_ata = get_associated_token_address_with_program_id(to_pubkey, mint, &account.owner);

    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .context("Failed to get latest blockhash")?;

    let mut instructions = vec![];

    if rpc_client.get_account(&to_ata).is_err() {
        instructions.push(
            associated_token_instruction::create_associated_token_account(
                &from_keypair.pubkey(),
                to_pubkey,
                mint,
                &account.owner,
            ),
        );
    }

    println!("Amount: {}", amount);
    println!("Decimals: {}", mint_data.base.decimals);
    let token_amount = (amount * 10_f64.powi(mint_data.base.decimals as i32)) as u64;

    println!("Token Amount: {}", token_amount);
    let mut transfer_instruction = instruction::transfer_checked(
        &account.owner,
        &from_ata,
        mint,
        &to_ata,
        &from_keypair.pubkey(),
        &[&from_keypair.pubkey()],
        token_amount,
        mint_data.base.decimals,
    )
    .context("Failed to create transfer instruction")?;

    if let Some(program_id) = transfer_hook::get_program_id(&mint_data) {
        println!("Transfer hook program ID found: {}", program_id);
        add_extra_account_metas_for_execute(
            &mut transfer_instruction,
            &program_id,
            &from_ata,
            mint,
            &to_ata,
            &from_keypair.pubkey(),
            token_amount,
            |address| async move {
                println!("Fetching account for address: {}", address);
                RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed())
                    .get_account(&address)
                    .map(|account| {
                        println!("Account fetched successfully");
                        Some(account.data)
                    })
                    .or_else(|e| {
                        println!("Account does not exist: {:?}", e);
                        Ok(None)
                    })
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add extra account metas: {:?}", e))?;
        println!("Added extra account metas successfully");
    } else {
        println!("No transfer hook program ID found");
    }
    instructions.push(transfer_instruction);

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&from_keypair.pubkey()),
        &[from_keypair],
        recent_blockhash,
    );

    rpc_client
        .send_and_confirm_transaction(&transaction)
        .context("Failed to send SPL token transfer transaction")
}
