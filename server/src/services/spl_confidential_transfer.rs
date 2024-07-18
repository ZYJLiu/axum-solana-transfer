use crate::config::RPC_URL;
use anyhow::Result;
use futures::future::join_all;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction::create_account,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::TransferAccountInfo,
            instruction::{transfer_with_split_proofs, TransferSplitContextStateAccounts},
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        BaseStateWithExtensions, StateWithExtensionsOwned,
    },
    solana_zk_token_sdk::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{self, ElGamalKeypair},
        },
        instruction::ciphertext_commitment_equality::CiphertextCommitmentEqualityProofContext,
        zk_token_elgamal::pod::ElGamalPubkey,
        zk_token_proof_instruction::{
            close_context_state, BatchedGroupedCiphertext2HandlesValidityProofContext,
            BatchedRangeProofContext, ContextStateInfo, ProofInstruction,
        },
        zk_token_proof_program,
        zk_token_proof_state::ProofContextState,
    },
    state::{Account, Mint},
};
use std::mem::size_of;
use tokio::task;

pub async fn confidential_transfer(
    from_keypair: &Keypair,
    to_pubkey: &Pubkey,
    mint: &Pubkey,
    amount: f64,
) -> Result<Signature> {
    let rpc_client =
        RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

    // 1. Get associated token addresses
    let from_ata = get_associated_token_address_with_program_id(
        &from_keypair.pubkey(),
        mint,
        &spl_token_2022::id(),
    );
    let to_ata =
        get_associated_token_address_with_program_id(to_pubkey, mint, &spl_token_2022::id());

    // 2. Generate proof account keypairs
    let equality_proof_account = Keypair::new();
    let ciphertext_validity_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();

    // 3. Set up transfer context state accounts
    let transfer_context_state_accounts = TransferSplitContextStateAccounts {
        equality_proof: &equality_proof_account.pubkey(),
        ciphertext_validity_proof: &ciphertext_validity_proof_account.pubkey(),
        range_proof: &range_proof_account.pubkey(),
        authority: &from_keypair.pubkey(),
        no_op_on_uninitialized_split_context_state: false,
        close_split_context_state_accounts: None,
    };

    // 4. Get sender token account data and prepare transfer account info
    let sender_account_data = rpc_client.get_account(&from_ata)?;
    let sender_account = StateWithExtensionsOwned::<Account>::unpack(sender_account_data.data)?;
    let sender_extension_data = sender_account.get_extension::<ConfidentialTransferAccount>()?;
    let transfer_account_info = TransferAccountInfo::new(sender_extension_data);

    // 5. Generate sender's ElGamal keypair and AES key
    let sender_elgamal_keypair =
        ElGamalKeypair::new_from_signer(from_keypair, &from_ata.to_bytes()).unwrap();
    let sender_aes_key = AeKey::new_from_signer(from_keypair, &from_ata.to_bytes()).unwrap();

    // 6. Get recipient's ElGamal pubkey
    let recipient_account_data = rpc_client.get_account(&to_ata)?;
    let recipient_elgamal_pubkey: elgamal::ElGamalPubkey =
        StateWithExtensionsOwned::<Account>::unpack(recipient_account_data.data)?
            .get_extension::<ConfidentialTransferAccount>()?
            .elgamal_pubkey
            .try_into()?;

    // 7. Get mint data, auditor's ElGamal pubkey, and adjust transfer amount by decimals
    let mint_account_data = rpc_client.get_account(mint)?;
    let mint_state = StateWithExtensionsOwned::<Mint>::unpack(mint_account_data.data)?;

    // Get mint decimals and adjust amount
    let decimals = mint_state.base.decimals;
    let amount = (amount * 10u64.pow(decimals as u32) as f64) as u64;

    // Get auditor's ElGamal pubkey (stored in mint account) if it exists
    let auditor_elgamal_pubkey: Option<elgamal::ElGamalPubkey> = Option::<ElGamalPubkey>::from(
        mint_state
            .get_extension::<ConfidentialTransferMint>()?
            .auditor_elgamal_pubkey,
    )
    .map(|pubkey| pubkey.try_into())
    .transpose()?;

    // 8. Generate proof data
    let (
        equality_proof_data,
        ciphertext_validity_proof_data,
        range_proof_data,
        source_decrypt_handles,
    ) = transfer_account_info.generate_split_transfer_proof_data(
        amount,
        &sender_elgamal_keypair,
        &sender_aes_key,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
    )?;

    // 9. Create and initialize proof accounts
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    let mut transactions = Vec::new();

    // Range Proof
    let range_proof_space = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let range_proof_rent = rpc_client.get_minimum_balance_for_rent_exemption(range_proof_space)?;
    let create_range_proof_ix = create_account(
        &from_keypair.pubkey(),
        &range_proof_account.pubkey(),
        range_proof_rent,
        range_proof_space as u64,
        &zk_token_proof_program::id(),
    );
    // Range Proof is too large for to create and initialize in one transaction
    let transaction = Transaction::new_signed_with_payer(
        &[create_range_proof_ix],
        Some(&from_keypair.pubkey()),
        &[from_keypair, &range_proof_account],
        recent_blockhash,
    );
    // First send and confirm transaction to create the range proof account
    rpc_client.send_and_confirm_transaction(&transaction)?;

    let verify_range_proof_ix = ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: transfer_context_state_accounts.range_proof,
            context_state_authority: transfer_context_state_accounts.authority,
        }),
        &range_proof_data,
    );

    transactions.push(Transaction::new_signed_with_payer(
        &[verify_range_proof_ix],
        Some(&from_keypair.pubkey()),
        &[from_keypair],
        recent_blockhash,
    ));

    // Equality Proof
    let equality_proof_space =
        size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let equality_proof_rent =
        rpc_client.get_minimum_balance_for_rent_exemption(equality_proof_space)?;
    let create_equality_proof_ix = create_account(
        &from_keypair.pubkey(),
        &equality_proof_account.pubkey(),
        equality_proof_rent,
        equality_proof_space as u64,
        &zk_token_proof_program::id(),
    );
    let verify_equality_proof_ix = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: transfer_context_state_accounts.equality_proof,
                context_state_authority: transfer_context_state_accounts.authority,
            }),
            &equality_proof_data,
        );

    transactions.push(Transaction::new_signed_with_payer(
        &[create_equality_proof_ix, verify_equality_proof_ix],
        Some(&from_keypair.pubkey()),
        &[from_keypair, &equality_proof_account],
        recent_blockhash,
    ));

    // Ciphertext Validity Proof
    let ciphertext_validity_proof_space =
        size_of::<ProofContextState<BatchedGroupedCiphertext2HandlesValidityProofContext>>();
    let ciphertext_validity_proof_rent =
        rpc_client.get_minimum_balance_for_rent_exemption(ciphertext_validity_proof_space)?;
    let create_ciphertext_validity_proof_ix = create_account(
        &from_keypair.pubkey(),
        &ciphertext_validity_proof_account.pubkey(),
        ciphertext_validity_proof_rent,
        ciphertext_validity_proof_space as u64,
        &zk_token_proof_program::id(),
    );
    let verify_ciphertext_validity_proof_ix =
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity.encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: transfer_context_state_accounts.ciphertext_validity_proof,
                context_state_authority: transfer_context_state_accounts.authority,
            }),
            &ciphertext_validity_proof_data,
        );

    transactions.push(Transaction::new_signed_with_payer(
        &[
            create_ciphertext_validity_proof_ix,
            verify_ciphertext_validity_proof_ix,
        ],
        Some(&from_keypair.pubkey()),
        &[from_keypair, &ciphertext_validity_proof_account],
        recent_blockhash,
    ));

    let signature_futures: Vec<_> = transactions
        .into_iter()
        .map(|transaction| {
            // send_and_confirm_transaction is blocking, spawn new thread to send each transaction
            task::spawn_blocking(move || {
                RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed())
                    .send_and_confirm_transaction(&transaction)
            })
        })
        .collect();

    // Send and confirm proof transactions in parallel
    join_all(signature_futures).await;

    // 10. Confidential transfer
    let new_decryptable_available_balance = transfer_account_info
        .new_decryptable_available_balance(amount, &sender_aes_key)
        .map_err(|_| anyhow::anyhow!("Failed to calculate new decryptable balance"))?;

    let transfer_ix = transfer_with_split_proofs(
        &spl_token_2022::id(),
        &from_ata,
        mint,
        &to_ata,
        new_decryptable_available_balance.into(),
        &from_keypair.pubkey(),
        transfer_context_state_accounts,
        &source_decrypt_handles,
    )?;

    // 11. Close proof accounts
    let close_equality_proof_ix = close_context_state(
        ContextStateInfo {
            context_state_account: &equality_proof_account.pubkey(),
            context_state_authority: &from_keypair.pubkey(),
        },
        &from_keypair.pubkey(),
    );
    let close_ciphertext_validity_proof_ix = close_context_state(
        ContextStateInfo {
            context_state_account: &ciphertext_validity_proof_account.pubkey(),
            context_state_authority: &from_keypair.pubkey(),
        },
        &from_keypair.pubkey(),
    );
    let close_range_proof_ix = close_context_state(
        ContextStateInfo {
            context_state_account: &range_proof_account.pubkey(),
            context_state_authority: &from_keypair.pubkey(),
        },
        &from_keypair.pubkey(),
    );

    // Send transaction with confidential transfer and close account instructions
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[
            transfer_ix,
            close_equality_proof_ix,
            close_ciphertext_validity_proof_ix,
            close_range_proof_ix,
        ],
        Some(&from_keypair.pubkey()),
        &[from_keypair],
        recent_blockhash,
    );

    let transfer_signature = rpc_client.send_and_confirm_transaction(&transaction)?;

    Ok(transfer_signature)
}
