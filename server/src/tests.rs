// cargo test -- --nocapture
#[cfg(test)]
mod test {
    use crate::{
        app,
        tests::test_helpers::{
            setup_confidential_transfer_test, setup_sol_transfer_test,
            setup_spl_2022_with_transfer_hook_test, setup_spl_transfer_2022_test,
            setup_spl_transfer_test,
        },
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use solana_sdk::signature::Signer;
    use tower::ServiceExt;

    async fn send_transfer_request(request_body: Value) -> Value {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/transfer")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_sol_transfer() -> Result<(), Box<dyn std::error::Error>> {
        let (wallet_1, wallet_2) = setup_sol_transfer_test().await?;

        let request_body = json!({
            "from_keypair": format!("{:?}", wallet_1.to_bytes().to_vec()),
            "to": wallet_2.pubkey().to_string(),
            "amount": 0.01
        });

        let body = send_transfer_request(request_body).await;
        assert!(body.get("message").is_some());
        assert!(body.get("transaction_signature").is_some());

        let signature = body["transaction_signature"].as_str().unwrap();
        println!("Transfer SOL: {}", signature);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_spl_transfer() -> Result<(), Box<dyn std::error::Error>> {
        let (wallet_1, wallet_2, mint) = setup_spl_transfer_test().await?;

        let request_body = json!({
            "from_keypair": format!("{:?}", wallet_1.to_bytes().to_vec()),
            "to": wallet_2.pubkey().to_string(),
            "mint": mint.pubkey().to_string(),
            "amount": 0.01,
            "confidential": false
        });

        let body = send_transfer_request(request_body).await;
        assert!(body.get("message").is_some());
        assert!(body.get("transaction_signature").is_some());

        let signature = body["transaction_signature"].as_str().unwrap();
        println!("Transfer SPL: {}", signature);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_spl_transfer_2022() -> Result<(), Box<dyn std::error::Error>> {
        let (wallet_1, wallet_2, mint) = setup_spl_transfer_2022_test().await?;

        let request_body = json!({
            "from_keypair": format!("{:?}", wallet_1.to_bytes().to_vec()),
            "to": wallet_2.pubkey().to_string(),
            "mint": mint.pubkey().to_string(),
            "amount": 0.01,
        });

        let body = send_transfer_request(request_body).await;
        assert!(body.get("message").is_some());
        assert!(body.get("transaction_signature").is_some());

        let signature = body["transaction_signature"].as_str().unwrap();
        println!("Transfer SPL 2022: {}", signature);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_spl_transfer_2022_with_transfer_hook() -> Result<(), Box<dyn std::error::Error>> {
        let (wallet_1, wallet_2, mint) = setup_spl_2022_with_transfer_hook_test().await?;

        let request_body = json!({
            "from_keypair": format!("{:?}", wallet_1.to_bytes().to_vec()),
            "to": wallet_2.pubkey().to_string(),
            "mint": mint.pubkey().to_string(),
            "amount": 0.01,
        });

        let body = send_transfer_request(request_body).await;
        assert!(body.get("message").is_some());
        assert!(body.get("transaction_signature").is_some());

        let signature = body["transaction_signature"].as_str().unwrap();
        println!("Transfer SPL 2022 with Transfer Hook: {}", signature);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_confidential_transfer() -> Result<(), Box<dyn std::error::Error>> {
        let (wallet_1, wallet_2, mint) = setup_confidential_transfer_test().await?;

        let request_body = json!({
            "from_keypair": format!("{:?}", wallet_1.to_bytes().to_vec()),
            "to": wallet_2.pubkey().to_string(),
            "mint": mint.pubkey().to_string(),
            "amount": 0.01,
            "confidential": true
        });

        let body = send_transfer_request(request_body).await;
        assert!(body.get("message").is_some());
        assert!(body.get("transaction_signature").is_some());

        let signature = body["transaction_signature"].as_str().unwrap();
        println!(
            "Transfer SPL 2022 with Confidential Transfer: {}",
            signature
        );
        Ok(())
    }
}

#[cfg(test)]
mod test_helpers {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::Instruction,
        native_token::LAMPORTS_PER_SOL,
        program_pack::Pack,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    };
    use spl_associated_token_account::{
        get_associated_token_address, get_associated_token_address_with_program_id,
        instruction::create_associated_token_account,
    };
    use spl_token_2022::{
        extension::{
            confidential_transfer::{
                account_info::ApplyPendingBalanceAccountInfo, instruction::*,
                ConfidentialTransferAccount,
            },
            BaseStateWithExtensions, ExtensionType, StateWithExtensionsOwned,
        },
        instruction::{initialize_mint, mint_to, reallocate},
        proof::ProofLocation,
        solana_zk_token_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
        state::{Account, Mint},
    };
    use spl_token_client::token::ExtensionInitializationParams;
    use spl_transfer_hook_interface::{
        get_extra_account_metas_address, instruction::initialize_extra_account_meta_list,
    };
    use std::{str::FromStr, time::Duration};

    use crate::config::RPC_URL;

    pub async fn setup_sol_transfer_test() -> Result<(Keypair, Keypair), Box<dyn std::error::Error>>
    {
        // Set up RPC client
        let client =
            RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

        // Create keypairs
        let from_keypair = Keypair::new();
        let to_keypair = Keypair::new();

        // Request airdrops
        client.request_airdrop(&from_keypair.pubkey(), LAMPORTS_PER_SOL)?;
        client.request_airdrop(&to_keypair.pubkey(), LAMPORTS_PER_SOL)?;

        // Wait for airdrop transactions to be confirmed
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok((from_keypair, to_keypair))
    }

    pub async fn setup_spl_transfer_test(
    ) -> Result<(Keypair, Keypair, Keypair), Box<dyn std::error::Error>> {
        // Set up RPC client
        let client =
            RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

        // Create keypairs
        let wallet_1 = Keypair::new();
        let wallet_2 = Keypair::new();
        let mint = Keypair::new();

        // Request airdrops
        client.request_airdrop(&wallet_1.pubkey(), LAMPORTS_PER_SOL)?;
        client.request_airdrop(&wallet_2.pubkey(), LAMPORTS_PER_SOL)?;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Create Mint Account (without extensions)
        let decimals = 2;
        let space = Mint::get_packed_len();
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let create_account_instruction = system_instruction::create_account(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token::id(),
        );

        let initialize_mint_instruction = initialize_mint(
            &spl_token::id(),
            &mint.pubkey(),
            &wallet_1.pubkey(),
            Some(&wallet_1.pubkey()),
            decimals,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[create_account_instruction, initialize_mint_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1, &mint],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Create Sender Token Account
        let sender_associated_token_address =
            get_associated_token_address(&wallet_1.pubkey(), &mint.pubkey());

        let create_sender_ata_instruction = create_associated_token_account(
            &wallet_1.pubkey(),
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token::id(),
        );

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[create_sender_ata_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Mint Tokens
        let amount = 10000;
        let mint_to_instruction = spl_token::instruction::mint_to(
            &spl_token::id(),
            &mint.pubkey(),
            &sender_associated_token_address,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
            amount,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[mint_to_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        Ok((wallet_1, wallet_2, mint))
    }

    pub async fn setup_spl_transfer_2022_test(
    ) -> Result<(Keypair, Keypair, Keypair), Box<dyn std::error::Error>> {
        let client =
            RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

        let wallet_1 = Keypair::new();
        let wallet_2 = Keypair::new();
        let mint = Keypair::new();

        client.request_airdrop(&wallet_1.pubkey(), LAMPORTS_PER_SOL)?;
        client.request_airdrop(&wallet_2.pubkey(), LAMPORTS_PER_SOL)?;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let decimals = 2;
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[])?;
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let create_account_instruction = system_instruction::create_account(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token_2022::id(),
        );

        let initialize_mint_instruction = initialize_mint(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &wallet_1.pubkey(),
            Some(&wallet_1.pubkey()),
            decimals,
        )?;

        let transaction = Transaction::new_signed_with_payer(
            &[create_account_instruction, initialize_mint_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1, &mint],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        let sender_ata = get_associated_token_address_with_program_id(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let create_sender_ata_ix = create_associated_token_account(
            &wallet_1.pubkey(),
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let transaction = Transaction::new_signed_with_payer(
            &[create_sender_ata_ix],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        let amount = 100 * 10u64.pow(decimals as u32);
        let mint_to_ix = spl_token_2022::instruction::mint_to(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &sender_ata,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
            amount,
        )?;

        let transaction = Transaction::new_signed_with_payer(
            &[mint_to_ix],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        Ok((wallet_1, wallet_2, mint))
    }

    pub async fn setup_spl_2022_with_transfer_hook_test(
    ) -> Result<(Keypair, Keypair, Keypair), Box<dyn std::error::Error>> {
        let client =
            RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

        let wallet_1 = Keypair::new();
        let wallet_2 = Keypair::new();
        let mint = Keypair::new();
        let transfer_hook_program_id =
            Pubkey::from_str("3C3pUh5XxUd9Nz1P85mDYfUu4PXAFRg1aHCos66epHQK")?;

        client.request_airdrop(&wallet_1.pubkey(), LAMPORTS_PER_SOL)?;
        client.request_airdrop(&wallet_2.pubkey(), LAMPORTS_PER_SOL)?;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let decimals = 2;
        let extensions = vec![ExtensionType::TransferHook];
        let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let create_account_instruction = system_instruction::create_account(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token_2022::id(),
        );

        let transfer_hook_extension = ExtensionInitializationParams::TransferHook {
            authority: Some(wallet_1.pubkey()),
            program_id: Some(transfer_hook_program_id),
        };

        let initialize_transfer_hook_instruction =
            transfer_hook_extension.instruction(&spl_token_2022::id(), &mint.pubkey())?;

        let initialize_mint_instruction = initialize_mint(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &wallet_1.pubkey(),
            Some(&wallet_1.pubkey()),
            decimals,
        )?;

        let transaction = Transaction::new_signed_with_payer(
            &[
                create_account_instruction,
                initialize_transfer_hook_instruction,
                initialize_mint_instruction,
            ],
            Some(&wallet_1.pubkey()),
            &[&wallet_1, &mint],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        let extra_account_metas_address =
            get_extra_account_metas_address(&mint.pubkey(), &transfer_hook_program_id);
        let init_extra_account_metas = [];

        let init_extra_account_metas_ix = initialize_extra_account_meta_list(
            &transfer_hook_program_id,
            &extra_account_metas_address,
            &mint.pubkey(),
            &wallet_1.pubkey(),
            &init_extra_account_metas,
        );

        let transaction = Transaction::new_signed_with_payer(
            &[init_extra_account_metas_ix],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        let sender_ata = get_associated_token_address_with_program_id(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let create_sender_ata_ix = create_associated_token_account(
            &wallet_1.pubkey(),
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let transaction = Transaction::new_signed_with_payer(
            &[create_sender_ata_ix],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        let amount = 100 * 10u64.pow(decimals as u32);
        let mint_to_ix = spl_token_2022::instruction::mint_to(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &sender_ata,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
            amount,
        )?;

        let transaction = Transaction::new_signed_with_payer(
            &[mint_to_ix],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            client.get_latest_blockhash()?,
        );
        client.send_and_confirm_transaction(&transaction)?;

        Ok((wallet_1, wallet_2, mint))
    }

    pub async fn setup_confidential_transfer_test(
    ) -> Result<(Keypair, Keypair, Keypair), Box<dyn std::error::Error>> {
        // Set up RPC client
        let client =
            RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());

        // Create keypairs
        let wallet_1 = Keypair::new();
        let wallet_2 = Keypair::new();
        let mint = Keypair::new();

        // Request airdrops
        client.request_airdrop(&wallet_1.pubkey(), LAMPORTS_PER_SOL)?;
        client.request_airdrop(&wallet_2.pubkey(), LAMPORTS_PER_SOL)?;

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Create Mint Account
        let decimals = 2;
        let auditor_elgamal_keypair = ElGamalKeypair::new_rand();

        let confidential_transfer_mint_extension =
            ExtensionInitializationParams::ConfidentialTransferMint {
                authority: Some(wallet_1.pubkey()),
                auto_approve_new_accounts: true,
                auditor_elgamal_pubkey: Some((*auditor_elgamal_keypair.pubkey()).into()),
            };

        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let create_account_instruction = system_instruction::create_account(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token_2022::id(),
        );

        let extension_instruction = confidential_transfer_mint_extension
            .instruction(&spl_token_2022::id(), &mint.pubkey())?;

        let initialize_mint_instruction = initialize_mint(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &wallet_1.pubkey(),
            Some(&wallet_1.pubkey()),
            decimals,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[
                create_account_instruction,
                extension_instruction,
                initialize_mint_instruction,
            ],
            Some(&wallet_1.pubkey()),
            &[&wallet_1, &mint],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Create Sender Token Account
        let sender_associated_token_address = get_associated_token_address_with_program_id(
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let create_sender_ata_instruction = create_associated_token_account(
            &wallet_1.pubkey(),
            &wallet_1.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let reallocate_sender_instruction = reallocate(
            &spl_token_2022::id(),
            &sender_associated_token_address,
            &wallet_1.pubkey(),
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
            &[ExtensionType::ConfidentialTransferAccount],
        )?;

        let sender_elgamal_keypair = ElGamalKeypair::new_from_signer(
            &wallet_1,
            &sender_associated_token_address.to_bytes(),
        )?;
        let sender_aes_key =
            AeKey::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())?;

        let maximum_pending_balance_credit_counter = 65536;
        let sender_decryptable_balance = sender_aes_key.encrypt(0);

        let sender_proof_data = PubkeyValidityData::new(&sender_elgamal_keypair)?;
        let sender_proof_location =
            ProofLocation::InstructionOffset(1.try_into().unwrap(), &sender_proof_data);

        let configure_sender_account_instruction = configure_account(
            &spl_token_2022::id(),
            &sender_associated_token_address,
            &mint.pubkey(),
            sender_decryptable_balance,
            maximum_pending_balance_credit_counter,
            &wallet_1.pubkey(),
            &[],
            sender_proof_location,
        )?;

        // Create Recipient Token Account
        let recipient_associated_token_address = get_associated_token_address_with_program_id(
            &wallet_2.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let create_recipient_ata_instruction = create_associated_token_account(
            &wallet_1.pubkey(), // funding account (using wallet_1 to fund)
            &wallet_2.pubkey(),
            &mint.pubkey(),
            &spl_token_2022::id(),
        );

        let reallocate_recipient_instruction = reallocate(
            &spl_token_2022::id(),
            &recipient_associated_token_address,
            &wallet_1.pubkey(), // payer (using wallet_1 to pay)
            &wallet_2.pubkey(),
            &[&wallet_2.pubkey()],
            &[ExtensionType::ConfidentialTransferAccount],
        )?;

        let recipient_elgamal_keypair = ElGamalKeypair::new_from_signer(
            &wallet_2,
            &recipient_associated_token_address.to_bytes(),
        )?;
        let recipient_aes_key =
            AeKey::new_from_signer(&wallet_2, &recipient_associated_token_address.to_bytes())?;

        let recipient_decryptable_balance = recipient_aes_key.encrypt(0);

        let recipient_proof_data = PubkeyValidityData::new(&recipient_elgamal_keypair)?;
        let recipient_proof_location =
            ProofLocation::InstructionOffset(1.try_into().unwrap(), &recipient_proof_data);

        let configure_recipient_account_instruction = configure_account(
            &spl_token_2022::id(),
            &recipient_associated_token_address,
            &mint.pubkey(),
            recipient_decryptable_balance,
            maximum_pending_balance_credit_counter,
            &wallet_2.pubkey(),
            &[],
            recipient_proof_location,
        )?;

        let mut instructions = vec![
            create_sender_ata_instruction,
            reallocate_sender_instruction,
            create_recipient_ata_instruction,
            reallocate_recipient_instruction,
        ];
        instructions.extend(configure_sender_account_instruction);
        instructions.extend(configure_recipient_account_instruction);

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&wallet_1.pubkey()),
            &[&wallet_1, &wallet_2],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Mint Tokens
        let amount = 10000;
        let mint_to_instruction: Instruction = mint_to(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &sender_associated_token_address,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
            amount,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[mint_to_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Deposit Tokens
        let deposit_amount = 10000;
        let deposit_instruction = deposit(
            &spl_token_2022::id(),
            &sender_associated_token_address,
            &mint.pubkey(),
            deposit_amount,
            decimals,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[deposit_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        // Apply Pending Balance
        let data = client.get_account(&sender_associated_token_address)?;
        let account = StateWithExtensionsOwned::<Account>::unpack(data.data)?;
        let confidential_transfer_account =
            account.get_extension::<ConfidentialTransferAccount>()?;
        let apply_pending_balance_account_info =
            ApplyPendingBalanceAccountInfo::new(confidential_transfer_account);
        let expected_pending_balance_credit_counter =
            apply_pending_balance_account_info.pending_balance_credit_counter();
        let new_decryptable_available_balance = apply_pending_balance_account_info
            .new_decryptable_available_balance(sender_elgamal_keypair.secret(), &sender_aes_key)?;

        let apply_pending_balance_instruction = apply_pending_balance(
            &spl_token_2022::id(),
            &sender_associated_token_address,
            expected_pending_balance_credit_counter,
            new_decryptable_available_balance,
            &wallet_1.pubkey(),
            &[&wallet_1.pubkey()],
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[apply_pending_balance_instruction],
            Some(&wallet_1.pubkey()),
            &[&wallet_1],
            recent_blockhash,
        );
        client.send_and_confirm_transaction(&transaction)?;

        Ok((wallet_1, wallet_2, mint))
    }
}
