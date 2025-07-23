use std::{fs, path::Path};

use miden_client::transaction::{
    InputNote, InputNotes, OutputNote, OutputNotes, TransactionExecutorError,
};
use miden_client::{
    Client, ClientError, Felt, Word, ZERO, asset::FungibleAsset, crypto::SecretKey,
    keystore::FilesystemKeyStore, note::NoteType, rpc::Endpoint,
    transaction::TransactionRequestBuilder,
};

use miden_client::crypto::FeltRng;
use miden_client_tools::{
    create_exact_p2id_note, create_library, create_tx_script, delete_keystore_and_store,
    instantiate_client, setup_accounts_and_faucets,
};
use miden_crypto::{dsa::rpo_falcon512::Polynomial, hash::rpo::Rpo256 as Hasher};
use miden_multisig::common::build_multisig;
use miden_objects::account::Account;
use miden_objects::vm::AdviceMap;

// ================================================================================================
// SHARED SETUP FUNCTIONS (copied from working tests)
// ================================================================================================

/// Common test setup that both tests need
struct MultisigTestSetup {
    client: Client,
    keys: Vec<SecretKey>,
    pub_keys: Vec<Word>,
    multisig_wallet: Account,
    faucet_a: miden_objects::account::Account,
    sig_check_script: miden_objects::transaction::TransactionScript,
    consume_tx_script: miden_objects::transaction::TransactionScript,
    accounts: Vec<Account>,
}

async fn setup_multisig_test() -> Result<MultisigTestSetup, ClientError> {
    delete_keystore_and_store(None).await;

    let endpoint = Endpoint::localhost();
    let mut client = instantiate_client(endpoint, None).await.unwrap();

    let sync_summary = client.sync_state().await.unwrap();
    println!("Latest block: {}", sync_summary.block_num);

    // Generate keys and public keys
    let number_of_keys = 3;
    let mut keys = Vec::new();
    let mut pub_keys: Vec<Word> = Vec::new();

    for i in 0..number_of_keys {
        let key = SecretKey::with_rng(client.rng());
        keys.push(key.clone());
        pub_keys.push(key.public_key().into());

        let pub_key_word: Word = keys[i].public_key().into();
        println!("pub key #{:?}: {:?}", i, pub_key_word);
    }

    // Create scripts
    let script_code =
        fs::read_to_string(Path::new("./masm/scripts/sig_check_script.masm")).unwrap();
    let account_code = fs::read_to_string(Path::new("./masm/auth/multisig_auth.masm")).unwrap();
    let account_component_lib = create_library(account_code.clone(), "multisig::multisig").unwrap();
    let sig_check_script = create_tx_script(script_code, Some(account_component_lib)).unwrap();

    let consume_script_code =
        fs::read_to_string(Path::new("./masm/scripts/helper_note_consume_script.masm")).unwrap();
    let library = create_library(account_code, "multisig::multisig").unwrap();
    let consume_tx_script = create_tx_script(consume_script_code, Some(library)).unwrap();

    // Create multisig wallet
    let multisig_wallet =
        build_multisig(&mut client, pub_keys.clone(), Some(pub_keys.len() as u64))
            .await
            .unwrap();

    println!(
        "multisig accountid: {:?} {:?}",
        multisig_wallet.id().prefix(),
        multisig_wallet.id().suffix()
    );

    // Setup accounts and balances
    let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();
    let balances = vec![
        vec![100, 0], // For account[0] => Alice 100 tokens A & B
        vec![100, 0], // For account[1] => Bob 100 tokens A & B
    ];
    let (accounts, faucets) =
        setup_accounts_and_faucets(&mut client, keystore, 2, 2, balances).await?;

    let faucet_a = faucets[0].clone();

    Ok(MultisigTestSetup {
        client,
        keys,
        pub_keys,
        multisig_wallet,
        faucet_a,
        sig_check_script,
        consume_tx_script,
        accounts,
    })
}

/// Generate signature data for a transaction message digest
/// This function makes it clear what we're signing: the transaction message digest
fn generate_signature_advice_map(
    keys: &[SecretKey],
    transaction_message_digest: miden_crypto::hash::rpo::RpoDigest,
    description: &str,
) -> AdviceMap {
    println!("Generating signatures for: {}", description);
    println!(
        "Signing digest: {:?}",
        Word::from(transaction_message_digest)
    );

    let mut advice_map = AdviceMap::default();

    for (i, key) in keys.iter().enumerate() {
        let signature = key.sign(transaction_message_digest.into());

        let nonce = signature.nonce().to_elements();
        let s2 = signature.sig_poly();
        let h = key.compute_pub_key_poly().0;
        let pi = Polynomial::mul_modulo_p(&h, s2);

        let mut polynomials: Vec<Felt> = h
            .coefficients
            .iter()
            .map(|a| Felt::from(a.value() as u32))
            .collect();
        polynomials.extend(s2.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
        polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

        let digest_polynomials = Hasher::hash_elements(&polynomials);
        let challenge = (digest_polynomials[0], digest_polynomials[1]);

        let pub_key_felts: Word = key.public_key().into();
        let msg_felts: Word = transaction_message_digest.into();

        let mut result: Vec<Felt> = vec![
            pub_key_felts[0],
            pub_key_felts[1],
            pub_key_felts[2],
            pub_key_felts[3],
            msg_felts[0],
            msg_felts[1],
            msg_felts[2],
            msg_felts[3],
            challenge.0,
            challenge.1,
        ];

        result.extend_from_slice(&polynomials);
        result.extend_from_slice(&nonce);

        // Insert the signature data into the advice map
        let advice_key: Word = [Felt::new(i as u64), ZERO, ZERO, ZERO];
        advice_map.insert(advice_key.into(), result.clone());

        println!("Generated signature #{} for key: {:?}", i, key.public_key());
    }

    advice_map
}

/// Compute transaction message digest from transaction components
/// This makes it clear what components are being hashed together
fn compute_transaction_message_digest(
    account_delta_commitment: Word,
    input_notes_commitment: Word,
    output_notes_commitment: Word,
    salt: Word,
    description: &str,
) -> miden_crypto::hash::rpo::RpoDigest {
    println!("Computing transaction message digest for: {}", description);
    println!("  Account delta commitment: {:?}", account_delta_commitment);
    println!("  Input notes commitment: {:?}", input_notes_commitment);
    println!("  Output notes commitment: {:?}", output_notes_commitment);
    println!("  Salt: {:?}", salt);

    // Compute the same hash as in MASM: hash([ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT, SALT])
    let mut hash_input = vec![];
    hash_input.extend(account_delta_commitment);
    hash_input.extend(input_notes_commitment);
    hash_input.extend(output_notes_commitment);
    hash_input.extend(salt);

    let digest = Hasher::hash_elements(&hash_input);
    println!("  Computed digest: {:?}", Word::from(digest));

    digest
}

// ================================================================================================
// INVARIANT TESTS - These should fail to demonstrate multisig security
// ================================================================================================

#[tokio::test]
async fn multisig_fails_insufficient_signers() -> Result<(), ClientError> {
    let mut setup = setup_multisig_test().await?;

    // -------------------------------------------------------------------------
    // STEP 1: Fund Multisig with a note to consume
    // -------------------------------------------------------------------------
    let multisig_amount = 100;
    let asset = FungibleAsset::new(setup.faucet_a.id(), multisig_amount).unwrap();
    let mint_req = TransactionRequestBuilder::new()
        .build_mint_fungible_asset(
            asset,
            setup.multisig_wallet.id(),
            NoteType::Public,
            setup.client.rng(),
        )
        .unwrap();

    let mint_exec = setup
        .client
        .new_transaction(setup.faucet_a.id(), mint_req)
        .await?;
    setup.client.submit_transaction(mint_exec.clone()).await?;

    let minted_note = match mint_exec.created_notes().get_note(0) {
        OutputNote::Full(note) => note.clone(),
        _ => panic!("Expected full minted note"),
    };

    // -------------------------------------------------------------------------
    // STEP 2: Consume the input note first
    // -------------------------------------------------------------------------
    let account_delta_commitment =
        Word::from([Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)]);
    let input_notes =
        InputNotes::new(vec![InputNote::unauthenticated(minted_note.clone())]).unwrap();
    let input_notes_commitment = input_notes.commitment();
    let output_notes = OutputNotes::new(vec![]).unwrap();
    let output_notes_commitment = output_notes.commitment();
    let salt = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);

    let transaction_message_digest = compute_transaction_message_digest(
        account_delta_commitment,
        input_notes_commitment.into(),
        output_notes_commitment.into(),
        salt,
        "input note consumption",
    );

    let advice_map = generate_signature_advice_map(
        &setup.keys,
        transaction_message_digest,
        "input note consumption",
    );

    let consume_req = TransactionRequestBuilder::new()
        .unauthenticated_input_notes([(minted_note, None)])
        .extend_advice_map(advice_map)
        .custom_script(setup.consume_tx_script)
        .build()?;

    let consume_exec = setup
        .client
        .new_transaction(setup.multisig_wallet.id(), consume_req)
        .await
        .unwrap();

    setup
        .client
        .submit_transaction(consume_exec.clone())
        .await?;
    setup.client.sync_state().await?;

    // -------------------------------------------------------------------------
    // STEP 3: Try to create output note with INSUFFICIENT SIGNATURES
    // -------------------------------------------------------------------------
    let asset_amount = 50;
    let p2id_asset = FungibleAsset::new(setup.faucet_a.id(), asset_amount).unwrap();
    let p2id_assets = vec![p2id_asset.into()];
    let serial_num = setup.client.rng().draw_word();

    let recipient_account = &setup.accounts[0];

    let p2id_output_note = create_exact_p2id_note(
        setup.multisig_wallet.id(),
        recipient_account.id(),
        p2id_assets,
        NoteType::Public,
        ZERO,
        serial_num,
    )
    .unwrap();

    let account_delta_commitment =
        Word::from([Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)]);
    let input_notes: InputNotes<InputNote> = InputNotes::new(vec![]).unwrap();
    let input_notes_commitment = input_notes.commitment();
    let output_notes = OutputNotes::new(vec![OutputNote::Full(p2id_output_note.clone())]).unwrap();
    let output_notes_commitment = output_notes.commitment();
    let salt = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);

    let transaction_message_digest = compute_transaction_message_digest(
        account_delta_commitment,
        input_notes_commitment.into(),
        output_notes_commitment.into(),
        salt,
        "output note creation with insufficient signatures",
    );

    // ONLY SIGN WITH FIRST 2 KEYS (insufficient for 3-key multisig)
    let insufficient_keys = &setup.keys[0..2];
    let mut advice_map = generate_signature_advice_map(
        insufficient_keys,
        transaction_message_digest,
        "output note creation with insufficient signatures",
    );

    // Add note data to AdviceMap
    let note_key = [Felt::new(6000), ZERO, ZERO, ZERO];

    let note_asset: Vec<Felt> = vec![
        setup.faucet_a.id().prefix().into(),
        setup.faucet_a.id().suffix(),
        ZERO,
        Felt::new(asset_amount),
    ];

    let mut note_recipient: Vec<Felt> = p2id_output_note.recipient().digest().to_vec();
    note_recipient.reverse();

    let mut note_data: Vec<Felt> = vec![
        p2id_output_note.metadata().tag().into(),
        p2id_output_note.metadata().aux(),
        p2id_output_note.metadata().note_type().into(),
        p2id_output_note.metadata().execution_hint().into(),
    ];

    note_data.extend(note_recipient);
    note_data.extend(note_asset);
    note_data.reverse();

    advice_map.insert(note_key.into(), note_data);

    setup.client.sync_state().await.unwrap();

    let tx_request = TransactionRequestBuilder::new()
        .extend_advice_map(advice_map)
        .own_output_notes(vec![OutputNote::Full(p2id_output_note)])
        .build()
        .unwrap();

    // This should fail because we don't have enough signatures
    let err_tx = setup
        .client
        .new_transaction(setup.multisig_wallet.id(), tx_request)
        .await
        .expect_err("transaction was expected to fail due to insufficient signatures");

    let err_code = match err_tx {
        ClientError::TransactionExecutorError(
            TransactionExecutorError::TransactionProgramExecutionFailed(assertion),
        ) => assertion,
        other => panic!("unexpected error variant: {other:?}"),
    };
    println!(
        "Expected failure due to insufficient signatures: {:?}",
        err_code
    );

    Ok(())
}

#[tokio::test]
async fn multisig_fails_mismatched_signatures() -> Result<(), ClientError> {
    let mut setup = setup_multisig_test().await?;

    // -------------------------------------------------------------------------
    // STEP 1: Fund Multisig with a note to consume
    // -------------------------------------------------------------------------
    let multisig_amount = 100;
    let asset = FungibleAsset::new(setup.faucet_a.id(), multisig_amount).unwrap();
    let mint_req = TransactionRequestBuilder::new()
        .build_mint_fungible_asset(
            asset,
            setup.multisig_wallet.id(),
            NoteType::Public,
            setup.client.rng(),
        )
        .unwrap();

    let mint_exec = setup
        .client
        .new_transaction(setup.faucet_a.id(), mint_req)
        .await?;
    setup.client.submit_transaction(mint_exec.clone()).await?;

    let minted_note = match mint_exec.created_notes().get_note(0) {
        OutputNote::Full(note) => note.clone(),
        _ => panic!("Expected full minted note"),
    };

    // -------------------------------------------------------------------------
    // STEP 2: Consume the input note first
    // -------------------------------------------------------------------------
    let account_delta_commitment =
        Word::from([Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)]);
    let input_notes =
        InputNotes::new(vec![InputNote::unauthenticated(minted_note.clone())]).unwrap();
    let input_notes_commitment = input_notes.commitment();
    let output_notes = OutputNotes::new(vec![]).unwrap();
    let output_notes_commitment = output_notes.commitment();
    let salt = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);

    let transaction_message_digest = compute_transaction_message_digest(
        account_delta_commitment,
        input_notes_commitment.into(),
        output_notes_commitment.into(),
        salt,
        "input note consumption",
    );

    let advice_map = generate_signature_advice_map(
        &setup.keys,
        transaction_message_digest,
        "input note consumption",
    );

    let consume_req = TransactionRequestBuilder::new()
        .unauthenticated_input_notes([(minted_note, None)])
        .extend_advice_map(advice_map)
        .custom_script(setup.consume_tx_script)
        .build()?;

    let consume_exec = setup
        .client
        .new_transaction(setup.multisig_wallet.id(), consume_req)
        .await
        .unwrap();

    setup
        .client
        .submit_transaction(consume_exec.clone())
        .await?;
    setup.client.sync_state().await?;

    // -------------------------------------------------------------------------
    // STEP 3: Try to create output note with MISMATCHED SIGNATURES
    // -------------------------------------------------------------------------
    let asset_amount = 50;
    let p2id_asset = FungibleAsset::new(setup.faucet_a.id(), asset_amount).unwrap();
    let p2id_assets = vec![p2id_asset.into()];
    let serial_num = setup.client.rng().draw_word();

    let recipient_account = &setup.accounts[0];

    let p2id_output_note = create_exact_p2id_note(
        setup.multisig_wallet.id(),
        recipient_account.id(),
        p2id_assets,
        NoteType::Public,
        ZERO,
        serial_num,
    )
    .unwrap();

    let account_delta_commitment =
        Word::from([Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)]);
    let input_notes: InputNotes<InputNote> = InputNotes::new(vec![]).unwrap();
    let input_notes_commitment = input_notes.commitment();
    let output_notes = OutputNotes::new(vec![OutputNote::Full(p2id_output_note.clone())]).unwrap();
    let output_notes_commitment = output_notes.commitment();
    let salt = Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);

    let correct_transaction_message_digest = compute_transaction_message_digest(
        account_delta_commitment,
        input_notes_commitment.into(),
        output_notes_commitment.into(),
        salt,
        "correct output note creation",
    );

    // Create a DIFFERENT message digest that some signers will sign
    let wrong_salt = Word::from([Felt::new(99), Felt::new(99), Felt::new(99), Felt::new(99)]);
    let wrong_transaction_message_digest = compute_transaction_message_digest(
        account_delta_commitment,
        input_notes_commitment.into(),
        output_notes_commitment.into(),
        wrong_salt,
        "wrong output note creation",
    );

    // Generate mixed signatures - some sign correct message, some sign wrong message
    let mut advice_map = AdviceMap::default();

    // First key signs the CORRECT message
    let signature1 = setup.keys[0].sign(correct_transaction_message_digest.into());
    // Second key signs the WRONG message
    let signature2 = setup.keys[1].sign(wrong_transaction_message_digest.into());
    // Third key signs the CORRECT message
    let signature3 = setup.keys[2].sign(correct_transaction_message_digest.into());

    let signatures = [signature1, signature2, signature3];
    let message_digests = [
        correct_transaction_message_digest,
        wrong_transaction_message_digest,
        correct_transaction_message_digest,
    ];

    for (i, ((key, signature), message_digest)) in setup
        .keys
        .iter()
        .zip(signatures.iter())
        .zip(message_digests.iter())
        .enumerate()
    {
        let nonce = signature.nonce().to_elements();
        let s2 = signature.sig_poly();
        let h = key.compute_pub_key_poly().0;
        let pi = Polynomial::mul_modulo_p(&h, s2);

        let mut polynomials: Vec<Felt> = h
            .coefficients
            .iter()
            .map(|a| Felt::from(a.value() as u32))
            .collect();
        polynomials.extend(s2.coefficients.iter().map(|a| Felt::from(a.value() as u32)));
        polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

        let digest_polynomials = Hasher::hash_elements(&polynomials);
        let challenge = (digest_polynomials[0], digest_polynomials[1]);

        let pub_key_felts: Word = key.public_key().into();
        let msg_felts: Word = (*message_digest).into();

        let mut result: Vec<Felt> = vec![
            pub_key_felts[0],
            pub_key_felts[1],
            pub_key_felts[2],
            pub_key_felts[3],
            msg_felts[0],
            msg_felts[1],
            msg_felts[2],
            msg_felts[3],
            challenge.0,
            challenge.1,
        ];

        result.extend_from_slice(&polynomials);
        result.extend_from_slice(&nonce);

        let advice_key: Word = [Felt::new(i as u64), ZERO, ZERO, ZERO];
        advice_map.insert(advice_key.into(), result.clone());

        println!(
            "Generated signature #{} for key: {:?} (signing message: {:?})",
            i,
            key.public_key(),
            Word::from(*message_digest)
        );
    }

    // Add note data to AdviceMap
    let note_key = [Felt::new(6000), ZERO, ZERO, ZERO];

    let note_asset: Vec<Felt> = vec![
        setup.faucet_a.id().prefix().into(),
        setup.faucet_a.id().suffix(),
        ZERO,
        Felt::new(asset_amount),
    ];

    let mut note_recipient: Vec<Felt> = p2id_output_note.recipient().digest().to_vec();
    note_recipient.reverse();

    let mut note_data: Vec<Felt> = vec![
        p2id_output_note.metadata().tag().into(),
        p2id_output_note.metadata().aux(),
        p2id_output_note.metadata().note_type().into(),
        p2id_output_note.metadata().execution_hint().into(),
    ];

    note_data.extend(note_recipient);
    note_data.extend(note_asset);
    note_data.reverse();

    advice_map.insert(note_key.into(), note_data);

    setup.client.sync_state().await.unwrap();

    let tx_request = TransactionRequestBuilder::new()
        .extend_advice_map(advice_map)
        .own_output_notes(vec![OutputNote::Full(p2id_output_note)])
        .build()
        .unwrap();

    // This should fail because the signatures are for different messages
    let err_tx = setup
        .client
        .new_transaction(setup.multisig_wallet.id(), tx_request)
        .await
        .expect_err("transaction was expected to fail due to mismatched signatures");

    let err_code = match err_tx {
        ClientError::TransactionExecutorError(
            TransactionExecutorError::TransactionProgramExecutionFailed(assertion),
        ) => assertion,
        other => panic!("unexpected error variant: {other:?}"),
    };
    println!(
        "Expected failure due to mismatched signatures: {:?}",
        err_code
    );

    Ok(())
}
