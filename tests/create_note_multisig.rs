use std::{fs, path::Path};

use miden_client::transaction::{OutputNote, OutputNotes};
use miden_client::{
    ClientError, Felt, Word, ZERO, asset::FungibleAsset, crypto::SecretKey,
    keystore::FilesystemKeyStore, note::NoteType, rpc::Endpoint,
    transaction::TransactionRequestBuilder,
};

use miden_client::crypto::FeltRng;
use miden_client_tools::{
    create_exact_p2id_note, create_library, create_tx_script, delete_keystore_and_store,
    instantiate_client, mint_from_faucet_for_account, setup_accounts_and_faucets,
};
use miden_crypto::{FieldElement, dsa::rpo_falcon512::Polynomial, hash::rpo::Rpo256 as Hasher};
use miden_multisig::common::build_multisig;
use miden_objects::vm::AdviceMap;
use tokio::time::Instant;

#[tokio::test]
async fn multisig_note_creation_success() -> Result<(), ClientError> {
    delete_keystore_and_store(None).await;

    let endpoint = Endpoint::testnet();
    let mut client = instantiate_client(endpoint, None).await.unwrap();

    let sync_summary = client.sync_state().await.unwrap();
    println!("Latest block: {}", sync_summary.block_num);

    // -------------------------------------------------------------------------
    // STEP 1: Prepare the Script
    // -------------------------------------------------------------------------
    let number_of_iterations = 3;

    let script_code =
        fs::read_to_string(Path::new("./masm/scripts/sig_check_script.masm")).unwrap();

    let mut keys = Vec::new();
    let mut pub_keys: Vec<Word> = Vec::new();

    let number_of_keys: usize = number_of_iterations;
    for i in 0..number_of_keys {
        let key = SecretKey::with_rng(client.rng());
        keys.push(key.clone());

        pub_keys.push(key.public_key().into());

        let pub_key_word: Word = keys[i].public_key().into();

        println!("pub key #{:?}: {:?}", i, pub_key_word);
    }

    let account_code = fs::read_to_string(Path::new("./masm/accounts/multisig.masm")).unwrap();
    let account_component_lib = create_library(account_code, "multisig::multisig").unwrap();
    let sig_check_script = create_tx_script(script_code, Some(account_component_lib)).unwrap();

    // -------------------------------------------------------------------------
    // STEP 2: Create signature check smart contract
    // -------------------------------------------------------------------------
    let multisig_wallet =
        build_multisig(&mut client, pub_keys.clone(), Some(pub_keys.len() as u64))
            .await
            .unwrap();

    let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

    println!(
        "multisig accountid: {:?} {:?}",
        multisig_wallet.id().prefix(),
        multisig_wallet.id().suffix()
    );

    // Setup accounts and balances
    let balances = vec![
        vec![100, 0], // For account[0] => Alice 100 tokens A & B
        vec![100, 0], // For account[1] => Bob 100 tokens A & B
    ];
    let (accounts, faucets) =
        setup_accounts_and_faucets(&mut client, keystore, 2, 2, balances).await?;

    // rename for clarity
    let alice_account = accounts[0].clone();
    let _bob_account = accounts[1].clone();
    let faucet_a = faucets[0].clone();
    let _faucet_b = faucets[1].clone();

    // -------------------------------------------------------------------------
    // STEP 3: Fund Multisig
    // -------------------------------------------------------------------------
    let script_code =
        fs::read_to_string(Path::new("./masm/scripts/helper_note_consume_script.masm")).unwrap();
    let account_code = fs::read_to_string(Path::new("./masm/accounts/multisig.masm")).unwrap();
    let library_path = "multisig::multisig";
    let library = create_library(account_code, library_path).unwrap();

    let consume_tx_script = create_tx_script(script_code, Some(library)).unwrap();

    let multisig_amount = 100;
    let _ = mint_from_faucet_for_account(
        &mut client,
        &multisig_wallet,
        &faucet_a,
        multisig_amount,
        Some(consume_tx_script),
    )
    .await
    .unwrap();

    client.sync_state().await.unwrap();

    let account_balance = client
        .get_account(multisig_wallet.id())
        .await
        .unwrap()
        .expect("not found");

    println!(
        "multisig bal:\nfaucet: {:?} {:?} \namount: {:?}",
        faucet_a.id().prefix(),
        faucet_a.id().suffix(),
        account_balance.account().vault().get_balance(faucet_a.id())
    );

    assert_eq!(
        account_balance
            .account()
            .vault()
            .get_balance(faucet_a.id())
            .unwrap(),
        multisig_amount
    );

    // -------------------------------------------------------------------------
    // STEP 4: Compute output note
    // -------------------------------------------------------------------------
    let asset_amount = 50;
    let p2id_asset = FungibleAsset::new(faucet_a.id(), asset_amount).unwrap();
    let p2id_assets = vec![p2id_asset.into()];
    let serial_num = client.rng().draw_word();

    let p2id_output_note = create_exact_p2id_note(
        multisig_wallet.id(),
        alice_account.id(),
        p2id_assets,
        NoteType::Public,
        ZERO,
        serial_num,
    )
    .unwrap();

    let output_notes = OutputNotes::new(vec![OutputNote::Full(p2id_output_note.clone())]).unwrap();
    let output_notes_commitment = output_notes.commitment();
    println!("output_notes_commitment: {:?}", output_notes_commitment);

    // -------------------------------------------------------------------------
    // STEP 5: Hash & Sign Data with Each Key and Populate the Advice Map
    // -------------------------------------------------------------------------
    // Initialize an empty advice map.
    let mut advice_map = AdviceMap::default();

    let mut i = 0;
    for key in keys.iter() {
        let signature = key.sign(output_notes_commitment.into());

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
        let msg_felts: Word = output_notes_commitment.into();

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

        // Insert the final advice vector into the advice map.
        let advice_key: Word = [Felt::new(i), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        advice_map.insert(advice_key.into(), result.clone());

        i += 1;
    }

    // Add note data to AdviceMap at key [6000,0,0,0]
    let note_key = [Felt::new(6000), ZERO, ZERO, ZERO];

    let note_asset: Vec<Felt> = vec![
        faucet_a.id().prefix().into(),
        faucet_a.id().suffix(),
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

    client.sync_state().await.unwrap();

    let tx_request = TransactionRequestBuilder::new()
        .with_custom_script(sig_check_script)
        .extend_advice_map(advice_map)
        .with_expected_output_notes(vec![p2id_output_note])
        .build()
        .unwrap();

    // BEGIN TIMING PROOF GENERATION
    let start = Instant::now();

    let tx_result = client
        .new_transaction(multisig_wallet.id(), tx_request)
        .await
        .unwrap();

    println!("tx result: {:?}", tx_result.account_delta());

    // -------------------------------------------------------------------------
    // Benchmark Performance
    // -------------------------------------------------------------------------
    // Calculate the elapsed time for proof generation
    let duration = start.elapsed();
    println!("multisig verify proof generation time: {:?}", duration);
    println!(
        "time per pub key recovery: {:?}",
        duration / number_of_keys.try_into().unwrap()
    );

    let tx_id = tx_result.executed_transaction().id();
    println!(
        "View transaction on MidenScan: https://testnet.midenscan.com/tx/{:?}",
        tx_id
    );

    let executed_tx: &miden_client::transaction::ExecutedTransaction =
        tx_result.executed_transaction();
    let total_cycles = executed_tx.measurements().total_cycles();

    println!("total cycles: {:?}", total_cycles);

    // Submit transaction to the network
    let _ = client.submit_transaction(tx_result).await;

    // Calculate the time for complete onchain settlement
    let complete_settlement_time = start.elapsed();
    println!(
        "multisig verify tx settled in: {:?}",
        complete_settlement_time
    );
    println!(
        "time per pub key recovery: {:?}",
        complete_settlement_time / number_of_keys.try_into().unwrap()
    );

    client.sync_state().await.unwrap();

    let new_account_state = client.get_account(multisig_wallet.id()).await.unwrap();

    if let Some(account) = &new_account_state {
        println!(
            "new account state: {:?}",
            account.account().storage().get_item(0)
        );
    }

    Ok(())
}
