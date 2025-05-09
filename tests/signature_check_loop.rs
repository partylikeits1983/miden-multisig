use std::{fs, path::Path};

use miden_client::{
    ClientError, Felt, Word, crypto::SecretKey, rpc::Endpoint,
    transaction::TransactionRequestBuilder,
};

use miden_client_tools::{
    create_library, create_tx_script, delete_keystore_and_store, instantiate_client,
};
use miden_crypto::{FieldElement, dsa::rpo_falcon512::Polynomial, hash::rpo::Rpo256 as Hasher};
use miden_objects::vm::AdviceMap;
use tokio::time::Instant;

use miden_multisig::common::build_multisig;

#[tokio::test]
async fn signature_check_loop_test() -> Result<(), ClientError> {
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

    let account_component_lib =
        create_library(account_code, "external_contract::signature_check_contract").unwrap();

    let tx_script = create_tx_script(script_code, Some(account_component_lib)).unwrap();

    // -------------------------------------------------------------------------
    // STEP 2: Create signature check smart contract
    // -------------------------------------------------------------------------
    let signature_check_contract = build_multisig(&mut client, pub_keys, None).await.unwrap();

    // -------------------------------------------------------------------------
    // STEP 1: Hash & Sign Data with Each Key and Populate the Advice Map
    // -------------------------------------------------------------------------
    // Prepare some data to hash.
    let mut data = vec![Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    data.splice(0..0, Word::default().iter().cloned());
    let hashed_data = Hasher::hash_elements(&data);
    println!("digest: {:?}", hashed_data);

    // Initialize an empty advice map.
    let mut advice_map = AdviceMap::default();

    let mut i = 0;
    for key in keys.iter() {
        let signature = key.sign(hashed_data.into());

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
        let msg_felts: Word = hashed_data.into();

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

    client.sync_state().await.unwrap();

    let tx_increment_request = TransactionRequestBuilder::new()
        .with_custom_script(tx_script)
        .extend_advice_map(advice_map)
        .build()
        .unwrap();

    // BEGIN TIMING PROOF GENERATION
    let start = Instant::now();

    let tx_result = client
        .new_transaction(signature_check_contract.id(), tx_increment_request)
        .await
        .unwrap();

    println!("tx result: {:?}", tx_result.account_delta());

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

    let new_account_state = client
        .get_account(signature_check_contract.id())
        .await
        .unwrap();

    if let Some(account) = &new_account_state {
        println!(
            "new account state: {:?}",
            account.account().storage().get_item(0)
        );
    }

    Ok(())
}
