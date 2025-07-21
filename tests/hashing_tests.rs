use std::{fs, path::Path};

use miden_assembly::Assembler;
use miden_client::{ClientError, rpc::Endpoint, transaction::TransactionRequestBuilder};
use miden_client::{
    Felt, Word,
    account::{AccountBuilder, AccountStorageMode, AccountType, StorageSlot},
    account::{StorageMap, component::AccountComponent},
    transaction::TransactionKernel,
};
use miden_client_tools::{
    create_library, create_tx_script, delete_keystore_and_store, instantiate_client,
};
use miden_crypto::hash::rpo::Rpo256 as Hasher;
use rand::RngCore;
#[tokio::test]
async fn basic_hashing_test() -> Result<(), ClientError> {
    delete_keystore_and_store(None).await;

    let endpoint = Endpoint::localhost();
    let mut client = instantiate_client(endpoint, None).await.unwrap();

    let sync_summary = client.sync_state().await.unwrap();
    println!("Latest block: {}", sync_summary.block_num);
    println!("sync state: {:?}", sync_summary.block_num);

    let script_code =
        fs::read_to_string(Path::new("./masm/scripts/hash_testing_script.masm")).unwrap();

    let auth_code = fs::read_to_string(Path::new("./masm/auth/no_auth.masm")).unwrap();

    let mut init_seed = [0_u8; 32];
    client.rng().fill_bytes(&mut init_seed);

    let file_path = Path::new("./masm/accounts/hashing_test.masm");
    let account_code = fs::read_to_string(file_path).unwrap();

    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);

    let empty_storage_slot = StorageSlot::empty_value();
    let storage_map = StorageMap::new();
    let storage_slot_map = StorageSlot::Map(storage_map.clone());

    let account_component = AccountComponent::compile(
        account_code.clone(),
        assembler.clone(),
        vec![empty_storage_slot.clone(), storage_slot_map.clone()],
    )
    .unwrap()
    .with_supports_all_types();

    let auth_component = AccountComponent::compile(
        auth_code.clone(),
        assembler.clone(),
        vec![empty_storage_slot, storage_slot_map],
    )
    .unwrap()
    .with_supports_all_types();

    let builder = AccountBuilder::new(init_seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(auth_component)
        .with_component(account_component);

    let (account, seed) = builder.build().unwrap();

    client
        .add_account(&account, Some(seed), false)
        .await
        .unwrap();

    let account_component_lib = create_library(account_code, "hasher::hashing").unwrap();
    let tx_script = create_tx_script(script_code, Some(account_component_lib)).unwrap();

    let tx = TransactionRequestBuilder::new()
        .custom_script(tx_script)
        .build()
        .unwrap();

    let tx_result = client.new_transaction(account.id(), tx).await?;
    client.submit_transaction(tx_result.clone()).await?;

    let account_delta_commitment =
        Word::from([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]);

    let input_notes_commitment =
        Word::from([Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)]);

    let output_notes_commitment =
        Word::from([Felt::new(2), Felt::new(2), Felt::new(2), Felt::new(2)]);
    let salt = Word::from([Felt::new(3), Felt::new(3), Felt::new(3), Felt::new(3)]);

    let mut hash_input = vec![];
    hash_input.extend(account_delta_commitment);
    hash_input.extend(input_notes_commitment);
    hash_input.extend(output_notes_commitment);
    hash_input.extend(salt);

    let hash = Hasher::hash_elements(&hash_input);

    println!("hash: {:?}", hash);

    Ok(())
}
