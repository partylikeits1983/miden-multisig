use std::{fs, path::Path};

use miden_client::{
    Client, ClientError,
    account::{
        AccountBuilder, AccountStorageMode, AccountType, StorageSlot, component::BasicWallet,
    },
};
use miden_crypto::{Felt, Word, ZERO};
use miden_lib::transaction::TransactionKernel;
use miden_objects::{
    account::{AccountComponent, StorageMap},
    assembly::Assembler,
};
use rand::RngCore;

const THRESHOLD_KEY: Word = [Felt::new(5000), ZERO, ZERO, ZERO];

pub async fn build_multisig(
    client: &mut Client,
    authed_pub_keys: Vec<Word>,
    threshold: Option<u64>,
) -> Result<miden_client::account::Account, ClientError> {
    let mut init_seed = [0_u8; 32];
    client.rng().fill_bytes(&mut init_seed);

    let file_path = Path::new("./masm/accounts/multisig.masm");
    let account_code = fs::read_to_string(file_path).unwrap();

    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);

    let empty_storage_slot = StorageSlot::empty_value();
    let mut storage_map = StorageMap::new();

    let true_value = [Felt::new(1), Felt::new(1), Felt::new(1), Felt::new(1)];

    for key in authed_pub_keys.iter() {
        storage_map.insert(key.into(), true_value);
    }

    // Use provided thresholds or fall back to the number of authorized public keys
    let threshold = threshold.unwrap_or(authed_pub_keys.len() as u64);

    // [threshold_key, 0,0,0] => [threshold_value, 0,0,0]
    storage_map.insert(
        THRESHOLD_KEY.into(),
        [Felt::new(threshold), ZERO, ZERO, ZERO],
    );

    let storage_slot_map = StorageSlot::Map(storage_map.clone());

    let account_component = AccountComponent::compile(
        account_code.clone(),
        assembler.clone(),
        vec![empty_storage_slot, storage_slot_map],
    )
    .unwrap()
    .with_supports_all_types();

    let anchor_block = client.get_latest_epoch_block().await.unwrap();
    let builder = AccountBuilder::new(init_seed)
        .anchor((&anchor_block).try_into().unwrap())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_component(BasicWallet);

    let (account, seed) = builder.build().unwrap();
    client.add_account(&account, Some(seed), false).await?;

    Ok(account)
}
