# Miden Multisig

### Running Tests

Running all tests sequentially:
```bash
cargo test --release -- --test-threads=1
```

Successful multisig note creation test
```bash
cargo test --release  multisig_note_creation_success -- --exact --nocapture
```

Invalid signature multisig
```bash
cargo test --release  multisig_sig_check_fails_invalid_output_commitment -- --exact --nocapture
```