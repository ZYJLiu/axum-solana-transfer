- clone repo, `cd` to this project and run:

```
solana-test-validator --clone-upgradeable-program 3C3pUh5XxUd9Nz1P85mDYfUu4PXAFRg1aHCos66epHQK --url https://api.devnet.solana.com --bpf-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb spl_token_2022.so --reset
```

- the `spl_token_2022.so` file which includes confidential transfers is included
- the `solana-test-validator` command above also clones a transfer hook program from devnet for testing

- open a new terminal
- `cd server`, then run:

```
cargo test -- --nocapture
```

- this runs the tests in `test.rs` and prints the transaction signatures to inspect on solana explorer (localnet)
