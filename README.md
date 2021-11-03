# xyz NFT Contract

This repository contains the core NFT smart contract that implements xyz, a base layer for metaverses on the [Terra](https://terra.money) blockchain.

The xyz contract extends CosmWasm's [CW721-base contract](https://github.com/CosmWasm/cw-plus/tree/v0.9.1/contracts/cw721-base) and supports query and execute messages from the [CW721 spec](https://github.com/CosmWasm/cw-plus/tree/v0.9.1/packages/cw721#cw721-spec-non-fungible-tokens).

## Integrating with xyz

Developers who wish to integrate with xyz should depend on the [`collectxyz` package](https://crates.io/crates/collectxyz), which contains common data types and helpers for interacting with xyz smart contracts.

## Development

### Environment Setup

- Rust v1.44.1+
- `wasm32-unknown-unknown` target
- Docker

1. Install `rustup` via https://rustup.rs/

2. Run the following:

```sh
rustup default stable
rustup target add wasm32-unknown-unknown
```

3. Make sure [Docker](https://www.docker.com/) is installed

### Testing

Run all tests for the workspace:

```sh
cargo test
```

### Compiling

To compile the NFT contract, first `cd` into `contracts/collectxyz-nft-contract`, then run:

```sh
RUSTFLAGS='-C link-arg=-s' cargo wasm
shasum -a 256  ../../target/wasm32-unknown-unknown/release/collectxyz_nft_contract.wasm
```

#### Production

For production builds, run the following:

```sh
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/workspace-optimizer:0.11.5
```

This uses [rust-optimizer](https://github.com/cosmwasm/rust-optimizer) to perform several optimizations which can significantly reduce the final size of the contract binaries, which will be available inside the `artifacts/` directory.
