#![cfg(test)]
use std::str;

use collectxyz::nft::{Config, Coordinates, ExecuteMsg, InstantiateMsg, QueryMsg, XyzExtension};
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{BankMsg, Binary, Coin, DepsMut, StdError, Uint128};
use serde_json::json;

use crate::contract::{execute, instantiate, query};
use crate::error::ContractError;
use crate::execute as ExecHandler;
use crate::query as QueryHandler;

const OWNER: &str = "owner";
const NONOWNER: &str = "nonowner";

// rsa public key with corresponding private key:
//
// (DO NOT USE THIS PRIVATE KEY FOR ANYTHING REAL, OBVIOUSLY!!!!!)
//
// -----BEGIN RSA PRIVATE KEY-----
// MIIEowIBAAKCAQEAvuwZ6A6CWwOUkSN0ZIkGurUiFCkV/HBanARwNTXGfEzPW5j3
// nkKM1V/oVDQ0dScm39SFlaHOrCINnU/IK+xNo9fiSRD4oRG1Wa6w/sIWIZgMKsaF
// dvLv/+JtTvMfFSXi2Z8FeF3jz8jWFEc7RhwndTtBA6KNXTW7EPTLk03+HUFi2yO7
// 9HQaFHdBQkQPgdry2AHI+y2BOPKgwhQJM6Ys3KMp8CYPAhhmBNttG2L9xwW3N91P
// yth6jBxOmrwuHRO+9Wq7UhA6LG0O5m/VO7Th4WnFviwnoFeLnIiam2FGJnbM4uUL
// mhExnz7aIH4lyNIHbl/zOp5cs5MA09HBNvIbtwIDAQABAoIBAQCXAXDgHRG3YNaS
// ESPPHJ4I8Jj6ryBnoInaGpyRSW4rBCmBvjQjpWl0nr3IU94lxwi1QodBuVAYz3pL
// MT4Wl3k1HNwqhFTSOIpiW4w8g1Az0+nTr18CnNV8Yx+nsR2lgWiyTVdrQ3+a6bOB
// KHHWWxBOZcZfVKNQ1N2XZLbbVHWntp79hWSJnbqNwgTWvzYb3wBATKilcufL+Gng
// TI7PhtPTBfM9jOxcIKzJSz3Qq8zvyrUS9MvcK7Y6u85XN/4YkZgpIJN0UitWk7nK
// gj+A1P+8jUGhHJvhsjIc99nz8JLV3YCmHjRSj3BpWQRvB7A4RAuzUAOoGCNyvlDs
// uHXd+OXpAoGBAPX9O7ifI5t7W5OJPewLQeq86VSJVnAr+7A3tTm3fUFkYQDYvG1c
// xbykxN293LBAZSg2cgMJddn40a95ZXAW0I5KJrsun7UPeHi+CuZM+uVxtWXhIoDA
// grtgV2rdJ4A9nf0xTC7yUNzOZf/SJX2dRlX3uhtrJqnTA2fgMzUquO/dAoGBAMax
// K1KrVM9mBhkoD8URji49ymm8qM8fuI8dgN4X6PTTEXzjwKSKJlTz2bMEwekX8RSj
// zQYTwDlzvNbz6RxDTAqr8YuW5P39fspomQl83v6HFGhTnalF56ul5/1dKrN9pRDE
// wBQPL0aGLRB+ZlTBP2jT2S0vnv5hoFs1DQdlUcqjAoGAGpbg2bf59ViEMZJoKxec
// bG83GXgu67kVX5rl7/Mxitv60EidNYUNqrJ0xTM8o6CSTqJz+HgRURpgMAODP3Z3
// 3KmPPjRv9vZRI1wHeZVgmWSNIxIO1LP6bZ6gVGDLYEVIypGFlp2CuBtnUxu4Cbfy
// XmCEsWoHp9uzRospfdm8W9ECgYBG2ulzKqws5doo4HN3OIJ2lQx41pFwg4RibQgG
// q4okvJxQ6DtLsgRnaSpqP7kS8bnEPYGguCxlkJN4KDUqIgmdCKIzwFTbCqpLbi+d
// BY3UQMGTTrY7pjUurhRj8vSGW7kgmLlSrfOS98hcSGcftGZzcJDTH1dYqeHwhKOn
// zobzdwKBgDWZ86AmjCrsFJpjbpikm7taCXC7n9A5UIl2qouDwLdZpeSsXwVEhw02
// 60pBcDbp8zpeNQKM3dCG6luhtu6jkC02YchWCEL/1PjlislUCbQ8Al/dj2PGN7rq
// xJPwpXCTmZKyW5j0kBthltS2pKz2RybSiKVdQUMB9cuh8WCeFTLb
// -----END RSA PRIVATE KEY-----
const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvuwZ6A6CWwOUkSN0ZIkG
urUiFCkV/HBanARwNTXGfEzPW5j3nkKM1V/oVDQ0dScm39SFlaHOrCINnU/IK+xN
o9fiSRD4oRG1Wa6w/sIWIZgMKsaFdvLv/+JtTvMfFSXi2Z8FeF3jz8jWFEc7Rhwn
dTtBA6KNXTW7EPTLk03+HUFi2yO79HQaFHdBQkQPgdry2AHI+y2BOPKgwhQJM6Ys
3KMp8CYPAhhmBNttG2L9xwW3N91Pyth6jBxOmrwuHRO+9Wq7UhA6LG0O5m/VO7Th
4WnFviwnoFeLnIiam2FGJnbM4uULmhExnz7aIH4lyNIHbl/zOp5cs5MA09HBNvIb
twIDAQAB
-----END PUBLIC KEY-----
";
const SIG_X1Y2Z3: &str = "rGU6WeFYjeIluTAcl5PeNn5VOvpfUjIFQ/Zan87wqvRSPZXkBo7k4/IAGNAs/qmcwFgbIcBeXmyCc9x+lVXvdq0fLGen0TTRCpgFgv7cpFw8BkAeEeZrJDvYgKVbwinOvmUKfQafPLnN7E7oIqk0s2GWXWRJJLzky54DeaUzhhcoxz6iCYck2GEPKd9i7QmFEz52rqqGDQorDj3ojYVj5pzilRPXgYkEfdU432YgPfpcmAmnL8vL2PczBeB/jFUETvQnuMawTTU+aDI4APIIPUjmy2eVYsTIJvoU1lDAskjzqA57rNG4+w0XovH0rtXfG0BV1hb+1fPpnBgpqNixPQ==";
const SIG_X3Y2Z1: &str = "tz4YIUjHJZwdcExPe6YLmGuzPHemygNzVQ02F1C/d1iAboPhnsrPchlKKcHAKb2MbghN72HD1rtlvzPPNrJWjbwE5zeZG8lQq5a7Sjzh+xeYYy938I0l/HtY7gyOaqD/DMsQYV4tIxY6LIJS9oC+5uuhxXpqs/HARnMQbhcbmRpPbGjlXM4YTOHeSLp4Ve8Xts6bKRyEA6MIEJPTxrk8QX0sTJPeDWEGQzN1QotSw2wN/xppFRGRAenPbUMx1+kGVbiuk44FmcwQ2GwZapX/ab1x3TaTynSccHo9w63nBl42RXmnZvNanjwcu15Jc84cQOsNmeh8PB35qhHr2iLXUg==";
const SIG_X2Y2Z2: &str = "Q5lblSk4zba0rILfiUs+ZS+PU9XZHTMrblriZ8TGILIC9PfzHApoEtzzm530VeQVrwY5CaaCTp8k34w8ySsJtgMBa5MKAbqDOeerEVQiKGEV3eBvUVIVSePVUwE9UuQXLeImzqqlARQki/cI2hK8kLFKkrolKzurv8kwKdAG3iHZUXApVse4Dhpx7nLMM8k/4P01VnujJG4DtCjZJzizcKxHCW03PCg83k3Kc3WG6bg7Don91gCSs+RpA4hVDlG/RKD5MdDZh4ktAE7VFg7Yv6uAoyqulUFlHbZcHXAgiXkliVhTVKMalQXltYsqpr1GV6FNbe/iki/C58RMO5acuQ==";
const SIG_X1Y1Z1: &str = "fFF0OW5vgKkqU+0L39/26vCc0SoRYD9KhzkeG1q6xb5+gXp+QSE4tZDNr02Bg5av+gOfGLn5JQCofpjSqZ+m3VyDQUvgaJ8DeGV4GW+dht7kkULFL39cW0xiiYSHH3g4hAntwPO/40bI9tBm40pNwfLA6cS7O1a8509uL63h4WBEtUvre2MmbbzIc/cdKKpQWH0sBKOZG3jMHnShp9YvGvfM3OzEUZpOjkBG1U/fUM2JsbdBQjIXum3DIn2vGvHxtPkkRf4AkLLp5MWpULqV7MdIk8wPd8KS+kjUY33TMdeN6Xz9YJsKeshLMvO80jm/usZFDrLz+sr9dF89RWZ+oQ==";
const SIG_X0Y0Z0: &str = "deu6I5cNYdtWt3WcUxVixs5t/A0udL1/I86RvqChSZ5RRUtN6L3QtG6HqqpkuFXkSQvVwAMWV5NMkB4CKuB/i3CrpHJxKtK5xia8C3PQDYpgAl0QaScuTEGSL3P4Kct/8ntBCcaF2Oatc8t6VwzvKUsVC5t4sxTBp11JldfY3P9tm6iUC1IZCj/GweWNyuPHFYqPJXIAFx5yG9LYUL2CGmYCjOZwFYJpAheTiqdMD/hnMPaVg3N80WQmCdmch7aepfIH17DFIrBaeIVBry52HUco098mpFQznqmXt5Ki1pJSx+/w+pst/Z9T87f6MVy63cS57bKL2Lx+nQH30G5fJg==";

fn mock_config() -> Config {
    Config {
        public_minting_enabled: true,
        max_coordinate_value: 1000,
        mint_fee: Coin::new(0, "uluna"),
        token_supply: 10000,
        wallet_limit: 5,
        move_nanos_per_step: 1,
        base_move_nanos: 10,
        move_fee_per_step: Uint128::new(1),
        base_move_fee: Coin::new(100, "uluna"),
    }
}

fn setup_contract(
    deps: DepsMut,
    mint_fee: Option<Coin>,
    token_supply: Option<u64>,
    wallet_limit: Option<u32>,
) {
    let mut msg = InstantiateMsg {
        captcha_public_key: String::from(RSA_PUBLIC_KEY),
        config: mock_config(),
    };
    if let Some(mint_fee) = mint_fee {
        msg.config.mint_fee = mint_fee;
    }
    if let Some(token_supply) = token_supply {
        msg.config.token_supply = token_supply;
    }
    if let Some(wallet_limit) = wallet_limit {
        msg.config.wallet_limit = wallet_limit;
    }
    let info = mock_info(OWNER, &[]);
    let res = instantiate(deps, mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
}

fn as_json(binary: &Binary) -> serde_json::Value {
    let b64_binary = binary.to_base64();
    let decoded_bytes = base64::decode(&b64_binary).unwrap();
    let decoded_str = str::from_utf8(&decoded_bytes).unwrap();
    serde_json::from_str(decoded_str).unwrap()
}

#[test]
fn minting() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    // nonowner with invalid signature cannot mint
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from("Zm9vYmFyCg=="), // "foobar" in base64
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // nonowner with mismatched signature cannot mint
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 1, z: 1 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // nonowner with valid signature can mint
    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap();

    // ensure response event emits the minted token_id
    assert!(res
        .attributes
        .iter()
        .any(|attr| attr.key == "token_id" && attr.value == "1"));

    // random cannot mint a token with same coordinates twice
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Claimed {});
    assert!(format!("{}", err).contains("Coordinates already claimed"));

    // random cannot mint out-of-bounds coordinates
    let config = mock_config();
    for cfg in &["x", "y", "z", "xy", "xz", "yz", "xyz"] {
        for sign in &[-1, 1] {
            let mut coords = Coordinates {
                x: sign * config.max_coordinate_value,
                y: sign * config.max_coordinate_value,
                z: sign * config.max_coordinate_value,
            };
            if cfg.contains('x') {
                coords.x += sign;
            }
            if cfg.contains('y') {
                coords.y += sign;
            }
            if cfg.contains('z') {
                coords.z += sign;
            }
            let oob_mint_msg = ExecuteMsg::Mint {
                captcha_signature: String::from(SIG_X1Y2Z3),
                coordinates: coords,
            };
            let err = execute(
                deps.as_mut(),
                mock_env(),
                mock_info(NONOWNER, &[]),
                oob_mint_msg,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ContractError::Std(StdError::GenericErr {
                    msg: String::from("coordinate values must be between -1000 and 1000")
                })
            );
        }
    }

    // ensure num tokens increases
    let count = as_json(&query(deps.as_ref(), mock_env(), QueryMsg::NumTokens {}).unwrap());
    assert_eq!(count["count"], 1);

    // non-existent token_id returns error
    let _ = query(
        deps.as_ref(),
        mock_env(),
        QueryMsg::NftInfo {
            token_id: String::from("foo"),
        },
    )
    .unwrap_err();

    // correct token_id yields expected token info
    let info = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::NftInfo {
                token_id: String::from("1"),
            },
        )
        .unwrap(),
    );
    assert_eq!(info["extension"]["name"], "xyz #1");
    assert_eq!(
        info["extension"]["description"],
        "Explore the metaverse, starting with xyz."
    );
    if let serde_json::Value::String(image) = &info["extension"]["image"] {
        assert!(image.starts_with("data:image/svg+xml;base64,"));
    } else {
        panic!("NftInfo response 'image' had wrong data type");
    }

    // owner info is correct
    let owner = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::OwnerOf {
                token_id: "1".to_string(),
                include_expired: None,
            },
        )
        .unwrap(),
    );
    assert_eq!(owner["owner"], NONOWNER);
    assert_eq!(owner["approvals"], serde_json::Value::Array(vec![]));

    // list the token_ids
    let tokens = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllTokens {
                limit: None,
                start_after: None,
            },
        )
        .unwrap(),
    );
    assert_eq!(
        tokens["tokens"],
        serde_json::Value::Array(vec![serde_json::Value::String(String::from("1"))])
    );
}

#[test]
fn mint_fee() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), Some(Coin::new(10000, "uluna")), None, None);

    // mint blocked when insufficient funds or incorrect denoms sent
    for funds in vec![
        vec![],
        vec![Coin::new(1000, "uusd")],
        vec![Coin::new(9999, "uluna")],
    ]
    .iter()
    {
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NONOWNER, funds),
            ExecuteMsg::Mint {
                captcha_signature: String::from(SIG_X1Y2Z3),
                coordinates: Coordinates { x: 1, y: 2, z: 3 },
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ContractError::Std(StdError::generic_err("insufficient funds sent"))
        );
    }

    // non-owner can mint when sufficient funds sent
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[Coin::new(10000, "uluna")]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap();

    // owner is allowed to mint with insufficient funds
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap();
}

#[test]
fn wallet_limit() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, Some(1));

    // non-owner is allowed to mint within wallet limit
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap();

    // non-owner isn't allowed to mint beyond of wallet limit
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::WalletLimit {});

    // owner is allowed to mint beyond wallet limit
    for msg in vec![
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y1Z1),
            coordinates: Coordinates { x: 1, y: 1, z: 1 },
        },
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X0Y0Z0),
            coordinates: Coordinates { x: 0, y: 0, z: 0 },
        },
    ] {
        let _ = execute(deps.as_mut(), mock_env(), mock_info(OWNER, &[]), msg).unwrap();
    }
}

#[test]
fn token_supply_and_public_minting() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, Some(5), None);

    // mint 4 tokens for the non-owner
    for (sig, coords) in &[
        (SIG_X1Y2Z3, Coordinates { x: 1, y: 2, z: 3 }),
        (SIG_X3Y2Z1, Coordinates { x: 3, y: 2, z: 1 }),
        (SIG_X0Y0Z0, Coordinates { x: 0, y: 0, z: 0 }),
        (SIG_X1Y1Z1, Coordinates { x: 1, y: 1, z: 1 }),
    ] {
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(NONOWNER, &[]),
            ExecuteMsg::Mint {
                captcha_signature: String::from(*sig),
                coordinates: *coords,
            },
        )
        .unwrap();
    }

    // disable public minting
    let mut config = QueryHandler::query_config(deps.as_ref()).unwrap();
    config.public_minting_enabled = false;
    let _ =
        ExecHandler::execute_update_config(deps.as_mut(), mock_info(OWNER, &[]), config.clone())
            .unwrap();

    // non-owner can't mint when public minting is disabled
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // owner is allowed to mint when public minting is disabled
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X2Y2Z2),
            coordinates: Coordinates { x: 2, y: 2, z: 2 },
        },
    )
    .unwrap();

    // owner can't mint beyond token supply
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::SupplyExhausted {});

    // re-enable public minting
    config.public_minting_enabled = true;
    let _ =
        ExecHandler::execute_update_config(deps.as_mut(), mock_info(OWNER, &[]), config).unwrap();

    // non-owner can't mint beyond token supply
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::SupplyExhausted {});
}

#[test]
fn update_and_query_config() {
    let initial_config = mock_config();

    let mut deps = mock_dependencies(&[]);
    setup_contract(
        deps.as_mut(),
        Some(initial_config.mint_fee.clone()),
        Some(initial_config.token_supply),
        Some(initial_config.wallet_limit),
    );

    // query initial config
    let res = QueryHandler::query_config(deps.as_ref()).unwrap();
    assert_eq!(res, initial_config);

    // change the config
    let mut new_config = initial_config.clone();
    new_config.mint_fee = Coin::new(10000, "uluna");
    new_config.move_nanos_per_step = 123456;

    // nonowner can't update config
    let err = ExecHandler::execute_update_config(
        deps.as_mut(),
        mock_info(NONOWNER, &[]),
        new_config.clone(),
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // check config was unchanged
    let res = QueryHandler::query_config(deps.as_ref()).unwrap();
    assert_eq!(res, initial_config);

    // owner can update config
    let _ = ExecHandler::execute_update_config(
        deps.as_mut(),
        mock_info(OWNER, &[]),
        new_config.clone(),
    )
    .unwrap();

    // check config was updated
    let res = QueryHandler::query_config(deps.as_ref()).unwrap();
    assert_eq!(res, new_config);
}

#[test]
fn update_captcha_public_key() {
    let new_public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu+hYpXLZ9Ja495clsIcc
aAycTgtO0/ZDlfU4LUrLxENW8KtF/qJ8TNDRYWIqx614AFPZh1Eyj4XCwZmy1Ixg
fVZe1ZUHvlc6Hbozym76XfnQdM64QVpRh+6ZwzL76V3G1Iy6mur4Sa8at/3pJBpI
kdHOhBe4vfjazZz0jKM8RWbz67mjw45nKRiEB9GksywibhUdXvnXODNeSKjGwJ34
CaFpJ7aRiqaXJwH1SMpcniMWP22mjKt1zA8nipSmr3EUU7eNAYSQoK3QzEZSRayE
BSiq+BBw9jGcrekeFQll1zX95pHttBsm9tB4CHOIJPyxTMM5oGWzCRLouSJR9TJq
8wIDAQAB
-----END PUBLIC KEY-----
";

    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    // non-owner can't update the public key
    let err = ExecHandler::execute_update_captcha_public_key(
        deps.as_mut(),
        mock_info(NONOWNER, &[]),
        new_public_key.to_string(),
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // owner can't update to an invalid public key
    let err = ExecHandler::execute_update_captcha_public_key(
        deps.as_mut(),
        mock_info(OWNER, &[]),
        "foobar".to_string(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::Std(StdError::generic_err("invalid public key"))
    );

    // owner can update to a valid public key
    let _ = ExecHandler::execute_update_captcha_public_key(
        deps.as_mut(),
        mock_info(OWNER, &[]),
        new_public_key.to_string(),
    )
    .unwrap();

    let stored_key = QueryHandler::query_captcha_public_key(deps.as_ref()).unwrap();
    assert_eq!(stored_key, new_public_key);
}

#[test]
fn withdraw() {
    let balance = vec![Coin::new(10000, "uluna")];
    let mut deps = mock_dependencies(&balance);
    setup_contract(deps.as_mut(), None, None, None);

    // non-owner can't withdraw
    let err = ExecHandler::execute_withdraw(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        vec![Coin::new(100, "uluna")],
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // owner can withdraw
    let res = ExecHandler::execute_withdraw(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        vec![Coin::new(100, "uluna")],
    )
    .unwrap();
    assert_eq!(
        res.messages[0].msg,
        BankMsg::Send {
            amount: vec![Coin::new(100, "uluna")],
            to_address: mock_info(OWNER, &[]).sender.to_string()
        }
        .into()
    )
}

#[test]
fn num_tokens_for_owner() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap();

    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X3Y2Z1),
            coordinates: Coordinates { x: 3, y: 2, z: 1 },
        },
    )
    .unwrap();

    for owner in &[OWNER, NONOWNER] {
        let num_tokens = QueryHandler::query_num_tokens_for_owner(
            deps.as_ref(),
            mock_info(owner, &[]).sender.to_string(),
        )
        .unwrap();
        assert_eq!(num_tokens.count, 1);
    }

    let num_tokens = QueryHandler::query_num_tokens_for_owner(
        deps.as_ref(),
        mock_info("someotherguy", &[]).sender.to_string(),
    )
    .unwrap();
    assert_eq!(num_tokens.count, 0)
}

#[test]
fn move_token() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    // mint some tokens
    let nonowner_xyz_id = "xyz #1";
    let nonowner_coords = Coordinates { x: 0, y: 0, z: 0 };
    let owner_xyz_id = "xyz #2";
    let owner_coords = Coordinates { x: 1, y: 1, z: 1 };
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: SIG_X0Y0Z0.to_string(),
            coordinates: nonowner_coords,
        },
    )
    .unwrap();
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: SIG_X1Y1Z1.to_string(),
            coordinates: owner_coords,
        },
    )
    .unwrap();

    // can't move a non-existent token
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Move {
            token_id: "foo".to_string(),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::Std(StdError::not_found("collectxyz::nft::XyzTokenInfo"))
    );

    // can't move a token that isn't yours
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // can't move to a space that's occupied
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: nonowner_coords,
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});

    // can't move to a space that's out of bounds
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Move {
            token_id: owner_xyz_id.to_string(),
            coordinates: Coordinates {
                x: 0,
                y: 0,
                z: mock_config().max_coordinate_value + 1,
            },
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::Std(StdError::generic_err(
            "coordinate values must be between -1000 and 1000"
        ))
    );

    // non-owner must pay a move fee
    let nonowner_target = Coordinates {
        x: 400,
        y: 500,
        z: 600,
    };
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: nonowner_target,
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::Std(StdError::generic_err("insufficient funds sent"))
    );

    // look up the move fee
    let move_params = QueryHandler::query_move_params(
        deps.as_ref(),
        nonowner_xyz_id.to_string(),
        nonowner_target,
    )
    .unwrap();

    println!("{:#?}", move_params);

    // nonowner can move with sufficient move fee paid
    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[move_params.fee.clone()]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: nonowner_target,
        },
    )
    .unwrap();

    // ensure response event emits the moved token_id
    assert!(res
        .attributes
        .iter()
        .any(|attr| attr.key == "token_id" && attr.value == "1"));

    // look up the updated token
    let res = QueryHandler::query_xyz_nft_info(deps.as_ref(), nonowner_xyz_id.to_string()).unwrap();
    // check that the token metadata is correct
    assert_eq!(
        res.extension,
        XyzExtension {
            coordinates: nonowner_target,
            prev_coordinates: Some(nonowner_coords),
            arrival: mock_env().block.time.plus_nanos(move_params.duration_nanos),
        }
    );

    // can't move a token that's currently moving
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[move_params.fee.clone()]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: nonowner_coords,
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::MoveInProgress {});

    // can move a moved coordinate once it's arrived
    let mut env = mock_env();
    env.block.time = env.block.time.plus_nanos(move_params.duration_nanos + 1);
    let _ = execute(
        deps.as_mut(),
        env,
        mock_info(NONOWNER, &[move_params.fee]),
        ExecuteMsg::Move {
            token_id: nonowner_xyz_id.to_string(),
            coordinates: nonowner_coords,
        },
    );

    // owner can move without paying a move fee
    let owner_target = Coordinates { x: 2, y: 1, z: 1 };
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OWNER, &[]),
        ExecuteMsg::Move {
            token_id: owner_xyz_id.to_string(),
            coordinates: owner_target,
        },
    )
    .unwrap();

    let res = QueryHandler::query_xyz_nft_info(deps.as_ref(), owner_xyz_id.to_string()).unwrap();
    assert_eq!(
        res.extension,
        XyzExtension {
            coordinates: owner_target,
            prev_coordinates: Some(owner_coords),
            arrival: mock_env().block.time.plus_nanos(10 + 1),
        }
    );
}

#[test]
fn xyz_nft_info_by_coords() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    // throws error on coordinate with no nft
    let err = query(
        deps.as_ref(),
        mock_env(),
        QueryMsg::XyzNftInfoByCoords {
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap_err();
    assert_eq!(err, StdError::not_found("xyz_token_info"));

    // mint the associated nft
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y2Z3),
            coordinates: Coordinates { x: 1, y: 2, z: 3 },
        },
    )
    .unwrap();

    let res = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::XyzNftInfoByCoords {
                coordinates: Coordinates { x: 1, y: 2, z: 3 },
            },
        )
        .unwrap(),
    );
    assert_eq!(res["name"], "xyz #1");
    assert_eq!(res["owner"], NONOWNER);
}

#[test]
fn all_xyz_tokens() {
    let mut deps = mock_dependencies(&[]);
    setup_contract(deps.as_mut(), None, None, None);

    // check no tokens returned
    let res = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllXyzTokens {
                limit: Some(1),
                start_after: None,
            },
        )
        .unwrap(),
    );
    assert_eq!(res, json!({ "tokens": [] }));

    // mint the associated nft
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X0Y0Z0),
            coordinates: Coordinates { x: 0, y: 0, z: 0 },
        },
    )
    .unwrap();

    // mint the associated nft
    let _ = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(NONOWNER, &[]),
        ExecuteMsg::Mint {
            captcha_signature: String::from(SIG_X1Y1Z1),
            coordinates: Coordinates { x: 1, y: 1, z: 1 },
        },
    )
    .unwrap();

    // check both tokens returned
    let res = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllXyzTokens {
                limit: Some(2),
                start_after: None,
            },
        )
        .unwrap(),
    );
    assert_eq!(res["tokens"][0]["name"], "xyz #1");
    assert_eq!(res["tokens"][1]["name"], "xyz #2");

    // check only second token returned
    let res = as_json(
        &query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllXyzTokens {
                limit: Some(2),
                start_after: Some("xyz #1".to_string()),
            },
        )
        .unwrap(),
    );
    assert_eq!(res["tokens"][0]["name"], "xyz #2");
}
