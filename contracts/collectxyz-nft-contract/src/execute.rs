use rsa::{hash::Hash, padding::PaddingScheme, PublicKey};
use serde_json;
use sha2::{Digest, Sha256};

use collectxyz::nft::{
    base64_token_image, full_token_id, numeric_token_id, Config, Coordinates, ExecuteMsg,
    InstantiateMsg, MigrateMsg, XyzExtension, XyzTokenInfo,
};
use cosmwasm_std::{
    Attribute, BankMsg, Binary, Coin, DepsMut, Empty, Env, MessageInfo, Order, Response, StdError,
    StdResult, Storage,
};
use cw721::{ContractInfoResponse, Cw721ReceiveMsg};
use cw721_base::{msg::ExecuteMsg as Cw721ExecuteMsg, Cw721Contract};

use crate::error::ContractError;
use crate::state::{load_captcha_public_key, save_captcha_public_key, tokens, CONFIG, OWNER};

const XYZ: &str = "xyz";

pub fn instantiate(deps: DepsMut, info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    let cw721_contract = Cw721Contract::<Coordinates, Empty>::default();

    let contract_info = ContractInfoResponse {
        name: XYZ.to_string(),
        symbol: XYZ.to_string(),
    };
    cw721_contract
        .contract_info
        .save(deps.storage, &contract_info)?;

    CONFIG.save(deps.storage, &msg.config)?;
    OWNER.save(deps.storage, &info.sender.to_string())?;

    save_captcha_public_key(deps.storage, &msg.captcha_public_key)?;

    Ok(Response::default())
}

pub fn execute_mint(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    coordinates: Coordinates,
    captcha_signature: String,
) -> Result<Response, ContractError> {
    let cw721_contract = Cw721Contract::<Coordinates, Empty>::default();

    let owner = OWNER.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;
    let num_tokens = cw721_contract.token_count(deps.storage)?;

    if num_tokens >= config.token_supply {
        return Err(ContractError::SupplyExhausted {});
    }

    if info.sender != owner {
        if !config.public_minting_enabled {
            return Err(ContractError::Unauthorized {});
        }

        // check that mint fee is covered if sender isn't an owner
        check_sufficient_funds(info.funds, config.mint_fee)?;

        // check that wallet limit isn't exceeded if sender isn't an owner
        check_wallet_limit(deps.storage, info.sender.clone(), config.wallet_limit)?;
    }

    // check that the coordinates are valid and available
    check_coordinates(deps.storage, &coordinates)?;

    // check that the recaptcha lambda signature is valid
    check_captcha_signature(deps.storage, &coordinates, &captcha_signature)?;

    // create the token
    let num_tokens = 1 + num_tokens;
    let token_id = format!("xyz #{}", &num_tokens);
    let token = XyzTokenInfo {
        owner: info.sender.clone(),
        approvals: vec![],
        name: token_id.clone(),
        description: String::from("Explore the metaverse, starting with xyz."),
        image: Some(base64_token_image(&coordinates)),
        extension: XyzExtension {
            coordinates,
            prev_coordinates: None,
            arrival: env.block.time,
        },
    };
    tokens().update(deps.storage, &token_id, |old| match old {
        Some(_) => Err(ContractError::Claimed {}),
        None => Ok(token),
    })?;

    cw721_contract.increment_tokens(deps.storage)?;

    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("minter", info.sender)
        .add_attribute("token_id", numeric_token_id(token_id)?))
}

fn check_sufficient_funds(funds: Vec<Coin>, required: Coin) -> Result<(), ContractError> {
    if required.amount.u128() == 0 {
        return Ok(());
    }
    let sent_sufficient_funds = funds.iter().any(|coin| {
        // check if a given sent coin matches denom
        // and has sufficient amount
        coin.denom == required.denom && coin.amount.u128() >= required.amount.u128()
    });
    if sent_sufficient_funds {
        Ok(())
    } else {
        Err(ContractError::Std(StdError::generic_err(
            "insufficient funds sent",
        )))
    }
}

fn check_wallet_limit(
    storage: &dyn Storage,
    owner: cosmwasm_std::Addr,
    limit: u32,
) -> Result<(), ContractError> {
    let num_wallet_tokens = tokens()
        .idx
        .owner
        .prefix(owner)
        .range(storage, None, None, Order::Ascending)
        .count();

    if num_wallet_tokens >= limit as usize {
        Err(ContractError::WalletLimit {})
    } else {
        Ok(())
    }
}

fn check_captcha_signature(
    storage: &dyn Storage,
    coordinates: &Coordinates,
    captcha_signature: &str,
) -> Result<(), ContractError> {
    let key = load_captcha_public_key(storage).unwrap();

    let signature_bytes = base64::decode(captcha_signature).unwrap();

    let coords_json_bytes = serde_json::to_vec(coordinates).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&coords_json_bytes);
    let digest = hasher.finalize();

    if key
        .verify(
            PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            },
            &digest,
            &signature_bytes,
        )
        .is_ok()
    {
        Ok(())
    } else {
        Err(ContractError::Unauthorized {})
    }
}

fn check_coordinates(storage: &dyn Storage, coords: &Coordinates) -> Result<(), ContractError> {
    let config = CONFIG.load(storage)?;
    config.check_bounds(*coords).map_err(ContractError::Std)?;
    match tokens().idx.coordinates.item(storage, coords.to_bytes())? {
        Some(_) => Err(ContractError::Claimed {}),
        None => Ok(()),
    }
}

pub fn execute_move(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    token_id: String,
    coordinates: Coordinates,
) -> Result<Response, ContractError> {
    let owner = OWNER.load(deps.storage)?;
    let config = CONFIG.load(deps.storage)?;
    let token = tokens().load(deps.storage, &token_id)?;

    // check that the sender owns the token
    if token.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }

    // check that a move isn't currently in progess
    if !token.extension.has_arrived(env.block.time) {
        return Err(ContractError::MoveInProgress {});
    }

    // check that a non-owner sent funds greater than the move fee
    if owner != info.sender {
        let move_fee = config.get_move_fee(token.extension.coordinates, coordinates);
        check_sufficient_funds(info.funds, move_fee)?;
    }

    // check that move target is unoccupied and in bounds
    check_coordinates(deps.storage, &coordinates)?;

    // update token with new coordinates, prev coordinates, and arrival time
    let mut new_token = token.clone();
    new_token.image = Some(base64_token_image(&coordinates));
    new_token.extension.coordinates = coordinates;
    new_token.extension.prev_coordinates = Some(token.extension.coordinates);
    let travel_time_nanos = config.get_move_nanos(token.extension.coordinates, coordinates);
    new_token.extension.arrival = env.block.time.plus_nanos(travel_time_nanos);
    tokens().replace(deps.storage, &token_id, Some(&new_token), Some(&token))?;

    Ok(Response::default()
        .add_attribute("action", "move")
        .add_attribute("mover", info.sender)
        .add_attribute("token_id", numeric_token_id(token_id)?))
}

pub fn execute_update_config(
    deps: DepsMut,
    info: MessageInfo,
    config: Config,
) -> Result<Response, ContractError> {
    let owner = OWNER.load(deps.storage)?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new().add_attribute("action", "update_config"))
}

pub fn execute_update_captcha_public_key(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> Result<Response, ContractError> {
    let owner = OWNER.load(deps.storage)?;

    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    save_captcha_public_key(deps.storage, &public_key)?;

    Ok(Response::new().add_attribute("action", "update_captcha_public_key"))
}

pub fn execute_withdraw(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Vec<Coin>,
) -> Result<Response, ContractError> {
    let owner = OWNER.load(deps.storage)?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    Ok(Response::new().add_message(BankMsg::Send {
        amount,
        to_address: owner,
    }))
}

pub fn cw721_base_execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let cw721_contract = Cw721Contract::<XyzExtension, Empty>::default();
    let cw721_msg: Cw721ExecuteMsg<XyzExtension> = msg.into();
    let cw721_msg_full_token_id = match cw721_msg {
        Cw721ExecuteMsg::Approve {
            spender,
            token_id,
            expires,
        } => Cw721ExecuteMsg::Approve {
            spender,
            expires,
            token_id: full_token_id(token_id)?,
        },
        Cw721ExecuteMsg::Revoke { spender, token_id } => Cw721ExecuteMsg::Revoke {
            spender,
            token_id: full_token_id(token_id)?,
        },
        Cw721ExecuteMsg::TransferNft {
            recipient,
            token_id,
        } => Cw721ExecuteMsg::TransferNft {
            recipient,
            token_id: full_token_id(token_id)?,
        },
        Cw721ExecuteMsg::SendNft {
            contract,
            token_id,
            msg,
        } => Cw721ExecuteMsg::SendNft {
            contract,
            msg,
            token_id: full_token_id(token_id)?,
        },
        _ => cw721_msg,
    };

    let mut response = (match cw721_msg_full_token_id {
        Cw721ExecuteMsg::SendNft {
            contract,
            token_id,
            msg,
        } => execute_send_nft(deps, env, info, contract, token_id, msg),
        _ => cw721_contract
            .execute(deps, env, info, cw721_msg_full_token_id)
            .map_err(|err| err.into()),
    })?;

    response.attributes = response
        .attributes
        .iter()
        .map(|attr| {
            if attr.key == "token_id" {
                Attribute::new(
                    "token_id",
                    numeric_token_id(attr.value.to_string()).unwrap(),
                )
            } else {
                attr.clone()
            }
        })
        .collect();
    Ok(response)
}

pub fn execute_send_nft(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    contract: String,
    token_id: String,
    msg: Binary,
) -> Result<Response, ContractError> {
    let cw721_contract = Cw721Contract::<XyzExtension, Empty>::default();
    // Transfer token
    cw721_contract._transfer_nft(deps, &env, &info, &contract, &token_id)?;

    let send = Cw721ReceiveMsg {
        sender: info.sender.to_string(),
        token_id: numeric_token_id(token_id.clone())?,
        msg,
    };

    // Send message
    Ok(Response::new()
        .add_message(send.into_cosmos_msg(contract.clone())?)
        .add_attribute("action", "send_nft")
        .add_attribute("sender", info.sender)
        .add_attribute("recipient", contract)
        .add_attribute("token_id", token_id))
}

pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default().add_attribute("action", "migrate"))
}

#[cfg(test)]
mod test {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{to_binary, Addr, Timestamp};
    use cw721::{Cw721ReceiveMsg, Expiration};
    use cw721_base::state::Approval;

    const ADDR1: &str = "addr1";
    const ADDR2: &str = "addr2";

    fn token_examples() -> Vec<XyzTokenInfo> {
        vec![
            XyzTokenInfo {
                owner: Addr::unchecked(ADDR1),
                approvals: vec![],
                name: "xyz #1".to_string(),
                description: "".to_string(),
                image: None,
                extension: XyzExtension {
                    coordinates: Coordinates { x: 1, y: 1, z: 1 },
                    arrival: Timestamp::from_nanos(0),
                    prev_coordinates: None,
                },
            },
            XyzTokenInfo {
                owner: Addr::unchecked(ADDR2),
                approvals: vec![],
                name: "xyz #2".to_string(),
                description: "".to_string(),
                image: None,
                extension: XyzExtension {
                    coordinates: Coordinates { x: 2, y: 2, z: 2 },
                    arrival: Timestamp::from_nanos(0),
                    prev_coordinates: None,
                },
            },
        ]
    }

    fn setup_storage(deps: DepsMut) {
        for token in token_examples().iter() {
            tokens().save(deps.storage, &token.name, token).unwrap();
        }
    }

    fn numeric_id_error() -> ContractError {
        ContractError::Std(StdError::generic_err("expected numeric token identifier"))
    }

    #[test]
    fn cw721_transfer() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        // blocks full token identifiers
        let err = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::TransferNft {
                recipient: ADDR2.to_string(),
                token_id: "xyz #1".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // transfer xyz #1
        let res = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::TransferNft {
                recipient: ADDR2.to_string(),
                token_id: "1".to_string(),
            },
        )
        .unwrap();

        // ensure response event emits the transferred token_id
        assert!(res
            .attributes
            .iter()
            .any(|attr| attr.key == "token_id" && attr.value == "1"));

        // check ownership was updated
        let token = tokens().load(&deps.storage, "xyz #1").unwrap();
        assert_eq!(token.name, "xyz #1");
        assert_eq!(token.owner.to_string(), ADDR2.to_string());
    }

    #[test]
    fn cw721_approve_revoke() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        // approve blocks full token identifiers
        let err = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::Approve {
                spender: ADDR2.to_string(),
                token_id: "xyz #1".to_string(),
                expires: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // grant an approval
        let res = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::Approve {
                spender: ADDR2.to_string(),
                token_id: "1".to_string(),
                expires: None,
            },
        )
        .unwrap();

        // ensure response event emits the transferred token_id
        assert!(res
            .attributes
            .iter()
            .any(|attr| attr.key == "token_id" && attr.value == "1"));

        // check approval was added
        let token = tokens().load(&deps.storage, "xyz #1").unwrap();
        assert_eq!(token.name, "xyz #1");
        assert_eq!(
            token.approvals,
            vec![Approval {
                spender: Addr::unchecked(ADDR2),
                expires: Expiration::Never {}
            }]
        );

        // revoke blocks full token identifiers
        let err = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::Revoke {
                spender: ADDR2.to_string(),
                token_id: "xyz #1".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // revoke the approval
        let res = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::Revoke {
                spender: ADDR2.to_string(),
                token_id: "1".to_string(),
            },
        )
        .unwrap();

        // ensure response event emits the transferred token_id
        assert!(res
            .attributes
            .iter()
            .any(|attr| attr.key == "token_id" && attr.value == "1"));

        // check approval was revoked
        let token = tokens().load(&deps.storage, "xyz #1").unwrap();
        assert_eq!(token.name, "xyz #1");
        assert_eq!(token.approvals, vec![]);
    }

    #[test]
    fn cw721_send_nft() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        let token_id = "1".to_string();
        let target = "another_contract".to_string();
        let msg = to_binary("my msg").unwrap();

        // blocks full token identifiers
        let err = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::SendNft {
                contract: target.clone(),
                token_id: "xyz #1".to_string(),
                msg: msg.clone(),
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // send a token to a contract
        let res = cw721_base_execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADDR1, &[]),
            ExecuteMsg::SendNft {
                contract: target.clone(),
                token_id: token_id.clone(),
                msg: msg.clone(),
            },
        )
        .unwrap();

        let payload = Cw721ReceiveMsg {
            sender: ADDR1.to_string(),
            token_id: token_id.clone(),
            msg,
        };
        let expected = payload.into_cosmos_msg(target).unwrap();
        assert_eq!(
            res,
            Response::new()
                .add_message(expected)
                .add_attribute("action", "send_nft")
                .add_attribute("sender", ADDR1)
                .add_attribute("recipient", "another_contract")
                .add_attribute("token_id", token_id)
        );
    }
}
