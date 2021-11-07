use base64;
use rsa::{hash::Hash, padding::PaddingScheme, PublicKey};
use serde_json;
use sha2::{Digest, Sha256};

use collectxyz::nft::{
    Config, Coordinates, ExecuteMsg, InstantiateMsg, MigrateMsg, XyzExtension, XyzTokenInfo,
};
use cosmwasm_std::{
    BankMsg, Coin, DepsMut, Empty, Env, MessageInfo, Order, Response, StdError, StdResult, Storage,
};
use cw721::ContractInfoResponse;
use cw721_base::Cw721Contract;

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
    let token_id = format!("{}", &num_tokens);
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
        .add_attribute("token_id", token_id))
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

fn base64_token_image(coords: &Coordinates) -> String {
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMinYMin meet" viewBox="0 0 240 240"><g class="container"><rect style="width:240px;height:240px;fill:#000;"/><text x="120" y="120" dominant-baseline="middle" text-anchor="middle" style="fill:#fff;font-family:serif;font-size:16px;text-align:center;">[{}, {}, {}]</text></g></svg>"#,
        coords.x, coords.y, coords.z
    );
    let base64_uri = format!("data:image/svg+xml;base64,{}", base64::encode(svg));
    base64_uri
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
        .add_attribute("token_id", token_id))
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

    cw721_contract
        .execute(deps, env, info, msg.into())
        .map_err(|err| err.into())
}

pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    let cw721_contract = Cw721Contract::<XyzExtension, Empty>::default();
    let num_tokens = 1 + cw721_contract.token_count(deps.storage)?;
    for token_num in 1..num_tokens {
        let token_id = format!("xyz #{}", token_num);
        let new_token_id = format!("#{}", token_num);
        let token = tokens().load(deps.storage, &token_id)?;
        let mut new_token = token.clone();
        new_token.name = new_token_id.clone();
        tokens().remove(deps.storage, &token_id)?;
        tokens().update(deps.storage, &new_token_id, |old| match old {
            Some(_) => Ok(new_token),
            None => Err(StdError::generic_err("migration")),
        })?;
    }

    Ok(Response::default().add_attribute("action", "migrate"))
}
