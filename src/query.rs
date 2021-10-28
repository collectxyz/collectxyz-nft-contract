use rsa::pkcs8::ToPublicKey;

use cosmwasm_std::{Binary, Deps, Empty, Env, Order, StdError, StdResult};
use cw0::maybe_addr;
use cw721::NumTokensResponse;
use cw721_base::Cw721Contract;
use cw_storage_plus::Bound;

use crate::msg::{MoveParamsResponse, QueryMsg, XyzTokensResponse};
use crate::state::{
    load_captcha_public_key, tokens, Config, Coordinates, XyzExtension, XyzTokenInfo, CONFIG,
};

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_captcha_public_key(deps: Deps) -> StdResult<String> {
    let public_key = load_captcha_public_key(deps.storage)?;

    public_key
        .to_public_key_pem()
        .map_err(|_| StdError::generic_err("couldn't serialize public key"))
}

pub fn query_xyz_nft_info(deps: Deps, token_id: String) -> StdResult<XyzTokenInfo> {
    let token = tokens().load(deps.storage, &token_id)?;
    Ok(token)
}

pub fn query_xyz_nft_info_by_coords(deps: Deps, coords: Coordinates) -> StdResult<XyzTokenInfo> {
    let token = tokens()
        .idx
        .coordinates
        .item(deps.storage, coords.to_bytes())?
        .map(|(_, item)| item);
    if let Some(token) = token {
        Ok(token)
    } else {
        Err(StdError::not_found("xyz_token_info"))
    }
}

const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 30;

pub fn query_xyz_tokens(
    deps: Deps,
    owner: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<XyzTokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let owner = deps.api.addr_validate(&owner)?;
    let tokens: StdResult<Vec<_>> = tokens()
        .idx
        .owner
        .prefix(owner)
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, token)| token))
        .collect();
    Ok(XyzTokensResponse { tokens: tokens? })
}

pub fn query_all_xyz_tokens(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<XyzTokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_addr = maybe_addr(deps.api, start_after)?;
    let start = start_addr.map(|addr| Bound::exclusive(addr.as_ref()));

    let tokens: StdResult<Vec<_>> = tokens()
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, token)| token))
        .collect();
    Ok(XyzTokensResponse { tokens: tokens? })
}

pub fn query_num_tokens_for_owner(deps: Deps, owner: String) -> StdResult<NumTokensResponse> {
    let owner = deps.api.addr_validate(&owner)?;
    let count = tokens()
        .idx
        .owner
        .prefix(owner)
        .range(deps.storage, None, None, Order::Ascending)
        .count() as u64;
    Ok(NumTokensResponse { count })
}

pub fn query_move_params(
    deps: Deps,
    token_id: String,
    coordinates: Coordinates,
) -> StdResult<MoveParamsResponse> {
    let config = CONFIG.load(deps.storage)?;
    let token = tokens().load(deps.storage, &token_id)?;

    config.check_bounds(coordinates)?;

    let fee = config.get_move_fee(token.extension.coordinates, coordinates);
    let duration_nanos = config.get_move_nanos(token.extension.coordinates, coordinates);
    Ok(MoveParamsResponse {
        fee,
        duration_nanos,
    })
}

pub fn cw721_base_query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let cw721_contract = Cw721Contract::<XyzExtension, Empty>::default();
    cw721_contract.query(deps, env, msg.into())
}
