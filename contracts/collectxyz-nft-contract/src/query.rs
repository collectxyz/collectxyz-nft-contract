use rsa::pkcs8::ToPublicKey;

use collectxyz::nft::{
    full_token_id, numeric_token_id, Config, Coordinates, Cw721AllNftInfoResponse,
    Cw721NftInfoResponse, MoveParamsResponse, QueryMsg, XyzExtension, XyzTokenInfo,
    XyzTokensResponse,
};
use cosmwasm_std::{to_binary, Binary, BlockInfo, Deps, Empty, Env, Order, StdError, StdResult};
use cw0::maybe_addr;
use cw721::{NumTokensResponse, OwnerOfResponse, TokensResponse};
use cw721_base::{msg::QueryMsg as Cw721QueryMsg, Cw721Contract};
use cw_storage_plus::Bound;

use crate::state::{load_captcha_public_key, tokens, CONFIG};

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

    let cw721_msg: Cw721QueryMsg = msg.into();
    match cw721_msg {
        Cw721QueryMsg::NftInfo { token_id } => {
            to_binary(&query_nft_info(deps, env, full_token_id(token_id))?)
        }
        Cw721QueryMsg::AllNftInfo {
            token_id,
            include_expired,
        } => to_binary(&query_all_nft_info(
            deps,
            env,
            full_token_id(token_id),
            include_expired.unwrap_or(false),
        )?),
        Cw721QueryMsg::Tokens {
            owner,
            start_after,
            limit,
        } => to_binary(&query_tokens(deps, owner, start_after, limit)?),
        Cw721QueryMsg::AllTokens { start_after, limit } => {
            to_binary(&query_all_tokens(deps, start_after, limit)?)
        }
        Cw721QueryMsg::OwnerOf {
            token_id,
            include_expired,
        } => to_binary(&owner_of(
            deps,
            env,
            full_token_id(token_id),
            include_expired.unwrap_or(false),
        )?),
        _ => cw721_contract.query(deps, env, cw721_msg),
    }
}

pub fn query_nft_info(deps: Deps, _env: Env, token_id: String) -> StdResult<Cw721NftInfoResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(info.as_cw721_nft_info())
}

pub fn query_all_nft_info(
    deps: Deps,
    env: Env,
    token_id: String,
    include_expired: bool,
) -> StdResult<Cw721AllNftInfoResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(Cw721AllNftInfoResponse {
        access: OwnerOfResponse {
            owner: info.owner.to_string(),
            approvals: humanize_approvals(&env.block, &info, include_expired),
        },
        info: info.as_cw721_nft_info(),
    })
}

pub fn query_tokens(
    deps: Deps,
    owner: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let owner_addr = deps.api.addr_validate(&owner)?;
    let pks: Vec<_> = tokens()
        .idx
        .owner
        .prefix(owner_addr)
        .keys(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .collect();

    let res: Result<Vec<_>, _> = pks.iter().map(|v| String::from_utf8(v.to_vec())).collect();
    let tokens = res.map_err(StdError::invalid_utf8)?;
    let numeric_tokens: Vec<String> = tokens
        .iter()
        .map(|s| numeric_token_id(s.to_string()))
        .collect();
    Ok(TokensResponse {
        tokens: numeric_tokens,
    })
}

pub fn query_all_tokens(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let res: StdResult<Vec<String>> = tokens()
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(k, _)| String::from_utf8_lossy(&k).to_string()))
        .collect();
    let tokens = res.map_err(StdError::invalid_utf8)?;
    let numeric_tokens: Vec<String> = tokens
        .iter()
        .map(|s| numeric_token_id(s.to_string()))
        .collect();
    Ok(TokensResponse {
        tokens: numeric_tokens,
    })
}

pub fn owner_of(
    deps: Deps,
    env: Env,
    token_id: String,
    include_expired: bool,
) -> StdResult<OwnerOfResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(OwnerOfResponse {
        owner: info.owner.to_string(),
        approvals: humanize_approvals(&env.block, &info, include_expired),
    })
}

// adapted from: https://github.com/CosmWasm/cw-nfts/blob/5e1e72a3682f988d4504b94f2e203dd4a5a99ad9/contracts/cw721-base/src/query.rs#L211-L228
fn humanize_approvals(
    block: &BlockInfo,
    info: &XyzTokenInfo,
    include_expired: bool,
) -> Vec<cw721::Approval> {
    info.approvals
        .iter()
        .filter(|apr| include_expired || !apr.is_expired(block))
        .map(humanize_approval)
        .collect()
}

fn humanize_approval(approval: &cw721_base::state::Approval) -> cw721::Approval {
    cw721::Approval {
        spender: approval.spender.to_string(),
        expires: approval.expires,
    }
}
