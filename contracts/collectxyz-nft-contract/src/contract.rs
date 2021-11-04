use collectxyz::nft::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw2::{get_contract_version, set_contract_version};

use crate::error::ContractError;
use crate::execute as ExecHandler;
use crate::query as QueryHandler;

const CONTRACT_NAME: &str = "crates.io:collectxyz-nft-contract";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    ExecHandler::instantiate(deps, info, msg)
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Mint {
            coordinates,
            captcha_signature,
        } => ExecHandler::execute_mint(deps, env, info, coordinates, captcha_signature),
        ExecuteMsg::Move {
            token_id,
            coordinates,
        } => ExecHandler::execute_move(deps, env, info, token_id, coordinates),
        ExecuteMsg::UpdateConfig { config } => {
            ExecHandler::execute_update_config(deps, info, config)
        }
        ExecuteMsg::UpdateCaptchaPublicKey { public_key } => {
            ExecHandler::execute_update_captcha_public_key(deps, info, public_key)
        }
        ExecuteMsg::Withdraw { amount } => ExecHandler::execute_withdraw(deps, env, info, amount),
        _ => ExecHandler::cw721_base_execute(deps, env, info, msg),
    }
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&QueryHandler::query_config(deps)?),
        QueryMsg::CaptchaPublicKey {} => to_binary(&QueryHandler::query_captcha_public_key(deps)?),
        QueryMsg::XyzNftInfo { token_id } => {
            to_binary(&QueryHandler::query_xyz_nft_info(deps, token_id)?)
        }
        QueryMsg::XyzNftInfoByCoords { coordinates } => to_binary(
            &QueryHandler::query_xyz_nft_info_by_coords(deps, coordinates)?,
        ),
        QueryMsg::XyzTokens {
            owner,
            start_after,
            limit,
        } => to_binary(&QueryHandler::query_xyz_tokens(
            deps,
            owner,
            start_after,
            limit,
        )?),
        QueryMsg::AllXyzTokens { start_after, limit } => to_binary(
            &QueryHandler::query_all_xyz_tokens(deps, start_after, limit)?,
        ),
        QueryMsg::NumTokensForOwner { owner } => {
            to_binary(&QueryHandler::query_num_tokens_for_owner(deps, owner)?)
        }
        QueryMsg::MoveParams {
            token_id,
            coordinates,
        } => to_binary(&QueryHandler::query_move_params(
            deps,
            token_id,
            coordinates,
        )?),
        _ => QueryHandler::cw721_base_query(deps, env, msg),
    }
}

#[entry_point]
pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
    let version = get_contract_version(deps.storage)?;
    if version.contract != CONTRACT_NAME {
        return Err(StdError::generic_err(
            "can't migrate to contract with different name",
        ));
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    ExecHandler::migrate(deps, env, msg)
}
