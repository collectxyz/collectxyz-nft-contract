use rsa::pkcs8::ToPublicKey;

use collectxyz::nft::{
    full_token_id, numeric_token_id, Config, Coordinates, Cw721AllNftInfoResponse,
    Cw721NftInfoResponse, MoveParamsResponse, QueryMsg, XyzExtension, XyzTokenInfo,
    XyzTokensResponse,
};
use cosmwasm_std::{to_binary, Binary, BlockInfo, Deps, Empty, Env, Order, StdError, StdResult};
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
    let start = start_after.map(Bound::exclusive);

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
            to_binary(&query_nft_info(deps, env, full_token_id(token_id)?)?)
        }
        Cw721QueryMsg::AllNftInfo {
            token_id,
            include_expired,
        } => to_binary(&query_all_nft_info(
            deps,
            env,
            full_token_id(token_id)?,
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
            full_token_id(token_id)?,
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
        .map(|s| numeric_token_id(s.to_string()).unwrap())
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
        .map(|s| numeric_token_id(s.to_string()).unwrap())
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

#[cfg(test)]
mod test {
    use super::*;

    use collectxyz::nft::{Cw721AllNftInfoResponse, Cw721Metadata, Cw721Trait};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{from_binary, Addr, DepsMut, Timestamp};

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

    fn numeric_id_error() -> StdError {
        StdError::generic_err("expected numeric token identifier")
    }

    #[test]
    fn nft_info() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        let expected = Cw721NftInfoResponse {
            token_uri: None,
            extension: Cw721Metadata {
                image: Some(
                    "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHByZXNlcnZlQXNwZWN0UmF0aW89InhNaW5ZTWluIG1lZXQiIHZpZXdCb3g9IjAgMCAyNDAgMjQwIj48ZyBjbGFzcz0iY29udGFpbmVyIj48cmVjdCBzdHlsZT0id2lkdGg6MjQwcHg7aGVpZ2h0OjI0MHB4O2ZpbGw6IzAwMDsiLz48dGV4dCB4PSIxMjAiIHk9IjEyMCIgZG9taW5hbnQtYmFzZWxpbmU9Im1pZGRsZSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgc3R5bGU9ImZpbGw6I2ZmZjtmb250LWZhbWlseTpzZXJpZjtmb250LXNpemU6MTZweDt0ZXh0LWFsaWduOmNlbnRlcjsiPlsxLCAxLCAxXTwvdGV4dD48L2c+PC9zdmc+".to_string(),
                ),
                image_data: None,
                external_url: None,
                description: Some("".to_string()
                ),
                name: Some(
                    "xyz #1".to_string()
                ),
                attributes: Some(
                    vec![
                        Cw721Trait {
                            display_type: None,
                            trait_type: "x".to_string(),
                            value: "1".to_string(),
                        },
                        Cw721Trait {
                            display_type: None,
                            trait_type: "y".to_string(),
                            value: "1".to_string(),
                        },
                        Cw721Trait {
                            display_type: None,
                            trait_type: "z".to_string(),
                            value: "1".to_string(),
                        },
                    ],
                ),
                background_color: None,
                animation_url: None,
                youtube_url: None,
            },
        };

        // nft_info blocks full token identifiers
        let err = cw721_base_query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::NftInfo {
                token_id: "xyz #1".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // nft_info looks up token info for numeric id
        let info = from_binary::<Cw721NftInfoResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::NftInfo {
                    token_id: "1".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(info, expected);

        // all_nft_info blocks full token identifiers
        let err = cw721_base_query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllNftInfo {
                token_id: "xyz #1".to_string(),
                include_expired: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // all_nft_info looks up token access and info for numeric id
        let all_info = from_binary::<Cw721AllNftInfoResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::AllNftInfo {
                    token_id: "1".to_string(),
                    include_expired: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            all_info,
            Cw721AllNftInfoResponse {
                access: OwnerOfResponse {
                    owner: ADDR1.to_string(),
                    approvals: vec![]
                },
                info: expected
            }
        );
    }

    #[test]
    fn list_tokens() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        // list tokens for owner
        let res = from_binary::<TokensResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Tokens {
                    owner: ADDR1.to_string(),
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res.tokens, vec!["1".to_string()]);

        // list all tokens
        let res = from_binary::<TokensResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::AllTokens {
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(res.tokens, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn owner_of() {
        let mut deps = mock_dependencies(&[]);
        setup_storage(deps.as_mut());

        // owner_of blocks full token identifiers
        let err = cw721_base_query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::OwnerOf {
                token_id: "xyz #1".to_string(),
                include_expired: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, numeric_id_error());

        // owner_of looks up token ownership for numeric id
        let res = from_binary::<OwnerOfResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::OwnerOf {
                    token_id: "1".to_string(),
                    include_expired: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: ADDR1.to_string(),
                approvals: vec![]
            }
        );

        let res = from_binary::<OwnerOfResponse>(
            &cw721_base_query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::OwnerOf {
                    token_id: "2".to_string(),
                    include_expired: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: ADDR2.to_string(),
                approvals: vec![]
            }
        );
    }
}
