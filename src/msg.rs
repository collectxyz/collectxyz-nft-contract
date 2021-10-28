use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, Coin};
use cw721::Expiration;
use cw721_base::msg::{ExecuteMsg as CW721ExecuteMsg, QueryMsg as CW721QueryMsg};

use crate::state::{Config, Coordinates, XyzExtension, XyzTokenInfo};

/// This overrides the ExecuteMsg enum defined in cw721-base
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct InstantiateMsg {
    pub captcha_public_key: String,
    pub config: Config,
}

/// This overrides the ExecuteMsg enum defined in cw721-base
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Mint a new NFT for the message sender with the given set of coordinates and signature
    /// from the recaptcha verifier lambda function.
    Mint {
        coordinates: Coordinates,
        captcha_signature: String,
    },
    /// Move an existing NFT to the given set of coordinates.
    Move {
        token_id: String,
        coordinates: Coordinates,
    },

    /// Update token minting and supply configuration.
    UpdateConfig {
        config: Config,
    },
    /// Update public key used for captcha verification.
    UpdateCaptchaPublicKey {
        public_key: String,
    },
    /// Withdraw from current contract balance to owner address.
    Withdraw {
        amount: Vec<Coin>,
    },

    /// BELOW ARE COPIED FROM CW721-BASE
    TransferNft {
        recipient: String,
        token_id: String,
    },
    SendNft {
        contract: String,
        token_id: String,
        msg: Binary,
    },
    Approve {
        spender: String,
        token_id: String,
        expires: Option<Expiration>,
    },
    Revoke {
        spender: String,
        token_id: String,
    },
    ApproveAll {
        operator: String,
        expires: Option<Expiration>,
    },
    RevokeAll {
        operator: String,
    },
}

impl From<ExecuteMsg> for CW721ExecuteMsg<XyzExtension> {
    fn from(msg: ExecuteMsg) -> CW721ExecuteMsg<XyzExtension> {
        match msg {
            ExecuteMsg::TransferNft {
                recipient,
                token_id,
            } => CW721ExecuteMsg::TransferNft {
                recipient,
                token_id,
            },
            ExecuteMsg::SendNft {
                contract,
                token_id,
                msg,
            } => CW721ExecuteMsg::SendNft {
                contract,
                token_id,
                msg,
            },
            ExecuteMsg::Approve {
                spender,
                token_id,
                expires,
            } => CW721ExecuteMsg::Approve {
                spender,
                token_id,
                expires,
            },
            ExecuteMsg::Revoke { spender, token_id } => {
                CW721ExecuteMsg::Revoke { spender, token_id }
            }
            ExecuteMsg::ApproveAll { operator, expires } => {
                CW721ExecuteMsg::ApproveAll { operator, expires }
            }
            ExecuteMsg::RevokeAll { operator } => CW721ExecuteMsg::RevokeAll { operator },
            _ => panic!("cannot covert {:?} to CW721ExecuteMsg", msg),
        }
    }
}

/// This overrides the ExecuteMsg enum defined in cw721-base
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Returns the current contract config
    /// Return type: Config
    Config {},
    /// Returns the currently configured captcha public key
    CaptchaPublicKey {},

    /// Returns all tokens owned by the given address, [] if unset.
    /// Return type: XyzTokensResponse.
    XyzTokens {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// Lists all token_ids controlled by the contract.
    /// Return type: XyzTokensResponse.
    AllXyzTokens {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// Returns metadata about one particular token, based on *ERC721 Metadata JSON Schema*
    /// but directly from the contract: XyzTokenInfo.
    XyzNftInfo {
        token_id: String,
    },
    /// Returns metadata about the token associated with the given coordinates, if any.
    /// Return type: XyzTokenInfo.
    XyzNftInfoByCoords {
        coordinates: Coordinates,
    },
    /// Returns the number of tokens owned by the given address
    /// Return type: NumTokensResponse
    NumTokensForOwner {
        owner: String,
    },

    /// Calculates the price to move the given token to the given coordinate.
    /// Return type: MoveParamsResponse
    MoveParams {
        token_id: String,
        coordinates: Coordinates,
    },

    // BELOW ARE COPIED FROM CW721-BASE
    OwnerOf {
        token_id: String,
        include_expired: Option<bool>,
    },
    ApprovedForAll {
        owner: String,
        include_expired: Option<bool>,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    NumTokens {},
    ContractInfo {},
    NftInfo {
        token_id: String,
    },
    AllNftInfo {
        token_id: String,
        include_expired: Option<bool>,
    },
    Tokens {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    AllTokens {
        start_after: Option<String>,
        limit: Option<u32>,
    },
}

impl From<QueryMsg> for CW721QueryMsg {
    fn from(msg: QueryMsg) -> CW721QueryMsg {
        match msg {
            QueryMsg::XyzTokens {
                owner,
                start_after,
                limit,
            } => CW721QueryMsg::Tokens {
                owner,
                start_after,
                limit,
            },
            QueryMsg::AllXyzTokens { start_after, limit } => {
                CW721QueryMsg::AllTokens { start_after, limit }
            }
            QueryMsg::XyzNftInfo { token_id } => CW721QueryMsg::NftInfo { token_id },
            QueryMsg::OwnerOf {
                token_id,
                include_expired,
            } => CW721QueryMsg::OwnerOf {
                token_id,
                include_expired,
            },
            QueryMsg::ApprovedForAll {
                owner,
                include_expired,
                start_after,
                limit,
            } => CW721QueryMsg::ApprovedForAll {
                owner,
                include_expired,
                start_after,
                limit,
            },
            QueryMsg::NumTokens {} => CW721QueryMsg::NumTokens {},
            QueryMsg::ContractInfo {} => CW721QueryMsg::ContractInfo {},
            QueryMsg::NftInfo { token_id } => CW721QueryMsg::NftInfo { token_id },
            QueryMsg::AllNftInfo {
                token_id,
                include_expired,
            } => CW721QueryMsg::AllNftInfo {
                token_id,
                include_expired,
            },
            QueryMsg::Tokens {
                owner,
                start_after,
                limit,
            } => CW721QueryMsg::Tokens {
                owner,
                start_after,
                limit,
            },
            QueryMsg::AllTokens { start_after, limit } => {
                CW721QueryMsg::AllTokens { start_after, limit }
            }
            _ => panic!("cannot covert {:?} to CW721QueryMsg", msg),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct XyzTokensResponse {
    pub tokens: Vec<XyzTokenInfo>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct MoveParamsResponse {
    pub fee: Coin,
    pub duration_nanos: u64,
}

/// This is a custom message type, not present in cw721-base
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {
    pub config: Config,
}
