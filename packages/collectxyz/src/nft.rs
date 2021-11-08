use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use cosmwasm_std::{Addr, Binary, Coin, StdError, StdResult, Timestamp, Uint128};
use cw721::{Expiration, OwnerOfResponse};
use cw721_base::msg::{ExecuteMsg as CW721ExecuteMsg, QueryMsg as CW721QueryMsg};
use cw721_base::state::Approval;

// ----------------- begin CW721 ^0.9.2 shim ----------------- //

// adapted from: https://github.com/CosmWasm/cw-nfts/blob/5e1e72a3682f988d4504b94f2e203dd4a5a99ad9/contracts/cw721-metadata-onchain/src/lib.rs#L7-L26
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug, Default)]
pub struct Cw721Trait {
    pub display_type: Option<String>,
    pub trait_type: String,
    pub value: String,
}

// see: https://docs.opensea.io/docs/metadata-standards
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug, Default)]
pub struct Cw721Metadata {
    pub image: Option<String>,
    pub image_data: Option<String>,
    pub external_url: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    pub attributes: Option<Vec<Cw721Trait>>,
    pub background_color: Option<String>,
    pub animation_url: Option<String>,
    pub youtube_url: Option<String>,
}

// adapted from: https://github.com/CosmWasm/cw-nfts/blob/5e1e72a3682f988d4504b94f2e203dd4a5a99ad9/packages/cw721/src/query.rs#L93-L109
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Cw721NftInfoResponse {
    /// Universal resource identifier for this NFT
    /// Should point to a JSON file that conforms to the ERC721
    /// Metadata JSON Schema
    pub token_uri: Option<String>,
    /// You can add any custom metadata here when you extend cw721-base
    pub extension: Cw721Metadata,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Cw721AllNftInfoResponse {
    /// Who can transfer the token
    pub access: OwnerOfResponse,
    /// Data on the token itself,
    pub info: Cw721NftInfoResponse,
}

// ----------------- end CW721 ^0.9.2 shim----------------- //

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    /// If true, then anyone can mint an xyz token. If false, then only the
    /// contract owner is authorized to mint.
    pub public_minting_enabled: bool,
    /// The maximum value of a coordinate in any dimension. The minimum
    /// will be set to the negation of this value.
    pub max_coordinate_value: i64,
    /// The maximum allowed number of xyz tokens
    pub token_supply: u64,
    /// The maximum number of tokens a particular wallet can hold
    pub wallet_limit: u32,
    /// The price to mint a new xyz (doesn't apply to the contract owner)
    pub mint_fee: Coin,
    /// The time it takes to initiate a move. To get overall move time:
    ///   base_move_nanos + move_nanos_per_step * distance
    pub base_move_nanos: u64,
    /// The move travel time per marginal step taken, where a
    /// step is a one-dimensional coordinate increment or decrement.
    pub move_nanos_per_step: u64,
    /// The base fee to initiate a move. To get overall move fee:
    ///   base_move_fee.amount + move_fee_per_step * distance
    pub base_move_fee: Coin,
    /// The increase in move fee price per marginal step taken, where
    /// a step is a one-dimensional coordinate increment or decrement.
    /// Assumed to be in the denom associated with base_move_fee.
    pub move_fee_per_step: Uint128,
}

impl Config {
    pub fn get_move_fee(&self, start: Coordinates, end: Coordinates) -> Coin {
        let distance = start.distance(end) as u128;
        let move_fee_amount =
            self.base_move_fee.amount.u128() + self.move_fee_per_step.u128() * distance;
        Coin::new(move_fee_amount, &self.base_move_fee.denom)
    }

    pub fn get_move_nanos(&self, start: Coordinates, end: Coordinates) -> u64 {
        let distance = start.distance(end) as u64;
        self.base_move_nanos + self.move_nanos_per_step * distance
    }

    pub fn check_bounds(&self, coords: Coordinates) -> StdResult<()> {
        let min_coordinate_value = -self.max_coordinate_value;
        if vec![coords.x, coords.y, coords.z]
            .iter()
            .any(|c| c < &min_coordinate_value || c > &self.max_coordinate_value)
        {
            let error = StdError::generic_err(format!(
                "coordinate values must be between {} and {}",
                min_coordinate_value, self.max_coordinate_value
            ));
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Copy)]
pub struct Coordinates {
    pub x: i64,
    pub y: i64,
    pub z: i64,
}

impl Coordinates {
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.x.to_be_bytes(),
            self.y.to_be_bytes(),
            self.z.to_be_bytes(),
        ]
        .concat()
    }

    pub fn distance(&self, other: Self) -> u64 {
        let distance =
            (self.x - other.x).abs() + (self.y - other.y).abs() + (self.z - other.z).abs();
        // the distance will always be positive, since it's a sum of absolute values
        distance.try_into().unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Copy)]
pub struct XyzExtension {
    pub coordinates: Coordinates,
    pub prev_coordinates: Option<Coordinates>,
    pub arrival: Timestamp,
}

impl XyzExtension {
    pub fn has_arrived(&self, current_time: Timestamp) -> bool {
        self.arrival <= current_time
    }

    pub fn as_traits(&self) -> Vec<Cw721Trait> {
        vec![
            Cw721Trait {
                display_type: None,
                trait_type: "x".to_string(),
                value: self.coordinates.x.to_string(),
            },
            Cw721Trait {
                display_type: None,
                trait_type: "y".to_string(),
                value: self.coordinates.y.to_string(),
            },
            Cw721Trait {
                display_type: None,
                trait_type: "z".to_string(),
                value: self.coordinates.z.to_string(),
            },
        ]
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct XyzTokenInfo {
    pub owner: Addr,
    pub approvals: Vec<Approval>,
    pub name: String,
    pub description: String,
    pub image: Option<String>,
    pub extension: XyzExtension,
}

impl XyzTokenInfo {
    pub fn as_cw721_nft_info(&self) -> Cw721NftInfoResponse {
        Cw721NftInfoResponse {
            token_uri: None,
            extension: Cw721Metadata {
                name: Some(self.name.clone()),
                image: Some(self.base64_token_image()),
                description: Some(self.description.clone()),
                attributes: Some(self.extension.as_traits()),
                image_data: None,
                external_url: None,
                animation_url: None,
                background_color: None,
                youtube_url: None,
            },
        }
    }

    pub fn base64_token_image(&self) -> String {
        base64_token_image(&self.extension.coordinates)
    }
}

pub fn base64_token_image(coords: &Coordinates) -> String {
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMinYMin meet" viewBox="0 0 240 240"><g class="container"><rect style="width:240px;height:240px;fill:#000;"/><text x="120" y="120" dominant-baseline="middle" text-anchor="middle" style="fill:#fff;font-family:serif;font-size:16px;text-align:center;">[{}, {}, {}]</text></g></svg>"#,
        coords.x, coords.y, coords.z
    );
    let base64_uri = format!("data:image/svg+xml;base64,{}", base64::encode(svg));
    base64_uri
}

pub fn full_token_id(numeric_token_id: String) -> StdResult<String> {
    // make sure the string is an integer
    numeric_token_id
        .parse::<u64>()
        .map_err(|_| StdError::generic_err("expected numeric token identifier"))?;
    Ok(format!("xyz #{}", numeric_token_id))
}

pub fn numeric_token_id(full_token_id: String) -> StdResult<String> {
    if !full_token_id.starts_with("xyz #") {
        return Err(StdError::generic_err(
            "expected full token identifier, like 'xyz #123'",
        ));
    }
    Ok(full_token_id.trim_start_matches("xyz #").to_string())
}

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

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xyz_token_info_as_cw721_nft_info() {
        let info = XyzTokenInfo {
            name: "xyz #1".to_string(),
            owner: Addr::unchecked("test owner"),
            description: "test description".to_string(),
            image: None,
            approvals: vec![],
            extension: XyzExtension {
                coordinates: Coordinates { x: 1, y: 2, z: 3 },
                prev_coordinates: None,
                arrival: Timestamp::from_nanos(1),
            },
        };

        assert_eq!(
            info.as_cw721_nft_info(),
            Cw721NftInfoResponse {
                token_uri: None,
                extension: Cw721Metadata {
                    name: Some("xyz #1".to_string()),
                    description: Some("test description".to_string()),
                    image: Some("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHByZXNlcnZlQXNwZWN0UmF0aW89InhNaW5ZTWluIG1lZXQiIHZpZXdCb3g9IjAgMCAyNDAgMjQwIj48ZyBjbGFzcz0iY29udGFpbmVyIj48cmVjdCBzdHlsZT0id2lkdGg6MjQwcHg7aGVpZ2h0OjI0MHB4O2ZpbGw6IzAwMDsiLz48dGV4dCB4PSIxMjAiIHk9IjEyMCIgZG9taW5hbnQtYmFzZWxpbmU9Im1pZGRsZSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgc3R5bGU9ImZpbGw6I2ZmZjtmb250LWZhbWlseTpzZXJpZjtmb250LXNpemU6MTZweDt0ZXh0LWFsaWduOmNlbnRlcjsiPlsxLCAyLCAzXTwvdGV4dD48L2c+PC9zdmc+".to_string()),
                    attributes: Some(vec![
                        Cw721Trait {
                            display_type: None,
                            trait_type: "x".to_string(),
                            value: "1".to_string(),
                        },
                        Cw721Trait {
                            display_type: None,
                            trait_type: "y".to_string(),
                            value: "2".to_string(),
                        },
                        Cw721Trait {
                            display_type: None,
                            trait_type: "z".to_string(),
                            value: "3".to_string(),
                        },
                    ]),
                    image_data: None,
                    animation_url: None,
                    youtube_url: None,
                    external_url: None,
                    background_color: None
                }
            }
        )
    }
}
