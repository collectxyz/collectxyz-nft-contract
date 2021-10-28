use rsa::{pkcs8::FromPublicKey, RsaPublicKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use cosmwasm_std::{Addr, Coin, StdError, StdResult, Storage, Timestamp, Uint128};
use cw721_base::state::TokenInfo;
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex, UniqueIndex};

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

pub const CONFIG: Item<Config> = Item::new("config");

const CAPTCHA_PUBLIC_KEY: Item<String> = Item::new("captcha_public_key");
pub fn save_captcha_public_key(storage: &mut dyn Storage, public_key: &str) -> StdResult<()> {
    RsaPublicKey::from_public_key_pem(public_key)
        .map_err(|_| StdError::generic_err("invalid public key"))?;
    CAPTCHA_PUBLIC_KEY.save(storage, &public_key.to_string())?;
    Ok(())
}
pub fn load_captcha_public_key(storage: &dyn Storage) -> StdResult<RsaPublicKey> {
    let public_key = CAPTCHA_PUBLIC_KEY.load(storage)?;
    RsaPublicKey::from_public_key_pem(&public_key)
        .map_err(|_| StdError::generic_err("invalid public key"))
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

    pub fn distance(&self, other: Self) -> u16 {
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

pub type XyzTokenInfo = TokenInfo<XyzExtension>;

pub struct TokenIndexes<'a> {
    pub owner: MultiIndex<'a, (Addr, Vec<u8>), XyzTokenInfo>,
    pub coordinates: UniqueIndex<'a, Vec<u8>, XyzTokenInfo>,
}

impl<'a> IndexList<XyzTokenInfo> for TokenIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<XyzTokenInfo>> + '_> {
        let v: Vec<&dyn Index<XyzTokenInfo>> = vec![&self.owner, &self.coordinates];
        Box::new(v.into_iter())
    }
}

pub fn tokens<'a>() -> IndexedMap<'a, &'a str, XyzTokenInfo, TokenIndexes<'a>> {
    let indexes = TokenIndexes {
        owner: MultiIndex::new(
            |d: &XyzTokenInfo, k: Vec<u8>| (d.owner.clone(), k),
            "tokens",
            "tokens__owner",
        ),
        coordinates: UniqueIndex::new(
            |d: &XyzTokenInfo| d.extension.coordinates.to_bytes(),
            "tokens__coordinates",
        ),
    };
    IndexedMap::new("tokens", indexes)
}

pub const OWNER: Item<String> = Item::new("owner");
