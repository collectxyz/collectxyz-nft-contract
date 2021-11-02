use rsa::{pkcs8::FromPublicKey, RsaPublicKey};

use collectxyz::nft::{Config, XyzTokenInfo};
use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex, UniqueIndex};

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
