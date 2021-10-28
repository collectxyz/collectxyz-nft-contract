use cosmwasm_std::StdError;
use cw721_base::ContractError as CW721ContractError;
use thiserror::Error;

/// This overrides the ContractError enum defined in cw721-base
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Coordinates already claimed")]
    Claimed {},

    #[error("Cannot set approval that is already expired")]
    Expired {},

    #[error("xyz token supply has been exhausted")]
    SupplyExhausted {},

    #[error("Per-wallet token allotment exceeded")]
    WalletLimit {},

    #[error("Move target out-of-bounds or already occupied")]
    InvalidMoveTarget {},

    #[error("Move already in progress")]
    MoveInProgress {},
}

impl From<CW721ContractError> for ContractError {
    fn from(msg: CW721ContractError) -> ContractError {
        match msg {
            CW721ContractError::Unauthorized {} => ContractError::Unauthorized {},
            CW721ContractError::Claimed {} => ContractError::Claimed {},
            CW721ContractError::Expired {} => ContractError::Expired {},
            CW721ContractError::Std(e) => ContractError::Std(e),
        }
    }
}
