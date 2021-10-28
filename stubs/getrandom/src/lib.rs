mod error;

pub use crate::error::Error;

pub fn getrandom(_: &mut [u8]) -> Result<(), Error> {
    Ok(())
}
