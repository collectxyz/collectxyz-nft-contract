use core::{convert::From, fmt, num::NonZeroU32};
use std;
use std::io;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error(NonZeroU32);

impl Error {
    #[inline]
    pub fn raw_os_error(self) -> Option<i32> {
        None
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}

impl std::error::Error for Error {}
