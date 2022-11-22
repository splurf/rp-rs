use {hyper::header::ToStrError, std::num::ParseIntError};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(String);

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<tokio_rustls::rustls::Error> for Error {
    fn from(e: tokio_rustls::rustls::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<ToStrError> for Error {
    fn from(e: ToStrError) -> Self {
        Self(e.to_string())
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Self(e.to_string())
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Self(e.to_string())
    }
}
