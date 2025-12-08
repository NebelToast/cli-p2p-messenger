use std::{fmt, io};

#[derive(Debug)]
pub enum KeyGenerationError {
    ReadFile(io::Error),
    GenerateKey(snow::Error),
}

#[derive(Debug)]
pub enum ConnectErrors {
    SendMessage(io::Error),
    GenerateKey(snow::Error),
    Timeout,
}

impl fmt::Display for ConnectErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectErrors::SendMessage(e) => write!(f, "Failed to send message: {}", e),
            ConnectErrors::GenerateKey(e) => write!(f, "Failed to generate key: {}", e),
            ConnectErrors::Timeout => write!(f, "Connection timed out"),
        }
    }
}

impl fmt::Display for KeyGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyGenerationError::ReadFile(e) => write!(f, "Failed to read file: {}", e),
            KeyGenerationError::GenerateKey(e) => write!(f, "Failed to generate key: {}", e),
        }
    }
}

impl From<io::Error> for ConnectErrors {
    fn from(error: io::Error) -> Self {
        ConnectErrors::SendMessage(error)
    }
}

impl From<snow::Error> for ConnectErrors {
    fn from(error: snow::Error) -> Self {
        ConnectErrors::GenerateKey(error)
    }
}

impl From<io::Error> for KeyGenerationError {
    fn from(error: io::Error) -> Self {
        KeyGenerationError::ReadFile(error)
    }
}

impl From<snow::Error> for KeyGenerationError {
    fn from(error: snow::Error) -> Self {
        KeyGenerationError::GenerateKey(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connecterror_formating_send_message() {
        let err = ConnectErrors::SendMessage(io::Error::new(io::ErrorKind::Other, "test error"));
        assert_eq!(err.to_string(), "Failed to send message: test error");
    }
    #[test]
    fn test_connecterror_formating_timeout() {
        let err = ConnectErrors::Timeout;
        assert_eq!(err.to_string(), "Connection timed out");
    }
    #[test]
    fn test_connecterror_formating_generate_key() {
        let err = ConnectErrors::GenerateKey(snow::Error::Input);
        assert_eq!(err.to_string(), "Failed to generate key: input error");
    }

    #[test]
    fn test_keygenerationerror_read_file() {
        let err = KeyGenerationError::ReadFile(io::Error::new(io::ErrorKind::Other, "read error"));
        assert_eq!(err.to_string(), "Failed to read file: read error");
    }

    #[test]
    fn test_keygenerationerror_generate_key() {
        let err = KeyGenerationError::GenerateKey(snow::Error::Input);
        assert_eq!(err.to_string(), "Failed to generate key: input error");
    }
    #[test]
    fn test_io_to_key_generation_error() {
        let err = io::Error::new(io::ErrorKind::Other, "test error");
        let key_err: KeyGenerationError = err.into();
        assert!(matches!(key_err, KeyGenerationError::ReadFile(_)))
    }
    #[test]
    fn test_io_to_connect_error() {
        let err = io::Error::new(io::ErrorKind::Other, "test error");
        let connect_err: ConnectErrors = err.into();
        assert!(matches!(connect_err, ConnectErrors::SendMessage(_)))
    }
    #[test]
    fn test_snow_to_connect_error() {
        let err = snow::Error::Input;
        let connect_err: ConnectErrors = err.into();
        assert!(matches!(connect_err, ConnectErrors::GenerateKey(_)))
    }
    #[test]
    fn test_snow_to_key_generation_error() {
        let err = snow::Error::Input;
        let key_err: KeyGenerationError = err.into();
        assert!(matches!(key_err, KeyGenerationError::GenerateKey(_)))
    }
}
