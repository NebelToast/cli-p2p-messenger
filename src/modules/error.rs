use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Peer was not found in the registry")]
    PeerNotFound,

    #[error("Session has not been established yet")]
    SessionNotEstablished,

    #[error("Encryption failed: {0}")]
    Encryption(#[from] snow::Error),

    #[error("Network I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to read file: {0}")]
    ReadFile(#[from] io::Error),
    #[error("Failed to generate key: {0}")]
    GenerateKey(#[from] snow::Error),
}

#[derive(Error, Debug)]
pub enum ConnectErrors {
    #[error("Failed to send message: {0}")]
    SendMessage(#[from] io::Error),
    #[error("Failed to generate key: {0}")]
    GenerateKey(#[from] snow::Error),
    #[error("Connection timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connecterror_formating_send_message() {
        let err = ConnectErrors::SendMessage(io::Error::other("test error"));
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
        let err = KeyGenerationError::ReadFile(io::Error::other("read error"));
        assert_eq!(err.to_string(), "Failed to read file: read error");
    }

    #[test]
    fn test_keygenerationerror_generate_key() {
        let err = KeyGenerationError::GenerateKey(snow::Error::Input);
        assert_eq!(err.to_string(), "Failed to generate key: input error");
    }
    #[test]
    fn test_io_to_key_generation_error() {
        let err = io::Error::other("test error");
        let key_err: KeyGenerationError = err.into();
        assert!(matches!(key_err, KeyGenerationError::ReadFile(_)))
    }
    #[test]
    fn test_io_to_connect_error() {
        let err = io::Error::other("test error");
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
