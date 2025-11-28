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
