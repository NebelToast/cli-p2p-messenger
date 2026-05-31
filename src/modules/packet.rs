use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionFlag {
    Handshake = 0x01,
    Transport = 0x02,
    HandshakeResponse = 0x03,
    Reject = 0x04,
}

impl TryFrom<u8> for SessionFlag {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SessionFlag::Handshake),
            0x02 => Ok(SessionFlag::Transport),
            0x03 => Ok(SessionFlag::HandshakeResponse),
            0x04 => Ok(SessionFlag::Reject),
            _ => Err(()),
        }
    }
}

pub fn split_flagged_payload(packet: &[u8]) -> Option<(SessionFlag, &[u8])> {
    let (&flag, payload) = packet.split_first()?;
    Some((SessionFlag::try_from(flag).ok()?, payload))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    pub sender: SocketAddr,
    pub bytes: usize,
    pub payload: Box<[u8]>,
}

impl Packet {
    pub fn new(sender: SocketAddr, bytes: usize, payload: Box<[u8]>) -> Self {
        Self {
            sender,
            bytes,
            payload,
        }
    }

    pub fn print_message(&self) {
        println!(
            "Message: {} from {} consisting of {} bytes",
            String::from_utf8_lossy(&self.payload[..self.bytes]),
            &self.sender,
            &self.bytes
        );
    }

    pub fn _save_message(&self, dir: &Path) -> Result<(), io::Error> {
        let mut file = File::options()
            .create(true)
            .append(true)
            .open(dir.join("messages.txt"))?;
        writeln!(
            &mut file,
            "Message: {} from {} consisting of {} bytes",
            String::from_utf8_lossy(&self.payload[..self.bytes]),
            self.sender,
            self.bytes
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_save_message() {
        let dir = tempdir().unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut payload = [0u8; 65535];
        let msg = b"File contents";
        payload[..msg.len()].copy_from_slice(msg);

        let packet = Packet::new(addr, msg.len(), Box::new(payload));

        assert!(packet._save_message(dir.path()).is_ok());
        assert_eq!(
            fs::read_to_string(dir.path().join("messages.txt"))
                .unwrap()
                .trim(),
            format!(
                "Message: {} from {} consisting of {} bytes",
                String::from_utf8_lossy(&payload[..msg.len()]),
                addr,
                msg.len()
            )
        )
    }

    #[test]
    fn test_split_flagged_payload_handshake() {
        let packet = [0x01, 10, 20, 30];
        let (flag, payload) = split_flagged_payload(&packet).unwrap();

        assert_eq!(flag, SessionFlag::Handshake);
        assert_eq!(payload, &[10, 20, 30]);
    }

    #[test]
    fn test_split_flagged_payload_transport() {
        let packet = [0x02, 99];
        let (flag, payload) = split_flagged_payload(&packet).unwrap();

        assert_eq!(flag, SessionFlag::Transport);
        assert_eq!(payload, &[99]);
    }

    #[test]
    fn test_split_flagged_payload_invalid_flag() {
        assert!(split_flagged_payload(&[0xFF, 1, 2]).is_none());
    }

    #[test]
    fn test_split_flagged_payload_empty() {
        assert!(split_flagged_payload(&[]).is_none());
    }

    #[test]
    fn test_split_flagged_payload_handshake_response() {
        let packet = [0x03, 5, 6];
        let (flag, payload) = split_flagged_payload(&packet).unwrap();

        assert_eq!(flag, SessionFlag::HandshakeResponse);
        assert_eq!(payload, &[5, 6]);
    }

    #[test]
    fn test_split_flagged_payload_reject() {
        let packet = [0x04];
        let (flag, payload) = split_flagged_payload(&packet).unwrap();

        assert_eq!(flag, SessionFlag::Reject);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_save_message_error() {
        let dir = Path::new("invalid");
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut payload = [0u8; 65535];
        let msg = b"File contents";
        payload[..msg.len()].copy_from_slice(msg);

        let packet = Packet::new(addr, msg.len(), Box::new(payload));

        assert!(packet._save_message(dir).is_err());
    }
}
