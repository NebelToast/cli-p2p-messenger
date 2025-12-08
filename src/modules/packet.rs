use std::{
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    str::Utf8Error,
};

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

    pub fn print_message(&self) -> Result<(), Utf8Error> {
        println!(
            "Message: {} from {} consisting of {} bytes",
            std::str::from_utf8(&self.payload[..self.bytes])?,
            &self.sender,
            &self.bytes
        );
        Ok(())
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
    fn test_print_message_valid_utf8() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut payload = [0u8; 65535];
        let msg = b"Valid";
        payload[..msg.len()].copy_from_slice(msg);

        let packet = Packet::new(addr, msg.len(), Box::new(payload));
        assert!(packet.print_message().is_ok());
    }

    #[test]
    fn test_print_message_invalid_utf8() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut payload = [0u8; 65535];
        payload[0] = 0xFF;
        payload[1] = 0xFE;

        let packet = Packet::new(addr, 2, Box::new(payload));
        assert!(packet.print_message().is_err());
    }

    #[test]
    fn test_print_message_empty() {
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let payload = Box::new([0u8; 65535]);

        let packet = Packet::new(addr, 0, payload);
        assert!(packet.print_message().is_ok());
    }

    #[test]
    fn test_print_message_with_special_chars() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut payload = [0u8; 65535];
        let msg = "Héllo Wörld! 日本語".as_bytes();
        payload[..msg.len()].copy_from_slice(msg);

        let packet = Packet::new(addr, msg.len(), Box::new(payload));
        assert!(packet.print_message().is_ok());
    }
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
