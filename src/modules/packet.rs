use std::{
    fs::File,
    io::{self, Write},
    net::SocketAddr,
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

    pub fn _save_message(&self) -> Result<(), io::Error> {
        let mut file = File::options().create(true).append(true).open("lol.txt")?;
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
