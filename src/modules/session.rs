pub enum Session {
    None,
    Handshaking(snow::HandshakeState),
    Established(snow::TransportState),
}
pub struct Peer {
    pub public_key: Option<Box<[u8]>>,
    pub session: Session,
    pub username: Option<String>,
}

impl Peer {
    pub fn new(public_key: Option<Box<[u8]>>, session: Session, username: Option<String>) -> Self {
        Self {
            public_key: public_key,
            session: session,
            username: username,
        }
    }
    pub fn has_static_key(&self) -> bool {
        self.public_key.is_some()
    }
}
