use ring::digest;
use serde::{Deserialize, Serialize};

pub enum Session {
    None,
    Handshaking(snow::HandshakeState),
    Established(snow::TransportState),
}

impl Default for Session {
    fn default() -> Self {
        Session::None
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Session::None => write!(f, "Session::None"),
            Session::Handshaking(_) => write!(f, "Session::Handshaking"),
            Session::Established(_) => write!(f, "Session::Established"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub public_key: Option<[u8; 32]>,
    #[serde(skip, default)]
    pub session: Session,
    pub username: Option<String>,
    pub trusted: bool,
}

impl Peer {
    pub fn new(public_key: Option<[u8; 32]>, session: Session, username: Option<String>) -> Self {
        Self {
            public_key: public_key,
            session: session,
            username: username,
            trusted: false,
        }
    }
    pub fn has_static_key(&self) -> bool {
        self.public_key.is_some()
    }
    pub fn fingerprint(&self) -> String {
        let public_key_bytes = self.public_key.unwrap();

        let actual_digest = digest::digest(&digest::SHA256, &public_key_bytes);

        hex::encode(actual_digest.as_ref())
    }
}
