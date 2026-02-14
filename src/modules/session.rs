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
    pub trusted: bool,
    #[serde(skip)]
    pub session: Session,
}

impl Peer {
    pub fn new(public_key: Option<[u8; 32]>) -> Self {
        Self {
            public_key,
            trusted: false,
            session: Session::None,
        }
    }
    pub fn new_trusted(public_key: Option<[u8; 32]>, trusted: bool) -> Self {
        Self {
            public_key,
            trusted,
            session: Session::None,
        }
    }
    pub fn has_static_key(&self) -> bool {
        self.public_key.is_some()
    }
    pub fn fingerprint(&self) -> String {
        let Some(public_key_bytes) = self.public_key else {
            return "<unknown>".to_string();
        };

        let actual_digest = digest::digest(&digest::SHA256, &public_key_bytes);

        hex::encode(actual_digest.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Builder;

    const PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

    fn create_keypair() -> snow::Keypair {
        Builder::new(PATTERN_XX.parse().unwrap())
            .generate_keypair()
            .unwrap()
    }

    fn complete_handshake_xx() -> (snow::TransportState, snow::TransportState) {
        let mut initiator = Builder::new(PATTERN_XX.parse().unwrap())
            .local_private_key(&create_keypair().private)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = Builder::new(PATTERN_XX.parse().unwrap())
            .local_private_key(&create_keypair().private)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut buf = [0u8; 65535];
        let mut tmp = [0u8; 65535];

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut tmp).unwrap();
        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..len], &mut tmp).unwrap();
        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut tmp).unwrap();

        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    #[test]
    fn test_peer_has_static_key() {
        let keypair = create_keypair();
        let peer_without_key = Peer::new(None);
        assert!(!peer_without_key.has_static_key());

        let peer_with_key = Peer::new(Some(keypair.public.try_into().expect("invalid key length")));
        assert!(peer_with_key.has_static_key());
    }

    #[test]
    fn test_session_debug_handshaking() {
        let keypair = create_keypair();
        let handshake = Builder::new(PATTERN_XX.parse().unwrap())
            .local_private_key(&keypair.private)
            .unwrap()
            .build_initiator()
            .unwrap();
        let session = Session::Handshaking(handshake);
        let debug_str = format!("{:?}", session);
        assert_eq!(debug_str, "Session::Handshaking");
    }

    #[test]
    fn test_session_debug_established() {
        let (transport, _) = complete_handshake_xx();
        let session = Session::Established(transport);
        let debug_str = format!("{:?}", session);
        assert_eq!(debug_str, "Session::Established");
    }

    #[test]
    fn test_peer_fingerprint_consistent() {
        let public_key = [1u8; 32];
        let peer1 = Peer::new(Some(public_key));
        let peer2 = Peer::new(Some(public_key));

        assert_eq!(peer1.fingerprint(), peer2.fingerprint());
    }

    #[test]
    fn test_peer_fingerprint_no_key() {
        let peer = Peer::new(None);
        assert_eq!(peer.fingerprint(), "<unknown>");
    }

    #[test]
    fn test_session_debug_none() {
        let session = Session::None;
        assert_eq!(format!("{:?}", session), "Session::None");
    }

    #[test]
    fn test_peer_new_trusted() {
        let key = [7u8; 32];
        let peer = Peer::new_trusted(Some(key), true);

        assert!(peer.trusted);
        assert_eq!(peer.public_key, Some(key));
        assert!(matches!(peer.session, Session::None));
    }
}
