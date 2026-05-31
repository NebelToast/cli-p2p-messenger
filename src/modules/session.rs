use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use ring::digest;
use serde::{Deserialize, Serialize};

use super::error::SessionError;

#[derive(Default)]
pub enum Session {
    #[default]
    None,
    Handshaking(Box<snow::HandshakeState>),
    Established(snow::TransportState),
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

#[derive(Clone)]
pub struct PeerRegistry {
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
}

impl PeerRegistry {
    pub fn new(initial_peers: HashMap<SocketAddr, Peer>) -> Self {
        Self {
            peers: Arc::new(Mutex::new(initial_peers)),
        }
    }
    pub fn is_known(&self, addr: &SocketAddr) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(addr)
            .map(|p| p.has_static_key())
            .unwrap_or(false)
    }
    pub fn set_public_key(&self, addr: &SocketAddr, key: Option<[u8; 32]>) {
        self.peers
            .lock()
            .unwrap()
            .entry(*addr)
            .or_insert_with(|| Peer::new(None))
            .public_key = key;
    }
    pub fn set_session(&self, addr: &SocketAddr, session: Session) {
        if let Some(peer) = self.peers.lock().unwrap().get_mut(addr) {
            peer.session = session;
        }
    }
    pub fn with_peers_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<SocketAddr, Peer>) -> R,
    {
        let mut peers = self.peers.lock().unwrap();
        f(&mut peers)
    }
    pub fn with_peers<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&HashMap<SocketAddr, Peer>) -> R,
    {
        let peers = self.peers.lock().unwrap();
        f(&peers)
    }

    pub fn get_fingerprint(&self, addr: &SocketAddr) -> String {
        self.peers
            .lock()
            .unwrap()
            .get(addr)
            .map(|peer| peer.fingerprint())
            .unwrap_or_else(|| "<unknown>".to_string())
    }
    pub fn get_trusted_peers(&self) -> Vec<SocketAddr> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, peer)| peer.trusted)
            .map(|(addr, _)| *addr)
            .collect()
    }
    pub fn clear(&self) {
        self.peers.lock().unwrap().clear();
    }
    pub fn set_trusted(&self, addr: &SocketAddr, trusted: bool) {
        if let Some(peer) = self.peers.lock().unwrap().get_mut(addr) {
            peer.trusted = trusted;
        }
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.peers.lock().unwrap().remove(addr);
    }
    pub fn is_established(&self, addr: &SocketAddr) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(addr)
            .map(|p| matches!(p.session, Session::Established(_)))
            .unwrap_or(false)
    }
    pub fn get_public_key(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        self.peers
            .lock()
            .unwrap()
            .get(addr)
            .and_then(|p| p.public_key)
    }
    pub fn create_peer(&self, addr: &SocketAddr, peer: Peer) {
        self.peers.lock().unwrap().insert(*addr, peer);
    }
    pub fn is_empty(&self) -> bool {
        self.peers.lock().unwrap().is_empty()
    }
    pub fn contains_key(&self, addr: &SocketAddr) -> bool {
        self.peers.lock().unwrap().contains_key(addr)
    }
    pub fn is_trusted(&self, addr: &SocketAddr) -> bool {
        self.peers
            .lock()
            .unwrap()
            .get(addr)
            .map(|p| p.trusted)
            .unwrap_or(false)
    }
    pub fn encrypt_message(
        &self,
        addr: &SocketAddr,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SessionError> {
        let mut peers = self.peers.lock().unwrap();

        let peer = peers.get_mut(addr).ok_or(SessionError::PeerNotFound)?;

        if let Session::Established(transport) = &mut peer.session {
            transport
                .write_message(plaintext, ciphertext)
                .map_err(SessionError::Encryption)
        } else {
            Err(SessionError::SessionNotEstablished)
        }
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
        let session = Session::Handshaking(Box::new(handshake));
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
