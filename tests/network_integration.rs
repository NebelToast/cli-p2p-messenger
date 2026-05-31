use cli_p2p_messenger::{
    modules::{
        crypto::generate_or_load_keypair,
        network::send_message,
        packet::{Packet, SessionFlag},
        session::{Peer, PeerRegistry},
    },
    network::{connect, delete_contacts, handle_incoming_packets, load_peers, save_peers},
};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use cli_p2p_messenger::error::SessionError;
use tempfile::tempdir;

fn create_keypair() -> snow::Keypair {
    let dir = tempdir().unwrap();
    generate_or_load_keypair(dir.path()).unwrap()
}

struct TestNode {
    keypair: Arc<Mutex<snow::Keypair>>,
    peer_map: PeerRegistry,
    packets: Arc<Mutex<Vec<Packet>>>,
    socket: UdpSocket,
}

impl TestNode {
    fn new() -> Self {
        Self {
            keypair: Arc::new(Mutex::new(create_keypair())),
            peer_map: PeerRegistry::new(HashMap::new()),
            packets: Arc::new(Mutex::new(vec![])),
            socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.lock().unwrap().public.clone()
    }

    fn handle_packet(&self, data: &[u8], src: SocketAddr) {
        let _ = handle_incoming_packets(
            data,
            data.len(),
            src,
            &self.socket,
            &self.keypair,
            self.peer_map.clone(),
            &self.packets,
        );
    }

    fn spawn_listener(&self) {
        let pm = self.peer_map.clone();
        let kp = Arc::clone(&self.keypair);
        let pk = Arc::clone(&self.packets);
        let sock = self.socket.try_clone().unwrap();
        thread::spawn(move || {
            loop {
                let mut buf = [0u8; 65535];
                match sock.recv_from(&mut buf) {
                    Ok((bytes, src)) => {
                        let _ = handle_incoming_packets(&buf, bytes, src, &sock, &kp, pm.clone(), &pk);
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[test]
fn invalid_flag_byte_does_not_create_peer() {
    let node = TestNode::new();
    let src: SocketAddr = "127.0.0.1:6666".parse().unwrap();

    node.handle_packet(&[0x00, 1, 2, 3, 4, 5], src);

    assert!(node.peer_map.is_empty());
    assert!(node.packets.lock().unwrap().is_empty());
}

#[test]
fn transport_message_stored_only_for_trusted_peer() {
    let initiator = TestNode::new();
    let responder = TestNode::new();
    responder.spawn_listener();
    initiator.spawn_listener();

    let result = connect(
        &responder.addr(),
        &initiator.keypair,
        &initiator.socket,
        initiator.peer_map.clone(),
    );
    assert!(result.is_ok());

    thread::sleep(Duration::from_millis(300));
    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "Untrusted message",
        &initiator.socket,
    ).unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(responder.packets.lock().unwrap().is_empty());

    responder.peer_map.set_trusted(&initiator.addr(), true);

    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "Trusted message",
        &initiator.socket,
    ).unwrap();
    thread::sleep(Duration::from_millis(150));

    let stored = responder.packets.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(&stored[0].payload[..stored[0].bytes], b"Trusted message");
    assert_eq!(stored[0].sender, initiator.addr());
}

#[test]
fn send_message_without_peer() {
    let node = TestNode::new();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let dest = receiver_socket.local_addr().unwrap();

    let err = send_message(node.peer_map.clone(), &dest, "Should not arrive", &node.socket).unwrap_err();
    assert!(matches!(err, SessionError::PeerNotFound));
    let mut recv_buf = [0u8; 65535];
    assert!(receiver_socket.recv_from(&mut recv_buf).is_err());
}

#[test]
fn save_and_load_peers() {
    let dir = tempdir().unwrap();
    let peer_registry = PeerRegistry::new(HashMap::new());
    let addr1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let addr2: SocketAddr = "192.168.0.5:5678".parse().unwrap();
    let key = [42u8; 32];

    {
        let mut peer1 = Peer::new(Some(key));
        peer1.trusted = true;
        peer_registry.create_peer(&addr1, peer1);
        peer_registry.create_peer(&addr2, Peer::new(None));
    }
    save_peers(dir.path(), &peer_registry).unwrap();
    let loaded = load_peers(dir.path());

    assert_eq!(loaded.len(), 2);

    let p1 = loaded.get(&addr1).expect("addr1 must be present");

    assert_eq!(p1.public_key, Some(key));
    assert!(p1.trusted);

    let p2 = loaded.get(&addr2).expect("addr2 must be present");

    assert!(p2.public_key.is_none());
    assert!(!p2.trusted);
}

#[test]
fn end_to_end_kk() {
    let initiator = TestNode::new();
    let responder = TestNode::new();

    responder.peer_map.create_peer(
        &initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );
    initiator.peer_map.create_peer(
        &responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );

    responder.spawn_listener();
    initiator.spawn_listener();

    let result = connect(
        &responder.addr(),
        &initiator.keypair,
        &initiator.socket,
        initiator.peer_map.clone(),
    );

    assert!(result.is_ok());

    initiator.peer_map.with_peers(|peers: &HashMap<SocketAddr, Peer>| {
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map");
        assert!(peer.trusted);
    });

    thread::sleep(Duration::from_millis(200));
    assert!(responder.peer_map.contains_key(&initiator.addr()));

    responder.peer_map.set_trusted(&initiator.addr(), true);

    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "Integration test message",
        &initiator.socket,
    ).unwrap();

    thread::sleep(Duration::from_millis(200));

    let stored = responder.packets.lock().unwrap();
    assert!(!stored.is_empty());
    assert_eq!(
        std::str::from_utf8(&stored[0].payload[..stored[0].bytes]).unwrap(),
        "Integration test message"
    );
    assert_eq!(stored[0].sender, initiator.addr());
    assert_eq!(stored[0].bytes, "Integration test message".len());
}

#[test]
fn end_to_end_xx() {
    let initiator = TestNode::new();
    let responder = TestNode::new();
    responder.spawn_listener();
    initiator.spawn_listener();

    let result = connect(
        &responder.addr(),
        &initiator.keypair,
        &initiator.socket,
        initiator.peer_map.clone(),
    );
    assert!(result.is_ok());

    thread::sleep(Duration::from_millis(300));
    initiator.peer_map.with_peers(|peers: &HashMap<SocketAddr, Peer>| {
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map");
        assert!(peer.public_key.is_some());
        assert_eq!(
            peer.public_key.as_ref().map(|k| k.as_slice()),
            Some(responder.public_key().as_slice())
        );
    });

    responder.peer_map.with_peers(|peers: &HashMap<SocketAddr, Peer>| {
        let peer = peers
            .get(&initiator.addr())
            .expect("Responder must have a peer entry for the initiator");
        assert!(peer.public_key.is_some());
        assert_eq!(
            peer.public_key.as_ref().map(|k| k.as_slice()),
            Some(initiator.public_key().as_slice())
        );
    });

    responder.peer_map.set_trusted(&initiator.addr(), true);

    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "XX handshake message",
        &initiator.socket,
    ).unwrap();

    thread::sleep(Duration::from_millis(200));

    let stored = responder.packets.lock().unwrap();
    assert!(!stored.is_empty());
    assert_eq!(
        std::str::from_utf8(&stored[0].payload[..stored[0].bytes]).unwrap(),
        "XX handshake message"
    );
}

#[test]
fn end_to_end_save_reload_and_reconnect() {
    let initiator = TestNode::new();
    let responder = TestNode::new();
    let dir = tempdir().unwrap();

    initiator.peer_map.create_peer(
        &responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );
    responder.peer_map.create_peer(
        &initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );

    save_peers(dir.path(), &initiator.peer_map).unwrap();
    let loaded = load_peers(dir.path());
    initiator.peer_map.with_peers_mut(|peers: &mut HashMap<SocketAddr, Peer>| {
        peers.clear();
        for (addr, peer) in loaded {
            peers.insert(addr, peer);
        }
    });

    responder.spawn_listener();
    initiator.spawn_listener();

    assert!(
        connect(
            &responder.addr(),
            &initiator.keypair,
            &initiator.socket,
            initiator.peer_map.clone(),
        )
        .is_ok()
    );

    thread::sleep(Duration::from_millis(200));

    initiator.peer_map.with_peers(|peers: &HashMap<SocketAddr, Peer>| {
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map after reconnect");
        assert!(peer.trusted);
        assert!(peer.public_key.is_some());
    });

    responder.peer_map.set_trusted(&initiator.addr(), true);

    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "After reload",
        &initiator.socket,
    ).unwrap();
    thread::sleep(Duration::from_millis(200));
    let stored = responder.packets.lock().unwrap();
    assert!(!stored.is_empty());
    assert_eq!(
        std::str::from_utf8(&stored[0].payload[..stored[0].bytes]).unwrap(),
        "After reload"
    );
}

#[test]
fn reject_from_unknown_peer() {
    let node = TestNode::new();
    let src: SocketAddr = "127.0.0.1:4444".parse().unwrap();
    let flagged = vec![SessionFlag::Reject as u8];
    node.handle_packet(&flagged, src);

    assert!(!node.peer_map.contains_key(&src));
}

#[test]
fn end_to_end_save_reload_and_reconnect_deletion_of_contacts() {
    let initiator = TestNode::new();
    let responder = TestNode::new();
    let dir = tempdir().unwrap();

    initiator.peer_map.create_peer(
        &responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );
    responder.peer_map.create_peer(
        &initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );

    save_peers(dir.path(), &initiator.peer_map).unwrap();
    delete_contacts(dir.path()).unwrap();
    let loaded = load_peers(dir.path());
    initiator.peer_map.with_peers_mut(|peers: &mut HashMap<SocketAddr, Peer>| {
        peers.clear();
        for (addr, peer) in loaded {
            peers.insert(addr, peer);
        }
    });

    responder.spawn_listener();
    initiator.spawn_listener();

    assert!(
        connect(
            &responder.addr(),
            &initiator.keypair,
            &initiator.socket,
            initiator.peer_map.clone(),
        )
        .is_ok()
    );

    thread::sleep(Duration::from_millis(200));

    responder.peer_map.set_trusted(&initiator.addr(), true);

    send_message(
        initiator.peer_map.clone(),
        &responder.addr(),
        "After reload",
        &initiator.socket,
    ).unwrap();
    thread::sleep(Duration::from_millis(200));
    let stored = responder.packets.lock().unwrap();
    assert!(!stored.is_empty());
    assert_eq!(
        std::str::from_utf8(&stored[0].payload[..stored[0].bytes]).unwrap(),
        "After reload"
    );
}
