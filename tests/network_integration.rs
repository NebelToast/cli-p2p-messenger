use cli_p2p_messenger::{
    modules::{
        crypto::generate_or_load_keypair,
        network::send_message,
        packet::{Packet, SessionFlag},
        session::Peer,
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
use tempfile::tempdir;

fn create_keypair() -> snow::Keypair {
    let dir = tempdir().unwrap();
    generate_or_load_keypair(dir.path()).unwrap()
}

struct TestNode {
    keypair: Arc<Mutex<snow::Keypair>>,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    packets: Arc<Mutex<Vec<Packet>>>,
    socket: UdpSocket,
}

impl TestNode {
    fn new() -> Self {
        Self {
            keypair: Arc::new(Mutex::new(create_keypair())),
            peer_map: Arc::new(Mutex::new(HashMap::new())),
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
        handle_incoming_packets(
            data,
            data.len(),
            src,
            &self.socket,
            &self.keypair,
            &self.peer_map,
            &self.packets,
        );
    }

    fn spawn_listener(&self) {
        let pm = Arc::clone(&self.peer_map);
        let kp = Arc::clone(&self.keypair);
        let pk = Arc::clone(&self.packets);
        let sock = self.socket.try_clone().unwrap();
        thread::spawn(move || {
            loop {
                let mut buf = [0u8; 65535];
                match sock.recv_from(&mut buf) {
                    Ok((bytes, src)) => {
                        handle_incoming_packets(&buf, bytes, src, &sock, &kp, &pm, &pk);
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

    assert!(node.peer_map.lock().unwrap().is_empty());
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
        Arc::clone(&initiator.peer_map),
    );
    assert!(result.is_ok());

    thread::sleep(Duration::from_millis(300));
    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "Untrusted message",
        &initiator.socket,
    );
    thread::sleep(Duration::from_millis(150));
    assert!(responder.packets.lock().unwrap().is_empty());


    responder
        .peer_map
        .lock()
        .unwrap()
        .get_mut(&initiator.addr())
        .unwrap()
        .trusted = true;

    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "Trusted message",
        &initiator.socket,
    );
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

    send_message(&node.peer_map, &dest, "Should not arrive", &node.socket);
    let mut recv_buf = [0u8; 65535];

    assert!(receiver_socket.recv_from(&mut recv_buf).is_err());
}

#[test]
fn save_and_load_peers() {
    let dir = tempdir().unwrap();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let addr1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let addr2: SocketAddr = "192.168.0.5:5678".parse().unwrap();
    let key = [42u8; 32];

    {
        let mut peers = peer_map.lock().unwrap();
        let mut peer1 = Peer::new(Some(key));
        peer1.trusted = true;
        peers.insert(addr1, peer1);
        peers.insert(addr2, Peer::new(None));
    }
    save_peers(dir.path(), &peer_map);
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

    responder.peer_map.lock().unwrap().insert(
        initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );
    initiator.peer_map.lock().unwrap().insert(
        responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );

    responder.spawn_listener();
    initiator.spawn_listener();

    let result = connect(
        &responder.addr(),
        &initiator.keypair,
        &initiator.socket,
        Arc::clone(&initiator.peer_map),
    );

    assert!(result.is_ok());

    {
        let peers = initiator.peer_map.lock().unwrap();
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map");

        assert!(peer.trusted);
    }

    thread::sleep(Duration::from_millis(200));
    {
        let peers = responder.peer_map.lock().unwrap();
        assert!(peers.contains_key(&initiator.addr()));
    }
    responder
        .peer_map
        .lock()
        .unwrap()
        .get_mut(&initiator.addr())
        .unwrap()
        .trusted = true;

    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "Integration test message",
        &initiator.socket,
    );

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
        Arc::clone(&initiator.peer_map),
    );
    assert!(result.is_ok());

    thread::sleep(Duration::from_millis(300));
    {
        let peers = initiator.peer_map.lock().unwrap();
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map");
        assert!(peer.public_key.is_some());
        assert_eq!(
            peer.public_key.as_ref().map(|k| k.as_slice()),
            Some(responder.public_key().as_slice())
        );
    }

    {
        let peers = responder.peer_map.lock().unwrap();
        let peer = peers
            .get(&initiator.addr())
            .expect("Responder must have a peer entry for the initiator");
        assert!(peer.public_key.is_some());
        assert_eq!(
            peer.public_key.as_ref().map(|k| k.as_slice()),
            Some(initiator.public_key().as_slice())
        );
    }
    responder
        .peer_map
        .lock()
        .unwrap()
        .get_mut(&initiator.addr())
        .unwrap()
        .trusted = true;

    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "XX handshake message",
        &initiator.socket,
    );

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

    initiator.peer_map.lock().unwrap().insert(
        responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );
    responder.peer_map.lock().unwrap().insert(
        initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );

    save_peers(dir.path(), &initiator.peer_map);
    let loaded = load_peers(dir.path());
    {
        let mut peers = initiator.peer_map.lock().unwrap();
        peers.clear();
        for (addr, peer) in loaded {
            peers.insert(addr, peer);
        }
    }

    responder.spawn_listener();
    initiator.spawn_listener();

    assert!(
        connect(
            &responder.addr(),
            &initiator.keypair,
            &initiator.socket,
            Arc::clone(&initiator.peer_map),
        )
        .is_ok()
    );

    thread::sleep(Duration::from_millis(200));

    {
        let peers = initiator.peer_map.lock().unwrap();
        let peer = peers
            .get(&responder.addr())
            .expect("Peer must be in initiator's map after reconnect");
        assert!(peer.trusted);
        assert!(peer.public_key.is_some());
    }

    {
        let mut peers = responder.peer_map.lock().unwrap();
        let peer = peers
            .get_mut(&initiator.addr())
            .expect("Responder must have a peer entry for the initiator after reconnect");
        assert!(peer.public_key.is_some());
        peer.trusted = true;
    }

    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "After reload",
        &initiator.socket,
    );
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

    assert!(!node.peer_map.lock().unwrap().contains_key(&src));
}
#[test]
fn end_to_end_save_reload_and_reconnect_deletion_of_contacts() {
    let initiator = TestNode::new();
    let responder = TestNode::new();
    let dir = tempdir().unwrap();

    initiator.peer_map.lock().unwrap().insert(
        responder.addr(),
        Peer::new(Some(responder.public_key().try_into().unwrap())),
    );
    responder.peer_map.lock().unwrap().insert(
        initiator.addr(),
        Peer::new(Some(initiator.public_key().try_into().unwrap())),
    );

    save_peers(dir.path(), &initiator.peer_map);
    delete_contacts(dir.path());
    let loaded = load_peers(dir.path());
    {
        let mut peers = initiator.peer_map.lock().unwrap();
        peers.clear();
        for (addr, peer) in loaded {
            peers.insert(addr, peer);
        }
    }

    responder.spawn_listener();
    initiator.spawn_listener();

    assert!(
        connect(
            &responder.addr(),
            &initiator.keypair,
            &initiator.socket,
            Arc::clone(&initiator.peer_map),
        )
        .is_ok()
    );

    thread::sleep(Duration::from_millis(200));

    {
        let mut peers = responder.peer_map.lock().unwrap();
        let peer = peers
            .get_mut(&initiator.addr())
            .expect("Responder must have a peer entry for the initiator after reconnect");
        assert!(peer.public_key.is_some());
        peer.trusted = true;
    }
    send_message(
        &initiator.peer_map,
        &responder.addr(),
        "After reload",
        &initiator.socket,
    );
    thread::sleep(Duration::from_millis(200));
    let stored = responder.packets.lock().unwrap();
    assert!(!stored.is_empty());
    assert_eq!(
        std::str::from_utf8(&stored[0].payload[..stored[0].bytes]).unwrap(),
        "After reload"
    );
}
