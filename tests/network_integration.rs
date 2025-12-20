use networktesting::{
    modules::{
        crypto::generate_or_load_keypair,
        network::{
            handle_established_session, handle_handshake_message, handle_new_connection,
            send_message,
        },
        packet::Packet,
        session::{Peer, Session},
    },
    network::{
        connect, handle_incoming_packets, load_messages, load_peers, save_message, save_peers,
    },
};
use snow::Builder;
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tempfile::tempdir;

const PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PATTERN_KK: &str = "Noise_KK_25519_ChaChaPoly_SHA256";

fn create_keypair() -> snow::Keypair {
    let dir = tempdir().unwrap();
    generate_or_load_keypair(dir.path()).unwrap()
}

fn complete_handshake() -> (snow::TransportState, snow::TransportState) {
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
fn test_handle_established_session_stores_decrypted_packet() {
    let (mut sender, mut receiver) = complete_handshake();
    let src: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let mut buf = [0u8; 65535];
    let len = sender.write_message(b"Hello!", &mut buf).unwrap();

    handle_established_session(&mut receiver, &buf, len, src, &packets, true);

    let stored = packets.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(&stored[0].payload[..stored[0].bytes], b"Hello!");
}

#[test]
fn test_handle_new_connection_returns_handshake_state() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let mut initiator = Builder::new(PATTERN_XX.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let result = handle_new_connection(&buf, len, src, &socket, &keypair, None);

    assert!(result.is_some());
}

#[test]
fn test_send_message_delivers_encrypted_message() {
    let (sender_transport, mut receiver_transport) = complete_handshake();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    peer_map.lock().unwrap().insert(
        receiver_addr,
        Peer::new(None, Session::Established(sender_transport), None),
    );

    send_message(&peer_map, &receiver_addr, "Test message", &sender_socket);

    let mut recv_buf = [0u8; 65535];
    let (len, _) = receiver_socket.recv_from(&mut recv_buf).unwrap();

    let mut plaintext = [0u8; 65535];
    let plaintext_len = receiver_transport
        .read_message(&recv_buf[..len], &mut plaintext)
        .unwrap();

    assert_eq!(
        std::str::from_utf8(&plaintext[..plaintext_len]).unwrap(),
        "Test message"
    );
}

#[test]
fn test_handle_handshake_message() {
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

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let mut buf = [0u8; 65535];
    let mut tmp = [0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder.read_message(&buf[..len], &mut tmp).unwrap();
    let len = responder.write_message(&[], &mut buf).unwrap();

    let finished = handle_handshake_message(&mut initiator, &buf, len, src, &socket);

    assert!(finished);
    assert!(initiator.is_handshake_finished());
}

#[test]
fn test_handle_incoming_packet_new_connection() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let mut initiator = Builder::new(PATTERN_XX.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:6666".parse().unwrap();

    let mut buf = [0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    handle_incoming_packets(&buf, len, src, &socket, &keypair, &peer_map, &packets);

    assert!(peer_map.lock().unwrap().contains_key(&src));
    let peers = peer_map.lock().unwrap();
    let peer = peers.get(&src).unwrap();
    assert!(matches!(peer.session, Session::Handshaking(_)));
}

#[test]
fn test_handle_incoming_invalid_packet() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:6666".parse().unwrap();

    let invalid_data = [0u8; 10];

    handle_incoming_packets(
        &invalid_data,
        invalid_data.len(),
        src,
        &socket,
        &keypair,
        &peer_map,
        &packets,
    );

    assert!(peer_map.lock().unwrap().is_empty());
    assert!(packets.lock().unwrap().is_empty());
}

#[test]
fn test_handshake_upgrade() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
    let mut initiator = Builder::new(PATTERN_XX.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();

    let socket_responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_initiator = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket_initiator
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let src: SocketAddr = socket_initiator.local_addr().unwrap();
    let mut buf = [0u8; 65535];
    let mut tmp_buffer = [0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    handle_incoming_packets(
        &buf,
        len,
        src,
        &socket_responder,
        &keypair,
        &peer_map,
        &packets,
    );
    {
        let peers = peer_map.lock().unwrap();
        let peer = peers.get(&src).unwrap();
        assert!(matches!(peer.session, Session::Handshaking(_)));
    }

    let len = socket_initiator.recv(&mut buf).unwrap();
    initiator
        .read_message(&buf[..len], &mut tmp_buffer)
        .unwrap();

    let len = initiator.write_message(&[], &mut buf).unwrap();

    handle_incoming_packets(
        &buf,
        len,
        src,
        &socket_responder,
        &keypair,
        &peer_map,
        &packets,
    );
    {
        let peers = peer_map.lock().unwrap();
        let peer = peers.get(&src).unwrap();
        assert!(matches!(peer.session, Session::Established(_)));
    }
}
#[test]
fn test_decrypted_message_stored() {
    let (mut sender, receiver) = complete_handshake();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let keypair = Arc::new(Mutex::new(create_keypair()));

    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:3333".parse().unwrap();
    peer_map
        .lock()
        .unwrap()
        .insert(src, Peer::new(None, Session::Established(receiver), None));
    peer_map.lock().unwrap().get_mut(&src).unwrap().trusted = true;

    let mut buf = [0u8; 65535];
    let len = sender.write_message(b"Established", &mut buf).unwrap();

    handle_incoming_packets(&buf, len, src, &socket, &keypair, &peer_map, &packets);

    let stored = packets.lock().unwrap();
    assert_eq!(&stored[0].payload[..stored[0].bytes], b"Established");
}

#[test]
fn test_send_message_no_connection() {
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    send_message(&peer_map, &receiver_addr, "Test message", &sender_socket);
}
#[test]
fn test_connect_to_known_peer() {
    let (sender_transport, _receiver_transport) = complete_handshake();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let keypair = Arc::new(Mutex::new(create_keypair()));

    let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let sender_addr = sender_socket.local_addr().unwrap();

    peer_map.lock().unwrap().insert(
        sender_addr,
        Peer::new(None, Session::Established(sender_transport), None),
    );
    assert!(connect(&sender_addr, &keypair, &receiver_socket, peer_map).is_ok())
}

#[test]
fn test_connect_to_new_peer() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination: SocketAddr = "127.0.0.1:7777".parse().unwrap();

    let peer_map_clone = Arc::clone(&peer_map);

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(100));
            let mut peers = peer_map_clone.lock().unwrap();
            if let Some(peer) = peers.get(&destination) {
                if matches!(peer.session, Session::Handshaking(_)) {
                    peers.remove(&destination);
                    let (_, transport) = complete_handshake();
                    peers.insert(
                        destination,
                        Peer::new(None, Session::Established(transport), None),
                    );
                    break;
                }
            }
        }
    });

    let result = connect(&destination, &keypair, &socket, peer_map);

    assert!(result.is_ok());
}
#[test]
fn test_connect_timeout() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination: SocketAddr = "127.0.0.1:8888".parse().unwrap();
    assert!(connect(&destination, &keypair, &socket, peer_map).is_err())
}
#[test]
fn test_decrypted_message_error() {
    let (mut sender, mut receiver) = complete_handshake();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let keypair = Arc::new(Mutex::new(create_keypair()));

    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:3333".parse().unwrap();
    receiver.set_receiving_nonce(10);
    peer_map
        .lock()
        .unwrap()
        .insert(src, Peer::new(None, Session::Established(receiver), None));

    let mut buf = [0u8; 65535];
    let len = sender.write_message(b"invalod", &mut buf).unwrap();

    handle_incoming_packets(&buf, len, src, &socket, &keypair, &peer_map, &packets);

    let stored = packets.lock().unwrap();
    assert!(stored.is_empty());
}

fn complete_kk_handshake(
    initiator_keypair: &snow::Keypair,
    responder_keypair: &snow::Keypair,
) -> (snow::TransportState, snow::TransportState) {
    let mut initiator = Builder::new(PATTERN_KK.parse().unwrap())
        .local_private_key(&initiator_keypair.private)
        .unwrap()
        .remote_public_key(&responder_keypair.public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = Builder::new(PATTERN_KK.parse().unwrap())
        .local_private_key(&responder_keypair.private)
        .unwrap()
        .remote_public_key(&initiator_keypair.public)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 65535];
    let mut tmp = [0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder.read_message(&buf[..len], &mut tmp).unwrap();
    let len = responder.write_message(&[], &mut buf).unwrap();
    initiator.read_message(&buf[..len], &mut tmp).unwrap();

    (
        initiator.into_transport_mode().unwrap(),
        responder.into_transport_mode().unwrap(),
    )
}

#[test]
fn test_kk_pattern_handshake() {
    let initiator_keypair = create_keypair();
    let responder_keypair = create_keypair();

    let (mut sender, mut receiver) = complete_kk_handshake(&initiator_keypair, &responder_keypair);

    let mut buf = [0u8; 65535];
    let mut plaintext = [0u8; 65535];

    let len = sender.write_message(b"Hello KK pattern", &mut buf).unwrap();
    let plaintext_len = receiver.read_message(&buf[..len], &mut plaintext).unwrap();

    assert_eq!(&plaintext[..plaintext_len], b"Hello KK pattern");
}

#[test]
fn test_handle_new_connection_with_kk_pattern() {
    let initiator_keypair = create_keypair();
    let responder_keypair = Arc::new(Mutex::new(create_keypair()));

    let mut initiator = Builder::new(PATTERN_KK.parse().unwrap())
        .local_private_key(&initiator_keypair.private)
        .unwrap()
        .remote_public_key(&responder_keypair.lock().unwrap().public)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:8889".parse().unwrap();

    let result = handle_new_connection(
        &buf,
        len,
        src,
        &socket,
        &responder_keypair,
        Some(&initiator_keypair.public),
    );

    assert!(result.is_some());
}

#[test]
fn test_peer_has_static_key() {
    let keypair = create_keypair();
    let (_, transport) = complete_handshake();

    let peer_without_key = Peer::new(None, Session::Established(transport), None);
    assert!(!peer_without_key.has_static_key());

    let (_, transport2) = complete_handshake();

    let peer_with_key = Peer::new(
        Some(keypair.public.try_into().expect("invalid key length")),
        Session::Established(transport2),
        None,
    );
    assert!(peer_with_key.has_static_key());
}

#[test]
fn test_handshake_captures_remote_static_key() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let initiator_keypair = create_keypair();
    let mut initiator = Builder::new(PATTERN_XX.parse().unwrap())
        .local_private_key(&initiator_keypair.private)
        .unwrap()
        .build_initiator()
        .unwrap();

    let socket_responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_initiator = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket_initiator
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let src: SocketAddr = socket_initiator.local_addr().unwrap();
    let mut buf = [0u8; 65535];
    let mut tmp_buffer = [0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    handle_incoming_packets(
        &buf,
        len,
        src,
        &socket_responder,
        &keypair,
        &peer_map,
        &packets,
    );

    let len = socket_initiator.recv(&mut buf).unwrap();
    initiator
        .read_message(&buf[..len], &mut tmp_buffer)
        .unwrap();

    let len = initiator.write_message(&[], &mut buf).unwrap();
    handle_incoming_packets(
        &buf,
        len,
        src,
        &socket_responder,
        &keypair,
        &peer_map,
        &packets,
    );

    let peers = peer_map.lock().unwrap();
    let peer = peers.get(&src).unwrap();
    assert!(matches!(peer.session, Session::Established(_)));
    assert!(peer.public_key.is_some());
    assert_eq!(
        peer.public_key.as_ref().unwrap().as_ref(),
        &initiator_keypair.public
    );
}
#[test]
fn test_save_message() {
    let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
    let sender: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let payload = b"Saved";
    let bytes = payload.len();

    packages
        .lock()
        .unwrap()
        .push(Packet::new(sender, bytes, Box::new(*payload)));

    let dir = tempdir().unwrap();
    save_message(dir.path(), &packages);

    let loaded_messages = load_messages(dir.path());
    assert_eq!(loaded_messages.len(), 1);
    assert_eq!(loaded_messages[0].sender, sender);
    assert_eq!(loaded_messages[0].bytes, bytes);
    assert_eq!(loaded_messages[0].payload.iter().as_slice(), payload)
}

#[test]
fn test_save_peers() {
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();

    let peer = Peer::new(Some([10; 32]), Session::None, Some("test_user".to_string()));
    peer_map.lock().unwrap().insert(addr, peer);

    let dir = tempdir().unwrap();
    save_peers(dir.path(), &peer_map);

    let loaded_peers = load_peers(dir.path());
    let peer = loaded_peers.get(&addr).unwrap();
    assert_eq!(loaded_peers.len(), 1);
    assert!(loaded_peers.contains_key(&addr));
    assert!(matches!(peer.session, Session::None));
    assert_eq!(peer.username, Some("test_user".to_string()));
}

#[test]
fn test_session_default() {
    let session = Session::default();
    assert!(matches!(session, Session::None));
}

#[test]
fn test_session_debug_none() {
    let session = Session::None;
    let debug_str = format!("{:?}", session);
    assert_eq!(debug_str, "Session::None");
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
    let (transport, _) = complete_handshake();
    let session = Session::Established(transport);
    let debug_str = format!("{:?}", session);
    assert_eq!(debug_str, "Session::Established");
}

#[test]
fn test_peer_fingerprint_consistent() {
    let public_key = vec![1u8; 32];
    let peer1 = Peer::new(
        Some(public_key.clone().try_into().expect("invalid key length")),
        Session::None,
        None,
    );
    let peer2 = Peer::new(
        Some(public_key.try_into().expect("invalid key length")),
        Session::None,
        None,
    );

    assert_eq!(peer1.fingerprint(), peer2.fingerprint());
}

#[test]
fn test_handle_incoming_packets_with_session_none() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:5555".parse().unwrap();

    let initiator_keypair = create_keypair();
    peer_map.lock().unwrap().insert(
        src,
        Peer::new(
            Some(
                initiator_keypair
                    .public
                    .clone()
                    .try_into()
                    .expect("invalid key length"),
            ),
            Session::None,
            Some("loaded_peer".to_string()),
        ),
    );

    let mut initiator = Builder::new(PATTERN_KK.parse().unwrap())
        .local_private_key(&initiator_keypair.private)
        .unwrap()
        .remote_public_key(&keypair.lock().unwrap().public)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    handle_incoming_packets(&buf, len, src, &socket, &keypair, &peer_map, &packets);

    let peers = peer_map.lock().unwrap();
    let peer = peers.get(&src).unwrap();
    assert!(matches!(peer.session, Session::Handshaking(_)));
}

#[test]
fn test_connect_with_kk_pattern_known_peer() {
    let initiator_keypair = Arc::new(Mutex::new(create_keypair()));
    let responder_keypair = Arc::new(Mutex::new(create_keypair()));
    let writer: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let peer_map_initiator: Arc<Mutex<HashMap<SocketAddr, Peer>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let peer_map_responder: Arc<Mutex<HashMap<SocketAddr, Peer>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let socket_initiator = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_responder = UdpSocket::bind("127.0.0.1:7779").unwrap();

    let destination_initiator: SocketAddr = socket_responder.local_addr().unwrap();
    let initiator_addr: SocketAddr = socket_initiator.local_addr().unwrap();

    peer_map_responder.lock().unwrap().insert(
        initiator_addr,
        Peer::new(
            Some(
                initiator_keypair
                    .lock()
                    .unwrap()
                    .public
                    .clone()
                    .try_into()
                    .expect("invalid key length"),
            ),
            Session::None,
            None,
        ),
    );

    peer_map_initiator.lock().unwrap().insert(
        destination_initiator,
        Peer::new(
            Some(
                responder_keypair
                    .lock()
                    .unwrap()
                    .public
                    .clone()
                    .try_into()
                    .expect("invalid key length"),
            ),
            Session::None,
            None,
        ),
    );

    let peer_map_responder_cl = Arc::clone(&peer_map_responder);
    let responder_k = Arc::clone(&responder_keypair);
    let writer_responder = Arc::clone(&writer);
    thread::spawn(move || {
        loop {
            let mut recv_buffer = [0_u8; 65535];
            let (bytes, src) = socket_responder
                .recv_from(&mut recv_buffer)
                .expect("responder recv error");

            handle_incoming_packets(
                &recv_buffer,
                bytes,
                src,
                &socket_responder,
                &responder_k,
                &peer_map_responder_cl,
                &writer_responder,
            );
        }
    });

    let peer_map_initiator_cl = Arc::clone(&peer_map_initiator);
    let initiator_k = Arc::clone(&initiator_keypair);
    let socket_initiator_clone = socket_initiator.try_clone().unwrap();
    thread::spawn(move || {
        loop {
            let mut recv_buffer = [0_u8; 65535];
            let (bytes, src) = socket_initiator_clone
                .recv_from(&mut recv_buffer)
                .expect("initiator recv error");

            handle_incoming_packets(
                &recv_buffer,
                bytes,
                src,
                &socket_initiator_clone,
                &initiator_k,
                &peer_map_initiator_cl,
                &Arc::new(Mutex::new(vec![])),
            );
        }
    });

    let result = connect(
        &destination_initiator,
        &initiator_keypair,
        &socket_initiator,
        peer_map_initiator,
    );

    assert!(result.is_ok());
}
