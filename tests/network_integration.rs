use networktesting::modules::{
    crypto::{PATTERN, generate_or_load_keypair},
    network::{
        handle_established_session, handle_handshake_message, handle_new_connection, send_message,
    },
    packet::Packet,
    session::Session,
};
use snow::Builder;
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::tempdir;

fn create_keypair() -> snow::Keypair {
    let dir = tempdir().unwrap();
    generate_or_load_keypair(dir.path()).unwrap()
}

fn complete_handshake() -> (snow::TransportState, snow::TransportState) {
    let mut initiator = Builder::new(PATTERN.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = Builder::new(PATTERN.parse().unwrap())
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

    handle_established_session(&mut receiver, &buf, len, src, &packets);

    let stored = packets.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(&stored[0].payload[..stored[0].bytes], b"Hello!");
}

#[test]
fn test_handle_new_connection_returns_handshake_state() {
    let keypair = Arc::new(Mutex::new(create_keypair()));
    let mut initiator = Builder::new(PATTERN.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let src: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let result = handle_new_connection(&buf, len, src, &socket, &keypair);

    assert!(result.is_some());
}

#[test]
fn test_send_message_delivers_encrypted_message() {
    let (sender_transport, mut receiver_transport) = complete_handshake();
    let peer_map: Arc<Mutex<HashMap<SocketAddr, Session>>> = Arc::new(Mutex::new(HashMap::new()));

    let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    peer_map
        .lock()
        .unwrap()
        .insert(receiver_addr, Session::Established(sender_transport));

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
    let mut initiator = Builder::new(PATTERN.parse().unwrap())
        .local_private_key(&create_keypair().private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = Builder::new(PATTERN.parse().unwrap())
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
