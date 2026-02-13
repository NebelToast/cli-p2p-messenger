use networktesting::{
    modules::{
        crypto::generate_or_load_keypair,
        network::send_message,
        packet::Packet,
        session::{Peer, Session},
    },
    network::{connect, handle_incoming_packets, load_peers, save_peers},
};
use snow::Builder;
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self},
    time::Duration,
};
use tempfile::tempdir;

const PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PATTERN_KK: &str = "Noise_KK_25519_ChaChaPoly_SHA256";

fn create_keypair() -> snow::Keypair {
    let dir = tempdir().unwrap();
    generate_or_load_keypair(dir.path()).unwrap()
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
    let (mut sender, receiver) = complete_handshake_xx();
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
    let (sender_transport, _receiver_transport) = complete_handshake_xx();
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
                    let (_, transport) = complete_handshake_xx();
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
    let (mut sender, mut receiver) = complete_handshake_xx();
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
    assert!(matches!(peer.session, Session::Established(_)));
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

#[test]
fn test_session_saved_and_continued() {
    let initiator_keypair = Arc::new(Mutex::new(create_keypair()));
    let responder_keypair = Arc::new(Mutex::new(create_keypair()));

    let peer_map_initiator: Arc<Mutex<HashMap<SocketAddr, Peer>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let peer_map_responder: Arc<Mutex<HashMap<SocketAddr, Peer>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let responder_packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

    let socket_initiator = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_responder = UdpSocket::bind("127.0.0.1:0").unwrap();

    let destination_initiator: SocketAddr = socket_responder.local_addr().unwrap();
    let initiator_addr: SocketAddr = socket_initiator.local_addr().unwrap();

    let peer_map_responder_cl = Arc::clone(&peer_map_responder);
    let responder_k = Arc::clone(&responder_keypair);
    let socket_responder_clone = socket_responder.try_clone().unwrap();
    let responder_packets_cl = Arc::clone(&responder_packets);
    let _responder_handle = thread::spawn(move || {
        loop {
            let mut recv_buffer = [0_u8; 65535];
            match socket_responder_clone.recv_from(&mut recv_buffer) {
                Ok((bytes, src)) => {
                    handle_incoming_packets(
                        &recv_buffer,
                        bytes,
                        src,
                        &socket_responder_clone,
                        &responder_k,
                        &peer_map_responder_cl,
                        &responder_packets_cl,
                    );
                }
                Err(_) => break,
            }
        }
    });

    let peer_map_initiator_cl = Arc::clone(&peer_map_initiator);
    let initiator_k = Arc::clone(&initiator_keypair);
    let socket_initiator_clone = socket_initiator.try_clone().unwrap();
    let _initiator_handle = thread::spawn(move || {
        let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
        loop {
            let mut recv_buffer = [0_u8; 65535];
            match socket_initiator_clone.recv_from(&mut recv_buffer) {
                Ok((bytes, src)) => {
                    handle_incoming_packets(
                        &recv_buffer,
                        bytes,
                        src,
                        &socket_initiator_clone,
                        &initiator_k,
                        &peer_map_initiator_cl,
                        &packets,
                    );
                }
                Err(_) => break,
            }
        }
    });

    let result = connect(
        &destination_initiator,
        &initiator_keypair,
        &socket_initiator,
        Arc::clone(&peer_map_initiator),
    );
    assert!(result.is_ok());

    {
        let peers = peer_map_initiator.lock().unwrap();
        let peer = peers.get(&destination_initiator).unwrap();
        assert!(matches!(peer.session, Session::Established(_)));
        assert!(peer.public_key.is_some());
    }

    let dir = tempdir().unwrap();
    save_peers(dir.path(), &peer_map_initiator);

    let loaded_peers = load_peers(dir.path());

    let loaded_peer = loaded_peers.get(&destination_initiator).unwrap();
    assert!(matches!(loaded_peer.session, Session::None),);
    assert!(loaded_peer.public_key.is_some());

    {
        let mut peers = peer_map_initiator.lock().unwrap();
        peers.clear();
        for (addr, peer) in loaded_peers {
            peers.insert(addr, peer);
        }
    }

    {
        let mut peers = peer_map_responder.lock().unwrap();
        if let Some(peer) = peers.get_mut(&initiator_addr) {
            let public_key = peer.public_key.clone();
            let username = peer.username.clone();
            *peer = Peer::new(public_key, Session::None, username);
        }
    }

    let reconnect_result = connect(
        &destination_initiator,
        &initiator_keypair,
        &socket_initiator,
        Arc::clone(&peer_map_initiator),
    );
    assert!(reconnect_result.is_ok());

    {
        let peers = peer_map_initiator.lock().unwrap();
        let peer = peers.get(&destination_initiator).unwrap();
        assert!(matches!(peer.session, Session::Established(_)));
    }

    thread::sleep(Duration::from_millis(100));

    {
        let peers = peer_map_responder.lock().unwrap();
        let peer = peers.get(&initiator_addr).unwrap();
        assert!(matches!(peer.session, Session::Established(_)));
    }

    {
        let mut peers = peer_map_responder.lock().unwrap();
        if let Some(peer) = peers.get_mut(&initiator_addr) {
            peer.trusted = true;
        }
    }

    send_message(
        &peer_map_initiator,
        &destination_initiator,
        "Hello",
        &socket_initiator,
    );

    thread::sleep(Duration::from_millis(100));

    {
        let packets = responder_packets.lock().unwrap();
        assert!(
            !packets.is_empty(),
            "Responder should have received the message"
        );
        let received_msg = std::str::from_utf8(&packets[0].payload[..packets[0].bytes]).unwrap();
        assert_eq!(received_msg, "Hello");
    }
}