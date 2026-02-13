use snow::{Builder, Keypair};
use std::{
    collections::{HashMap, hash_map::Entry},
    fs,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::session::Peer;

use super::{error::ConnectErrors, packet::Packet, session::Session};

pub fn connect(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
) -> Result<(), ConnectErrors> {
    let mut static_key = false;
    let mut static_key_k: Option<[u8; 32]> = None;
    if let Some(peer) = map.lock().expect("mutex poisoned").get(&destination) {
        if let Session::Established(_) = peer.session {
            return Ok(());
        } else if peer.has_static_key() {
            static_key = true;
            static_key_k = peer.public_key.clone()
        }
    }
    let mut transport_state = if static_key {
        println!("Using Noise_KK pattern (known peer)");
        Builder::new(
            "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Invalid snow pattern"),
        )
        .local_private_key(&key.lock().unwrap().private)?
        .remote_public_key(static_key_k.as_ref().unwrap())?
        .build_initiator()?
    } else {
        println!("Using Noise_XX pattern (new peer)");
        Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Invalid snow pattern"),
        )
        .local_private_key(&key.lock().unwrap().private)?
        .build_initiator()?
    };

    let mut message_buffer = vec![0_u8; 65535];

    let len = transport_state.write_message(&[], &mut message_buffer)?;

    sock.send_to(&message_buffer[..len], destination)?;

    map.lock().expect("mutex poisoned").insert(
        destination,
        Peer::new_trusted(
            static_key_k,
            Session::Handshaking(transport_state),
            None,
            static_key,
        ),
    );

    for n in 1..6 {
        thread::sleep(Duration::from_millis(750));
        println!("Connection is being established {} try", n);
        if let Some(peer) = map.lock().expect("mutex poisoned").get(&destination) {
            if let Session::Established(_) = peer.session {
                return Ok(());
            }
        }
    }
    Err(ConnectErrors::Timeout)
}

pub fn handle_established_session(
    transport: &mut snow::TransportState,
    recv_buffer: &[u8],
    bytes: usize,
    src: SocketAddr,
    writer: &Arc<Mutex<Vec<Packet>>>,
    trusted: bool,
) {
    let mut message_buffer = [0_u8; 65535];
    let len = match transport.read_message(&recv_buffer[..bytes], &mut message_buffer) {
        Ok(len) => len,
        Err(e) => {
            println!("Failed to decrypt message from {}: {}", src, e);
            return;
        }
    };
    if trusted {
        let packet = Packet::new(src, len, message_buffer[..len].to_vec().into_boxed_slice());
        if let Err(e) = packet.print_message() {
            print!("{}", e);
        }
        writer.lock().expect("mutex poisoned").push(packet);
    }
}

pub fn handle_handshake_message(
    handshake: &mut snow::HandshakeState,
    recv_buffer: &[u8],
    bytes: usize,
    src: SocketAddr,
    socket: &UdpSocket,
) -> bool {
    let mut message_buffer = [0_u8; 65535];

    if let Err(e) = handshake.read_message(&recv_buffer[..bytes], &mut message_buffer) {
        println!("Failed to read handshake message from {}: {}", src, e);
        return false;
    }

    if !handshake.is_handshake_finished() {
        match handshake.write_message(&[], &mut message_buffer) {
            Ok(len) => {
                let _ = socket.send_to(&message_buffer[..len], src);
            }
            Err(e) => println!("Failed to write handshake message: {}", e),
        }
    }

    handshake.is_handshake_finished()
}

pub fn handle_new_connection(
    recv_buffer: &[u8],
    bytes: usize,
    src: SocketAddr,
    socket: &UdpSocket,
    key_pair: &Arc<Mutex<Keypair>>,
    remote_public_key: Option<&[u8]>,
) -> Option<snow::HandshakeState> {
    let mut message_buffer = [0_u8; 65535];

    let pattern = if remote_public_key.is_some() {
        "Noise_KK_25519_ChaChaPoly_SHA256"
    } else {
        "Noise_XX_25519_ChaChaPoly_SHA256"
    };
    println!("Responding with {} pattern", pattern);

    let key_guard = key_pair.lock().expect("mutex poisoned");
    let mut builder = Builder::new(pattern.parse().expect("invalid noise pattern"))
        .local_private_key(&key_guard.private)
        .expect("couldn't build transport state");

    if let Some(remote_key) = remote_public_key {
        builder = builder
            .remote_public_key(remote_key)
            .expect("invalid remote public key");
    }

    let mut transport_state = builder
        .build_responder()
        .expect("couldn't build transport state");

    if let Err(e) = transport_state.read_message(&recv_buffer[..bytes], &mut message_buffer) {
        println!(
            "Failed to read initial handshake message from {}: {}",
            src, e
        );
        return None;
    }

    match transport_state.write_message(&[], &mut message_buffer) {
        Ok(len) => {
            let _ = socket.send_to(&message_buffer[..len], src);
            Some(transport_state)
        }
        Err(e) => {
            println!("Failed to write initial handshake response: {}", e);
            None
        }
    }
}

pub fn send_message(
    peer_map: &Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    &destination: &SocketAddr,
    input: &str,
    socket: &UdpSocket,
) {
    let mut peers = peer_map.lock().expect("mutex poisoned");
    if let Some(peer) = peers.get_mut(&destination) {
        if let Session::Established(ref mut transport) = peer.session {
            let mut buf = vec![0_u8; 65535];
            match transport.write_message(input.trim().as_bytes(), &mut buf) {
                Ok(len) => match socket.send_to(&buf[..len], destination) {
                    Ok(_) => {
                        println!("{} bytes sent", input.trim().len());
                    }
                    Err(erro) => println!("{}", erro),
                },
                Err(_) => println!("couldn't send message"),
            }
        }
    } else {
        println!(
            "No connection to {}. Please run 'connect' first.",
            &destination
        );
    }
}

pub fn handle_incoming_packets(
    recv_buffer: &[u8],
    bytes: usize,
    src: SocketAddr,
    socket_clone: &UdpSocket,
    key_pair_clone: &Arc<Mutex<snow::Keypair>>,
    peers: &Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    writer: &Arc<Mutex<Vec<Packet>>>,
) {
    let mut peers = peers.lock().unwrap();
    let mut session_to_upgrade = None;

    match peers.entry(src) {
        Entry::Occupied(mut entry) => {
            let peer = entry.get_mut();
            let finished = match &mut peer.session {
                Session::Established(transport) => {
                    handle_established_session(
                        transport,
                        recv_buffer,
                        bytes,
                        src,
                        &writer,
                        peer.trusted,
                    );
                    false
                }
                Session::Handshaking(handshake) => {
                    handle_handshake_message(handshake, recv_buffer, bytes, src, socket_clone)
                }
                Session::None => {
                    let remote_key = peer.public_key.as_ref().map(|k| k.as_slice());
                    if let Some(handshake) = handle_new_connection(
                        recv_buffer,
                        bytes,
                        src,
                        socket_clone,
                        key_pair_clone,
                        remote_key,
                    ) {
                        if handshake.is_handshake_finished() {
                            peer.session = Session::Handshaking(handshake);
                            true
                        } else {
                            peer.session = Session::Handshaking(handshake);
                            false
                        }
                    } else {
                        false
                    }
                }
            };
            if finished {
                session_to_upgrade = Some(entry.remove());
            }
        }
        Entry::Vacant(entry) => {
            if let Some(handshake) =
                handle_new_connection(&recv_buffer, bytes, src, socket_clone, key_pair_clone, None)
            {
                entry.insert(Peer::new(None, Session::Handshaking(handshake), None));
            } else {
                println!("new connection failed");
            }
        }
    }

    if let Some(mut peer) = session_to_upgrade {
        if let Session::Handshaking(handshake) = peer.session {
            match handshake.into_transport_mode() {
                Ok(transport) => {
                    if peer.public_key.is_none() {
                        peer.public_key = transport
                            .get_remote_static()
                            .map(|k| k.try_into().expect("invalid key length"));
                    }
                    peer.session = Session::Established(transport);
                    println!("New peer wants to connect");
                    peers.insert(src, peer);
                }
                Err(_) => {
                    println!("couldn't transform handshake to transport state");
                    peers.remove(&src);
                }
            }
        }
    }
}

pub fn load_peers(dir: &Path) -> HashMap<SocketAddr, Peer> {
    match fs::read(dir.join("peers.json")) {
        Ok(data) => serde_json::from_slice(&data).unwrap(),
        Err(_) => HashMap::new(),
    }
}

pub fn load_messages(dir: &Path) -> Vec<Packet> {
    match fs::read(dir.join("messages.json")) {
        Ok(data) => serde_json::from_slice(&data).unwrap(),
        Err(_) => vec![],
    }
}
pub fn save_peers(dir: &Path, peer_map: &Arc<Mutex<HashMap<SocketAddr, Peer>>>) {
    let serialized_peers = serde_json::to_string(&*peer_map.lock().unwrap()).unwrap();
    std::fs::write(dir.join("peers.json"), serialized_peers).expect("Unable to write file");
}
pub fn save_message(dir: &Path, packages: &Arc<Mutex<Vec<Packet>>>) {
    let serialized_messages = serde_json::to_string(&*packages.lock().unwrap()).unwrap();
    std::fs::write(dir.join("messages.json"), serialized_messages).expect("Unable to write file");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::crypto::generate_or_load_keypair;
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

    fn complete_handshake_kk(
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
    fn test_handle_established_session_stores_decrypted_packet() {
        let (mut sender, mut receiver) = complete_handshake_xx();
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
        let (sender_transport, mut receiver_transport) = complete_handshake_xx();
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
    fn test_kk_pattern_handshake() {
        let initiator_keypair = create_keypair();
        let responder_keypair = create_keypair();

        let (mut sender, mut receiver) =
            complete_handshake_kk(&initiator_keypair, &responder_keypair);

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
}
