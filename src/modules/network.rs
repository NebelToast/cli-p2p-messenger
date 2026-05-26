use snow::{Builder, Keypair};
use std::{
    collections::HashMap,
    fs,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
};

use crate::session::{Peer, Session};

use super::{
    error::ConnectErrors,
    packet::{Packet, SessionFlag, split_flagged_payload},
};

pub fn connect(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
) -> Result<(), ConnectErrors> {
    if let Some(peer) = map.lock().expect("mutex poisoned").get(&destination)
        && matches!(peer.session, Session::Established(_))
    {
        println!("Session already established with {}", destination);
        return Ok(());
    }

    let mut static_key = false;
    let mut static_key_k: Option<[u8; 32]> = None;
    if let Some(peer) = map.lock().expect("mutex poisoned").get(&destination)
        && peer.has_static_key()
    {
        static_key = true;
        static_key_k = peer.public_key
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

    let mut flagged = vec![SessionFlag::Handshake as u8];
    flagged.extend_from_slice(&message_buffer[..len]);

    sock.send_to(&flagged, destination)?;

    let mut peer = Peer::new_trusted(static_key_k, static_key);
    peer.session = Session::Handshaking(Box::new(transport_state));
    map.lock()
        .expect("mutex poisoned")
        .insert(destination, peer);
    Ok(())
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
        println!(
            "Failed to read handshake message from {}: {} falling back to XX pattern",
            src, e
        );
        return false;
    }

    if !handshake.is_handshake_finished() {
        match handshake.write_message(&[], &mut message_buffer) {
            Ok(len) => {
                let mut flagged = vec![SessionFlag::HandshakeResponse as u8];
                flagged.extend_from_slice(&message_buffer[..len]);
                let _ = socket.send_to(&flagged, src);
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

    if recv_buffer[..bytes].len() == 48 && pattern == "Noise_XX_25519_ChaChaPoly_SHA256" {
        println!(
            "Initiator sent KK handshake but we don't know them, rejecting so they retry with XX"
        );
        send_reject(socket, &src);
        return None;
    }
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
        if remote_public_key.is_some() {
            println!(
                "KK handshake failed with {}: {}, falling back to XX pattern",
                src, e
            );
            drop(key_guard);
            return handle_new_connection(recv_buffer, bytes, src, socket, key_pair, None);
        }
        println!(
            "Failed to read initial handshake message from {}: {}",
            src, e
        );
        return None;
    }

    match transport_state.write_message(&[], &mut message_buffer) {
        Ok(len) => {
            let mut flagged = vec![SessionFlag::HandshakeResponse as u8];
            flagged.extend_from_slice(&message_buffer[..len]);
            let _ = socket.send_to(&flagged, src);
            Some(transport_state)
        }
        Err(e) => {
            println!("Failed to write initial handshake response: {}", e);
            None
        }
    }
}

pub fn send_reject(socket: &UdpSocket, destination: &SocketAddr) {
    let flagged = vec![SessionFlag::Reject as u8];
    let _ = socket.send_to(&flagged, destination);
}

pub fn send_message(
    peer_map: &Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    &destination: &SocketAddr,
    input: &str,
    socket: &UdpSocket,
) {
    let mut peers = peer_map.lock().expect("mutex poisoned");
    if let Some(peer) = peers.get_mut(&destination) {
        if let Session::Established(transport) = &mut peer.session {
            let mut ciphertext = vec![0_u8; input.trim().len() + 16];
            match transport.write_message(input.trim().as_bytes(), &mut ciphertext) {
                Ok(len) => {
                    let mut packet = vec![SessionFlag::Transport as u8];
                    packet.extend_from_slice(&ciphertext[..len]);
                    match socket.send_to(&packet, destination) {
                        Ok(_) => {
                            println!("{} bytes sent", input.trim().len());
                        }
                        Err(erro) => println!("{}", erro),
                    }
                }
                Err(e) => println!("couldn't send message: {}", e),
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

    let Some((flag, payload)) = split_flagged_payload(&recv_buffer[..bytes]) else {
        println!("invalid packet from {}: missing/invalid flag", src);
        return;
    };

    match flag {
        SessionFlag::Handshake => {
            let peer = peers.entry(src).or_insert_with(|| Peer::new(None));
            let remote_key = peer.public_key.as_ref().map(|k| k.as_slice());
            if let Some(handshake) = handle_new_connection(
                payload,
                payload.len(),
                src,
                socket_clone,
                key_pair_clone,
                remote_key,
            ) {
                if handshake.is_handshake_finished() {
                    match handshake.into_transport_mode() {
                        Ok(transport) => {
                            if let Some(stored_key) = peer.public_key.as_ref() {
                                if let Some(remote_static) = transport.get_remote_static() {
                                    if remote_static != stored_key {
                                        println!(
                                            "Static key mismatch for {} after XX fallback, rejecting",
                                            src
                                        );
                                        send_reject(socket_clone, &src);
                                        return;
                                    }
                                }
                            }
                            if peer.public_key.is_none() {
                                peer.public_key = transport
                                    .get_remote_static()
                                    .map(|k| k.try_into().expect("invalid key length"));
                            }
                            peer.session = Session::Established(transport);
                            println!(
                                "Handshake completed with {} (fingerprint: {})",
                                src,
                                peer.fingerprint()
                            );
                        }
                        Err(_) => println!("couldn't transform handshake to transport state"),
                    }
                } else {
                    peer.session = Session::Handshaking(Box::new(handshake));
                }
            }
        }
        SessionFlag::HandshakeResponse => {
            let Some(peer) = peers.get_mut(&src) else {
                println!("Received handshake response from unknown peer {}", src);
                return;
            };
            let session = std::mem::take(&mut peer.session);
            if let Session::Handshaking(mut handshake) = session {
                let finished = handle_handshake_message(
                    &mut handshake,
                    payload,
                    payload.len(),
                    src,
                    socket_clone,
                );
                if finished {
                    match handshake.into_transport_mode() {
                        Ok(transport) => {
                            if peer.public_key.is_none() {
                                peer.public_key = transport
                                    .get_remote_static()
                                    .map(|k| k.try_into().expect("invalid key length"));
                            }
                            peer.session = Session::Established(transport);
                            println!(
                                "Handshake completed with {} (fingerprint: {})",
                                src,
                                peer.fingerprint()
                            );
                        }
                        Err(_) => println!("couldn't transform handshake to transport state"),
                    }
                } else {
                    peer.session = Session::Handshaking(handshake);
                }
            } else {
                println!(
                    "Received handshake response from {} but no handshake in progress",
                    src
                );
            }
        }
        SessionFlag::Reject => {
            println!("Connection terminated by {}", src);
            peers.remove(&src);
        }
        SessionFlag::Transport => {
            let Some(peer) = peers.get_mut(&src) else {
                return;
            };
            if let Session::Established(transport) = &mut peer.session {
                let mut message_buffer = [0_u8; 65535];
                let len =
                    match transport.read_message(&payload[..payload.len()], &mut message_buffer) {
                        Ok(len) => len,
                        Err(e) => {
                            println!("Failed to decrypt message from {}: {}", src, e);
                            return;
                        }
                    };

                if peer.trusted {
                    let packet = Packet::new(src, len, message_buffer[..len].to_vec().into_boxed_slice());
                    if let Err(e) = packet.print_message() {
                        print!("{}", e);
                    }
                    writer.lock().expect("mutex poisoned").push(packet);
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
pub fn delete_contacts(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("peers.json"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::crypto::generate_or_load_keypair;
    use std::time::Duration;
    use tempfile::tempdir;

    const PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

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
    fn test_handle_established_session_untrusted_ignored() {
        let (mut sender, mut receiver) = complete_handshake_xx();
        let src: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

        let mut buf = [0u8; 65535];
        let len = sender.write_message(b"Secret", &mut buf).unwrap();

        handle_established_session(&mut receiver, &buf, len, src, &packets, false);

        assert!(packets.lock().unwrap().is_empty());
    }

    #[test]
    fn test_handle_established_session_corrupted_ciphertext() {
        let (mut sender, mut receiver) = complete_handshake_xx();
        let src: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let packets: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));

        let mut buf = [0u8; 65535];
        let len = sender.write_message(b"Hello", &mut buf).unwrap();
        buf[0] ^= 0xFF;

        handle_established_session(&mut receiver, &buf, len, src, &packets, true);

        assert!(packets.lock().unwrap().is_empty());
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
    fn test_send_message_delivers_flagged_payload() {
        let (sender_transport, mut receiver_transport) = complete_handshake_xx();
        let peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

        let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();

        let mut peer = Peer::new(None);
        peer.session = Session::Established(sender_transport);
        peer_map.lock().unwrap().insert(receiver_addr, peer);

        send_message(&peer_map, &receiver_addr, "Test message", &sender_socket);

        let mut recv_buf = [0u8; 65535];
        let (len, _) = receiver_socket.recv_from(&mut recv_buf).unwrap();

        assert_eq!(recv_buf[0], 0x02);

        let mut plaintext = [0u8; 65535];
        let plaintext_len = receiver_transport
            .read_message(&recv_buf[1..len], &mut plaintext)
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
}
