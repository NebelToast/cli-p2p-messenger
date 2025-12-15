use snow::{Builder, Keypair};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::session::Peer;

use super::{error::ConnectErrors, packet::Packet, session::Session};
pub fn connect_kk(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
) -> Result<(), ConnectErrors> {
    let mut transport_state = Builder::new(
        "Noise_KK_25519_ChaChaPoly_SHA256"
            .parse()
            .expect("Invalid snow pattern"),
    )
    .local_private_key(&key.lock().unwrap().private)?
    .remote_public_key(
        map.lock()
            .expect("mutex poisoned")
            .get(&destination)
            .unwrap()
            .public_key
            .as_ref()
            .unwrap()
            .as_ref(),
    )?
    .build_initiator()?;
    let mut message_buffer = vec![0_u8; 65535];

    let len = transport_state.write_message(&[], &mut message_buffer)?;

    sock.send_to(&message_buffer[..len], destination)?;

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

pub fn connect(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
) -> Result<(), ConnectErrors> {
    if let Some(peer) = map.lock().expect("mutex poisoned").get(&destination) {
        if let Session::Established(_) = peer.session {
            return Ok(());
        } else if peer.has_static_key() {
            return connect_kk(&destination, key, sock, map.clone());
        }
    }

    let mut transport_state = Builder::new(
        "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .expect("Invalid snow pattern"),
    )
    .local_private_key(&key.lock().unwrap().private)?
    .build_initiator()?;
    let mut message_buffer = vec![0_u8; 65535];

    let len = transport_state.write_message(&[], &mut message_buffer)?;

    sock.send_to(&message_buffer[..len], destination)?;

    map.lock().expect("mutex poisoned").insert(
        destination,
        Peer::new(None, Session::Handshaking(transport_state), None),
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
) {
    let mut message_buffer = [0_u8; 65535];
    let len = match transport.read_message(&recv_buffer[..bytes], &mut message_buffer) {
        Ok(len) => len,
        Err(e) => {
            println!("Failed to decrypt message from {}: {}", src, e);
            return;
        }
    };

    let packet = Packet::new(src, len, Box::new(message_buffer));
    if let Err(e) = packet.print_message() {
        print!("{}", e);
    }
    writer.lock().expect("mutex poisoned").push(packet);
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
                    handle_established_session(transport, recv_buffer, bytes, src, &writer);
                    false
                }
                Session::Handshaking(handshake) => {
                    handle_handshake_message(handshake, recv_buffer, bytes, src, socket_clone)
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
                        peer.public_key = transport.get_remote_static().map(|k| k.into());
                    }
                    peer.session = Session::Established(transport);
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
