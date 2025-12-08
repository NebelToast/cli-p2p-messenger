use snow::{Builder, Keypair};
use std::{
    collections::{HashMap, hash_map::Entry},
    io::stdin,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use super::{crypto::PATTERN, error::ConnectErrors, packet::Packet, session::Session};

pub fn connect(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Session>>>,
) -> Result<(), ConnectErrors> {
    if let Some(Session::Established(_)) = map.lock().expect("mutex poisoned").get(&destination) {
        println!("Connection established!");
        return Ok(());
    }

    let mut transport_state = Builder::new(PATTERN.parse().expect("Invalid snow pattern"))
        .local_private_key(&key.lock().unwrap().private)?
        .build_initiator()?;
    let mut message_buffer = vec![0_u8; 65535];

    let len = transport_state.write_message(&[], &mut message_buffer)?;

    sock.send_to(&message_buffer[..len], destination)?;

    map.lock()
        .expect("mutex poisoned")
        .insert(destination, Session::Handshaking(transport_state));

    for n in 1..6 {
        thread::sleep(Duration::from_millis(750));
        println!("Connection is being established {} try", n);
        if let Some(Session::Established(_)) = map.lock().expect("mutex poisoned").get(&destination)
        {
            println!("Connection established!");
            return Ok(());
        }
    }
    println!("Connection timed out.");
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
) -> Option<snow::HandshakeState> {
    let mut message_buffer = [0_u8; 65535];

    let mut transport_state = Builder::new(PATTERN.parse().expect("invalid noise pattern"))
        .local_private_key(&key_pair.lock().expect("mutex poisoned").private)
        .expect("couldn't build transport state")
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
    peer_map: &Arc<Mutex<HashMap<SocketAddr, Session>>>,
    &destination: &SocketAddr,
    input: &str,
    socket: &UdpSocket,
) {
    let mut peers = peer_map.lock().expect("mutex poisoned");
    if let Some(Session::Established(transport)) = peers.get_mut(&destination) {
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
    } else {
        println!(
            "No connection to {}. Please run 'connect' first.",
            &destination
        );
    }
}
pub fn contacts(peer_map: &Arc<Mutex<HashMap<SocketAddr, Session>>>) -> Option<SocketAddr> {
    let contacts: Vec<SocketAddr> = peer_map
        .lock()
        .expect("poisoned mutex")
        .keys()
        .cloned()
        .collect();
    let mut input = String::new();

    contacts
        .iter()
        .enumerate()
        .for_each(|(i, key)| println!("[{}] {}", i + 1, key));
    println!("[N] Don't connect");
    stdin().read_line(&mut input).expect("Failed to read line");

    match input.trim().to_lowercase().as_str() {
        "n" => None,
        _ => {
            if let Ok(number) = input.trim().parse::<usize>() {
                if number > 0 && number <= contacts.len() {
                    let destination = contacts[number - 1];
                    println!("Selected: {}", destination);
                    Some(destination)
                } else {
                    println!("Invalid selection");
                    None
                }
            } else {
                println!("Invalid input");
                None
            }
        }
    }
}

pub fn handle_incoming_packets(
    recv_buffer: &[u8],
    bytes: usize,
    src: SocketAddr,
    socket_clone: &UdpSocket,
    key_pair_clone: &Arc<Mutex<snow::Keypair>>,
    peers: &Arc<Mutex<HashMap<SocketAddr, Session>>>,
    writer: &Arc<Mutex<Vec<Packet>>>,
) {
    let mut peers = peers.lock().unwrap();
    let mut session_to_upgrade = None;

    match peers.entry(src) {
        Entry::Occupied(mut entry) => {
            let finished = match entry.get_mut() {
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
                handle_new_connection(&recv_buffer, bytes, src, socket_clone, key_pair_clone)
            {
                entry.insert(Session::Handshaking(handshake));
            } else {
                println!("new connection failed");
            }
        }
    }

    if let Some(Session::Handshaking(handshake)) = session_to_upgrade {
        match handshake.into_transport_mode() {
            Ok(transport) => {
                peers.insert(src, Session::Established(transport));
            }
            Err(_) => {
                println!("couldn't transform handshake to transport state");
                peers.remove(&src);
            }
        }
    }
}
