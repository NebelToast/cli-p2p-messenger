use local_ip_address::local_ip;
use ring::digest;
use std::{
    collections::HashMap,
    env,
    io::stdin,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

use networktesting::{crypto::generate_or_load_keypair, network::*, packet::Packet, session::Peer};
fn set_destination(peer_map: &Arc<Mutex<HashMap<SocketAddr, Peer>>>) -> Option<SocketAddr> {
    let contacts: Vec<SocketAddr> = peer_map
        .lock()
        .expect("poisoned mutex")
        .keys()
        .cloned()
        .collect();
    let mut input = String::new();
    if !contacts.is_empty() {
        println!(
            "Do you want to connect to a known client?
[Y]: yes
[N]: no"
        );
        stdin().read_line(&mut input).unwrap();
    } else {
        input = "n".to_string();
    }

    match input.trim().to_lowercase().as_str() {
        "n" => {
            println!("IP (with port)?: ");
            input.clear();
            stdin().read_line(&mut input).expect("Failed to read line");
            match input.trim().parse() {
                Ok(destination) => Some(destination),
                Err(_) => None,
            }
        }
        "y" => {
            contacts
                .iter()
                .enumerate()
                .for_each(|(i, key)| println!("[{}] {}", i + 1, key));
            input.clear();
            stdin().read_line(&mut input).unwrap();

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
        _ => {
            println!("Invalid input");
            None
        }
    }
}

fn client(socket: UdpSocket) {
    {
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("invalid IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let loaded_messages: Vec<Packet> = load_messages(Path::new("."));
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(loaded_messages));
        let writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(
            generate_or_load_keypair(Path::new(".")).expect("couldn't generate keypair"),
        ));
        let key_pair_clone = Arc::clone(&key_pair);

        let loaded_peers: HashMap<SocketAddr, Peer> = load_peers(Path::new("."));
        let peer_map = Arc::new(Mutex::new(loaded_peers));
        let peer_map_clone = Arc::clone(&peer_map);
        thread::spawn(move || {
            let mut recv_buffer = [0_u8; 65535];
            loop {
                let (bytes, src) = socket_clone
                    .recv_from(&mut recv_buffer)
                    .expect("error in thread");

                handle_incoming_packets(
                    &recv_buffer,
                    bytes,
                    src,
                    &socket_clone,
                    &key_pair_clone,
                    &peer_map_clone,
                    &writer,
                );
            }
        });
        loop {
            stdin().read_line(&mut input).expect("Failed to read line");

            match input.trim().to_lowercase().as_ref() {
                "connect" => match set_destination(&peer_map) {
                    Some(new_destination) => {
                        destination = new_destination;
                        let was_known = peer_map
                            .lock()
                            .unwrap()
                            .get(&destination)
                            .map(|p| p.has_static_key())
                            .unwrap_or(false);
                        match connect(&destination, &key_pair, &socket, peer_map.clone()) {
                            Ok(_) => {
                                if !was_known {
                                    println!(
                                    "Peer is unknown. Do you want to connect to Peer with Fingerprint: {}
[y] connect
[any] do not connect",
peer_map.lock().unwrap().get(&destination).unwrap().fingerprint());
                                    input.clear();
                                    stdin().read_line(&mut input).expect("Failed to read line");
                                    if input.trim().to_lowercase() == "y" {
                                        peer_map
                                            .lock()
                                            .unwrap()
                                            .get_mut(&destination)
                                            .unwrap()
                                            .trusted = true;
                                    } else {
                                        peer_map.lock().unwrap().remove(&destination);
                                    }
                                }
                            }

                            Err(e) => println!("{}", e),
                        }
                    }
                    None => println!("coudln't get client ip"),
                },

                "messages" => {
                    let reader_data = Arc::clone(&packages);
                    for messages in reader_data.lock().expect("mutex poisoned").iter() {
                        if let Err(e) = messages.print_message() {
                            println!("{}", e);
                        }
                    }
                }
                "ip" => {
                    println!("Your IP address is: {}", socket.local_addr().unwrap());
                    input.clear();
                }
                "contacts" => {
                    peer_map
                        .lock()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .for_each(|(i, (addr, _))| println!("[{}] {}", i + 1, addr));
                }
                "save" => {
                    save_message(Path::new("."), &packages);
                    save_peers(Path::new("."), &peer_map);
                }
                "fingerprint" => {
                    let public_key_bytes = &key_pair.lock().expect("poisoned mutex").public;

                    let actual_digest = digest::digest(&digest::SHA256, &public_key_bytes);

                    println!("{}", hex::encode(actual_digest.as_ref()));
                }
                "approve" => {
                    let mut peer_map = peer_map.lock().expect("poisoned mutex");

                    let untrusted: Vec<SocketAddr> = peer_map
                        .iter()
                        .enumerate()
                        .filter_map(|(i, (addr, peer))| {
                            if !peer.trusted {
                                println!("[{}] {} fingerprint {}", i + 1, addr, peer.fingerprint());
                                return Some(*addr);
                            }
                            None
                        })
                        .collect();
                    if untrusted.is_empty() {
                        println!("No pending approvals");
                        continue;
                    }
                    input.clear();
                    stdin().read_line(&mut input).unwrap();

                    if let Ok(number) = input.trim().parse::<usize>() {
                        if number > 0 && number <= untrusted.len() {
                            let target_addr = untrusted[number - 1];
                            if let Some(peer) = peer_map.get_mut(&target_addr) {
                                peer.trusted = true;
                                println!("approved {}", peer.fingerprint());
                            }
                        } else {
                            println!("Invalid selection");
                        }
                    } else {
                        println!("Invalid input");
                    };
                }
                "help" => {
                    println!(
                        "\nconnect: Connect to new or known peer.
messages: Print the history of received messages.
ip: Display your current IP address and port.
contacts: List known peers.
help: Display help for commands.
save: Saves the connections to a file
fingerprint: Display own public key fingerprint
<text>: Send message to current destination"
                    );
                }

                _ => send_message(&peer_map, &destination, &input, &socket),
            };
            input.clear();
        }
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <port>", args[0]);
        std::process::exit(1);
    }

    let port = args[1].parse::<u16>().expect("Invalid port number");
    let socket =
        UdpSocket::bind(SocketAddr::new(local_ip().unwrap(), port)).expect("Failed to bind socket");
    client(socket);
}
