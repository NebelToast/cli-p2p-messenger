use local_ip_address::local_ip;
use ring::digest;
use std::{
    collections::HashMap,
    env, fs,
    io::stdin,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

use cli_p2p_messenger::{
    crypto::generate_or_load_keypair, network::*, packet::Packet, session::Peer,
    session::PeerRegistry,
};

fn set_destination(peers: &PeerRegistry) -> Option<SocketAddr> {
    let contacts: Vec<SocketAddr> = peers.with_peers(|peers| peers.keys().cloned().collect());
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
            input.trim().parse().ok()
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
        let path = std::env::home_dir()
            .unwrap()
            .join(".local/share/cli-p2p-messenger");
        if !fs::exists(&path).unwrap() {
            fs::create_dir(&path).unwrap();
        }
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("invalid IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let loaded_messages: Vec<Packet> = load_messages(Path::new(&path));
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(loaded_messages));
        let writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(
            generate_or_load_keypair(Path::new(&path)).expect("couldn't generate keypair"),
        ));
        let key_pair_clone = Arc::clone(&key_pair);

        let loaded_peers: HashMap<SocketAddr, Peer> = load_peers(Path::new(&path));
        let peers = PeerRegistry::new(loaded_peers);
        let peers_clone = peers.clone();
        thread::spawn(move || {
            let mut recv_buffer = [0_u8; 65535];
            loop {
                let (bytes, src) = socket_clone
                    .recv_from(&mut recv_buffer)
                    .expect("error in thread");

                if let Err(e) = handle_incoming_packets(
                    &recv_buffer,
                    bytes,
                    src,
                    &socket_clone,
                    &key_pair_clone,
                    peers_clone.clone(),
                    &writer,
                ) {
                    eprintln!("Error handling packet from {}: {}", src, e);
                }
            }
        });
        loop {
            stdin().read_line(&mut input).expect("Failed to read line");

            match input.trim().to_lowercase().as_ref() {
                "connect" => match set_destination(&peers) {
                    Some(new_destination) => {
                        destination = new_destination;
                        let was_known = peers.is_known(&destination);
                        match connect(&destination, &key_pair, &socket, peers.clone()) {
                            Ok(_) => {
                                if !was_known {
                                    println!("Waiting for handshake to complete...");
                                    let mut attempts = 0;
                                    loop {
                                        thread::sleep(std::time::Duration::from_millis(100));
                                        attempts += 1;
                                        let has_key = peers.is_known(&destination);
                                        if has_key || attempts > 50 {
                                            break;
                                        }
                                    }

                                    let fingerprint = peers.get_fingerprint(&destination);

                                    if fingerprint == "<unknown>" {
                                        println!("Handshake timed out.");
                                        peers.remove(&destination);
                                    } else {
                                        println!(
                                            "Do you want to connect to Peer with Fingerprint: {}\n\
                                            [y] connect\n\
                                            [any] do not connect",
                                            fingerprint
                                        );
                                        input.clear();
                                        stdin().read_line(&mut input).expect("Failed to read line");
                                        if input.trim().to_lowercase() == "y" {
                                            peers.set_trusted(&destination, true);
                                            println!("Peer approved and saved to contacts.");
                                        } else {
                                            send_reject(&socket, &destination);
                                            peers.remove(&destination);
                                            println!("Connection terminated.");
                                        }
                                    }
                                } else {
                                    println!(
                                        "Connected to known peer (fingerprint: {})",
                                        peers.get_fingerprint(&destination)
                                    );
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
                        messages.print_message();
                    }
                }
                "ip" => {
                    println!("Your IP address is: {}", socket.local_addr().unwrap());
                    input.clear();
                }
                "contacts" => {
                    peers.with_peers(|peers_map| {
                        peers_map.iter().for_each(|addr| println!("{}", addr.0));
                    });
                }
                "save" => {
                    if let Err(e) = save_message(Path::new(&path), &packages) {
                        println!("Failed to save messages: {}", e);
                    }
                    if let Err(e) = save_peers(Path::new(&path), &peers) {
                        println!("Failed to save peers: {}", e);
                    }
                }
                "fingerprint" => {
                    let public_key_bytes = &key_pair.lock().expect("poisoned mutex").public;

                    let actual_digest = digest::digest(&digest::SHA256, public_key_bytes);

                    println!("{}", hex::encode(actual_digest.as_ref()));
                }
                "approve" => {
                    let untrusted: Vec<SocketAddr> = peers.with_peers(|peers_map| {
                        peers_map
                            .iter()
                            .enumerate()
                            .filter_map(|(i, (addr, peer))| {
                                if !peer.trusted {
                                    println!(
                                        "[{}] {} fingerprint {}",
                                        i + 1,
                                        addr,
                                        peer.fingerprint()
                                    );
                                    return Some(*addr);
                                }
                                None
                            })
                            .collect()
                    });
                    if untrusted.is_empty() {
                        println!("No pending approvals");
                        continue;
                    }
                    input.clear();
                    stdin().read_line(&mut input).unwrap();

                    if let Ok(number) = input.trim().parse::<usize>() {
                        if number > 0 && number <= untrusted.len() {
                            let target_addr = untrusted[number - 1];
                            peers.set_trusted(&target_addr, true);
                            let fingerprint = peers.get_fingerprint(&target_addr);
                            println!("approved {}", fingerprint);
                        } else {
                            println!("Invalid selection");
                        }
                    } else {
                        println!("Invalid input");
                    };
                }
                "clear" => {
                    peers.clear();
                    if let Err(e) = delete_contacts(Path::new(&path)) {
                        println!("Failed to delete contacts: {}", e);
                    }
                }
                "disconnect" => {
                    let trusted: Vec<SocketAddr> = peers.get_trusted_peers();
                    if trusted.is_empty() {
                        println!("No one to disconnect from");
                        continue;
                    }
                    input.clear();
                    stdin().read_line(&mut input).unwrap();

                    if let Ok(number) = input.trim().parse::<usize>() {
                        if number > 0 && number <= trusted.len() {
                            let target_addr = trusted[number - 1];
                            send_reject(&socket, &target_addr);
                            peers.remove(&target_addr);
                            println!("disconnected");
                        } else {
                            println!("Invalid selection");
                        }
                    } else {
                        println!("Invalid input");
                    };
                }
                "exit" => {
                    let count = peers
                        .get_trusted_peers()
                        .iter()
                        .map(|addr| send_reject(&socket, addr))
                        .count();
                    println!("disconnected from {}", count);
                    if let Err(e) = save_message(Path::new(&path), &packages) {
                        println!("Failed to save messages: {}", e);
                    }
                    if let Err(e) = save_peers(Path::new(&path), &peers) {
                        println!("Failed to save peers: {}", e);
                    }
                    break;
                }
                "help" => {
                    println!(
                        "\nconnect: Connect to new or known peer.
messages: Print the history of received messages.
clear: delete contacts including file
ip: Display your current IP address and port.
contacts: List known peers.
help: Display help for commands.
save: Saves the connections to a file
fingerprint: Display own public key fingerprint
approve: approve clients that want to connect
disconnect: disconnects from a peer.
exit: disconnects from all peers and saves the contacts before exiting.
<text>: Send message to current destination"
                    );
                }

                _ => {
                    if let Err(e) = send_message(peers.clone(), &destination, &input, &socket) {
                        println!("Failed to send message: {}", e);
                    }
                }
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
