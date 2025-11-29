mod modules;

use local_ip_address::local_ip;
use std::{
    collections::{HashMap, hash_map::Entry},
    env,
    io::stdin,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread, vec,
};

use modules::{crypto::generate_or_load_keypair, network::*, packet::Packet, session::Session};

fn client(socket: UdpSocket) {
    {
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("invalid IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
        let writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(
            generate_or_load_keypair().expect("couldn't generate keypair"),
        ));
        let key_pair_clone = Arc::clone(&key_pair);
        let peer_map = Arc::new(Mutex::new(HashMap::<SocketAddr, Session>::new()));
        let peer_map_clone = Arc::clone(&peer_map);

        thread::spawn(move || {
            let mut recv_buffer = [0_u8; 65535];

            loop {
                let (bytes, src) = socket_clone
                    .recv_from(&mut recv_buffer)
                    .expect("error in thread");

                let mut peers = peer_map_clone.lock().unwrap();
                let mut session_to_upgrade = None;

                match peers.entry(src) {
                    Entry::Occupied(mut entry) => {
                        let finished = match entry.get_mut() {
                            Session::Established(transport) => {
                                handle_established_session(
                                    transport,
                                    &recv_buffer,
                                    bytes,
                                    src,
                                    &writer,
                                );
                                false
                            }
                            Session::Handshaking(handshake) => handle_handshake_message(
                                handshake,
                                &recv_buffer,
                                bytes,
                                src,
                                &socket_clone,
                            ),
                        };
                        if finished {
                            session_to_upgrade = Some(entry.remove());
                        }
                    }
                    Entry::Vacant(entry) => {
                        if let Some(handshake) = handle_new_connection(
                            &recv_buffer,
                            bytes,
                            src,
                            &socket_clone,
                            &key_pair_clone,
                        ) {
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
        });

        loop {
            stdin().read_line(&mut input).expect("Failed to read line");

            match input.trim().to_lowercase().as_ref() {
                "connect" => {
                    input.clear();
                    println!("IP (with port)?: ");
                    stdin().read_line(&mut input).expect("Failed to read line");
                    destination = input.trim().parse().unwrap();
                    if let Err(e) = connect(&destination, &key_pair, &socket, Arc::clone(&peer_map))
                    {
                        println!("couldn't connect due to {}", e);
                    }

                    if let Some(Session::Established(transportstate)) =
                        Some(peer_map.lock().unwrap().get(&destination).unwrap())
                    {
                        Some(transportstate)
                    } else {
                        None
                    };
                }
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
                "contacs" => {
                    let contacts: Vec<SocketAddr> = peer_map
                        .lock()
                        .expect("poisoned mutex")
                        .keys()
                        .cloned()
                        .collect();

                    contacts
                        .iter()
                        .enumerate()
                        .for_each(|(i, key)| println!("[{}] {}", i + 1, key));
                    println!("[N] Don't connect");

                    input.clear();
                    stdin().read_line(&mut input).expect("Failed to read line");

                    match input.trim().to_lowercase().as_str() {
                        "n" => {}
                        _ => {
                            if let Ok(number) = input.trim().parse::<usize>() {
                                if number > 0 && number <= contacts.len() {
                                    destination = contacts[number - 1];
                                    println!("Selected: {}", destination);
                                } else {
                                    println!("Invalid selection");
                                }
                            } else {
                                println!("Invalid input");
                            }
                        }
                    }
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
