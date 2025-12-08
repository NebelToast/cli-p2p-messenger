use local_ip_address::local_ip;
use std::{
    collections::HashMap,
    env,
    io::stdin,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
    thread, vec,
};

use networktesting::{
    crypto::generate_or_load_keypair, network::*, packet::Packet, session::Session,
};
fn set_destination(peer_map: &Arc<Mutex<HashMap<SocketAddr, Session>>>) -> Option<SocketAddr> {
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
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
        let writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(
            generate_or_load_keypair(Path::new(".")).expect("couldn't generate keypair"),
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
                        match connect(&destination, &key_pair, &socket, peer_map.clone()) {
                            Ok(_) => println!("connection established"),
                            Err(_) => println!("couldn't connect"),
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
                "help" => {
                    println!(
                        "\nconnect: connect to a new or already known client
messages: print received messages
ip: print own ip
contacts: select from known contacts
help: display help
<text>: send message to current destination"
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
