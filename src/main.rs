use local_ip_address::local_ip;
use snow::{Builder, Keypair};
use std::{
    collections::{HashMap, hash_map::Entry},
    env,
    fs::{self, File},
    io::{self, Write, stdin},
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self},
    time::Duration,
};
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

struct Packet {
    sender: SocketAddr,
    bytes: usize,
    payload: Box<[u8]>,
}
enum Session {
    Handshaking(snow::HandshakeState),
    Established(snow::TransportState),
}

impl Packet {
    fn new(sender: SocketAddr, bytes: usize, payload: Box<[u8]>) -> Self {
        Self {
            sender: sender,
            bytes: bytes,
            payload: payload,
        }
    }
    fn print_message(&self) {
        println!(
            "Naricht: {} von {} bestehend aus {} bytes",
            str::from_utf8(&self.payload).unwrap(),
            &self.sender,
            &self.bytes
        );
    }
    fn _save_message(&self) -> Result<(), io::Error> {
        let mut file = File::options().create(true).append(true).open("lol.txt")?;
        writeln!(
            &mut file,
            "Nachricht: {} von {} bestehend aus {} bytes",
            String::from_utf8_lossy(&self.payload[..self.bytes]),
            self.sender,
            self.bytes
        )?;

        Ok(())
    }
}

fn generate_or_load_keypair() -> Result<Keypair, std::io::Error> {
    if let Ok(private_key) = fs::read("private.key") {
        if let Ok(public_key) = fs::read("public.key") {
            println!("Vorhandenes Schlüsselpaar geladen.");
            return Ok(Keypair {
                public: public_key,
                private: private_key,
            });
        }
    }

    println!("Kein Schlüsselpaar gefunden, erstelle ein neues...");
    let keypair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
        .generate_keypair()
        .unwrap();

    fs::write("private.key", &keypair.private)?;
    fs::write("public.key", &keypair.public)?;
    println!("Neues Schlüsselpaar in private.key und public.key gespeichert.");

    Ok(keypair)
}
fn connect_2(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Session>>>,
) {
    if let Some(Session::Established(_)) = map.lock().unwrap().get(&destination) {
        println!("Connection established!");
        return;
    }

    let mut transport_state = Builder::new(PATTERN.parse().unwrap())
        .local_private_key(&key.lock().unwrap().private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut message_buffer = vec![0_u8; 65535];

    let len = transport_state
        .write_message(&[], &mut message_buffer)
        .unwrap();
    sock.send_to(&message_buffer[..len], &destination).unwrap();

    map.lock()
        .unwrap()
        .insert(destination, Session::Handshaking(transport_state));

    for n in 1..6 {
        thread::sleep(Duration::from_millis(750));
        println!("Connection is being established {} try", n);
        if let Some(Session::Established(_)) = map.lock().unwrap().get(&destination) {
            println!("Connection established!");
            return;
        }
    }
    println!("Connection timed out.");
}

fn client(socket: UdpSocket) {
    {
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("ungültige IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
        let _writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(generate_or_load_keypair().unwrap()));
        let key_pair_clone = Arc::clone(&key_pair);
        let peer_map = Arc::new(Mutex::new(HashMap::<SocketAddr, Session>::new()));
        let peer_map_clone = Arc::clone(&peer_map);
        thread::spawn(move || {
            let mut recv_buffer = [0_u8; 65535];
            let mut message_buffer = vec![0_u8; 65535];

            loop {
                let (bytes, src) = socket_clone
                    .recv_from(&mut recv_buffer)
                    .expect("Fehler in thread");
                let mut peers = peer_map_clone.lock().unwrap();
                let mut session_to_upgrade = None;

                match peers.entry(src) {
                    Entry::Occupied(mut occupied_entry) => {
                        let mut finished = false;
                        match occupied_entry.get_mut() {
                            Session::Established(transport) => {
                                match transport
                                    .read_message(&recv_buffer[..bytes], &mut message_buffer)
                                {
                                    Ok(len) => {
                                        println!(
                                            "Message from {}: {}",
                                            src,
                                            String::from_utf8_lossy(&message_buffer[..len])
                                        );
                                    }
                                    Err(e) => {
                                        println!("Failed to decrypt message from {}: {}", src, e);
                                    }
                                }
                            }
                            Session::Handshaking(handshake) => {
                                match handshake
                                    .read_message(&recv_buffer[..bytes], &mut message_buffer)
                                {
                                    Ok(_) => {
                                        if !handshake.is_handshake_finished() {
                                            match handshake.write_message(&[], &mut message_buffer)
                                            {
                                                Ok(len) => {
                                                    socket_clone
                                                        .send_to(&message_buffer[..len], &src)
                                                        .unwrap();
                                                }
                                                Err(e) => println!(
                                                    "Failed to write handshake message: {}",
                                                    e
                                                ),
                                            }
                                        }
                                        if handshake.is_handshake_finished() {
                                            finished = true;
                                        }
                                    }
                                    Err(e) => println!(
                                        "Failed to read handshake message from {}: {}",
                                        src, e
                                    ),
                                }
                            }
                        }
                        if finished {
                            session_to_upgrade = Some(occupied_entry.remove());
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        let mut transport_state = Builder::new(PATTERN.parse().unwrap())
                            .local_private_key(&key_pair_clone.lock().unwrap().private)
                            .unwrap()
                            .build_responder()
                            .unwrap();

                        match transport_state
                            .read_message(&recv_buffer[..bytes], &mut message_buffer)
                        {
                            Ok(_) => {
                                match transport_state.write_message(&[], &mut message_buffer) {
                                    Ok(len) => {
                                        socket_clone.send_to(&message_buffer[..len], &src).unwrap();
                                        vacant_entry.insert(Session::Handshaking(transport_state));
                                    }
                                    Err(e) => println!(
                                        "Failed to write initial handshake response: {}",
                                        e
                                    ),
                                }
                            }
                            Err(e) => println!(
                                "Failed to read initial handshake message from {}: {}",
                                src, e
                            ),
                        }
                    }
                }
                if let Some(Session::Handshaking(handshake)) = session_to_upgrade {
                    let transport = handshake.into_transport_mode().unwrap();
                    peers.insert(src, Session::Established(transport));
                }
            }
        });

        loop {
            stdin().read_line(&mut input).expect("Failed to read line");

            match input.trim().as_ref() {
                "connect" => {
                    input.clear();
                    println!("IP(mit port)?: ");
                    stdin().read_line(&mut input).expect("Failed to read line");
                    destination = input.trim().parse().unwrap();
                    connect_2(&destination, &key_pair, &socket, Arc::clone(&peer_map));

                    if let Some(Session::Established(transportstate)) =
                        Some(peer_map.lock().unwrap().get(&destination).unwrap())
                    {
                        Some(transportstate)
                    } else {
                        None
                    };
                }
                "nachrichten" => {
                    let reader_data = Arc::clone(&packages);
                    for messages in reader_data.lock().unwrap().iter() {
                        messages.print_message()
                    }
                }
                "ip" => {
                    println!("Deine IP addresse ist: {}", socket.local_addr().unwrap());
                    input.clear();
                }

                _ => {
                    let mut peers = peer_map.lock().unwrap();
                    if let Some(Session::Established(transport)) = peers.get_mut(&destination) {
                        let mut buf = vec![0_u8; 65535];
                        let len = transport
                            .write_message(input.trim().as_bytes(), &mut buf)
                            .unwrap();
                        match socket.send_to(&buf[..len], &destination) {
                            Ok(hallo) => {
                                println!("Es wurden {} bytes gesendet", hallo);
                                input.clear();
                            }
                            Err(erro) => println!("{}", erro),
                        }
                    } else {
                        println!(
                            "Keine Verbindung zu {}. Bitte erst 'connect' ausführen.",
                            destination
                        );
                        input.clear();
                    }
                }
            };
        }
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    args.get(0).ok_or("Bitte Port eingeben").expect("Fehler");
    let socket = UdpSocket::bind(SocketAddr::new(
        local_ip().unwrap(),
        args[1].parse::<u16>().unwrap(),
    ))
    .unwrap();

    client(socket);
}
