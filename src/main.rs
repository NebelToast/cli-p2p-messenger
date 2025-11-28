use local_ip_address::local_ip;
use snow::{Builder, Keypair};
use std::{
    collections::{HashMap, hash_map::Entry},
    env, fmt,
    fs::{self, File},
    io::{self, Write, stdin},
    net::{SocketAddr, UdpSocket},
    str::Utf8Error,
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
#[derive(Debug)]
enum KeyGenerationError {
    ReadFile(io::Error),
    GenerateKey(snow::Error),
}

#[derive(Debug)]
enum ConnectErrors {
    SendMessage(io::Error),
    GenerateKey(snow::Error),
    Timeout,
}

impl fmt::Display for ConnectErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectErrors::SendMessage(e) => write!(f, "Failed to send message: {}", e),
            ConnectErrors::GenerateKey(e) => write!(f, "Failed to generate key: {}", e),
            ConnectErrors::Timeout => write!(f, "Connection timed out"),
        }
    }
}

impl fmt::Display for KeyGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyGenerationError::ReadFile(e) => write!(f, "Failed to read file: {}", e),
            KeyGenerationError::GenerateKey(e) => write!(f, "Failed to generate key: {}", e),
        }
    }
}

impl From<io::Error> for ConnectErrors {
    fn from(error: io::Error) -> Self {
        ConnectErrors::SendMessage(error)
    }
}

impl From<snow::Error> for ConnectErrors {
    fn from(error: snow::Error) -> Self {
        ConnectErrors::GenerateKey(error)
    }
}

impl From<io::Error> for KeyGenerationError {
    fn from(error: io::Error) -> Self {
        KeyGenerationError::ReadFile(error)
    }
}

impl From<snow::Error> for KeyGenerationError {
    fn from(error: snow::Error) -> Self {
        KeyGenerationError::GenerateKey(error)
    }
}

impl Packet {
    fn new(sender: SocketAddr, bytes: usize, payload: Box<[u8]>) -> Self {
        Self {
            sender: sender,
            bytes: bytes,
            payload: payload,
        }
    }
    fn print_message(&self) -> Result<(), Utf8Error> {
        println!(
            "Message: {} from {} consisting of {} bytes",
            str::from_utf8(&self.payload[..self.bytes])?,
            &self.sender,
            &self.bytes
        );
        Ok(())
    }
    fn _save_message(&self) -> Result<(), io::Error> {
        let mut file = File::options().create(true).append(true).open("lol.txt")?;
        writeln!(
            &mut file,
            "Message: {} from {} consisting of {} bytes",
            String::from_utf8_lossy(&self.payload[..self.bytes]),
            self.sender,
            self.bytes
        )?;

        Ok(())
    }
}

fn generate_or_load_keypair() -> Result<Keypair, KeyGenerationError> {
    if let Ok(private_key) = fs::read("private.key") {
        if let Ok(public_key) = fs::read("public.key") {
            println!("Existing keypair loaded.");
            return Ok(Keypair {
                public: public_key,
                private: private_key,
            });
        }
    }

    println!("No keypair found, creating a new one...");
    let keypair =
        snow::Builder::new(PATTERN.parse().expect("Invalid snow pattern")).generate_keypair()?;

    fs::write("private.key", &keypair.private)?;
    fs::write("public.key", &keypair.public)?;
    println!("New keypair saved to private.key and public.key.");

    Ok(keypair)
}

fn connect(
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

    sock.send_to(&message_buffer[..len], &destination)?;

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

fn handle_established_session(
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

fn handle_handshake_message(
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
                let _ = socket.send_to(&message_buffer[..len], &src);
            }
            Err(e) => println!("Failed to write handshake message: {}", e),
        }
    }

    handshake.is_handshake_finished()
}

fn handle_new_connection(
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
            let _ = socket.send_to(&message_buffer[..len], &src);
            Some(transport_state)
        }
        Err(e) => {
            println!("Failed to write initial handshake response: {}", e);
            None
        }
    }
}

fn send_message(
    peer_map: &Arc<Mutex<HashMap<SocketAddr, Session>>>,
    &destination: &SocketAddr,
    input: &String,
    socket: &UdpSocket,
) {
    let mut peers = peer_map.lock().expect("mutex poisoned");
    if let Some(Session::Established(transport)) = peers.get_mut(&destination) {
        let mut buf = vec![0_u8; 65535];
        match transport.write_message(input.trim().as_bytes(), &mut buf) {
            Ok(len) => match socket.send_to(&buf[..len], &destination) {
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

            match input.trim().as_ref() {
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
