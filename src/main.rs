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
            KeyGenerationError::ReadFile(e) => write!(f, "Failed read file: {}", e),
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
            "Naricht: {} von {} bestehend aus {} bytes",
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
            "Nachricht: {} von {} bestehend aus {} bytes",
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
            println!("Vorhandenes Schlüsselpaar geladen.");
            return Ok(Keypair {
                public: public_key,
                private: private_key,
            });
        }
    }

    println!("Kein Schlüsselpaar gefunden, erstelle ein neues...");
    let keypair =
        snow::Builder::new(PATTERN.parse().expect("Invalid snow pattern")).generate_keypair()?;

    fs::write("private.key", &keypair.private)?;
    fs::write("public.key", &keypair.public)?;
    println!("Neues Schlüsselpaar in private.key und public.key gespeichert.");

    Ok(keypair)
}

fn connect(
    &destination: &SocketAddr,
    key: &Arc<Mutex<Keypair>>,
    sock: &UdpSocket,
    map: Arc<Mutex<HashMap<SocketAddr, Session>>>,
) -> Result<(), ConnectErrors> {
    if let Some(Session::Established(_)) = map.lock().expect("mutex poisend").get(&destination) {
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
        .expect("mutex poisend")
        .insert(destination, Session::Handshaking(transport_state));

    for n in 1..6 {
        thread::sleep(Duration::from_millis(750));
        println!("Connection is being established {} try", n);
        if let Some(Session::Established(_)) = map.lock().expect("mutex poisend").get(&destination)
        {
            println!("Connection established!");
            return Ok(());
        }
    }
    println!("Connection timed out.");
    Err(ConnectErrors::Timeout)
}

fn client(socket: UdpSocket) {
    {
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("ungültige IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let packages: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(vec![]));
        let writer = Arc::clone(&packages);
        let key_pair = Arc::new(Mutex::new(
            generate_or_load_keypair().expect("Couldnt generate keypair"),
        ));
        let key_pair_clone = Arc::clone(&key_pair);
        let peer_map = Arc::new(Mutex::new(HashMap::<SocketAddr, Session>::new()));
        let peer_map_clone = Arc::clone(&peer_map);

        thread::spawn(move || {
            let mut recv_buffer = [0_u8; 65535];
            let mut message_buffer = [0_u8; 65535];

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
                                        let packet =
                                            Packet::new(src, len, Box::new(message_buffer));
                                        if let Err(e) = packet.print_message() {
                                            print!("{}", e);
                                        }
                                        let mut vec = writer.lock().expect("mutex poisened");
                                        vec.push(packet);
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
                        let mut transport_state =
                            Builder::new(PATTERN.parse().expect("invalid noise pattern"))
                                .local_private_key(
                                    &key_pair_clone.lock().expect("mutex poisened").private,
                                )
                                .expect("couldnt build Transport state")
                                .build_responder()
                                .expect("couldnt build Transport state");

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
                    match handshake.into_transport_mode() {
                        Ok(transportstate) => {
                            peers.insert(src, Session::Established(transportstate));
                        }
                        Err(_) => {
                            println!("couldnt transform handshake to transportstate");
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
                    println!("IP(mit port)?: ");
                    stdin().read_line(&mut input).expect("Failed to read line");
                    destination = input.trim().parse().unwrap();
                    if let Err(e) =
                        connect(&destination, &key_pair, &socket, Arc::clone(&peer_map))
                    {
                        println!("couldnt print message due to {}", e);
                    }

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
                    for messages in reader_data.lock().expect("mutex poisened").iter() {
                        if let Err(e) = messages.print_message() {
                            println!("{}", e);
                        }
                    }
                }
                "ip" => {
                    println!("Deine IP addresse ist: {}", socket.local_addr().unwrap());
                    input.clear();
                }

                _ => {
                    let mut peers = peer_map.lock().expect("mutex poisned");
                    if let Some(Session::Established(transport)) = peers.get_mut(&destination) {
                        let mut buf = vec![0_u8; 65535];
                        match transport.write_message(input.trim().as_bytes(), &mut buf) {
                            Ok(len) => match socket.send_to(&buf[..len], &destination) {
                                Ok(_) => {
                                    println!("Es wurden {} bytes gesendet", input.trim().len());
                                    input.clear();
                                }
                                Err(erro) => println!("{}", erro),
                            },
                            Err(_) => println!("couldnt send message"),
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
