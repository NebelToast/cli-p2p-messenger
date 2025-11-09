use core::time;
use local_ip_address::local_ip;
use snow::{Builder, Keypair, TransportState};
use std::{
    env,
    fs::{self, File},
    io::{self, Write, stdin},
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self, sleep},
};

struct Packet {
    sender: SocketAddr,
    bytes: usize,
    payload: Box<[u8]>,
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
fn establish_connection(
    pk: &Vec<u8>,
    dest: Option<SocketAddr>,
    sock: &UdpSocket,
    initiator: bool,
) -> TransportState {
    let pattern = "Noise_XX_25519_ChaChaPoly_SHA256";

    let mut message_buffer = vec![0_u8; 65535];
    let mut recv_buffer = vec![0_u8; 65535];

    let transport = if initiator {
        let dest = dest.expect("Intitator needs Ip of reciever");
        let mut noise = Builder::new(pattern.parse().unwrap())
            .local_private_key(&pk)
            .unwrap()
            .build_initiator()
            .unwrap();
        // ->e
        let len = noise.write_message(&[], &mut message_buffer).unwrap();
        sock.send_to(&message_buffer[..len], &dest).unwrap();

        let (n_bytes, _src) = sock.recv_from(&mut recv_buffer).unwrap();

        // <- e, ee, s, es
        noise
            .read_message(&recv_buffer[..n_bytes], &mut message_buffer)
            .unwrap();

        // -> s, se
        let len = noise.write_message(&[], &mut message_buffer).unwrap();
        sock.send_to(&message_buffer[..len], &dest).unwrap();
        noise.into_transport_mode().unwrap()
    } else {
        let mut noise = Builder::new(pattern.parse().unwrap())
            .local_private_key(&pk)
            .unwrap()
            .build_responder()
            .unwrap();

        let mut message_buffer = vec![0_u8; 65535];
        let mut recv_buffer = vec![0_u8; 65535];
        let (n_bytes, src) = sock.recv_from(&mut recv_buffer).unwrap();

        noise
            .read_message(&recv_buffer[..n_bytes], &mut message_buffer)
            .unwrap();

        // -> e, ee, s, es
        let len = noise.write_message(&[], &mut message_buffer).unwrap();
        sock.send_to(&message_buffer[..len], &src).unwrap();
        let (n_bytes, _src) = sock.recv_from(&mut recv_buffer).unwrap();

        // <- s, se
        noise
            .read_message(&recv_buffer[..n_bytes], &mut message_buffer)
            .unwrap();
        noise.into_transport_mode().unwrap()
    };
    transport
}
fn connect(socket: &UdpSocket, mut input: &mut String) -> Option<TransportState> {
    let keypair = match generate_or_load_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Fehler beim Laden/Erstellen der Schlüssel: {}", e);
            return None;
        }
    };
    let private_key = keypair.private;
    input.clear();
    println!("Initiator or Responder?");
    println!("[1] Initiator");
    println!("[2] Responder");
    stdin().read_line(&mut input).expect("Failed to read line");

    let response: String = input.parse().unwrap();

    let transport = match response.as_str().trim() {
        "1" => {
            input.clear();
            println!("IP(mit port)?: ");
            stdin().read_line(&mut input).expect("Failed to read line");
            let destination = input.trim().parse().unwrap();
            input.clear();

            let mut transport = establish_connection(&private_key, Some(destination), socket, true);
            let mut buf = vec![0_u8; 65535];
            let len = transport
                .write_message(b"You cant read me OwO", &mut buf)
                .unwrap();
            socket.send_to(&buf[..len], &destination).unwrap();
            return Some(transport);
        }
        "2" => {
            let mut transport = establish_connection(&private_key, None, socket, false);

            let mut recv_buf = vec![0_u8; 65535];
            let mut dec_buf = vec![0_u8; 65535];

            let (n_bytes, src) = socket.recv_from(&mut recv_buf).unwrap();

            let len = transport
                .read_message(&recv_buf[..n_bytes], &mut dec_buf)
                .unwrap();

            println!(
                "client @ {} said: {}",
                src,
                String::from_utf8_lossy(&dec_buf[..len])
            );
            return Some(transport);
        }
        _ => None,
    };
    println!("funktion fertig");
    input.clear();
    transport
}

fn client(socket: UdpSocket) {
    {
        //let address_book: HashMap<SocketAddr, String> = HashMap::new();

        let mut input = String::new();
        let destination: SocketAddr = "127.0.0.1:500".parse().expect("ungültige IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let packages = Arc::new(Mutex::new(vec![]));
        let writer = Arc::clone(&packages);

        thread::spawn(move || {
            let mut buffer = [0; 65535];
            loop {
                let (bytes, src) = socket_clone
                    .recv_from(&mut buffer)
                    .expect("Fehler in thread");
                let packet = Packet::new(src, bytes, Box::new(buffer));
                packet.print_message();
                let mut vec = writer.lock().unwrap();
                vec.push(packet);
            }
        });

        loop {
            stdin().read_line(&mut input).expect("Failed to read line");

            match input.trim().as_ref() {
                "connect" => {
                    input.clear();
                    connect(&socket, &mut input);
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

                _ => match socket.send_to(input.trim().as_bytes(), &destination) {
                    Ok(hallo) => {
                        println!("Es wurden {} bytes gesendet", hallo);
                        input.clear();
                    }
                    Err(erro) => println!("{}", erro),
                },
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
