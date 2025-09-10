use local_ip_address::local_ip;
use std::{
    fs::File,
    io::{stdin, Write},
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread, {env, io},
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
    fn save_message(&self) -> Result<(), io::Error> {
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

fn sever(socket: UdpSocket) {
    loop {
        let mut buffer = [0; 256];
        let (bytes, src) = socket
            .recv_from(&mut buffer)
            .expect("Fehler beim Narichten empfangen");

        Packet::new(src, bytes, Box::new(buffer))
            .save_message()
            .expect("Fehler beim schreiben in datei");
    }
}

fn client(socket: UdpSocket) {
    {
        let mut input = String::new();
        let mut destination: SocketAddr = "127.0.0.1:500".parse().expect("ungültige IP");
        let socket_clone = socket.try_clone().expect("couldn't clone the socket");
        let packages = Arc::new(Mutex::new(vec![]));
        let writer = Arc::clone(&packages);

        thread::spawn(move || {
            let mut buffer = [0; 256];
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
                    stdin().read_line(&mut input).expect("Failed to read line");
                    destination = input
                        .split_off(8)
                        .trim()
                        .parse()
                        .expect("Ungültige IP-Addresse");
                    input.clear();
                }
                "narichten" => {
                    let reader_data = Arc::clone(&packages);
                    for messages in reader_data.lock().unwrap().iter() {
                        messages.print_message()
                    }
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
    args.get(1)
        .ok_or("Bitte argumente eingeben. Syntax server/client port")
        .expect("Fehler");
    let socket = UdpSocket::bind(SocketAddr::new(
        local_ip().unwrap(),
        args[2].parse::<u16>().unwrap(),
    ))
    .unwrap();

    if &args[1] == "server" {
        sever(socket);
    } else if &args[1] == "client" {
        client(socket);
    }
}
