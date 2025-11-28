pub enum Session {
    Handshaking(snow::HandshakeState),
    Established(snow::TransportState),
}
