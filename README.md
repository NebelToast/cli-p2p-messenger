# cli-p2p-messenger

A secure, peer-to-peer command-line messenger written in Rust. This tool establishes encrypted communication channels directly between clients using UDP and the Noise Protocol Framework.

## Features

- **End-to-End Encryption:** Uses the `Noise_XX_25519_ChaChaPoly_SHA256` pattern via the [snow](https://crates.io/crates/snow) crate to ensure secure handshakes and transport.
- **Peer-to-Peer (P2P):** No central server required; communicates directly via UDP.
- **Key Management:** Automatically generates and loads persistent `private.key` and `public.key` pairs.
- **Session Management:** Handles secure handshakes and maintains established transport sessions.
- **CLI Interface:** Simple command-line interface to connect, manage contacts, and send messages.

## Tech Stack

- **Language:** Rust
- **Transport:** UDP
- **Encryption:** Noise Protocol (Noise_XX)
- **Dependencies:** `snow`, `local-ip-address`

## Installation

Ensure you have [Rust and Cargo](https://www.rust-lang.org/tools/install) installed.

Run the project via:
```cargo run <port>```

## Usage example

**Instance A**

```cargo run 2135```

**Instance B**

```cargo run 2000```

**Get own IP via `ip` command in Istance B**
```
ip
Your IP address is: 192.168.1.2:2000
```

**In Instance A, type `connect` and enter the address of Instance B:**

```
connect
IP (with port)?:
192.168.1.2:2000
```

**Once the handshake is successful (Connection established!), you can start typing messages.**

## Commands
**connect** Initiate a secure handshake with a peer (requires IP:Port).

**messages** Print the history of received messages.

**ip** Display your current local IP address and port.

**contacs** List connected peers and select an active destination for messaging.

**Any text** Sends the text as a message to the currently selected destination.
