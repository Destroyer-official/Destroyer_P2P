# Secure P2P Chat with Multi-Layer Security

A high-security, peer-to-peer chat application with state-of-the-art cryptographic protection including post-quantum security, forward secrecy, and break-in recovery.

## Key Security Features

- **Hybrid X3DH+PQ Key Exchange**: Combines Extended Triple Diffie-Hellman with post-quantum cryptography
  - X25519 Diffie-Hellman exchanges for classical security
  - ML-KEM-1024 post-quantum key encapsulation for quantum resistance
  - FALCON-1024 post-quantum signatures for authentication
- **Double Ratchet Protocol**: Provides forward secrecy and break-in recovery
- **TLS 1.3 Transport Security**: Uses ChaCha20-Poly1305 for encrypted communications
- **Multi-Layer Encryption**: Defense-in-depth approach with multiple encryption algorithms
- **Secure Key Management**: Protected key storage using OS keyring or secure file storage
- **Memory Protection**: (When available) Prevents sensitive data exposure in memory

## Technical Architecture

The application combines multiple security layers:

1. **Network Layer**: UDP-based P2P communication with STUN for NAT traversal
2. **Transport Security**: TLS 1.3 with strong ciphers
3. **Key Exchange**: Hybrid X3DH+PQ protocol
4. **Message Security**: Double Ratchet encryption with post-quantum extensions
5. **Key Management**: Isolated process for secure key operations

## Requirements

- Python 3.8 or higher
- Windows, macOS, or Linux operating system
- Internet connection with ipv6 supported

## Installation

1. Clone the repository
```bash
git clone https://github.com/Destroyer-official/Destroyer_P2P.git
cd Destroyer_P2P
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

```

## Usage

1. Start the application

for windows 
```bash
python secure_p2p.py
```
for linux 
```bash
python secure_p2p.py
```

2. Initial setup:
   - The application will generate necessary cryptographic materials on first run
   - All keys are stored securely using your OS's native keyring when available

3. Connection options:
   - **Wait for incoming connection**: Acts as a server, waiting for peers
   - **Connect to a peer**: Acts as a client, initiating connection to another peer
   - **Retry STUN discovery**: Refreshes your public IP/port information

4. Share your connection information:
   - Your public endpoint will be displayed (e.g., `[2409:00e1:1117:1288:3101:2701:59f6:0ca2]:60973`)
   - Share this with your peer through a separate secure channel

5. Starting a chat:
   - When connected, you'll be prompted to enter a username
   - After both peers have connected, you can exchange messages securely

## Security Details

### Cryptographic Primitives

- **Symmetric Encryption**: ChaCha20-Poly1305, AES-256-GCM
- **Key Exchange**: X25519, ML-KEM-1024
- **Digital Signatures**: Ed25519, FALCON-1024
- **Key Derivation**: HKDF with SHA-512
- **Message Authentication**: HMAC-SHA-256, Poly1305

### Security Properties

| Property | Provided By |
|----------|-------------|
| Confidentiality | TLS 1.3, ML-KEM-1024, Double Ratchet, ChaCha20-Poly1305 |
| Authentication | TLS 1.3, X3DH, FALCON-1024 |
| Forward Secrecy | TLS 1.3, Double Ratchet |
| Post-Quantum Security | ML-KEM-1024, FALCON-1024 |
| Break-in Recovery | Double Ratchet |

### Security Verification

The application performs extensive validation of all cryptographic operations:
- Verifies key materials for proper entropy and format
- Validates all signatures before trust establishment
- Monitors integrity of sensitive data structures
- Rotates keys periodically for enhanced security

## Advanced Configuration

### Directory Structure

- `keys/`: Stores cryptographic key material
- `cert/`: Contains TLS certificates
- `logs/`: Application logs with security events

### Security Levels



### Connection Issues

1. **Cannot discover public IP**:
   - Ensure you have an publiv ipv6 address 
   - Try alternative STUN servers through the retry option
   - if no ipv6 address avilable only ipv4 address show uou can restart your network device to get an new public ipv6 address or use an vpn to get an public ipv6 address

2. **Connection timeout**:
   - Verify both peers have correct connection information
   - Check if both peers are behind symmetric NATs 

3. **TLS handshake failure**:
   - Ensure both peers are running the same version
   - Check certificate directory permissions

### Log Analysis

The application creates detailed logs that can help diagnose issues:
- Standard log messages in the console
- Detailed security logs in `hybrid_security.log`
- Debug information when run with higher logging level

## Development

### Code Structure

- `secure_p2p.py`: Main application class
- `hybrid_kex.py`: Hybrid key exchange implementation
- `double_ratchet.py`: Message encryption protocol
- `tls_secure_channel.py`: Transport security layer
- `secure_key_manager.py`: Secure key storage
- `p2p.py`: Peer-to-peer networking base

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Signal Protocol for the Double Ratchet algorithm
- NIST for post-quantum cryptography standards
- Google STUN servers for NAT traversal support 