
<div align="center">
  <img src="https://img.shields.io/badge/security-maximum-brightgreen" alt="Security: Maximum">
  <img src="https://img.shields.io/badge/encryption-hybrid_post_quantum-blue" alt="Encryption: Hybrid Post-Quantum">
  <img src="https://img.shields.io/badge/protocol-multi_layered-orange" alt="Protocol: Multi-Layered">
  <img src="https://img.shields.io/badge/platform-cross_platform-purple" alt="Platform: Cross-Platform">
  <img src="https://img.shields.io/badge/hardware_security-TPM_HSM-red" alt="Hardware Security: TPM/HSM">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License: MIT">
</div>

<br />

<div align="center">
  <h3 align="center">🔐 Secure P2P Chat</h3>
  <p align="center">
    Quantum-resistant, military-grade P2P communication with multi-layered cryptographic protection
    <br />
    <br />
    <a href="#architecture"><strong>Explore the Architecture »</strong></a>
    <br />
    <br />
    <a href="#setup-and-running">Installation Guide</a>
    ·
    <a href="#security-flow-summary">Security Flow</a>
    ·
    <a href="#module-breakdown--network-stages">Module Details</a>
  </p>
</div>

## ✨ Highlights

- **Quantum-Resistant Encryption**: Combines X25519 with ML-KEM-1024 and FALCON-1024 to protect against quantum computing threats
- **4 Independent Encryption Layers**: Unbreakable security with TLS 1.3, Double Ratchet, application ciphers, and certificate encryption
- **Advanced Traffic Analysis Protection**: Message length obfuscation makes all communications look identical regardless of content
- **Hardware Security Integration**: Leverages TPM on Windows and HSM on Linux/macOS for maximum key protection
- **Forward Secrecy & Break-in Recovery**: Automatically rotates keys and provides security even after key compromise
- **Zero Persistence Option**: In-memory only mode leaves no trace on disk after shutdown
- **Cross-Platform**: Works seamlessly across Windows, macOS, and Linux with native security features

## Table of Contents

- [About The Project](#about-the-project)
- [Architecture](#architecture)
- [Security Features In-Depth](#security-features-in-depth)
- [Module Breakdown & Network Stages](#module-breakdown--network-stages)
- [Security Flow Summary](#security-flow-summary)
- [Advanced Protection Features](#advanced-protection-features)
  - [Traffic Analysis Resistance](#traffic-analysis-resistance)
  - [Double Ratchet Enhancement](#double-ratchet-enhancement)
  - [Anti-Forensic Design](#anti-forensic-design)
  - [Security Monitoring](#security-monitoring)
  - [Ephemeral Identities](#ephemeral-identities)
- [Setup and Running](#setup-and-running)
- [Under The Hood](#under-the-hood)
- [Dependencies](#dependencies)
- [Potential Use Cases](#potential-use-cases)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security Considerations](#security-considerations)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## About The Project

### 🔒 Motivation

This project was developed to create the most secure peer-to-peer communication system possible by combining cutting-edge cryptographic techniques. The primary goals were:

1. **Future-proof security** - Implement post-quantum cryptographic methods that resist both classical and quantum attacks
2. **Defense in depth** - Create multiple independent security layers that would require breaking multiple encryption systems
3. **Cross-platform hardware security** - Leverage hardware security elements available on different platforms for maximum protection
4. **Zero-knowledge architecture** - Design a system where even if servers are compromised, messages remain protected
5. **Educational foundation** - Demonstrate advanced security concepts in a practical implementation

### 🌟 Key Features

- **Hybrid X3DH+PQ Key Exchange**: Extended Triple Diffie-Hellman with Post-Quantum enhancements
- **Multi-layered Protection**: TLS 1.3, Double Ratchet, and application-layer encryption
- **Traffic Analysis Resistance**: Advanced message length obfuscation techniques
- **Hardware Security Module Integration**: OS-specific hardware-backed crypto operations
- **Post-quantum Algorithms**: ML-KEM-1024 for key exchange and FALCON-1024 for signatures
- **Ephemeral Identity**: Automatic key rotation at configurable intervals
- **Memory Protection**: Security-hardened memory handling with canary values
- **Anti-Forensic Design**: Options for zero-persistence operation mode

## Architecture

The application employs a defense-in-depth security architecture with multiple specialized modules:

```mermaid
flowchart TB
    subgraph "User Interface"
        UI[User Interface]
    end

    subgraph "Security Orchestration"
        SecureP2P["secure_p2p.py\nMain Security Coordinator"]
    end

    subgraph "Network Layer"
        P2P["p2p_core.py\nP2P Networking & STUN"]
    end

    subgraph "Security Protocol Stack"
        direction TB
        TLS["tls_channel_manager.py\nTLS 1.3 with PQ Extensions"]
        CA["ca_services.py\nCertificate Exchange"]
        KEX["hybrid_kex.py\nX3DH + ML-KEM-1024"]
        DR["double_ratchet.py\nE2E Encryption & Forward Secrecy"]
    end

    subgraph "Hardware Security"
        HSM["platform_hsm_interface.py\nTPM/HSM Integration"]
        KeyMgr["secure_key_manager.py\nSecure Key Storage"]
    end

    UI <--> SecureP2P
    SecureP2P <--> P2P
    
    SecureP2P --> TLS
    SecureP2P --> CA
    SecureP2P --> KEX
    SecureP2P --> DR
    
    TLS --> CA
    KEX --> DR
    
    TLS --> HSM
    KEX --> HSM
    DR --> HSM
    CA --> HSM
    
    HSM <--> KeyMgr

    classDef primary fill:#f9f9f9,stroke:#333,stroke-width:2px,color:#333;
    classDef secondary fill:#f6f8fa,stroke:#666,stroke-width:1px,color:#666;
    
    class SecureP2P,HSM primary;
    class UI,P2P,TLS,CA,KEX,DR,KeyMgr secondary;
```

## Security Features In-Depth

### 🛡️ Hybrid Post-Quantum Cryptography

Combines traditional and post-quantum algorithms to ensure security against both classical and quantum attacks:

- **Key Exchange**: X3DH (Extended Triple Diffie-Hellman) with X25519 + ML-KEM-1024
- **Signatures**: FALCON-1024 for quantum-resistant digital signatures
- **Benefits**: Maintains security even if either classical or quantum algorithm is compromised

### 🔄 Multi-Layered Encryption

Four independent encryption layers with different security properties:

1. **TLS 1.3**: Transport security with PQ-enhanced cipher suites
2. **Double Ratchet**: End-to-end encryption with forward secrecy and break-in recovery
3. **Application-Layer Encryption**: Multiple ciphers (XChaCha20-Poly1305, AES-256-GCM)
4. **Certificate Exchange**: Additional ChaCha20-Poly1305 encryption for certificate exchange

### 🖥️ Hardware Security Integration

Cross-platform interface for hardware security elements:

- **Windows**: CNG (Cryptography API: Next Generation) with TPM 2.0 integration
- **Linux/macOS**: PKCS#11 for HSM interface
- **Capabilities**:
  - Secure random number generation from hardware sources
  - Hardware-backed key generation when available
  - Protected signing operations using keys stored in secure hardware

### 🔐 Secure Key Management

Advanced key storage with OS-specific best practices:

- **Storage Options**:
  - **OS Keyring**: Windows Credential Manager, macOS Keychain, Linux Keyring
  - **Secure Filesystem**: OS-specific secure locations with strict permissions
  - **In-Memory**: Zero-persistence mode for maximum security
- **Process Isolation**: Key operations in separate process on POSIX systems
- **Memory Protection**: Secure memory wiping, canary values, and anti-debugging features

## Advanced Protection Features

### 📊 Traffic Analysis Resistance

Sophisticated techniques to prevent message length analysis:

- **Variable Message Padding**: Random padding (1-30 bytes) added to each message
- **Constant-Size Messages**: All messages padded to similar size (~1350-1420 bytes)
- **FALCON Signature Padding**: Large signatures (~1270 bytes) provide baseline size
- **Indistinguishable Messages**: Heartbeats, short messages, and long messages all appear identical on the network

### 🔄 Double Ratchet Enhancement

Advanced improvements to the Signal Protocol's Double Ratchet:

- **Post-Quantum Integration**: ML-KEM for additional ratchet steps
- **Quantum-Resistant Authentication**: FALCON-1024 signatures for message authentication
- **Multiple Chain Keys**: Enhanced key derivation with additional entropy sources
- **Memory-Hardened Storage**: Protected memory for sensitive ratchet state

### 🧩 Anti-Forensic Design

Features to minimize persistent traces:

- **In-Memory Operation**: Option to keep all keys in RAM only
- **Secure Memory Wiping**: Explicit memory clearing with verification
- **Ephemeral Identity**: Automatic rotation of all cryptographic identities
- **Zero-Knowledge Design**: No central servers or persistent identifiers

### 🔍 Security Monitoring

Built-in security monitoring capabilities:

- **Entropy Verification**: Ensures cryptographic materials have sufficient randomness
- **Canary Values**: Memory integrity checks to detect tampering
- **Heartbeat Encryption**: Encrypted keepalive messages to maintain connection security
- **Anomaly Detection**: Identifies potential security issues during operation

### 🆔 Ephemeral Identities

Enhances privacy and thwarts long-term tracking:

- **Automatic Identity Rotation**: All cryptographic identifiers (keys, certificates) are automatically rotated at configurable intervals (e.g., every hour or day).
- **No Persistent Identifiers**: The system avoids long-term static identifiers that could be used to track users over time.
- **Untraceable Sessions**: Each communication session can appear to originate from a new, unrelated identity, making it difficult to link sessions or build a profile of a user.
- **Increased Anonymity**: Complements other security layers by making it harder to attribute communication to specific individuals over extended periods.

## Module Breakdown & Network Stages

The application's functionality is distributed across several Python modules:

### 1. `p2p_core.py` - Base P2P Networking
- **Functionality**: Handles TCP/IPv6 networking, STUN for NAT traversal
- **Security Feature**: Message framing with length obfuscation
- **Network Stage**: Connection discovery and establishment

### 2. `platform_hsm_interface.py` - Hardware Security
- **Functionality**: Unified hardware security interface
- **Security Feature**: TPM 2.0 integration on Windows, PKCS#11 on Linux/macOS
- **Key Capabilities**: Hardware-backed key generation, storage, and operations

### 3. `secure_key_manager.py` - Key Management
- **Functionality**: Cross-platform secure key storage
- **Security Feature**: OS-specific secure storage with multiple backends
- **Key Features**: Process isolation, strict permissions, in-memory mode

### 4. `ca_services.py` - Certificate Management
- **Functionality**: Certificate generation, exchange, and verification
- **Security Feature**: ChaCha20-Poly1305 encrypted certificate exchange
- **Key Features**: Strong certificate parameters, mutual authentication

### 5. `hybrid_kex.py` - Hybrid Key Exchange
- **Functionality**: X3DH with post-quantum enhancements
- **Security Feature**: ML-KEM-1024 integration for quantum resistance
- **Key Components**: Static, signed, and ephemeral keys with PQ protection

### 6. `tls_channel_manager.py` - TLS Management
- **Functionality**: TLS 1.3 connection establishment and management
- **Security Feature**: Post-quantum cipher preference and enhanced verification
- **Key Features**: Certificate pinning, strong cipher enforcement

### 7. `double_ratchet.py` - Message Encryption
- **Functionality**: Advanced Double Ratchet implementation
- **Security Feature**: Forward secrecy, break-in recovery, message length obfuscation
- **Key Features**: PQ-enhanced ratchet steps, FALCON signatures

### 8. `secure_p2p.py` - Main Application
- **Functionality**: Security orchestration and user interface
- **Security Feature**: Defense-in-depth coordination
- **Key Responsibility**: Proper sequencing and verification of security processes

## Security Flow Summary

1. **STUN Discovery & Connection Establishment**
   - Peers discover public endpoints using STUN
   - Initial TCP connection established

2. **Certificate Generation & Exchange**
   - Self-signed certificates generated with strong parameters
   - Certificates exchanged with ChaCha20-Poly1305 encryption

3. **Hybrid X3DH+PQ Key Exchange**
   - Static, signed, and ephemeral keys exchanged
   - ML-KEM-1024 encapsulation provides quantum resistance
   - FALCON-1024 signatures verify key authenticity

4. **Double Ratchet Initialization**
   - Shared secret from X3DH+PQ initializes Double Ratchet
   - Ratchet keys securely exchanged and verified

5. **TLS 1.3 Secure Channel**
   - TLS connection established using exchanged certificates
   - Strong ciphers enforced (ChaCha20-Poly1305, AES-256-GCM)

6. **Secure Messaging**
   - Messages encrypted with Double Ratchet (forward secrecy)
   - Message length obfuscation applied
   - Encrypted messages sent through TLS channel
   - Regular key rotation and ratchet steps maintain security

## Setup and Running

### Prerequisites

- Python 3.8 or newer
- Operating System: Windows, macOS, or Linux
- Internet connection for P2P communication
- For hardware security: TPM 2.0 (Windows) or compatible HSM (Linux/macOS)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/secure-p2p-chat.git
cd secure-p2p-chat
```

2. **Set up a virtual environment**

```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

### Running the Application

Start the secure chat:

```bash
python secure_p2p.py
```

The application will guide you through:
1. Discovering your public IP using STUN
2. Setting up as a server (waiting for connection) or client (connecting to peer)
3. Establishing a multi-layered secure connection
4. Exchanging messages with complete security and privacy

## Under The Hood

### Quantum Resistance

The hybrid approach ensures protection against quantum computers:

- **ML-KEM-1024**: NIST-approved Key Encapsulation Mechanism resistant to Grover's and Shor's algorithms
- **FALCON-1024**: Lattice-based signatures offering 128-bit post-quantum security
- **Hybrid Design**: Classical + post-quantum for defense-in-depth

### Traffic Analysis Protection

Multiple techniques prevent message pattern analysis:

- **Random Padding**: Variable padding makes messages unpredictable
- **Fixed Message Size**: FALCON signatures create consistent message sizes (~1350-1420 bytes)
- **Heartbeat Obfuscation**: System messages indistinguishable from user messages
- **Header Encryption**: All message metadata encrypted at multiple levels

### Hardware Security

The hardware security integration leverages:

- **Windows TPM**: Native CNG APIs for TPM-backed operations
- **HSM Support**: PKCS#11 interface for hardware security modules
- **Protected Operations**: Key generation and signing in secure hardware
- **Memory Protection**: Defense against cold boot and memory dumping attacks

## Dependencies

This project relies on several external Python libraries and core internal modules:

### External Libraries (from PyPI)

These should be installed via `pip install -r requirements.txt`:

```
cryptography>=3.4.0      # Core cryptographic operations (AES, ChaCha20, RSA, ECC)
keyring>=23.0.0          # Secure OS-specific credential storage (keychain, credential manager)
pyzmq>=22.0.0            # Inter-process communication for key management isolation (POSIX)
python-pkcs11            # PKCS#11 interface for HSMs (Linux/macOS only)
```

### Core Internal Modules & Custom Libraries

These modules are part of the project's codebase:

- **`quantcrypt`**: A custom local library providing implementations for the post-quantum algorithms ML-KEM (for Key Encapsulation) and FALCON (for digital signatures). This module is essential for the hybrid post-quantum security features.
- **`platform_hsm_interface.py`** (often imported as `cphs`): This is the core internal module that provides the cross-platform hardware security abstraction layer. It interfaces with Windows CNG/TPM and PKCS#11 for HSMs on Linux/macOS.
- Other Python files like `secure_p2p.py`, `hybrid_kex.py`, `double_ratchet.py`, etc., constitute the main application logic and security protocols.

## Potential Use Cases

- **Government & Military**: Secure communications with quantum resistance
- **Financial Institutions**: Protected discussion of sensitive financial matters
- **Journalists & Activists**: Communication in high-risk environments
- **Corporate Security**: Protection of intellectual property discussions
- **Healthcare**: HIPAA-compliant patient information exchange
- **Legal Sector**: Privileged attorney-client communications


## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

Important notes:

- **Research Project**: This is primarily an educational/research implementation
- **Ongoing Development**: Some features may be conceptual or partially implemented
- **No Formal Audit**: The code has not undergone professional security auditing
- **Post-Quantum Evolution**: PQ algorithms continue to evolve with NIST standardization

## License

This project is available under the MIT License. See the LICENSE file for details.

## Acknowledgments

- Signal Protocol for the Double Ratchet algorithm concept
- NIST Post-Quantum Cryptography standardization efforts
- The open-source cryptography community
- All contributors to this project


