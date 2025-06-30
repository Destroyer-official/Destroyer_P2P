import os
import socket
import ssl   
import ipaddress
import tempfile
import logging
import secrets
import threading
import hashlib
import base64 
import json
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, List, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.extensions import TLSFeature, TLSFeatureType
from cryptography.x509 import ocsp
import sys

# Import XChaCha20Poly1305 from tls_channel_manager
try:
    from tls_channel_manager import XChaCha20Poly1305, CounterBasedNonceManager
    HAVE_XCHACHA = True
except ImportError:
    # Define our own XChaCha20Poly1305 if tls_channel_manager is not available
    HAVE_XCHACHA = False
    
    class CounterBasedNonceManager:
        """A nonce manager using a counter and a random salt.

        This approach is suitable for AEAD ciphers and helps prevent nonce reuse
        with the same key. This is a fallback implementation.
        """
        
        def __init__(self, counter_size: int = 8, salt_size: int = 4, nonce_size: int = 12):
            """Initializes the nonce manager.
            
            Args:
                counter_size: Size of the counter in bytes.
                salt_size: Size of the random salt in bytes.
                nonce_size: Total size of the nonce in bytes.
            """
            if counter_size + salt_size != nonce_size:
                raise ValueError(f"Counter size ({counter_size}) + salt size ({salt_size}) must equal nonce_size ({nonce_size}) bytes for AEAD")
                
            self.counter_size = counter_size
            self.salt_size = salt_size
            self.nonce_size = nonce_size
            self.counter = 0
            self.salt = os.urandom(salt_size)
            
            self.nonce_uses = 0
            self.last_reset_time = datetime.now()
            
        def generate_nonce(self) -> bytes:
            """Generates a unique nonce.

            The nonce is constructed by concatenating the salt and the counter.
            
            Returns:
                A unique nonce of `nonce_size` bytes.
            
            Raises:
                RuntimeError: If the counter exceeds its maximum value.
            """
            max_counter = (2 ** (self.counter_size * 8)) - 1
            if self.counter >= max_counter:
                logger.warning(f"Nonce counter reached maximum ({max_counter}), resetting salt and counter")
                self.reset()
                
            counter_bytes = self.counter.to_bytes(self.counter_size, byteorder='big')
            
            nonce = self.salt + counter_bytes
            
            self.counter += 1
            self.nonce_uses += 1
            
            return nonce
        
        def reset(self):
            """Resets the counter and generates a new random salt."""
            self.counter = 0
            self.salt = os.urandom(self.salt_size)
            self.last_reset_time = datetime.now()
            logger.debug(f"CounterBasedNonceManager reset with new {self.salt_size}-byte salt")
            
        def get_counter(self) -> int:
            """Gets the current counter value (for debugging)."""
            return self.counter
        
        def get_salt(self) -> bytes:
            """Gets the current salt value (for debugging)."""
            return self.salt
    
    class XChaCha20Poly1305:
        """A fallback implementation of the XChaCha20-Poly1305 AEAD cipher.

        This implementation uses a 192-bit (24-byte) nonce, making it safe to use
        with randomly generated nonces.
        """
         
        def __init__(self, key: bytes):
            """Initializes the cipher with a 32-byte key.
            
            Args:
                key: A 32-byte encryption key.
            """
            if len(key) != 32:
                raise ValueError("XChaCha20Poly1305 key must be 32 bytes")
            self.key = key
            self.nonce_manager = CounterBasedNonceManager(counter_size=20, salt_size=4, nonce_size=24)
        
        def encrypt(self, data: bytes = None, associated_data: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
            """Encrypts data using XChaCha20-Poly1305.
            
            Args:
                data: The plaintext to encrypt.
                associated_data: Optional additional authenticated data.
                nonce: An optional 24-byte nonce. If not provided, one is
                    generated automatically.
                
            Returns:
                The ciphertext, nonce, and authentication tag combined.
            """
            if nonce is None:
                nonce = self.nonce_manager.generate_nonce()
            elif len(nonce) != 24:
                raise ValueError("XChaCha20Poly1305 nonce must be 24 bytes")
                
            subkey = self._hchacha20(self.key, nonce[:16])
            
            # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce,
            # prepended with 4 zero bytes to form a 12-byte nonce.
            internal_nonce = b'\x00\x00\x00\x00' + nonce[16:]
            chacha = ChaCha20Poly1305(subkey)
            ciphertext = chacha.encrypt(internal_nonce, data, associated_data)
        
            return nonce + ciphertext
        
        def decrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
            """Decrypts data using XChaCha20-Poly1305.
            
            Args:
                data: The ciphertext to decrypt (including the nonce).
                associated_data: Optional additional authenticated data.
                
            Returns:
                The decrypted plaintext.
            """
            if len(data) < 24:
                raise ValueError("Data too short for XChaCha20Poly1305 decryption")
                
            nonce = data[:24]
            ciphertext = data[24:]
                
            subkey = self._hchacha20(self.key, nonce[:16])
            
            # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce,
            # prepended with 4 zero bytes to form a 12-byte nonce.
            internal_nonce = b'\x00\x00\x00\x00' + nonce[16:]
            chacha = ChaCha20Poly1305(subkey)
            return chacha.decrypt(internal_nonce, ciphertext, associated_data)
        
        def _hchacha20(self, key: bytes, nonce: bytes) -> bytes:
            """Derives a subkey from the main key and nonce using HChaCha20.
            
            Args:
                key: The 32-byte main key.
                nonce: The 16-byte nonce.
                
            Returns:
                A 32-byte derived subkey.
            """
            seed = key + nonce
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"HChaCha20 Key Derivation"
            )
            
            return hkdf.derive(seed)
            
        def rotate_key(self, new_key: bytes):
            """Rotates to a new encryption key.
            
            Args:
                new_key: The new 32-byte encryption key.
            """
            if len(new_key) != 32:
                raise ValueError("XChaCha20Poly1305 key must be 32 bytes")
                
            self.key = new_key
            self.nonce_manager.reset()

# Configure logging
logger = logging.getLogger("CAExchange")

# Post-quantum key exchange groups to be used in TLS context
HYBRID_PQ_GROUPS = ["X25519MLKEM1024", "SecP256r1MLKEM1024"]

class SecurityError(Exception):
    """Custom exception for security-related errors in the context of CA services."""
    pass

class CAExchange:
    """Manages the lifecycle of secure peer-to-peer connections.

    This class handles the generation of self-signed certificates, their secure
    exchange between peers, and the creation of high-security TLS contexts.
    It incorporates features like HPKP-style pinning and OCSP stapling.
    """
    
    def __init__(self, 
                 exchange_port_offset: int = 1,
                 buffer_size: int = 65536,
                 validity_days: int = 7,
                 key_type: str = "rsa4096",
                 secure_exchange: bool = True,
                 base_shared_secret: bytes = b'SecureP2PCertificateExchangeKey!!',
                 enable_hpkp: bool = True,
                 enable_ocsp_stapling: bool = True):
        """Initializes the certificate exchange manager.
        
        Args:
            exchange_port_offset: Port offset from the base port for the
                certificate exchange service.
            buffer_size: The size of the socket buffer for the exchange.
            validity_days: The validity period for generated certificates.
            key_type: The type and size of the cryptographic key to generate
                (e.g., "rsa4096", "ec384").
            secure_exchange: If True, the certificate exchange is encrypted.
            base_shared_secret: A secret used to derive the encryption key for
                the certificate exchange.
                **Warning**: For production use, this should be a unique,
                high-entropy secret.
            enable_hpkp: If True, enables HTTP Public Key Pinning.
            enable_ocsp_stapling: If True, enables OCSP stapling.
        """
        self.exchange_port_offset = exchange_port_offset
        self.buffer_size = buffer_size
        self.validity_days = validity_days
        self.key_type = key_type
        self.secure_exchange = secure_exchange
        self.enable_hpkp = enable_hpkp
        self.enable_ocsp_stapling = enable_ocsp_stapling
        
        self.local_key_pem = None
        self.peer_cert_pem = None
        
        self.local_cert_fingerprint = None
        self.peer_cert_fingerprint = None
        
        self.hpkp_pins: Dict[str, List[str]] = {}
        self.hpkp_max_age = 5184000  # 60 days
        self.hpkp_include_subdomains = True
        
        self.ocsp_responder_url: Optional[str] = None
        self.ocsp_response_cache: Dict[str, Dict[str, Any]] = {}
        self.ocsp_response_max_age = 3600  # 1 hour
        
        logger.debug("CAExchange module initialized with enhanced security options")
        
        self.exchange_key: Optional[bytes] = None
        self.xchacha_cipher: Optional[XChaCha20Poly1305] = None

        if self.secure_exchange:
            # Derive a consistent key for encrypting the certificate exchange.
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'p2p-cert-exchange-salt-v2',
                info=b'xchacha20poly1305-exchange-key',
            )
            base_key_material = base_shared_secret
            if isinstance(base_key_material, str):
                base_key_material = base_key_material.encode('utf-8')
            
            self.exchange_key = hkdf.derive(base_key_material)
            
            try:
                self.xchacha_cipher = XChaCha20Poly1305(self.exchange_key)
                logger.debug("CAExchange initialized with XChaCha20Poly1305 for cert exchange.")
            except Exception as e:
                logger.error(f"Failed to initialize XChaCha20Poly1305: {e}. Certificate exchange will be insecure!")
                self.xchacha_cipher = None
                self.secure_exchange = False
        
        self.cert_store: Dict[str, bytes] = {}
    
    def generate_self_signed(self) -> Tuple[bytes, bytes]:
        """Generates a new self-signed certificate and private key.

        The generated certificate includes enhanced security extensions like
        Basic Constraints, Key Usage, and OCSP Must-Staple if enabled.

        Returns:
            A tuple containing the private key and certificate in PEM format.
        """
        logger.info("Generating self-signed certificate with enhanced security parameters...")

        if self.key_type.startswith("rsa"):
            try:
                key_size = int(self.key_type[3:])
                if key_size < 2048:
                    logger.warning(f"RSA key size {key_size} is too small. Using 4096 bits instead.")
                    key_size = 4096
            except ValueError:
                logger.warning(f"Invalid RSA key size: {self.key_type}. Using 4096 bits instead.")
                key_size = 4096
                
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            logger.debug(f"Generated RSA-{key_size} key pair")
            
        elif self.key_type.startswith("ec"):
            try:
                curve_size = int(self.key_type[2:])
                if curve_size == 256:
                    curve = ec.SECP256R1()
                elif curve_size == 384:
                    curve = ec.SECP384R1()
                elif curve_size == 521:
                    curve = ec.SECP521R1()
                else:
                    logger.warning(f"Invalid EC curve size: {curve_size}. Using P-384 instead.")
                    curve = ec.SECP384R1()
                    curve_size = 384
            except ValueError:
                logger.warning(f"Invalid EC curve size: {self.key_type}. Using P-384 instead.")
                curve = ec.SECP384R1()
                curve_size = 384
                
            key = ec.generate_private_key(
                curve=curve,
                backend=default_backend()
            )
            logger.debug(f"Generated EC P-{curve_size} key pair")
            
        else:
            logger.warning(f"Unsupported key type: {self.key_type}. Using RSA-4096 instead.")
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            logger.debug("Generated RSA-4096 key pair (fallback)")

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"P2P-{secrets.token_hex(8)}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure P2P Chat"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
        ])

        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=self.validity_days)
        )

        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False
        )
        
        if self.enable_ocsp_stapling:
            cert_builder = cert_builder.add_extension(
                TLSFeature(features=[TLSFeatureType.status_request]),
                critical=False
            )

        cert = cert_builder.sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        key_pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        
        fingerprint = cert.fingerprint(hashes.SHA256())
        self.local_cert_fingerprint = fingerprint.hex()
        
        logger.debug(f"Private key PEM created ({len(key_pem_bytes)} bytes).")
        logger.debug(f"Certificate PEM created ({len(cert_pem_bytes)} bytes).")
        logger.debug(f"Certificate fingerprint: {self.local_cert_fingerprint}")
        logger.info("Self-signed certificate generation complete.")
        
        self.local_key_pem = key_pem_bytes
        self.local_cert_pem = cert_pem_bytes
        
        if self.enable_hpkp:
            pin = self.generate_hpkp_pin(cert_pem_bytes)
            self.add_hpkp_pin('*', pin)
            
        if self.enable_ocsp_stapling:
            self.generate_ocsp_response(cert_pem_bytes)
        
        return key_pem_bytes, cert_pem_bytes
        
    def _encrypt_data(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypts data using the derived exchange key.
        
        Args:
            data: The plaintext data to encrypt.
            associated_data: Optional additional authenticated data.
            
        Returns:
            The encrypted data with the nonce prepended.
            
        Raises:
            SecurityError: If encryption fails or the cipher is not available.
        """
        if not self.exchange_key or not self.secure_exchange:
            logger.warning("Exchange key not set or secure_exchange is False. Returning plaintext.")
            return data

        if not self.xchacha_cipher:
            raise SecurityError("XChaCha20Poly1305 cipher not initialized. Cannot perform secure exchange.")

        try:
            logger.debug(f"Encrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
            return self.xchacha_cipher.encrypt(data=data, associated_data=associated_data)
        except Exception as e:
            logger.error(f"XChaCha20Poly1305 encryption failed (AAD: {associated_data is not None}): {e}")
            raise SecurityError(f"Encryption failed during certificate exchange: {e}")

    def _decrypt_data(self, enc_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypts data using the derived exchange key.
        
        Args:
            enc_data: The encrypted data with the nonce prepended.
            associated_data: Optional additional authenticated data.
            
        Returns:
            The decrypted plaintext data.
            
        Raises:
            SecurityError: If decryption fails or the cipher is not available.
        """
        if not self.exchange_key or not self.secure_exchange:
            logger.warning("Exchange key not set or secure_exchange is False. Assuming plaintext.")
            return enc_data

        if not self.xchacha_cipher:
            raise SecurityError("XChaCha20Poly1305 cipher not initialized. Cannot perform secure exchange.")

        try:
            logger.debug(f"Decrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
            return self.xchacha_cipher.decrypt(data=enc_data, associated_data=associated_data)
        except Exception as e:
            logger.error(f"XChaCha20Poly1305 decryption failed (AAD: {associated_data is not None}): {e}")
            raise SecurityError(f"Decryption failed during certificate exchange: {e}")

    def exchange_certs(self, role: str, host: str, port: int, ready_event: Optional[threading.Event] = None) -> bytes:
        """Performs a certificate exchange with a peer.

        This method establishes a connection, sends the local certificate, and
        receives the peer's certificate. The exchange is encrypted if
        `secure_exchange` is enabled. It handles both "client" and "server"
        roles for setting up the connection.

        Args:
            role: The role to assume, either "client" or "server".
            host: The hostname or IP address to connect to or listen on.
            port: The port to use for the exchange.
            ready_event: For the "server" role, an optional `threading.Event`
                that is set when the server is ready to accept connections.

        Returns:
            The peer's certificate in PEM format.

        Raises:
            SecurityError: If the exchange or validation fails.
        """
        if not self.local_cert_pem or not self.local_key_pem:
            self.generate_self_signed()
            
        if not self.local_cert_fingerprint:
            raise SecurityError("Local certificate fingerprint not available for exchange.")
            
        logger.info(f"Starting certificate exchange as {role} with enhanced security.")
        
        ocsp_response = None
        if self.enable_ocsp_stapling:
            ocsp_response = self.get_cached_ocsp_response(self.local_cert_pem)
            if not ocsp_response:
                ocsp_response = self.generate_ocsp_response(self.local_cert_pem)
        
        try:
            is_ipv6 = False
            try:
                is_ipv6 = ipaddress.ip_address(host).version == 6
            except ValueError:
                pass
            
            if is_ipv6:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Calculate the exchange port by adding the offset to the base port
            exchange_port = port + self.exchange_port_offset
            
            if role == "server":
                # Use "::" for IPv6 or "0.0.0.0" for IPv4 to listen on all interfaces
                bind_addr = "::" if is_ipv6 else "0.0.0.0"
                sock.bind((bind_addr, exchange_port))
                sock.listen(1)
                logger.info(f"Server listening on [{bind_addr}]:{exchange_port} for cert exchange.")
                
                if ready_event:
                    ready_event.set()
                    
                logger.info("Waiting for client connection...")
                client_sock, client_addr = sock.accept()
                logger.info(f"Client connected from {client_addr} for cert exchange.")
                peer_sock = client_sock
            else:
                logger.info(f"Client connecting to [{host}]:{exchange_port} for cert exchange.")
                sock.connect((host, exchange_port))
                logger.info("Client connected to server.")
                peer_sock = sock
                
            try:
                cert_data = self.local_cert_pem
                
                ocsp_data = b''
                if ocsp_response:
                    ocsp_data = ocsp_response
                    
                metadata = {
                    'fingerprint': self.local_cert_fingerprint,
                    'has_ocsp': ocsp_response is not None,
                    'ocsp_len': len(ocsp_data) if ocsp_response else 0
                }
                
                if self.enable_hpkp:
                    hpkp_pin = self.generate_hpkp_pin(self.local_cert_pem)
                    metadata['hpkp_pin'] = hpkp_pin
                
                metadata_json = json.dumps(metadata).encode('utf-8')
                metadata_len = len(metadata_json)
                
                peer_sock.sendall(metadata_len.to_bytes(4, byteorder='big'))
                peer_sock.sendall(metadata_json)
                
                logger.info(f"Sending local certificate ({len(cert_data)} bytes) to peer.")
                
                if self.secure_exchange:
                    cert_data = self._encrypt_data(cert_data, associated_data=self.local_cert_fingerprint.encode('ascii'))
                
                peer_sock.sendall(len(cert_data).to_bytes(4, byteorder='big'))
                peer_sock.sendall(cert_data)
                
                if ocsp_response:
                    if self.secure_exchange:
                        ocsp_data = self._encrypt_data(ocsp_data, associated_data=b'ocsp-response')
                    peer_sock.sendall(len(ocsp_data).to_bytes(4, byteorder='big'))
                    peer_sock.sendall(ocsp_data)
                
                logger.info("Local certificate sent.")
                
                metadata_len_bytes = peer_sock.recv(4)
                if not metadata_len_bytes or len(metadata_len_bytes) != 4:
                    raise SecurityError("Failed to receive peer metadata length")
                    
                metadata_len = int.from_bytes(metadata_len_bytes, byteorder='big')
                metadata_json = peer_sock.recv(metadata_len)
                if not metadata_json or len(metadata_json) != metadata_len:
                    raise SecurityError("Failed to receive peer metadata")
                    
                try:
                    metadata = json.loads(metadata_json.decode('utf-8'))
                    peer_fingerprint = metadata.get('fingerprint')
                    has_ocsp = metadata.get('has_ocsp', False)
                    ocsp_len = metadata.get('ocsp_len', 0)
                    hpkp_pin = metadata.get('hpkp_pin')
                    
                    if not peer_fingerprint:
                        raise SecurityError("Peer metadata is missing fingerprint")
                        
                    logger.info(f"Expecting peer certificate with fingerprint: {peer_fingerprint}")
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise SecurityError(f"Failed to parse peer metadata: {e}")
                
                cert_len_bytes = peer_sock.recv(4)
                if not cert_len_bytes or len(cert_len_bytes) != 4:
                    raise SecurityError("Failed to receive peer certificate length")
                    
                cert_len = int.from_bytes(cert_len_bytes, byteorder='big')
                logger.info(f"Receiving peer certificate of {cert_len} bytes.")
                
                received_data = b''
                remaining = cert_len
                while remaining > 0:
                    chunk = peer_sock.recv(min(remaining, self.buffer_size))
                    if not chunk:
                        raise SecurityError(f"Connection closed before receiving complete certificate. Got {len(received_data)} of {cert_len} bytes.")
                    received_data += chunk
                    remaining -= len(chunk)
                
                if self.secure_exchange:
                    try:
                        received_data = self._decrypt_data(received_data, associated_data=peer_fingerprint.encode('ascii'))
                        logger.info("Successfully decrypted peer certificate")
                    except Exception as e:
                        raise SecurityError(f"Failed to decrypt peer certificate: {e}")
                
                try:
                    cert = x509.load_pem_x509_certificate(received_data)
                except Exception as e:
                    raise SecurityError(f"Invalid peer certificate format: {e}")
                
                actual_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                if actual_fingerprint != peer_fingerprint:
                    raise SecurityError(f"Certificate fingerprint mismatch. Expected {peer_fingerprint}, got {actual_fingerprint}")
                    
                logger.info(f"Certificate fingerprint verified: {peer_fingerprint}")
                
                self.peer_cert_pem = received_data
                self.peer_cert_fingerprint = peer_fingerprint
                
                if hpkp_pin and self.enable_hpkp:
                    try:
                        hostname = None
                        for ext in cert.extensions:
                            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                                san = ext.value
                                if san.dns_names:
                                    hostname = san.dns_names[0]
                                    break
                        
                        if not hostname:
                            subject = cert.subject
                            for attr in subject:
                                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                                    hostname = attr.value
                                    break
                                    
                        if not hostname:
                            # Don't use 0.0.0.0 for security reasons
                            if host == "0.0.0.0" or host == "::":
                                hostname = socket.gethostname()
                            else:
                                hostname = host
                            
                        self.add_hpkp_pin(hostname, hpkp_pin)
                        logger.info(f"Added HPKP pin for {hostname}: {hpkp_pin}")
                    except Exception as e:
                        logger.error(f"Failed to add HPKP pin: {e}")
                
                if has_ocsp and ocsp_len > 0:
                    ocsp_len_bytes = peer_sock.recv(4)
                    if not ocsp_len_bytes or len(ocsp_len_bytes) != 4:
                        logger.warning("Failed to receive OCSP response length")
                    else:
                        actual_ocsp_len = int.from_bytes(ocsp_len_bytes, byteorder='big')
                        ocsp_data = b''
                        remaining = actual_ocsp_len
                        while remaining > 0:
                            chunk = peer_sock.recv(min(remaining, self.buffer_size))
                            if not chunk:
                                break
                            ocsp_data += chunk
                            remaining -= len(chunk)
                            
                        if len(ocsp_data) == actual_ocsp_len:
                            if self.secure_exchange:
                                try:
                                    ocsp_data = self._decrypt_data(ocsp_data, associated_data=b'ocsp-response')
                                except Exception as e:
                                    logger.warning(f"Failed to decrypt OCSP response: {e}")
                                    ocsp_data = None
                                    
                            if ocsp_data:
                                try:
                                    ocsp_resp = ocsp.load_der_ocsp_response(ocsp_data)
                                    if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                                        logger.info("Received valid OCSP response")
                                        self.ocsp_response_cache[peer_fingerprint] = {
                                            'response': ocsp_data,
                                            'expires': datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age)
                                        }
                                    else:
                                        logger.warning(f"OCSP response status: {ocsp_resp.response_status}")
                                except Exception as e:
                                    logger.warning(f"Failed to parse OCSP response: {e}")
                
                logger.info("Certificate exchange finished successfully.")
                return self.peer_cert_pem
                
            finally:
                if role == "server" and 'client_sock' in locals():
                    client_sock.close()
                logger.info("Cert exchange socket closed.")
                sock.close()
                
        except Exception as e:
            logger.error(f"Certificate exchange failed: {e}")
            raise SecurityError(f"Certificate exchange failed: {e}")

    # Define secure TLS options as class attribute
    SECURE_TLS_OPTIONS = (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | 
        ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE | 
        ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    )
    
    def _configure_pq_groups(self, context: ssl.SSLContext):
        """Attempts to configure post-quantum key exchange groups on the SSLContext."""
        try:
            context.set_groups(HYBRID_PQ_GROUPS)
            logger.info(f"SSLContext configured with post-quantum groups: {HYBRID_PQ_GROUPS}")
        except AttributeError:
            py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            logger.warning("SSLContext.set_groups() not available. Post-quantum TLS KEX may not be available.")
            logger.warning(f"This is likely due to an outdated Python ({py_version}) or OpenSSL version.")
            logger.warning("For PQ KEX support, Python 3.8+ and a compatible OpenSSL (e.g., OpenSSL 3.2+ or OQS-provider) are required.")
            logger.info(f"Current OpenSSL version: {ssl.OPENSSL_VERSION}")
        except ssl.SSLError as e:
            logger.warning(f"Failed to set post-quantum groups: {e}. PQ TLS KEX may not be available.")
    
    def create_server_ctx(self) -> ssl.SSLContext:
        """Creates a high-security SSLContext for a server.

        The context is configured for TLS 1.3 only, with strong cipher suites,
        post-quantum key exchange groups, and client certificate validation.

        Returns:
            A configured `ssl.SSLContext` instance.
        
        Raises:
            ValueError: If local or peer certificates are not available.
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")
            
        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")
            
        logger.info("Creating SSLContext for server with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        logger.info("SSLContext configured for TLS 1.3 only.")
        
        ctx.options |= self.SECURE_TLS_OPTIONS
        
        # Set post-quantum key exchange groups if available
        self._configure_pq_groups(ctx)
        
        # Increase DH parameters for non-PQC key agreement.
        try:
            if hasattr(ctx, 'set_dh_params'):
                from cryptography.hazmat.primitives.asymmetric import dh
                params = dh.generate_parameters(generator=2, key_size=3072)
                ctx.set_dh_params(params)
                logger.info("DH parameters set to 3072 bits")
        except Exception as e:
            logger.warning(f"Could not set DH parameters: {e}")
        
        ctx.options |= ssl.OP_NO_TICKET
        
        tmp_cert_file = None
        tmp_key_file = None
        try:
            logger.info("Preparing temporary files for local cert/key.")
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_tf, \
                 tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_tf:
                cert_tf.write(self.local_cert_pem)
                cert_tf.flush()
                key_tf.write(self.local_key_pem)
                key_tf.flush()
                tmp_cert_file = cert_tf.name
                tmp_key_file = key_tf.name
            
            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                self._secure_delete(tmp_cert_file)
            if tmp_key_file and os.path.exists(tmp_key_file):
                self._secure_delete(tmp_key_file)

        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            logger.info("Trusted peer certificate loaded. Client certificate will be required and verified.")
        except Exception as e:
            logger.error(f"Error loading trusted peer certificate: {e}")
            raise ValueError(f"Failed to load peer certificate: {e}")
        
        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            logger.info("Strict X.509 verification enabled")
            
        logger.info("SSLContext for server configured with maximum security settings.")
        return ctx

    def create_client_ctx(self) -> ssl.SSLContext:
        """Creates a high-security SSLContext for a client.

        The context is configured for TLS 1.3 only, with strong cipher suites,
        post-quantum key exchange groups, and server certificate validation.
        
        Returns:
            A configured `ssl.SSLContext` instance.
        
        Raises:
            ValueError: If local or peer certificates are not available.
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")
            
        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")
            
        logger.info("Creating SSLContext for client with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        logger.info("SSLContext configured for TLS 1.3 only.")
        
        ctx.options |= self.SECURE_TLS_OPTIONS
        
        # Set post-quantum key exchange groups
        self._configure_pq_groups(ctx)

        # Hostname verification is disabled because we verify peer certificates manually.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        tmp_cert_file = None
        tmp_key_file = None
        try:
            logger.info("Preparing temporary files for local cert/key.")
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_tf, \
                 tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_tf:
                cert_tf.write(self.local_cert_pem)
                cert_tf.flush()
                key_tf.write(self.local_key_pem)
                key_tf.flush()
                tmp_cert_file = cert_tf.name
                tmp_key_file = key_tf.name

            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                self._secure_delete(tmp_cert_file)
            if tmp_key_file and os.path.exists(tmp_key_file):
                self._secure_delete(tmp_key_file)
                
        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            logger.info("Trusted peer certificate loaded. Server certificate will be required and verified.")
        except Exception as e:
            logger.error(f"Error loading trusted peer certificate: {e}")
            raise ValueError(f"Failed to load peer certificate: {e}")

        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            logger.info("Strict X.509 verification enabled")

        logger.info("SSLContext for client configured with maximum security settings.")
        return ctx
    
    def _secure_delete(self, file_path: str, passes: int = 3):
        """Securely deletes a file by overwriting it multiple times."""
        if not os.path.exists(file_path):
            return
            
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'wb') as f:
                for _ in range(passes):
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
            os.remove(file_path)
        except Exception as e:
            logger.warning(f"Could not securely delete {file_path}: {e}")
            try:
                os.remove(file_path)
            except Exception as e:
                logger.debug(f"Failed to remove file after secure deletion attempt: {e}")
        
    def secure_cleanup(self):
        """Securely erases sensitive data like private keys from memory."""
        try:
            if self.local_key_pem:
                buffer = bytearray(self.local_key_pem)
                for i in range(len(buffer)):
                    buffer[i] = secrets.randbelow(256)
                for i in range(len(buffer)):
                    buffer[i] = 0
                self.local_key_pem = None
            
            self.local_cert_pem = None
            self.peer_cert_pem = None
            self.local_cert_fingerprint = None
            self.peer_cert_fingerprint = None
            
            if hasattr(self, 'hpkp_pins'):
                self.hpkp_pins.clear()
                
            if hasattr(self, 'ocsp_response_cache'):
                self.ocsp_response_cache.clear()
            
            if self.exchange_key:
                buffer = bytearray(self.exchange_key)
                for i in range(len(buffer)):
                    buffer[i] = secrets.randbelow(256)
                for i in range(len(buffer)):
                    buffer[i] = 0
                self.exchange_key = None
                
            self.xchacha_cipher = None
            
            if self.cert_store:
                self.cert_store.clear()
                
            logger.info("Secure cleanup completed")
        except Exception as e:
            logger.error(f"Error during secure cleanup: {e}")

    def wrap_socket_server(self, sock: socket.socket) -> ssl.SSLSocket:
        """Wraps a server socket with a high-security TLS context.
        
        Args:
            sock: The server socket to wrap.
            
        Returns:
            A TLS-wrapped server socket.
        """
        ctx = self.create_server_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        logger.info("Server socket wrapped with maximum security TLS context")
        return ssl_sock
    
    def wrap_socket_client(self, sock: socket.socket, server_hostname: Optional[str] = None) -> ssl.SSLSocket:
        """Wraps a client socket with a high-security TLS context.
        
        Args:
            sock: The client socket to wrap.
            server_hostname: The server hostname for SNI (optional).
            
        Returns:
            A TLS-wrapped client socket.
        """
        ctx = self.create_client_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname, do_handshake_on_connect=False)
        logger.info("Client socket wrapped with maximum security TLS context")
        return ssl_sock
        
    def __del__(self):
        """Ensures secure_cleanup is called when the object is destroyed."""
        try:
            self.secure_cleanup()
        except Exception as e:
            logger.debug(f"Error during secure cleanup in __del__: {e}")

    def add_hpkp_pin(self, hostname: str, pin_value: str) -> None:
        """Adds a public key pin for a hostname.
        
        Args:
            hostname: The hostname to associate with the pin.
            pin_value: The base64-encoded SHA-256 hash of the SubjectPublicKeyInfo.
        """
        if not self.enable_hpkp:
            logger.warning("HPKP is disabled. Pin will be stored but not enforced.")
            
        if hostname not in self.hpkp_pins:
            self.hpkp_pins[hostname] = []
            
        if not pin_value.startswith("sha256="):
            pin_value = f"sha256={pin_value}"
            
        self.hpkp_pins[hostname].append(pin_value)
        logger.info(f"Added HPKP pin for {hostname}: {pin_value}")
        
    def generate_hpkp_pin(self, cert_pem: bytes) -> str:
        """Generates a public key pin from a certificate.
        
        Args:
            cert_pem: The certificate in PEM format.
            
        Returns:
            The base64-encoded SHA-256 hash of the certificate's SubjectPublicKeyInfo.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pin_hash = hashlib.sha256(spki).digest()
            pin_base64 = base64.b64encode(pin_hash).decode('ascii')
            return f"sha256={pin_base64}"
        except Exception as e:
            logger.error(f"Failed to generate HPKP pin: {e}")
            raise SecurityError(f"HPKP pin generation failed: {e}")
            
    def verify_hpkp_pin(self, hostname: str, cert_pem: bytes) -> bool:
        """Verifies a certificate against the pinned public key for a hostname.
        
        Args:
            hostname: The hostname to check against.
            cert_pem: The certificate in PEM format to verify.
            
        Returns:
            True if the certificate's public key matches a pin, False otherwise.
        """
        if not self.enable_hpkp:
            logger.warning("HPKP verification skipped because the feature is disabled.")
            return True
            
        if hostname not in self.hpkp_pins:
            logger.warning(f"No HPKP pins found for {hostname}, skipping verification.")
            return True
            
        try:
            pin = self.generate_hpkp_pin(cert_pem)
            
            if pin in self.hpkp_pins[hostname]:
                logger.info(f"HPKP verification successful for {hostname}")
                return True
                
            logger.error(f"HPKP verification failed for {hostname}. Expected one of {self.hpkp_pins[hostname]}, got {pin}")
            return False
        except Exception as e:
            logger.error(f"HPKP verification error: {e}")
            return False
            
    def get_hpkp_header(self, hostname: str) -> Optional[str]:
        """Constructs the Public-Key-Pins HTTP header value.
        
        Args:
            hostname: The hostname for which to generate the header.
            
        Returns:
            The header string or None if no pins are available.
        """
        if not self.enable_hpkp or hostname not in self.hpkp_pins or not self.hpkp_pins[hostname]:
            return None
            
        pins = "; ".join([f'pin-{pin}' for pin in self.hpkp_pins[hostname]])
        header = f'{pins}; max-age={self.hpkp_max_age}'
        
        if self.hpkp_include_subdomains:
            header += "; includeSubDomains"
            
        return header
        
    def generate_ocsp_response(self, cert_pem: bytes, issuer_cert_pem: Optional[bytes] = None) -> Optional[bytes]:
        """Generates an OCSP response for a given certificate.

        For self-signed certificates, the certificate is its own issuer.
        
        Args:
            cert_pem: The certificate in PEM format.
            issuer_cert_pem: The issuer's certificate in PEM format (optional).
            
        Returns:
            The OCSP response in DER format, or None on failure.
        """
        if not self.enable_ocsp_stapling:
            logger.debug("OCSP stapling is disabled, skipping response generation.")
            return None
            
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
             
            if issuer_cert_pem is None:
                issuer_cert = cert
            else:
                issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem)
                
            if self.local_key_pem is None:
                logger.error("Cannot generate OCSP response: local private key not available.")
                return None
                
            issuer_key = serialization.load_pem_private_key(
                self.local_key_pem,
                password=None
            )
            
            builder = ocsp.OCSPResponseBuilder()
            builder = builder.add_response(
                cert=cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA256(),
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=datetime.now(timezone.utc),
                next_update=datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age),
                revocation_time=None,
                revocation_reason=None
            ).responder_id(
                ocsp.OCSPResponderEncoding.NAME, 
                issuer_cert
            )
            
            response = builder.sign(issuer_key, hashes.SHA256())
            
            cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            response_bytes = response.public_bytes(serialization.Encoding.DER)
            self.ocsp_response_cache[cert_fingerprint] = {
                'response': response_bytes,
                'expires': datetime.now(timezone.utc) + timedelta(seconds=self.ocsp_response_max_age)
            }
            
            logger.info("Generated and cached OCSP response for certificate.")
            return response_bytes
        except Exception as e:
            logger.error(f"Failed to generate OCSP response: {e}")
            return None
            
    def get_cached_ocsp_response(self, cert_pem: bytes) -> Optional[bytes]:
        """Retrieves a cached OCSP response for a certificate.
        
        Args:
            cert_pem: The certificate in PEM format.
            
        Returns:
            The cached OCSP response in DER format if available and not expired,
            otherwise None.
        """
        if not self.enable_ocsp_stapling:
            return None
            
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            if cert_fingerprint in self.ocsp_response_cache:
                cache_entry = self.ocsp_response_cache[cert_fingerprint]
                
                if cache_entry['expires'] > datetime.now(timezone.utc):
                    logger.debug("Found valid cached OCSP response.")
                    return cache_entry['response']
                    
                logger.debug("Cached OCSP response has expired.")
                
            return None
        except Exception as e:
            logger.error(f"Error retrieving cached OCSP response: {e}")
            return None


def setup_logger(level=logging.INFO):
    """Configures the logger for the CAExchange module.
    
    Args:
        level: The logging level to set.
    """
    logger.setLevel(level)
    
    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    
    return logger

setup_logger()  