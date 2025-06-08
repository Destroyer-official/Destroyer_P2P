import os
import socket
import ssl   
import ipaddress
import tempfile
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, List, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Attempt to import XChaCha20Poly1305 from tls_channel_manager
# This assumes tls_channel_manager.py is in a location where it can be imported
# and that it doesn't create circular dependencies with ca_services.py
try:
    from tls_channel_manager import XChaCha20Poly1305, CounterBasedNonceManager
    HAVE_XCHACHA = True
except ImportError as e:
    # Fallback or error handling if XChaCha20Poly1305 cannot be imported
    # For now, we'll log a warning and a simple fallback will occur later if XCHACHA isn't available
    # In a real scenario, this might need a more robust fallback or be a fatal error
    # For this specific change, we assume XChaCha20Poly1305 will be available.
    # If not, the original ChaCha20Poly1305 would need to be used with stricter nonce handling,
    # or the application might need to halt if XChaCha20 is essential.
    # Given the request, we are upgrading to XChaCha20.
    # If it's not found, the existing code would have used the basic ChaCha20Poly1305
    # which we are trying to replace due to nonce concerns with the fixed key.
    # So, ideally, this import should succeed or the application should have a clear strategy.
    # For now, we'll rely on it being present.
    HAVE_XCHACHA = False # This will be checked later
    # logger.warning(f"Could not import XChaCha20Poly1305 from tls_channel_manager: {e}. Certificate exchange security may be reduced if it falls back.")
    # Re-import basic ChaCha20Poly1305 for a potential (less ideal) fallback if needed,
    # though the goal is to use XChaCha20Poly1305.
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configure logging
logger = logging.getLogger("CAExchange")

# Post-quantum key exchange groups to be used in TLS context
HYBRID_PQ_GROUPS = ["X25519MLKEM1024", "SecP256r1MLKEM1024"]

class SecurityError(Exception):
    """Custom exception for security-related errors in the context of CA services."""
    pass

class CAExchange:
    """
    Enhanced Certificate Authority Exchange Module
    
    Handles certificate generation, exchange, and TLS context creation between peers
    
    """
    
    # Define stronger cipher suites
    # SECURE_CIPHER_SUITES = [
    #     "TLS_AES_256_GCM_SHA384",
    #     "TLS_CHACHA20_POLY1305_SHA256"
    # ]
    
    # Define secure TLS options
    SECURE_TLS_OPTIONS = (
        ssl.OP_NO_SSLv2 | 
        ssl.OP_NO_SSLv3 | 
        ssl.OP_NO_TLSv1 | 
        ssl.OP_NO_TLSv1_1 | 
        ssl.OP_NO_TLSv1_2 |
        ssl.OP_NO_COMPRESSION |
        ssl.OP_SINGLE_DH_USE |
        ssl.OP_SINGLE_ECDH_USE |
        ssl.OP_CIPHER_SERVER_PREFERENCE
    )
    
    def __init__(self, 
                 exchange_port_offset: int = 1,
                 buffer_size: int = 65536,
                 validity_days: int = 7,
                 key_type: str = "rsa4096",
                 secure_exchange: bool = True,
                 base_shared_secret: bytes = b'SecureP2PCertificateExchangeKey!!'):  # Changed to True by default for maximum security
        """
        Initialize the CAExchange module with enhanced security options
        
        Args:
            exchange_port_offset: Port offset from the main TLS port for cert exchange
            buffer_size: Buffer size for socket communication
            validity_days: Certificate validity period in days
            key_type: Type of key to use ("ec521" for ECC P-521, "rsa4096" for RSA-4096)
            secure_exchange: Whether to encrypt certificate exchange with a pre-shared key (default: True)
            base_shared_secret: The shared secret used for key derivation
        """
        self.exchange_port_offset = exchange_port_offset
        self.buffer_size = buffer_size
        self.validity_days = min(validity_days, 30)  # Cap at 30 days for security
        self.key_type = key_type
        self.secure_exchange = secure_exchange
        
        # Certificate data - will be populated during generation/exchange
        self.local_cert_pem = None
        self.local_key_pem = None
        self.peer_cert_pem = None
        
        # Certificate fingerprints for verification
        self.local_cert_fingerprint = None
        self.peer_cert_fingerprint = None
        
        logger.debug("CAExchange module initialized with enhanced security options")
        
        # Holds the exchange key for ChaCha20Poly1305 or XChaCha20Poly1305
        # This key is derived once and used for the lifetime of this instance.
        self.exchange_key: Optional[bytes] = None
        self.xchacha_cipher: Optional[XChaCha20Poly1305] = None # For XChaCha20Poly1305

        if self.secure_exchange:
            # Derive a consistent key for encrypting the certificate exchange
            # Using a fixed salt and info string for HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # ChaCha20Poly1305 and XChaCha20Poly1305 use a 32-byte key
                salt=b'p2p-cert-exchange-salt-v1', 
                info=b'chacha20poly1305-exchange-key', # Keep info generic as key is for an AEAD
            )
            # Ensure the input key material is bytes
            base_key_material = base_shared_secret
            if isinstance(base_key_material, str):
                base_key_material = base_key_material.encode('utf-8')
            
            self.exchange_key = hkdf.derive(base_key_material)
            
            # Initialize XChaCha20Poly1305 cipher if available
            if HAVE_XCHACHA:
                try:
                    # Create a custom implementation with the correct nonce size for XChaCha20Poly1305 (24 bytes)
                    self.xchacha_cipher = XChaCha20Poly1305(self.exchange_key)
                    logger.debug("CAExchange initialized with XChaCha20Poly1305 for cert exchange.")
                except Exception as e:
                    logger.error(f"Failed to initialize XChaCha20Poly1305: {e}. Falling back to direct key usage (if unencrypted).")
                    # This is a critical failure for secure exchange if XCHACHA was expected.
                    # Depending on policy, might need to raise an error or disable secure_exchange.
                    self.xchacha_cipher = None # Ensure it's None
                    # Potentially: self.secure_exchange = False
            else:
                # This path should ideally not be taken if XChaCha20 is the goal.
                # If HAVE_XCHACHA is False, it means the import failed.
                # The original code might have used ChaCha20Poly1305 directly here.
                # For this upgrade, lack of XChaCha20 is a problem for the intended security level.
                logger.warning("XChaCha20Poly1305 not available. Certificate exchange may be insecure or fail if encryption is required.")
                # self.cipher = ChaCha20Poly1305(self.exchange_key) # Old way

        self.cert_store = {}
    
    def generate_self_signed(self) -> Tuple[bytes, bytes]:
        """
        Generate a self-signed certificate with maximum security parameters
        
        Returns:
            Tuple[bytes, bytes]: (private_key_pem, certificate_pem)
        """
        logger.info("Starting self-signed certificate generation with enhanced security parameters...")
        
        # Generate key based on selected type
        if self.key_type == "ec521":
            # Use ECC P-521 (NIST curve with highest security margin)
            key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())
            logger.debug("EC P-521 private key generated.")
        else:
            # Default to RSA-4096
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            logger.debug("RSA-4096 private key generated.")
            
        # Generate a unique subject name with high entropy
        unique_id = secrets.token_hex(8)
        host_identifier = socket.gethostname().replace('.', '-')
        common_name = f"SecurePeer-{host_identifier}-{unique_id}"
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureP2P"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.now(timezone.utc)
        
        # Generate a strong random serial number (128 bits)
        serial = int.from_bytes(secrets.token_bytes(16), byteorder='big')

        builder = (
            x509.CertificateBuilder()
              .subject_name(subject)
              .issuer_name(issuer)
              .public_key(key.public_key())
              .serial_number(serial)
              .not_valid_before(now - timedelta(minutes=1))
              .not_valid_after(now + timedelta(days=self.validity_days))
              # Strong constraints
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(
                  x509.KeyUsage(
                      digital_signature=True,
                      content_commitment=False,
                      key_encipherment=True,
                      data_encipherment=False,
                      key_agreement=True,
                      key_cert_sign=True,
                      crl_sign=False,
                      encipher_only=False,
                      decipher_only=False
                  ),
                  critical=True
              )
              .add_extension(
                  x509.ExtendedKeyUsage([
                      ExtendedKeyUsageOID.SERVER_AUTH,
                      ExtendedKeyUsageOID.CLIENT_AUTH
                  ]),
                  critical=True
              )
        )
        
        # Add Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        builder = builder.add_extension(ski, critical=False)
        
        # Add Authority Key Identifier (same as SKI for self-signed)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False
        )
        
        # Use SHA-512 for maximum security
        cert = builder.sign(key, hashes.SHA512(), default_backend())
        logger.debug("Certificate signed with SHA-512.")

        # Store private key WITHOUT encryption since keys are ephemeral and in-memory only
        key_pem_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        
        # Calculate certificate fingerprint for verification
        fingerprint = cert.fingerprint(hashes.SHA256())
        self.local_cert_fingerprint = fingerprint.hex()
        
        logger.debug(f"Private key PEM created ({len(key_pem_bytes)} bytes).")
        logger.debug(f"Certificate PEM created ({len(cert_pem_bytes)} bytes).")
        logger.debug(f"Certificate fingerprint: {self.local_cert_fingerprint}")
        logger.info("Self-signed certificate generation complete with enhanced security parameters.")
        
        # Store locally
        self.local_key_pem = key_pem_bytes
        self.local_cert_pem = cert_pem_bytes
        
        return key_pem_bytes, cert_pem_bytes
        
    def _encrypt_data(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt data using XChaCha20-Poly1305 (preferred) or raw for secure exchange"""
        if not self.exchange_key or not self.secure_exchange:
            logger.warning("Exchange key not set or secure_exchange is False. Returning plaintext.")
            return data # Should not happen if secure_exchange is True as intended

        if self.xchacha_cipher:
            try:
                # XChaCha20Poly1305.encrypt handles nonce generation and prepends it
                logger.debug(f"Encrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
                return self.xchacha_cipher.encrypt(data=data, associated_data=associated_data)
            except Exception as e:
                logger.error(f"XChaCha20Poly1305 encryption failed (AAD: {associated_data is not None}): {e}")
                raise ValueError(f"Encryption failed during certificate exchange (AAD: {associated_data is not None}): {e}")
        else:
            # Fallback to ChaCha20Poly1305 if XChaCha20 is not available (less ideal due to nonce management for fixed key)
            # This path indicates a setup issue or failed import of XChaCha20Poly1305.
            # For the purpose of this fix, we are focusing on XChaCha20.
            # A robust implementation would need to decide if this fallback is acceptable
            # or if it should raise an error.
            logger.warning("Attempting fallback to basic ChaCha20Poly1305 for encryption - this is not the target state.")
            try:
                # Manual nonce generation for basic ChaCha20Poly1305
                nonce = secrets.token_bytes(12) # Standard 96-bit nonce
                cipher = ChaCha20Poly1305(self.exchange_key)
                encrypted = cipher.encrypt(nonce, data, associated_data)
                return nonce + encrypted
            except Exception as e:
                logger.error(f"Fallback ChaCha20Poly1305 encryption failed: {e}")
                raise ValueError(f"Fallback encryption failed: {e}")

    def _decrypt_data(self, enc_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using XChaCha20-Poly1305 (preferred) or raw for secure exchange"""
        if not self.exchange_key or not self.secure_exchange:
            logger.warning("Exchange key not set or secure_exchange is False. Assuming plaintext.")
            return enc_data # Should not happen

        if self.xchacha_cipher:
            try:
                # XChaCha20Poly1305.decrypt expects nonce to be prepended to enc_data
                logger.debug(f"Decrypting with XChaCha20Poly1305. AAD: {associated_data is not None}")
                return self.xchacha_cipher.decrypt(data=enc_data, associated_data=associated_data)
            except Exception as e: # Catch specific crypto errors if possible, e.g., InvalidTag
                logger.error(f"XChaCha20Poly1305 decryption failed (AAD: {associated_data is not None}): {e}")
                raise ValueError(f"Decryption failed during certificate exchange (AAD: {associated_data is not None}): {e}")
        else:
            # Fallback to ChaCha20Poly1305 (less ideal)
            logger.warning("Attempting fallback to basic ChaCha20Poly1305 for decryption - this is not the target state.")
            try:
                if len(enc_data) < 12: # Nonce + data
                    raise ValueError("Encrypted data too short for ChaCha20Poly1305 (missing nonce).")
                nonce = enc_data[:12]
                ciphertext = enc_data[12:]
                cipher = ChaCha20Poly1305(self.exchange_key)
                return cipher.decrypt(nonce, ciphertext, associated_data)
            except Exception as e:
                logger.error(f"Fallback ChaCha20Poly1305 decryption failed: {e}")
                raise ValueError(f"Fallback decryption failed: {e}")

    def exchange_certs(self, role: str, host: str, port: int, ready_event: Optional[threading.Event] = None) -> bytes:
        """
        Exchange certificates with peer using enhanced security measures
        
        Args:
            role: Either "server" or "client"
            host: IP address to use (for server binding or client connection)
            port: Base port (exchange port will be base_port + exchange_port_offset)
            ready_event: Optional threading.Event to signal when the server is ready
            
        Returns:
            bytes: Peer's certificate in PEM format
        """
        if not self.local_cert_pem:
            raise ValueError("Local certificate not generated yet. Call generate_self_signed() first.")
            
        exchange_port = port + self.exchange_port_offset
        logger.info(f"Starting certificate exchange as {role} with enhanced security.")
        
        # Create socket with appropriate timeout
        if role == "server":
            # For IPv6 addresses, need to determine socket family to bind to the correct "any" address
            is_ipv6 = ':' in host
            sock_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = socket.socket(sock_family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set socket timeout for security
            s.settimeout(30.0)
            
            # Use a wildcard address for binding, not the client's IP
            bind_addr = '::' if is_ipv6 else '0.0.0.0'
            
            # Format address properly based on socket family
            if sock_family == socket.AF_INET6:
                s.bind((bind_addr, exchange_port, 0, 0))  # Bind to wildcard IPv6
            else:
                s.bind((bind_addr, exchange_port))  # Bind to wildcard IPv4
                
            s.listen(1)
            logger.info(f"Server listening on [{bind_addr}]:{exchange_port} for cert exchange.")
            
            # Signal that the server is ready
            if ready_event:
                ready_event.set()
                
            logger.info("Waiting for client connection for cert exchange...")
            
            try:
                conn, addr = s.accept()
                logger.info(f"Client connected from {addr} for cert exchange.")
                peer_sock = conn
            except socket.timeout:
                logger.error("Timeout waiting for client connection")
                s.close()
                raise TimeoutError("Certificate exchange timed out")
        else:  # client
            logger.info(f"Client connecting to [{host}]:{exchange_port} for cert exchange.")
            # Handle IPv6 addresses
            if ':' in host:
                peer_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set socket timeout for security    
            peer_sock.settimeout(30.0)
                
            try:
                peer_sock.connect((host, exchange_port))
                logger.info("Client connected to server for cert exchange.")
            except (socket.timeout, socket.error) as e:
                logger.error(f"Failed to connect to server: {e}")
                peer_sock.close()
                raise ConnectionError(f"Failed to connect for certificate exchange: {e}")

        peer_cert_pem = None
        try:
            # --- Start of communication block ---
            
            # First send certificate length and fingerprint for validation
            cert_data = self.local_cert_pem
            
            # Only encrypt if secure exchange is enabled
            encrypted_payload = cert_data # Assume plaintext initially
            if self.secure_exchange:
                # Construct AAD from the connection context
                local_ip, local_port = peer_sock.getsockname()[:2]
                peer_ip, peer_port = peer_sock.getpeername()[:2]
                
                if role == 'client':
                    # Client is the initiator
                    aad_string = f"{local_ip}:{local_port}:{peer_ip}:{exchange_port}"
                else: # server
                    # Server is the listener, peer is the initiator
                    aad_string = f"{peer_ip}:{peer_port}:{local_ip}:{exchange_port}"

                current_aad = aad_string.encode('utf-8')
                logger.debug(f"Using AAD for cert encryption: {current_aad.decode('utf-8', errors='ignore')}")
                encrypted_payload = self._encrypt_data(cert_data, associated_data=current_aad)
            
            # Prepare metadata and send
            metadata = f"{len(encrypted_payload):08x}{self.local_cert_fingerprint}".encode()
            peer_sock.sendall(metadata)
            logger.info(f"Sending local certificate ({len(encrypted_payload)} bytes) to peer.")
            peer_sock.sendall(encrypted_payload)
            logger.info("Local certificate sent.")

            # --- Receive peer's certificate ---
            
            # Receive metadata first
            received_metadata = b""
            while len(received_metadata) < 72:
                chunk = peer_sock.recv(72 - len(received_metadata))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving metadata")
                received_metadata += chunk
                
            # Parse metadata
            cert_len = int(received_metadata[:8].decode(), 16)
            peer_fingerprint = received_metadata[8:].decode()
            logger.info(f"Expecting peer certificate of {cert_len} bytes with fingerprint: {peer_fingerprint}")

            # Receive the actual certificate data
            received_data = b""
            peer_sock.settimeout(10.0)
            remaining = min(cert_len, 100000)
            while remaining > 0:
                chunk = peer_sock.recv(min(self.buffer_size, remaining))
                if not chunk:
                    break
                received_data += chunk
                remaining -= len(chunk)

            # --- Process received data (decryption and validation) ---
            
            if len(received_data) == 0:
                 raise ValueError("No certificate data received from peer")

            if self.secure_exchange:
                # Reconstruct AAD for decryption
                local_ip, local_port = peer_sock.getsockname()[:2]
                peer_ip, peer_port = peer_sock.getpeername()[:2]
                
                if role == 'server':
                    # Server is decrypting a message from the client (initiator)
                    aad_string = f"{peer_ip}:{peer_port}:{local_ip}:{exchange_port}"
                else: # client
                    # Client is decrypting a message from the server (listener)
                    aad_string = f"{local_ip}:{local_port}:{peer_ip}:{exchange_port}"
                
                current_aad_for_decryption = aad_string.encode('utf-8')
                logger.debug(f"Using AAD for cert decryption: {current_aad_for_decryption.decode('utf-8', errors='ignore')}")
                decrypted_payload = self._decrypt_data(received_data, associated_data=current_aad_for_decryption)
                
                if not decrypted_payload.startswith(b"-----BEGIN CERTIFICATE-----"):
                    raise ValueError("Decrypted data is not a valid certificate.")
                
                peer_cert_pem = decrypted_payload
                logger.info("Successfully decrypted certificate data")
            else:
                peer_cert_pem = received_data
            
            # Validate certificate format and fingerprint
            x509.load_pem_x509_certificate(peer_cert_pem, default_backend())
            cert = x509.load_pem_x509_certificate(peer_cert_pem, default_backend())
            actual_fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            if actual_fingerprint != peer_fingerprint:
                logger.error(f"Certificate fingerprint mismatch! Expected {peer_fingerprint}, got {actual_fingerprint}")
                raise SecurityError("Certificate fingerprint mismatch")
            
            logger.info(f"Certificate fingerprint verified: {actual_fingerprint}")
            self.peer_cert_pem = peer_cert_pem
            logger.info("Certificate exchange process finished successfully.")

        except Exception as e:
            logger.error(f"Error during certificate exchange: {e}")
            raise
        finally:
            peer_sock.close()
            if role == "server":
                s.close()
            logger.info("Socket closed.")

        return self.peer_cert_pem

    def create_server_ctx(self) -> ssl.SSLContext:
        """
        Create a maximum security SSLContext for the server role
        
        Returns:
            ssl.SSLContext: Configured server SSL context with highest security settings
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")
            
        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")
            
        logger.info("Creating SSLContext for server with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set to TLS 1.3 only for maximum security
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        logger.info("SSLContext initialized with TLS 1.3 only.")
        
        # Apply security options
        ctx.options |= self.SECURE_TLS_OPTIONS
        
        # Set post-quantum groups for key exchange
        try:
            if hasattr(ctx, 'set_groups'):
                group_string = ":".join(HYBRID_PQ_GROUPS)
                ctx.set_groups(group_string)
                logger.info(f"Server KEM groups set to: {group_string}")
        except Exception as e:
            logger.error(f"Failed to set post-quantum key exchange groups for server: {e}")
        
        # Set strong cipher suites
        # try:
        #     ctx.set_ciphers(':'.join(self.SECURE_CIPHER_SUITES))
        #     logger.info(f"Using secure cipher suite: {':'.join(self.SECURE_CIPHER_SUITES)}")
        # except ssl.SSLError as e:
        #     logger.warning(f"Could not set custom ciphers: {e}. Using default secure TLS 1.3 ciphers.")
        
        # Increase DH parameters to 3072-bit
        try:
            if hasattr(ctx, 'set_dh_params'):
                ctx.set_dh_params(3072)
                logger.info("DH parameters set to 3072 bits")
        except Exception as e:
            logger.warning(f"Could not set DH parameters: {e}")
        
        # Configure session security
        ctx.options |= ssl.OP_NO_TICKET  # Disable session tickets for forward secrecy
        
        # Load certificate and key
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
                logger.debug(f"Local cert written to temp file: {tmp_cert_file}")
                logger.debug(f"Local key written to temp file: {tmp_key_file}")
            
            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            # Securely remove temporary files
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                self._secure_delete(tmp_cert_file)
                logger.debug(f"Temporary cert file {tmp_cert_file} securely removed.")
            if tmp_key_file and os.path.exists(tmp_key_file):
                self._secure_delete(tmp_key_file)
                logger.debug(f"Temporary key file {tmp_key_file} securely removed.")

        # Load peer certificate and require client authentication
        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False  # We verify manually via certificate exchange
            logger.info("Trusted peer certificate loaded. Client certificate will be required and verified.")
        except Exception as e:
            logger.error(f"Error loading trusted peer certificate: {e}. Cannot proceed with secure configuration.")
            raise ValueError(f"Failed to load peer certificate: {e}")
        
        # Set strong verification flags
        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            logger.info("Strict X.509 verification enabled")
            
        logger.info("SSLContext for server configured with maximum security settings.")
        return ctx

    def create_client_ctx(self) -> ssl.SSLContext:
        """
        Create a maximum security SSLContext for the client role
        
        Returns:
            ssl.SSLContext: Configured client SSL context with highest security settings
        """
        if not self.local_cert_pem or not self.local_key_pem:
            raise ValueError("Local certificate or key not available")
            
        if not self.peer_cert_pem:
            raise ValueError("Peer certificate not available. Exchange certificates first.")
            
        logger.info("Creating SSLContext for client with maximum security settings.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Set to TLS 1.3 only for maximum security
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        logger.info("SSLContext initialized with TLS 1.3 only.")
        
        # Apply security options
        ctx.options |= self.SECURE_TLS_OPTIONS
        
        # Set post-quantum groups for key exchange
        try:
            if hasattr(ctx, 'set_groups'):
                group_string = ":".join(HYBRID_PQ_GROUPS)
                ctx.set_groups(group_string)
                logger.info(f"Client KEM groups set to: {group_string}")
        except Exception as e:
            logger.error(f"Failed to set post-quantum key exchange groups for client: {e}")
        
        # Set strong cipher suites
        # try:
        #     ctx.set_ciphers(':'.join(self.SECURE_CIPHER_SUITES))
        #     logger.info(f"Using secure cipher suite: {':'.join(self.SECURE_CIPHER_SUITES)}")
        # except ssl.SSLError as e:
        #     logger.warning(f"Could not set custom ciphers: {e}. Using default secure TLS 1.3 ciphers.")
        
        # Disable session tickets for forward secrecy
        ctx.options |= ssl.OP_NO_TICKET
        
        # We don't use hostname verification since we verify certificates manually
        ctx.check_hostname = False

        # Load certificate and key
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
                logger.debug(f"Local cert written to temp file: {tmp_cert_file}")
                logger.debug(f"Local key written to temp file: {tmp_key_file}")

            ctx.load_cert_chain(tmp_cert_file, tmp_key_file)
            logger.info("Local certificate and key loaded into SSLContext.")
        finally:
            # Securely remove temporary files
            if tmp_cert_file and os.path.exists(tmp_cert_file):
                self._secure_delete(tmp_cert_file)
                logger.debug(f"Temporary cert file {tmp_cert_file} securely removed.")
            if tmp_key_file and os.path.exists(tmp_key_file):
                self._secure_delete(tmp_key_file)
                logger.debug(f"Temporary key file {tmp_key_file} securely removed.")
                
        # Load peer certificate
        try:
            ctx.load_verify_locations(cadata=self.peer_cert_pem.decode('utf-8'))
            ctx.verify_mode = ssl.CERT_REQUIRED
            logger.info("Trusted peer certificate loaded. Server certificate will be required and verified.")
        except Exception as e:
            logger.error(f"Error loading trusted peer certificate: {e}. Cannot proceed with secure configuration.")
            raise ValueError(f"Failed to load peer certificate: {e}")

        # Set strong verification flags
        if hasattr(ctx, 'verify_flags'):
            ctx.verify_flags = ssl.VERIFY_X509_STRICT
            logger.info("Strict X.509 verification enabled")

        logger.info("SSLContext for client configured with maximum security settings.")
        return ctx
    
    def _secure_delete(self, file_path: str, passes: int = 3):
        """Securely delete a file by overwriting it multiple times"""
        if not os.path.exists(file_path):
            return
            
        file_size = os.path.getsize(file_path)
        
        # Overwrite file with random data multiple times
        for i in range(passes):
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
                
        # Final pass with zeros
        with open(file_path, 'wb') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
            
        # Finally delete the file
        os.remove(file_path)
        
    def secure_cleanup(self):
        """Clean up sensitive data"""
        # Clear key material
        if hasattr(self, 'exchange_key') and self.exchange_key:
            self.exchange_key = b'\x00' * len(self.exchange_key)
            self.exchange_key = None
            
        logger.info("Secure cleanup completed")
    
    def wrap_socket_server(self, sock: socket.socket) -> ssl.SSLSocket:
        """
        Wrap a server socket with TLS using the generated context with maximum security
        
        Args:
            sock: Socket to wrap
            
        Returns:
            ssl.SSLSocket: TLS-wrapped socket
        """
        ctx = self.create_server_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        logger.info("Server socket wrapped with maximum security TLS context")
        return ssl_sock
    
    def wrap_socket_client(self, sock: socket.socket, server_hostname: Optional[str] = None) -> ssl.SSLSocket:
        """
        Wrap a client socket with TLS using the generated context with maximum security
        
        Args:
            sock: Socket to wrap
            server_hostname: Optional server hostname for SNI (ignored as we use secure certificate exchange)
            
        Returns:
            ssl.SSLSocket: TLS-wrapped socket
        """
        ctx = self.create_client_ctx()
        ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname, do_handshake_on_connect=False)
        logger.info("Client socket wrapped with maximum security TLS context")
        return ssl_sock
        
    def __del__(self):
        """Ensure cleanup when object is destroyed"""
        try:
            self.secure_cleanup()
        except:
            pass


def setup_logger(level=logging.INFO):
    """Set up the logger for the CAExchange module"""
    logger.setLevel(level)
    
    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    
    # Add handler to logger if not already added
    if not logger.handlers:
        logger.addHandler(ch)
    
    return logger

# Initialize logger with default settings
setup_logger() 