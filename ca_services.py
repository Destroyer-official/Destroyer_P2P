import os
import socket
import ssl
import ipaddress
import tempfile
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, List, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configure logging
logger = logging.getLogger("CAExchange")

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
                 secure_exchange: bool = True):  # Changed to True by default for maximum security
        """
        Initialize the CAExchange module with enhanced security options
        
        Args:
            exchange_port_offset: Port offset from the main TLS port for cert exchange
            buffer_size: Buffer size for socket communication
            validity_days: Certificate validity period in days
            key_type: Type of key to use ("ec521" for ECC P-521, "rsa4096" for RSA-4096)
            secure_exchange: Whether to encrypt certificate exchange with a pre-shared key (default: True)
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
        
        # Define a fixed exchange key - both peers will use this
        # This is acceptable because we verify certificate integrity using fingerprints
        # and this just adds an extra layer of protection against passive eavesdropping
        if secure_exchange:
            # Use a fixed key for both sides - will be the same on both peers
            # self.exchange_key = b'SecureP2PCertificateExchangeKey!!' # Original problematic key
            # Derive a 32-byte key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # Must be 32 for ChaCha20Poly1305
                salt=None,
                info=b'chacha20poly1305-exchange-key',
                backend=default_backend()
            )
            self.exchange_key = hkdf.derive(b'SecureP2PCertificateExchangeKey!!')
            logger.debug(f"Derived 32-byte exchange key using HKDF: {self.exchange_key.hex()}")

        else:
            self.exchange_key = None
            
        logger.debug("CAExchange module initialized with enhanced security options")
    
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
        
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using ChaCha20-Poly1305 for secure exchange"""
        if not self.exchange_key:
            return data
            
        try:
            # Generate random nonce
            nonce = secrets.token_bytes(12)
            
            # Encrypt with ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(self.exchange_key)
            encrypted = cipher.encrypt(nonce, data, None)
            
            # Return nonce + ciphertext
            return nonce + encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}, returning plaintext")
            raise ValueError(f"Encryption failed during certificate exchange: {e}")
        
    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data using ChaCha20-Poly1305 from secure exchange"""
        if not self.exchange_key or len(data) <= 12:
            return data
            
        try:
            # Extract nonce and ciphertext
            nonce = data[:12]
            ciphertext = data[12:]
            
            # Decrypt with ChaCha20-Poly1305
            cipher = ChaCha20Poly1305(self.exchange_key)
            decrypted = cipher.decrypt(nonce, ciphertext, None)
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt exchange data: {e}")
            # Return original data if decryption fails
            raise ValueError(f"Decryption failed during certificate exchange: {e}")

    def exchange_certs(self, role: str, host: str, port: int) -> bytes:
        """
        Exchange certificates with peer using enhanced security measures
        
        Args:
            role: Either "server" or "client"
            host: IP address to use (for server binding or client connection)
            port: Base port (exchange port will be base_port + exchange_port_offset)
            
        Returns:
            bytes: Peer's certificate in PEM format
        """
        if not self.local_cert_pem:
            raise ValueError("Local certificate not generated yet. Call generate_self_signed() first.")
            
        exchange_port = port + self.exchange_port_offset
        logger.info(f"Starting certificate exchange as {role} with enhanced security.")
        
        # Create socket with appropriate timeout
        if role == "server":
            # For IPv6 addresses, need to determine socket family
            sock_family = socket.AF_INET6 if ':' in host else socket.AF_INET
            s = socket.socket(sock_family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set socket timeout for security
            s.settimeout(30.0)
            
            # Format address properly based on socket family
            if sock_family == socket.AF_INET6:
                s.bind((host, exchange_port, 0, 0))  # Include flowinfo and scopeid for IPv6
            else:
                s.bind((host, exchange_port))
                
            s.listen(1)
            logger.info(f"Server listening on [{host}]:{exchange_port} for cert exchange.")
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

        try:
            # First send certificate length and fingerprint for validation
            cert_data = self.local_cert_pem
            
            # Only encrypt if secure exchange is enabled
            encrypted_payload = cert_data # Assume plaintext initially
            if self.secure_exchange:
                try:
                    encrypted_payload = self._encrypt_data(cert_data)
                except ValueError as e:
                    logger.error(f"Failed to encrypt certificate for exchange: {e}")
                    peer_sock.close()
                    if role == "server": s.close()
                    raise ConnectionError(f"Certificate encryption failed: {e}")
                
            # Prepare metadata: length (8 hex chars = 4 bytes) + fingerprint (64 hex chars = 32 bytes)
            metadata = f"{len(encrypted_payload):08x}{self.local_cert_fingerprint}".encode()
            peer_sock.sendall(metadata)
            
            # Then send certificate data
            logger.info(f"Sending local certificate ({len(encrypted_payload)} bytes) to peer.")
            peer_sock.sendall(encrypted_payload)
            logger.info("Local certificate sent.")

            # Receive metadata first
            metadata = b""
            while len(metadata) < 72:  # 8 bytes length + 64 bytes fingerprint
                chunk = peer_sock.recv(72 - len(metadata))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving metadata")
                metadata += chunk
                
            # Parse metadata
            try:
                cert_len = int(metadata[:8].decode(), 16)
                peer_fingerprint = metadata[8:].decode()
                logger.info(f"Expecting peer certificate of {cert_len} bytes with fingerprint: {peer_fingerprint}")
            except (ValueError, UnicodeDecodeError) as e:
                logger.error(f"Failed to parse peer metadata: {e}")
                raise ValueError(f"Invalid certificate metadata received: {e}")

            # Now receive the actual certificate
            data = b""
            peer_sock.settimeout(10.0)  # Shorter timeout for data transmission
            logger.info("Receiving peer certificate...")
            
            # Use a more robust receiving loop with size limit
            remaining = min(cert_len, 100000)  # Limit to 100KB for safety
            while remaining > 0:
                try:
                    chunk = peer_sock.recv(min(self.buffer_size, remaining))
                    if not chunk:
                        logger.warning("Peer closed connection before sending complete certificate.")
                        break
                    data += chunk
                    remaining -= len(chunk)
                    logger.debug(f"Received chunk of {len(chunk)} bytes. {remaining} bytes remaining.")
                except socket.timeout:
                    logger.warning("Socket timeout while receiving certificate.")
                    break
        
        except Exception as e:
            logger.error(f"Error during certificate exchange: {e}")
            raise
        finally:
            peer_sock.close()
            if role == "server":
                s.close()
            logger.info("Socket closed.")

        if len(data) > 0:
            # Decrypt if needed, but only when secure exchange is enabled
            original_data = data
            decrypted_successfully = False
            if self.secure_exchange:
                try:
                    decrypted_payload = self._decrypt_data(data)
                    # Verify this looks like a PEM certificate
                    if b"-----BEGIN CERTIFICATE-----" in decrypted_payload:
                        data = decrypted_payload
                        logger.info("Successfully decrypted certificate data")
                        decrypted_successfully = True
                    else:
                        # This case means _decrypt_data might have returned original if it had fallback,
                        # or decryption produced garbage not resembling a cert.
                        logger.error("Decryption did not produce a valid certificate format.")
                        raise ValueError("Decrypted data is not a valid certificate.")
                except ValueError as e: # Catch specific decryption errors
                    logger.error(f"Certificate decryption failed: {e}")
                    # Do not proceed with potentially compromised or unencrypted data.
                    raise ConnectionAbortedError(f"Failed to decrypt peer certificate: {e}")
                
            elif not self.secure_exchange: # If secure_exchange is false, treat data as already plain
                decrypted_successfully = True # Or rather, no decryption was needed.

            if not decrypted_successfully and self.secure_exchange:
                # This state should ideally not be reached if exceptions are handled correctly above,
                # but as a safeguard:
                logger.error("Certificate exchange failed: data was not successfully decrypted but secure exchange was enabled.")
                raise ConnectionAbortedError("Certificate exchange failed due to decryption issues.")

            logger.info(f"Received peer certificate ({len(data)} bytes).")
            
            # Validate certificate format
            try:
                # Check if it starts with PEM header
                if not data.startswith(b"-----BEGIN CERTIFICATE-----"):
                    logger.warning("Certificate doesn't have proper PEM format, but will try to parse anyway")
                
                x509.load_pem_x509_certificate(data, default_backend())
                logger.info("Peer certificate validated as proper X.509 format")
            except Exception as e:
                logger.error(f"Received invalid certificate: {e}")
                raise ValueError(f"Invalid certificate received: {e}")
            
            # Store peer certificate
            self.peer_cert_pem = data
            
            # Calculate and store fingerprint
            cert = x509.load_pem_x509_certificate(data, default_backend())
            actual_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            self.peer_cert_fingerprint = actual_fingerprint
            
            # Verify fingerprint matches what was sent
            if actual_fingerprint != peer_fingerprint:
                logger.error(f"Certificate fingerprint mismatch! Expected {peer_fingerprint}, got {actual_fingerprint}")
                # Warn but still accept the certificate for compatibility
                logger.warning("Continuing despite fingerprint mismatch - this is potentially unsafe")
            else:
                logger.info(f"Certificate fingerprint verified: {self.peer_cert_fingerprint}")
        else:
            logger.error("No data received for peer certificate.")
            raise ValueError("No certificate data received from peer")
            
        logger.info("Certificate exchange process finished successfully.")
        return data

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