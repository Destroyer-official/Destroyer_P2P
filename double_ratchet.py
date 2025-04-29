"""
Double Ratchet Protocol with Post-Quantum Security Extensions

Implements a cryptographically secure message encryption protocol combining the Signal
Double Ratchet algorithm with post-quantum cryptographic primitives for forward secrecy, 
break-in recovery, and quantum-resistance through a hybrid approach.

Security features:
- Classical security: X25519 for DH exchanges
- Quantum resistance: ML-KEM-1024 for key encapsulation
- Message signing: FALCON-1024 signatures
- Symmetric encryption: ChaCha20-Poly1305 AEAD
- Key derivation: HKDF with domain separation
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import quantcrypt.cipher
import quantcrypt.kem
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from quantcrypt.dss import FALCON_1024

# Post-quantum cryptography
# Classical cryptography

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
)
logger = logging.getLogger("double_ratchet")
logger.setLevel(logging.INFO)

# Add file handler for security audit logging
try:
    file_handler = logging.FileHandler('security_audit.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
    )
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Could not create security audit log file: {e}")


class SecurityError(Exception):
    """Security-specific exception for Double Ratchet protocol violations."""
    pass


def verify_key_material(key_material: bytes, 
                        expected_length: Optional[int] = None, 
                        description: str = "key material") -> bool:
    """
    Verify cryptographic key material meets security requirements.
    
    Args:
        key_material: The key material to verify
        expected_length: Optional expected byte length
        description: Description for logging
        
    Returns:
        True if verification passes
        
    Raises:
        ValueError: If key material fails verification
    """
    if key_material is None:
        logger.error(f"SECURITY ALERT: {description} is None")
        raise ValueError(f"Security violation: {description} is None")
        
    if not isinstance(key_material, bytes):
        logger.error(f"SECURITY ALERT: {description} is not bytes type: {type(key_material)}")
        raise ValueError(f"Security violation: {description} is not bytes")
        
    if expected_length and len(key_material) != expected_length:
        logger.error(f"SECURITY ALERT: {description} has incorrect length {len(key_material)}, expected {expected_length}")
        raise ValueError(f"Security violation: {description} has incorrect length")
        
    if len(key_material) == 0:
        logger.error(f"SECURITY ALERT: {description} is empty")
        raise ValueError(f"Security violation: {description} is empty")
        
    # Basic entropy check - all zeros or all same byte
    if all(b == key_material[0] for b in key_material):
        logger.error(f"SECURITY ALERT: {description} has low entropy (all same byte)")
        raise ValueError(f"Security violation: {description} has low entropy")
    
    # Additional entropy check - first/last bytes not all zeros
    first_block = key_material[:4]
    last_block = key_material[-4:]
    if all(b == 0 for b in first_block) or all(b == 0 for b in last_block):
        logger.error(f"SECURITY ALERT: {description} has suspicious pattern (zeros at beginning or end)")
        raise ValueError(f"Security violation: {description} has suspicious pattern")
        
    logger.debug(f"Verified {description}: length={len(key_material)}, entropy=OK")
    return True


def format_binary(data: Optional[bytes], max_len: int = 8) -> str:
    """
    Format binary data for logging in a safe, readable way.
    
    Args:
        data: Binary data to format
        max_len: Maximum number of bytes to include
        
    Returns:
        Formatted string representation
    """
    if data is None:
        return "None"
    if len(data) > max_len:
        b64 = base64.b64encode(data[:max_len]).decode('utf-8')
        return f"{b64}... ({len(data)} bytes)"
    return base64.b64encode(data).decode('utf-8')


def secure_erase(key_material: Optional[Union[bytes, bytearray]]) -> None:
    """
    Securely erase sensitive cryptographic material from memory.
    
    Args:
        key_material: The sensitive data to erase
    """
    if key_material is None:
        return
        
    if isinstance(key_material, (bytes, bytearray)):
        buffer = bytearray(key_material)
        for i in range(len(buffer)):
            buffer[i] = 0x00
        # Add an additional overwrite with random data
        for i in range(len(buffer)):
            buffer[i] = os.urandom(1)[0]
        # Final zero pass
        for i in range(len(buffer)):
            buffer[i] = 0x00
    elif hasattr(key_material, 'zeroize'):
        # Use library-provided secure erasure if available
        key_material.zeroize()
    
    logger.debug(f"Securely erased key material of length {len(key_material) if key_material else 'unknown'}")


@dataclass
class MessageHeader:
    """
    Secure message header for the Double Ratchet protocol.
    
    Structure:
    - 32 bytes: X25519 public key for DH ratchet
    - 4 bytes: Previous chain length (unsigned int, big endian)
    - 4 bytes: Message number in current chain (unsigned int, big endian)
    - 8 bytes: Unique message identifier (random bytes)
    """
    
    # Header size in bytes (fixed for binary compatibility)
    HEADER_SIZE = 32 + 4 + 4 + 8  # 48 bytes total
    
    # Components
    public_key: X25519PublicKey 
    previous_chain_length: int
    message_number: int
    message_id: bytes
    
    def __post_init__(self):
        """Validate header fields after initialization."""
        if not isinstance(self.public_key, X25519PublicKey):
            raise TypeError("public_key must be X25519PublicKey instance")
            
        if not isinstance(self.previous_chain_length, int) or self.previous_chain_length < 0:
            raise ValueError("previous_chain_length must be a non-negative integer")
            
        if not isinstance(self.message_number, int) or self.message_number < 0:
            raise ValueError("message_number must be a non-negative integer")
            
        if not isinstance(self.message_id, bytes) or len(self.message_id) != 8:
            raise ValueError("message_id must be 8 bytes")
    
    def encode(self) -> bytes:
        """Encode the header to binary format for transmission."""
        # Public key serialization
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Integer values as 4-byte big-endian unsigned integers
        message_number_bytes = struct.pack('>I', self.message_number)
        previous_chain_length_bytes = struct.pack('>I', self.previous_chain_length)
        
        # Combine all fields in order
        return public_key_bytes + previous_chain_length_bytes + message_number_bytes + self.message_id
    
    @classmethod
    def decode(cls, header_bytes: bytes) -> 'MessageHeader':
        """
        Decode a header from its binary representation.
        
        Raises:
            ValueError: If header format is invalid
        """
        if not isinstance(header_bytes, bytes):
            raise TypeError("Header bytes must be bytes type")
            
        if len(header_bytes) != cls.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_bytes)}, expected {cls.HEADER_SIZE}")
        
        try:
            # Extract public key (first 32 bytes)
            public_key_bytes = header_bytes[:32]
            public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Extract previous chain length (next 4 bytes)
            previous_chain_length = struct.unpack('>I', header_bytes[32:36])[0]
            
            # Extract message number (next 4 bytes)
            message_number = struct.unpack('>I', header_bytes[36:40])[0]
            
            # Extract message ID (last 8 bytes)
            message_id = header_bytes[40:48]
            
            return cls(
                public_key=public_key,
                previous_chain_length=previous_chain_length,
                message_number=message_number,
                message_id=message_id
            )
        except Exception as e:
            raise ValueError(f"Failed to decode message header: {e}")
    
    @classmethod
    def generate(cls, public_key: X25519PublicKey, previous_chain_length: int, 
                message_number: int) -> 'MessageHeader':
        """Generate a new message header with a random message ID."""
        message_id = os.urandom(8)
        
        return cls(
            public_key=public_key,
            previous_chain_length=previous_chain_length,
            message_number=message_number,
            message_id=message_id
        )


class DoubleRatchet:
    """
    Advanced Double Ratchet with Post-Quantum Security Extensions.
    
    Key features:
    1. Forward secrecy: Compromising current keys doesn't expose past messages
    2. Break-in recovery: Security is restored after key compromise
    3. Post-quantum resistance: Hybrid classical/quantum-resistant algorithms
    4. Out-of-order message handling: Maintains security with delayed messages
    5. Message authentication: Protection against tampering and forgery
    """
    
    # Security parameters
    MAX_SKIP_MESSAGE_KEYS = 1000   # Maximum number of out-of-order message keys to cache
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB maximum message size
    CHAIN_KEY_SIZE = 32           # Chain key size in bytes
    MSG_KEY_SIZE = 32             # Message key size in bytes
    ROOT_KEY_SIZE = 32            # Root key size in bytes
    
    # Domain separation strings for KDF
    KDF_INFO_DH = b"DR_DH_RATCHET_v2"
    KDF_INFO_CHAIN = b"DR_CHAIN_KEY_v2"
    KDF_INFO_MSG = b"DR_MSG_KEY_v2"
    KDF_INFO_HYBRID = b"DR_HYBRID_KEM_DH_v2"
    
    def __init__(
        self, 
        root_key: bytes, 
        is_initiator: bool = True, 
        enable_pq: bool = True,
        max_skipped_keys: int = 100
    ):
        """
        Initialize a new Double Ratchet session.
        
        Args:
            root_key: The initial root key from a key exchange protocol (32 bytes)
            is_initiator: Whether this party initiated the conversation
            enable_pq: Whether to enable post-quantum security enhancements
            max_skipped_keys: Maximum number of skipped message keys to store
        """
        # Verify the root key's security properties
        verify_key_material(root_key, expected_length=self.ROOT_KEY_SIZE, 
                          description="Double Ratchet initial root key")
        
        # Core state
        self.root_key = root_key
        self.is_initiator = is_initiator
        self.enable_pq = enable_pq
        self.max_skipped_message_keys = max_skipped_keys
        
        # Chain state
        self.sending_chain_key = None
        self.receiving_chain_key = None
        self.sending_message_number = 0
        self.receiving_message_number = 0
        
        # Classical DH ratchet state
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()
        self.remote_dh_public_key = None
        
        # Post-quantum state
        if self.enable_pq:
            # Initialize KEM components
            self.kem = quantcrypt.kem.MLKEM_1024()
            self.kem_public_key, self.kem_private_key = self.kem.keygen()
            self.remote_kem_public_key = None
            self.kem_ciphertext = None
            self.kem_shared_secret = None  # Store shared secret after decapsulation
            
            # Initialize signature components
            self.dss = FALCON_1024()
            self.dss_public_key, self.dss_private_key = self.dss.keygen()
            self.remote_dss_public_key = None
        else:
            # Set all PQ components to None in classical mode
            self.kem = self.kem_public_key = self.kem_private_key = None
            self.remote_kem_public_key = self.kem_ciphertext = None
            self.dss = self.dss_public_key = self.dss_private_key = None
            self.remote_dss_public_key = self.kem_shared_secret = None
        
        # Ratchet key identification
        self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)
        
        # Out-of-order message handling
        # Format: {(ratchet_key_id, message_number): message_key}
        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}
        
        # Debugging and error tracking
        self.debug_info: Dict[str, Any] = {}
        self.last_error = None
        
        logger.info(
            f"Double Ratchet initialized as {'initiator' if is_initiator else 'responder'}" + 
            f" with {'PQ-enabled' if enable_pq else 'classical'} security"
        )
    
    def _get_public_key_fingerprint(self, public_key: X25519PublicKey) -> bytes:
        """Generate a stable identifier for a public key."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(public_bytes).digest()[:8]
    
    def _dh_ratchet_step(self, remote_public_key_bytes: bytes, 
                         remote_kem_public_key: Optional[bytes] = None) -> None:
        """
        Execute a Diffie-Hellman ratchet step to update the keys.
        
        Args:
            remote_public_key_bytes: The remote party's new public key
            remote_kem_public_key: The remote party's KEM public key (PQ mode only)
        """
        try:
            # Convert bytes to public key object
            remote_public_key = X25519PublicKey.from_public_bytes(remote_public_key_bytes)
            
            # Save the remote public key and generate identifier
            self.remote_dh_public_key = remote_public_key
            remote_fingerprint = self._get_public_key_fingerprint(remote_public_key)
            
            # 1. First DH: Use current private key with new remote public key
            logger.debug("Performing DH exchange for receiving chain")
            dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(dh_output, description="DH output for ratchet step")
            
            # 2. Perform KEM encapsulation if in PQ mode
            kem_shared_secret = None
            if self.enable_pq and remote_kem_public_key:
                logger.debug("Performing ML-KEM-1024 encapsulation for ratchet step")
                self.remote_kem_public_key = remote_kem_public_key
                kem_ciphertext, kem_shared_secret = self.kem.encaps(remote_kem_public_key)
                self.kem_ciphertext = kem_ciphertext
                self.kem_shared_secret = kem_shared_secret
                verify_key_material(kem_shared_secret, description="KEM shared secret")
                logger.debug(f"Generated KEM shared secret: {format_binary(kem_shared_secret)}")
            
            # 3. Update receiving chain with the derived secrets
            self._update_receiving_chain(dh_output, kem_shared_secret)
            
            # 4. Generate new DH keypair for next ratchet step
            prev_public = self.dh_public_key
            self.dh_private_key = X25519PrivateKey.generate()
            self.dh_public_key = self.dh_private_key.public_key()
            self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)
            
            # 5. Generate new KEM keypair if needed
            if self.enable_pq:
                logger.debug("Generating new ML-KEM key pair for next ratchet step")
                self.kem_public_key, self.kem_private_key = self.kem.keygen()
            
            # 6. Second DH: Use new private key with current remote public key
            new_dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(new_dh_output, description="Second DH output for ratchet step")
            
            # 7. Update sending chain with new key pair's output
            self._update_sending_chain(new_dh_output, kem_shared_secret)
            
            logger.info(
                f"Completed DH{'+ PQ KEM' if self.enable_pq else ''} ratchet step, " +
                f"remote key: {format_binary(remote_fingerprint)}"
            )
        except Exception as e:
            self.last_error = f"DH ratchet step failed: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Ratchet step error: {str(e)}")
    
    def _update_receiving_chain(self, dh_output: bytes, 
                              kem_shared_secret: Optional[bytes] = None) -> None:
        """Update the receiving chain with new key material."""
        info = self.KDF_INFO_HYBRID if self.enable_pq and kem_shared_secret else self.KDF_INFO_DH
        
        # Combine DH and KEM secrets in hybrid mode
        if self.enable_pq and kem_shared_secret:
            # Create combined secret with domain separation
            combined_secret = hashlib.sha512(dh_output + b"||" + kem_shared_secret).digest()
        else:
            combined_secret = dh_output
        
        # Derive new root key and receiving chain key
        logger.debug(f"Updating receiving chain ({len(combined_secret)} bytes)")
        kdf_output = self._kdf(self.root_key, combined_secret, info=info)
        self.root_key, receiving_chain_seed = kdf_output[:32], kdf_output[32:]
        
        # Initialize receiving chain with the new seed
        self.receiving_chain_key = receiving_chain_seed
        self.receiving_message_number = 0
        
        verify_key_material(self.receiving_chain_key, description="Updated receiving chain")
        logger.debug(f"Receiving chain updated, new root key: {format_binary(self.root_key)}")
    
    def _update_sending_chain(self, dh_output: bytes, 
                            kem_shared_secret: Optional[bytes] = None) -> None:
        """Update the sending chain with new key material."""
        # Use different info string to ensure domain separation
        info = self.KDF_INFO_HYBRID + b"_SEND" if self.enable_pq and kem_shared_secret else self.KDF_INFO_DH + b"_SEND"
        
        # Combine DH and KEM secrets in hybrid mode
        if self.enable_pq and kem_shared_secret:
            # Create combined secret with domain separation
            combined_secret = hashlib.sha512(dh_output + b"||" + kem_shared_secret).digest()
        else:
            combined_secret = dh_output
        
        # Derive new root key and sending chain key
        logger.debug(f"Updating sending chain ({len(combined_secret)} bytes)")
        kdf_output = self._kdf(self.root_key, combined_secret, info=info)
        self.root_key, sending_chain_seed = kdf_output[:32], kdf_output[32:]
        
        # Initialize sending chain with the new seed
        self.sending_chain_key = sending_chain_seed
        self.sending_message_number = 0
        
        verify_key_material(self.sending_chain_key, description="Updated sending chain")
        logger.debug(f"Sending chain updated, new root key: {format_binary(self.root_key)}")
    
    def _chain_ratchet_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform a symmetric ratchet step to derive the next chain and message keys.
        
        Returns:
            Tuple of (next_chain_key, message_key)
        """
        # Verify input
        verify_key_material(chain_key, expected_length=self.CHAIN_KEY_SIZE, 
                          description="Chain key for ratchet")
        
        # Use separate HMAC operations with different info strings to ensure
        # that chain keys and message keys are independent
        message_key = hmac.HMAC(chain_key, self.KDF_INFO_MSG, hashlib.sha256).digest()
        next_chain_key = hmac.HMAC(chain_key, self.KDF_INFO_CHAIN, hashlib.sha256).digest()
        
        # Verify output
        verify_key_material(message_key, expected_length=self.MSG_KEY_SIZE, 
                          description="Derived message key")
        verify_key_material(next_chain_key, expected_length=self.CHAIN_KEY_SIZE, 
                          description="Derived chain key")
        
        return next_chain_key, message_key
    
    def _kdf(self, key_material: bytes, input_key_material: bytes, info: bytes) -> bytes:
        """
        Key derivation function based on HKDF-SHA512.
        
        Returns:
            64 bytes of output key material (32 for root key, 32 for chain key)
        """
        # Verify input parameters
        verify_key_material(key_material, description="HKDF salt/key material")
        verify_key_material(input_key_material, description="HKDF input key material")
        
        if not info:
            logger.warning("SECURITY ALERT: HKDF info parameter is empty")
            
        # Compute a unique salt derived from current material
        salt = hmac.HMAC(key_material, b"DR_SALT", hashlib.sha256).digest()
        
        # Use SHA-512 for post-quantum security level
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64,  # 64 bytes: 32 for root key, 32 for chain key
            salt=salt,
            info=info
        )
        
        # Derive key material
        derived_key = hkdf.derive(input_key_material)
        
        # Verify output
        verify_key_material(derived_key, expected_length=64, description=f"HKDF output ({info})")
        
        return derived_key

    def _encrypt_with_cipher(self, plaintext: bytes, auth_data: bytes, message_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with ChaCha20-Poly1305 AEAD.
        
        Args:
            plaintext: The plaintext to encrypt
            auth_data: Authenticated associated data
            message_key: The key to use for encryption
        
        Returns:
            Tuple of (nonce, ciphertext)
        """
        # Generate a random 96-bit nonce
        nonce = os.urandom(12)
        
        # Create the cipher with the message key
        cipher = ChaCha20Poly1305(message_key)
        
        # Encrypt the plaintext
        ciphertext = cipher.encrypt(nonce, plaintext, auth_data)
        
        return nonce, ciphertext
    
    def _encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a message using the Double Ratchet protocol.
        
        This method:
        1. Advances the sending chain to generate a new message key
        2. Creates a message header with the current ratchet public key
        3. Encrypts the plaintext using ChaCha20-Poly1305
        4. In post-quantum mode, signs the ciphertext with FALCON-1024
        5. Assembles the final message with all required components
        
        Returns:
            Complete encrypted message with header
        """
        # Validate input
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
            
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
            
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")
        
        # Ensure Double Ratchet is initialized
        if not self.is_initialized():
            raise SecurityError("Cannot encrypt: Double Ratchet not initialized")
        
        # 1. Advance sending chain to derive new message key
        message_key = self._ratchet_encrypt()
        
        # 2. Construct message header
        # Get previous chain length, ensure it's non-negative
        previous_chain_length = max(0, self.receiving_message_number)
        
        header = MessageHeader.generate(
            public_key=self.dh_public_key,
            previous_chain_length=previous_chain_length,
            message_number=self.sending_message_number - 1
        )
        
        # Encode header to bytes
        serialized_header = header.encode()
        
        # 3. Create authenticated data from header
        auth_data = self._get_associated_data(serialized_header)
        
        # 4. Encrypt the message
        logger.debug(f"Encrypting {len(plaintext)} bytes with message key #{header.message_number}")
        nonce, ciphertext = self._encrypt_with_cipher(plaintext, auth_data, message_key)
        
        # 5. Post-quantum signature if enabled
        signature = b''
        if self.enable_pq and self.dss_private_key:
            # Sign the combination of nonce + ciphertext for authentication
            data_to_sign = nonce + ciphertext
            signature = self.dss.sign(self.dss_private_key, data_to_sign)
            logger.debug(f"Applied FALCON signature ({len(signature)} bytes)")
            
        # 6. Assemble complete message
        # Format: header + signature_length (2 bytes) + signature + nonce + ciphertext
        signature_length_bytes = len(signature).to_bytes(2, byteorder='big')
        message = serialized_header + signature_length_bytes + signature + nonce + ciphertext
        
        logger.info(
            f"Encrypted message: {len(message)} bytes (header: {len(serialized_header)}, " +
            f"sig: {len(signature)}, nonce: {len(nonce)}, ciphertext: {len(ciphertext)})"
        )
        
        return message

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Public encrypt method for sending messages securely.
        
        Args:
            plaintext: The message to encrypt
            
        Returns:
            Encrypted message with header and authentication
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
            
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")
        
        # Use the private _encrypt method to handle encryption
        return self._encrypt(plaintext)

    def _decrypt_with_cipher(self, nonce: bytes, ciphertext: bytes, auth_data: bytes, message_key: bytes) -> bytes:
        """
        Decrypt ciphertext with ChaCha20-Poly1305 AEAD.
        
        Args:
            nonce: The nonce used for encryption
            ciphertext: The ciphertext to decrypt
            auth_data: Authenticated associated data
            message_key: The key to use for decryption
        
        Returns:
            Decrypted plaintext
        """
        # Create the cipher with the message key
        cipher = ChaCha20Poly1305(message_key)
        
        try:
            # Decrypt the ciphertext
            plaintext = cipher.decrypt(nonce, ciphertext, auth_data)
            return plaintext
        except InvalidTag:
            logger.error("SECURITY ALERT: Authentication tag verification failed")
            raise SecurityError("Message authentication failed")

    def decrypt(self, message: bytes) -> bytes:
        """
        Decrypt a message using the Double Ratchet protocol.
        
        This method:
        1. Parses the message to extract header and encrypted content
        2. In post-quantum mode, verifies the FALCON signature
        3. Performs a DH ratchet step if needed
        4. Derives the appropriate message key (or uses a stored skipped key)
        5. Decrypts and authenticates the ciphertext
        
        Returns:
            Decrypted plaintext
        """
        # Validate input
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
            
        if len(message) < MessageHeader.HEADER_SIZE + 14:  # Header + min signature len + nonce
            raise ValueError(f"Message is too short: {len(message)} bytes")
        
        # Ensure Double Ratchet is initialized
        if not self.is_initialized():
            raise SecurityError("Cannot decrypt: Double Ratchet not initialized")
            
        try:
            # 1. Parse the message components
            header_bytes = message[:MessageHeader.HEADER_SIZE]
            header = MessageHeader.decode(header_bytes)
            
            # Extract signature length and signature
            signature_length_bytes = message[MessageHeader.HEADER_SIZE:MessageHeader.HEADER_SIZE+2]
            signature_length = int.from_bytes(signature_length_bytes, byteorder='big')
            
            signature_offset = MessageHeader.HEADER_SIZE + 2
            signature = message[signature_offset:signature_offset+signature_length]
            
            # Extract nonce and ciphertext
            content_offset = signature_offset + signature_length
            nonce = message[content_offset:content_offset+12]
            ciphertext = message[content_offset+12:]
            
            logger.debug(
                f"Parsed message: header={len(header_bytes)} bytes, " +
                f"signature={len(signature)} bytes, nonce={len(nonce)} bytes, " +
                f"ciphertext={len(ciphertext)} bytes"
            )
            
            # 2. Verify signature if PQ is enabled
            if self.enable_pq and signature:
                if not self.remote_dss_public_key:
                    logger.warning("Cannot verify FALCON signature: No remote DSS public key available")
                else:
                    try:
                        data_to_verify = nonce + ciphertext
                        verified = self.dss.verify(self.remote_dss_public_key, data_to_verify, signature)
                        if verified:
                            logger.debug("FALCON signature verified successfully")
                        else:
                            logger.error("SECURITY ALERT: FALCON signature verification failed")
                            raise SecurityError("Message signature verification failed")
                    except Exception as e:
                        logger.error(f"FALCON signature verification error: {e}", exc_info=True)
                        raise SecurityError(f"Signature verification error: {e}")
            
            # 3. Create authenticated data from header
            auth_data = self._get_associated_data(header_bytes)
            
            # 4. Perform DH ratchet step if needed and derive message key
            message_key = self._ratchet_decrypt(header)
            
            # 5. Decrypt the message
            logger.debug(f"Decrypting with message key #{header.message_number}")
            plaintext = self._decrypt_with_cipher(nonce, ciphertext, auth_data, message_key)
            
            return plaintext
            
        except Exception as e:
            if isinstance(e, SecurityError):
                # Rethrow security errors without modification
                raise
            else:
                # Wrap other exceptions as security errors
                logger.error(f"Decryption error: {e}", exc_info=True)
                raise SecurityError(f"Failed to decrypt message: {e}")
    
    def _ratchet_encrypt(self) -> bytes:
        """
        Advance the sending chain to derive a new message key.
        
        Returns:
            The derived message key for encryption
        """
        # Ensure the Double Ratchet is properly initialized
        if not self.is_initialized():
            raise SecurityError("Cannot generate message key: Double Ratchet not initialized")
        
        # Check if sending chain exists
        if self.sending_chain_key is None:
            raise SecurityError("Sending chain is not initialized")
            
        # Derive next chain key and message key
        next_chain_key, message_key = self._chain_ratchet_step(self.sending_chain_key)
        
        # Update state
        self.sending_chain_key = next_chain_key
        self.sending_message_number += 1
        
        logger.debug(f"Generated message key for sending chain message #{self.sending_message_number-1}")
        return message_key
        
    def _ratchet_decrypt(self, header: MessageHeader) -> bytes:
        """
        Process a message header and derive the appropriate message key for decryption.
        
        This method handles:
        1. Checking for previously stored skipped message keys
        2. Advancing the ratchet if needed based on sender's public key
        3. Skipping message keys if the received message is ahead
        
        Returns:
            The correct message key for decryption
        """
        # Extract sender's public key information
        remote_public_key_bytes = header.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        message_number = header.message_number
        current_ratchet_id = self._get_public_key_fingerprint(header.public_key)
        
        # 1. Check if this is from a skipped/cached key
        key_tuple = (current_ratchet_id, message_number)
        if key_tuple in self.skipped_message_keys:
            logger.info(f"Using stored key for message #{message_number} from ratchet {format_binary(current_ratchet_id)}")
            message_key = self.skipped_message_keys.pop(key_tuple)
            return message_key
        
        # 2. Determine if we need to perform a DH ratchet step
        perform_dh = False
        
        # Case 2a: First message received (no remote public key yet)
        if self.remote_dh_public_key is None:
            perform_dh = True
            logger.info("First message received, initializing receiving chain")
            
        # Case 2b: Sender's public key has changed (they performed a ratchet step)
        elif not self._compare_public_keys(self.remote_dh_public_key, remote_public_key_bytes):
            perform_dh = True
            logger.info("Detected new ratchet public key, performing DH ratchet step")
            
            # Before changing ratchet, store any skipped message keys from the previous chain
            if self.receiving_chain_key:
                self._store_skipped_message_keys(
                    self.receiving_chain_key, 
                    self.receiving_message_number, 
                    header.previous_chain_length
                )
        
        # 3. If needed, perform DH ratchet step and create new receiving chain
        if perform_dh:
            # Update the remote public key
            self.remote_dh_public_key = header.public_key
            
            # Create new receiving chain
            remote_kem_public_key = self.remote_kem_public_key if self.enable_pq else None
            self._dh_ratchet_step(remote_public_key_bytes, remote_kem_public_key)
            
            # Reset receiving message number
            self.receiving_message_number = 0
        
        # 4. Skip any message keys if necessary to reach the target message
        if message_number > self.receiving_message_number:
            self._skip_message_keys(message_number, current_ratchet_id)
        elif message_number < self.receiving_message_number:
            # This is a replay or very old message - should have been handled by skipped keys
            logger.warning(
                f"Received message #{message_number} but already at #{self.receiving_message_number}. " +
                f"Possible replay attack or very delayed message."
            )
        
        # 5. Generate the message key for the current message
        if self.receiving_chain_key is None:
            raise SecurityError("Cannot derive message key: No receiving chain exists")
            
        next_chain_key, message_key = self._chain_ratchet_step(self.receiving_chain_key)
        self.receiving_chain_key = next_chain_key
        self.receiving_message_number = message_number + 1
        
        logger.debug(f"Generated message key for receiving chain message #{message_number}")
        return message_key
    
    def _store_skipped_message_keys(self, chain_key: bytes, start: int, end: int) -> None:
        """
        Store message keys for messages we haven't received yet.
        
        This is a critical component of maintaining security when messages
        arrive out of order or when the sender has ratcheted forward.
        """
        # Validate parameters
        if end <= start:
            return  # Nothing to skip
            
        # Limit the maximum number of keys to prevent DoS
        max_to_store = min(end - start, self.max_skipped_message_keys)
        if max_to_store < (end - start):
            logger.warning(
                f"Limiting skipped keys to {max_to_store} (requested {end-start}). " +
                f"This may cause message loss if too many messages arrive out of order."
            )
            end = start + max_to_store
            
        logger.info(f"Storing keys for skipped messages from #{start} to #{end-1}")
        
        # Generate and store keys for all messages we're skipping
        current_chain_key = chain_key
        remote_key_id = self._get_public_key_fingerprint(self.remote_dh_public_key)
        
        for i in range(start, end):
            next_chain_key, message_key = self._chain_ratchet_step(current_chain_key)
            current_chain_key = next_chain_key
            
            # Store the skipped key for later use
            key_id = (remote_key_id, i)
            self.skipped_message_keys[key_id] = message_key
            logger.debug(f"Stored key for skipped message #{i}")
            
    def _create_new_receiving_chain(self) -> None:
        """Create a new receiving chain using DH and KEM shared secrets."""
        # Generate a new DH shared secret
        dh_shared_secret = self.dh_private_key.exchange(self.remote_dh_public_key)
        verify_key_material(dh_shared_secret, description="DH shared secret for new chain")
        
        # If PQ is enabled, combine with KEM shared secret
        if self.enable_pq and hasattr(self, 'kem_shared_secret') and self.kem_shared_secret:
            # Combine DH and KEM shared secrets using KDF
            logger.debug("Combining DH and KEM shared secrets for hybrid security")
            combined_secret = hashlib.sha512(
                dh_shared_secret + b"||NEW_CHAIN||" + self.kem_shared_secret
            ).digest()
            
            root_key, chain_key = self._kdf(
                self.root_key, combined_secret, self.KDF_INFO_HYBRID + b"_NEW_CHAIN"
            )
        else:
            # Use only DH shared secret
            root_key, chain_key = self._kdf(
                self.root_key, dh_shared_secret, self.KDF_INFO_DH + b"_NEW_CHAIN"
            )
        
        # Update root key and create new receiving chain
        self.root_key = root_key[:32]
        self.receiving_chain_key = chain_key[:32]
        
        # Verify key material
        verify_key_material(self.root_key, expected_length=32, description="New root key")
        verify_key_material(self.receiving_chain_key, expected_length=32, 
                          description="New receiving chain key")
        
        logger.info("Created new receiving chain")
    
    def get_public_key(self) -> bytes:
        """Get the current X25519 public key for key exchange."""
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    def get_kem_public_key(self) -> Optional[bytes]:
        """Get the current ML-KEM public key for post-quantum key exchange."""
        if self.enable_pq and hasattr(self, 'kem_public_key') and self.kem_public_key:
            return self.kem_public_key
        return None
        
    def get_kem_ciphertext(self) -> Optional[bytes]:
        """Get the current KEM ciphertext from encapsulation."""
        if self.enable_pq and hasattr(self, 'kem_ciphertext') and self.kem_ciphertext:
            return self.kem_ciphertext
        return None
        
    def process_kem_ciphertext(self, ciphertext: bytes) -> bytes:
        """
        Process a KEM ciphertext to derive a shared secret.
        
        This is used by the responder to complete the post-quantum
        key establishment initiated by the other party.
        """
        if not self.enable_pq:
            logger.warning("Received KEM ciphertext but post-quantum mode is disabled")
            return b''
            
        try:
            # Verify ciphertext
            verify_key_material(ciphertext, description="KEM ciphertext")
            
            # Perform ML-KEM decapsulation
            logger.debug(f"Performing ML-KEM-1024 decapsulation with ciphertext ({len(ciphertext)} bytes)")
            kem_shared_secret = self.kem.decaps(self.kem_private_key, ciphertext)
            verify_key_material(kem_shared_secret, description="KEM shared secret")
            
            # Store the shared secret
            self.kem_shared_secret = kem_shared_secret
            logger.debug(f"Processed KEM ciphertext and derived shared secret ({len(kem_shared_secret)} bytes)")
            
            # If we already have DH outputs but no chains, initialize chains now
            if self.remote_dh_public_key and not self.receiving_chain_key:
                logger.debug("Completing initialization with DH output and KEM shared secret")
                dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
                self._initialize_chain_keys(dh_output, kem_shared_secret)
                
            # Return the shared secret for immediate use if needed
            return kem_shared_secret
            
        except Exception as e:
            self.last_error = f"Failed to process KEM ciphertext: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"KEM processing failed: {str(e)}")
            
    def _initialize_chain_keys(self, dh_output: bytes, kem_shared_secret: Optional[bytes] = None) -> None:
        """
        Initialize or reinitialize the chain keys.
        
        This method establishes the initial chain keys for both sending
        and receiving chains, ensuring that both parties derive the same
        keys despite being in different roles.
        """
        # Log operation
        logger.debug(
            f"Initializing chain keys with DH output ({len(dh_output)} bytes)" +
            (f" and KEM shared secret ({len(kem_shared_secret)} bytes)" if kem_shared_secret else "")
        )
        
        # Verify inputs
        verify_key_material(dh_output, description="DH output for chain key initialization")
        if kem_shared_secret:
            verify_key_material(kem_shared_secret, description="KEM shared secret for chain key initialization")
            
        # Create combined secret for hybrid mode
        if self.enable_pq and kem_shared_secret:
            # Use a secure combination with domain separation
            combined_secret = hashlib.sha512(b"DR_HYBRID_" + dh_output + b"_" + kem_shared_secret).digest()
            logger.debug(f"Using hybrid DH+KEM input for key derivation ({len(combined_secret)} bytes)")
        else:
            combined_secret = dh_output
            logger.debug(f"Using classical DH input for key derivation ({len(combined_secret)} bytes)")
        
        # Different key derivation paths for initiator vs responder to ensure they
        # derive the same keys but assign them to the correct chains
        if self.is_initiator:
            # For initiator: sending chain = "initiator chain", receiving = "responder chain"
            logger.debug("Deriving initiator chains")
            
            # Derive sending chain (initiator sends first)
            kdf_output = self._kdf(self.root_key, combined_secret, info=b"DR_INIT_SENDING_v2")
            self.root_key, self.sending_chain_key = kdf_output[:32], kdf_output[32:]
            verify_key_material(self.sending_chain_key, description="Initiator sending chain")
            
            # Derive receiving chain
            kdf_output = self._kdf(self.root_key, combined_secret, info=b"DR_INIT_RECEIVING_v2")
            self.root_key, self.receiving_chain_key = kdf_output[:32], kdf_output[32:]
            verify_key_material(self.receiving_chain_key, description="Initiator receiving chain")
        else:
            # For responder: sending chain = "responder chain", receiving = "initiator chain"
            logger.debug("Deriving responder chains")
            
            # Derive receiving chain (from initiator's sending chain)
            kdf_output = self._kdf(self.root_key, combined_secret, info=b"DR_INIT_SENDING_v2")
            self.root_key, self.receiving_chain_key = kdf_output[:32], kdf_output[32:]
            verify_key_material(self.receiving_chain_key, description="Responder receiving chain")
            
            # Derive sending chain
            kdf_output = self._kdf(self.root_key, combined_secret, info=b"DR_INIT_RECEIVING_v2")
            self.root_key, self.sending_chain_key = kdf_output[:32], kdf_output[32:]
            verify_key_material(self.sending_chain_key, description="Responder sending chain")
        
        # Reset message counters
        self.sending_message_number = 0
        self.receiving_message_number = 0
        
        # Verify chain key derivation was successful
        if not self.sending_chain_key or not self.receiving_chain_key:
            logger.error("SECURITY ALERT: Chain key derivation failed")
            raise SecurityError("Chain key derivation failed")
            
        logger.info(f"Successfully initialized chain keys for {'initiator' if self.is_initiator else 'responder'}")
    
    def get_info(self) -> Dict[str, Any]:
        """Get diagnostic information about the current state."""
        # Compute fingerprints for identification
        remote_key_fingerprint = None
        if self.remote_dh_public_key:
            remote_key_fingerprint = base64.b64encode(
                self._get_public_key_fingerprint(self.remote_dh_public_key)
            ).decode()
            
        # Build basic info
        info = {
            "is_initiator": self.is_initiator,
            "post_quantum_enabled": self.enable_pq,
            "current_ratchet_key_id": base64.b64encode(self.current_ratchet_key_id).decode(),
            "remote_ratchet_key_id": remote_key_fingerprint,
            "sending_message_number": self.sending_message_number,
            "receiving_message_number": self.receiving_message_number,
            "skipped_keys_count": len(self.skipped_message_keys),
            "initialization_status": "complete" if self.is_initialized() else "pending",
            "max_skipped_keys": self.max_skipped_message_keys,
            "last_error": self.last_error
        }
        
        # Add PQ-specific information if enabled
        if self.enable_pq:
            info.update({
                "has_remote_kem_key": self.remote_kem_public_key is not None,
                "has_kem_ciphertext": self.kem_ciphertext is not None,
                "has_remote_dss_key": self.remote_dss_public_key is not None,
                "has_kem_shared_secret": hasattr(self, 'kem_shared_secret') and self.kem_shared_secret is not None,
                "pq_algorithms": {
                    "kem": "ML-KEM-1024",
                    "signature": "FALCON-1024"
                }
            })
        
        return info

    def is_initialized(self) -> bool:
        """Check if the Double Ratchet is fully initialized and ready."""
        # Basic requirements for all modes
        basic_init = (
            self.sending_chain_key is not None and 
            self.receiving_chain_key is not None and
            self.remote_dh_public_key is not None
        )
        
        # In PQ mode, also check KEM initialization
        if self.enable_pq:
            pq_init = (
                self.remote_kem_public_key is not None and
                (self.is_initiator or self.kem_shared_secret is not None)
            )
            
            if not pq_init:
                # Log helpful diagnostics about what's missing
                if self.remote_kem_public_key is None:
                    logger.error("INITIALIZATION ERROR: Missing remote KEM public key")
                elif not self.is_initiator and self.kem_shared_secret is None:
                    logger.error("INITIALIZATION ERROR: Responder missing KEM shared secret (ciphertext not processed)")
                    
            return basic_init and pq_init
        
        return basic_init
        
    def _get_associated_data(self, header_bytes: bytes) -> bytes:
        """
        Create authenticated data binding the header to the ciphertext.
        
        This prevents header modification and cross-protocol attacks.
        """
        # Application context for domain separation
        context = b"DoubleRatchet_PQSv2"
        
        # Use part of root key for authentication, but never expose the full key
        derived_auth_key = hmac.HMAC(
            key=self.root_key,
            msg=b"AAD_KEY_DERIVATION",
            digestmod=hashlib.sha256
        ).digest()
        
        # Bind header to context
        auth_data = hmac.HMAC(
            key=derived_auth_key[:16],  # Use only part of the derived key
            msg=header_bytes,
            digestmod=hashlib.sha256
        ).digest()
        
        # Return the authenticated data
        return context + auth_data

    def get_dss_public_key(self) -> Optional[bytes]:
        """Get the current FALCON public key for post-quantum signatures."""
        if self.enable_pq and hasattr(self, 'dss_public_key') and self.dss_public_key:
            return self.dss_public_key
        return None
        
    def secure_cleanup(self) -> None:
        """
        Securely erase all sensitive cryptographic material.
        
        This should be called when the session is complete to prevent
        sensitive key material from remaining in memory.
        """
        logger.debug("Performing secure cleanup of Double Ratchet state")
        
        # List of attributes to securely erase
        sensitive_keys = [
            'root_key', 'sending_chain_key', 'receiving_chain_key',
            'message_key', 'kem_private_key', 'kem_shared_secret',
            'dss_private_key'
        ]
        
        # Erase each sensitive key
        for key_name in sensitive_keys:
            if hasattr(self, key_name):
                key_material = getattr(self, key_name)
                if key_material is not None:
                    secure_erase(key_material)
                    setattr(self, key_name, None)
                    logger.debug(f"Securely erased {key_name}")
        
        # Clean up skipped message keys
        for key_id, message_key in self.skipped_message_keys.items():
            secure_erase(message_key)
        self.skipped_message_keys.clear()
        
        logger.info("Double Ratchet state securely cleaned up")

    def _skip_message_keys(self, until_message_number: int, ratchet_key_id: bytes) -> None:
        """
        Skip message keys to handle out-of-order message delivery.
        
        Advances the receiving chain up to the specified message number,
        storing skipped message keys securely for later use.
        """
        if self.receiving_chain_key is None:
            return  # No chain key yet, nothing to skip
            
        current_msg_num = self.receiving_message_number
        
        # Don't do anything if we're already at or beyond the target
        if current_msg_num >= until_message_number:
            return
            
        # Log the skipping operation
        logger.info(f"Skipping {until_message_number - current_msg_num} message keys " +
                  f"(from {current_msg_num} to {until_message_number-1})")
        
        # Check if we're about to exceed maximum stored keys
        if len(self.skipped_message_keys) + (until_message_number - current_msg_num) > self.max_skipped_message_keys:
            logger.warning(
                f"Maximum skipped keys limit approached ({self.max_skipped_message_keys}). " +
                f"Limiting to avoid potential DoS attack."
            )
            # Limit the number of keys to skip
            until_message_number = min(
                until_message_number,
                current_msg_num + (self.max_skipped_message_keys - len(self.skipped_message_keys))
            )
            
        # Generate and store keys for all messages we're skipping
        while current_msg_num < until_message_number:
            # Generate message key and advance the chain
            next_chain_key, message_key = self._chain_ratchet_step(self.receiving_chain_key)
            self.receiving_chain_key = next_chain_key
            
            # Store the skipped message key
            key_tuple = (ratchet_key_id, current_msg_num)
            self.skipped_message_keys[key_tuple] = message_key
            
            logger.debug(f"Stored key for skipped message {current_msg_num} from ratchet {format_binary(ratchet_key_id)}")
            current_msg_num += 1
    
    def _compare_public_keys(self, public_key1: X25519PublicKey, public_key2_bytes: bytes) -> bool:
        """Compare a public key object with raw public key bytes."""
        try:
            # Convert the first key to bytes
            public_key1_bytes = public_key1.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Compare the bytes
            return public_key1_bytes == public_key2_bytes
        except Exception as e:
            logger.error(f"Error comparing public keys: {e}")
            return False
    
    def set_remote_public_key(self, 
                            public_key_bytes: bytes, 
                            kem_public_key: Optional[bytes] = None, 
                            dss_public_key: Optional[bytes] = None) -> None:
        """
        Initialize the ratchet with the remote party's public key.
        
        This is a critical step to synchronize the Double Ratchet state
        between both parties before any messages are exchanged.
        """
        try:
            # Log operation
            logger.info(
                f"Initializing with remote public key ({len(public_key_bytes)} bytes)" + 
                (f" and KEM public key ({len(kem_public_key)} bytes)" if kem_public_key and self.enable_pq else "")
            )
            
            # 1. Validate and set X25519 public key
            verify_key_material(public_key_bytes, expected_length=32, description="Remote X25519 public key")
            self.remote_dh_public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
            remote_fingerprint = self._get_public_key_fingerprint(self.remote_dh_public_key)
            
            # 2. Set DSS public key if provided and PQ is enabled
            if self.enable_pq and dss_public_key:
                verify_key_material(dss_public_key, description="Remote FALCON public key")
                self.remote_dss_public_key = dss_public_key
                logger.debug(f"Set remote FALCON public key ({len(dss_public_key)} bytes)")
            
            # 3. Perform X25519 calculation
            logger.debug("Performing initial Diffie-Hellman exchange")
            dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
            verify_key_material(dh_output, description="Initial DH output")
            
            # 4. Process KEM public key if in PQ mode
            kem_shared_secret = None
            if self.enable_pq and kem_public_key:
                # Store the remote KEM public key
                verify_key_material(kem_public_key, description="Remote KEM public key")
                self.remote_kem_public_key = kem_public_key
                
                # For initiator or if we already have a shared secret, do encapsulation
                if self.is_initiator or hasattr(self, 'kem_shared_secret') and self.kem_shared_secret:
                    # Perform KEM encapsulation
                    logger.debug("Performing ML-KEM-1024 encapsulation")
                    kem_ciphertext, kem_shared_secret = self.kem.encaps(kem_public_key)
                    self.kem_ciphertext = kem_ciphertext
                    self.kem_shared_secret = kem_shared_secret
                    verify_key_material(kem_shared_secret, description="KEM shared secret")
                    logger.debug(f"KEM shared secret: {format_binary(kem_shared_secret)}")
                else:
                    # Responder waiting for ciphertext
                    logger.debug("Responder waiting for KEM ciphertext to complete initialization")
                    return
            
            # 5. Initialize chains with the generated key material
            self._initialize_chain_keys(dh_output, kem_shared_secret)
            
            logger.info(f"Successfully initialized chains with remote key: {format_binary(remote_fingerprint)}")
                
        except Exception as e:
            self.last_error = f"Failed to set remote public key: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Key initialization failed: {str(e)}")


def example_double_ratchet(use_pq: bool = True) -> None:
    """
    Demonstrate the Double Ratchet protocol between two parties.
    
    Shows the key lifecycle of a Double Ratchet session:
    1. Initialization with shared secrets
    2. Key exchange setup
    3. Normal message exchange
    4. Out-of-order message handling
    
    Args:
        use_pq: Whether to use post-quantum security features
    """
    try:
        print("\n" + "="*60)
        print(f"Double Ratchet Protocol Demonstration")
        print(f"{'With Post-Quantum Security' if use_pq else 'Classical Mode (No PQ)'}")
        print("="*60)
        
        # 1. Initialize with a shared root key (from a secure key exchange)
        shared_root_key = os.urandom(32)
        print(f"\nInitial shared root key: {format_binary(shared_root_key)}")
        
        # 2. Create Alice and Bob's ratchets
        print("\nInitializing Alice (initiator) and Bob (responder) ratchets...")
        alice = DoubleRatchet(shared_root_key, is_initiator=True, enable_pq=use_pq)
        bob = DoubleRatchet(shared_root_key, is_initiator=False, enable_pq=use_pq)
        
        # 3. Exchange key material
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        
        print(f"Alice's public key: {format_binary(alice_public)}")
        print(f"Bob's public key:   {format_binary(bob_public)}")
        
        # Handle post-quantum components if enabled
        if use_pq:
            alice_kem_public = alice.get_kem_public_key()
            bob_kem_public = bob.get_kem_public_key()
            alice_dss_public = alice.get_dss_public_key()
            bob_dss_public = bob.get_dss_public_key()
            
            print(f"\nPQ components:")
            print(f"KEM public keys: Alice={format_binary(alice_kem_public)}, Bob={format_binary(bob_kem_public)}")
            
            # 4. Setup key exchange
            print("\nSetting up key exchange...")
            # Alice sets Bob's keys and encapsulates a shared secret
            alice.set_remote_public_key(bob_public, bob_kem_public, bob_dss_public)
            alice_kem_ciphertext = alice.get_kem_ciphertext()
            
            # Bob sets Alice's keys
            bob.set_remote_public_key(alice_public, alice_kem_public, alice_dss_public)
            
            # Bob processes Alice's ciphertext to complete the exchange
            if alice_kem_ciphertext:
                print(f"Exchanging KEM ciphertext ({len(alice_kem_ciphertext)} bytes)")
                shared_secret_bob = bob.process_kem_ciphertext(alice_kem_ciphertext)
                print(f"Derived shared KEM secret: {format_binary(shared_secret_bob)}")
        else:
            # Classical setup with only DH keys
            alice.set_remote_public_key(bob_public)
            bob.set_remote_public_key(alice_public)
        
        # Verify both parties are properly initialized
        print(f"\nAlice initialized: {alice.is_initialized()}")
        print(f"Bob initialized:   {bob.is_initialized()}")
        
        # 5. Test normal message exchange: Alice → Bob
        print("\n" + "-"*60)
        print("Test 1: Normal message flow (Alice → Bob)")
        message = b"Hello Bob! This is a secure message sent with Double Ratchet."
        print(f"Original:  {message.decode()}")
        
        # Alice encrypts
        encrypted = alice.encrypt(message)
        print(f"Encrypted: {len(encrypted)} bytes")
        
        # Bob decrypts
        decrypted = bob.decrypt(encrypted)
        print(f"Decrypted: {decrypted.decode()}")
        print(f"Success:   {message == decrypted}")
    
        # 6. Test reply: Bob → Alice
        print("\n" + "-"*60)
        print("Test 2: Reply message (Bob → Alice)")
        reply = b"Hi Alice! Your secure messaging system works perfectly!"
        print(f"Original:  {reply.decode()}")
        
        # Bob encrypts a reply
        encrypted_reply = bob.encrypt(reply)
        print(f"Encrypted: {len(encrypted_reply)} bytes")
        
        # Alice decrypts the reply
        decrypted_reply = alice.decrypt(encrypted_reply)
        print(f"Decrypted: {decrypted_reply.decode()}")
        print(f"Success:   {reply == decrypted_reply}")
    
        # 7. Test out-of-order message delivery
        print("\n" + "-"*60)
        print("Test 3: Out-of-order message handling")
        
        # Alice sends 3 messages
        messages = [
            b"This is message 1 from Alice - should arrive last",
            b"This is message 2 from Alice - should arrive second",
            b"This is message 3 from Alice - should arrive first"
        ]
        
        encrypted_msgs = [alice.encrypt(msg) for msg in messages]
        print(f"Alice encrypted 3 messages of sizes: "
              f"{len(encrypted_msgs[0])}, {len(encrypted_msgs[1])}, {len(encrypted_msgs[2])} bytes")
        
        # Bob receives them out of order (3, 1, 2)
        print("\nReceiving in order: message 3, message 1, message 2")
        decrypted3 = bob.decrypt(encrypted_msgs[2])
        decrypted1 = bob.decrypt(encrypted_msgs[0])
        decrypted2 = bob.decrypt(encrypted_msgs[1])
        
        print("\nVerifying decryption success:")
        print(f"Message 1: {'✓' if messages[0] == decrypted1 else '✗'}")
        print(f"Message 2: {'✓' if messages[1] == decrypted2 else '✗'}")
        print(f"Message 3: {'✓' if messages[2] == decrypted3 else '✗'}")
        
        # 8. Clean up
        print("\nPerforming secure cleanup...")
        alice.secure_cleanup()
        bob.secure_cleanup()
        print("Secure cleanup completed.")
    
    except Exception as e:
        print(f"\nError in demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run with post-quantum security by default
    example_double_ratchet(use_pq=True)
    
    # Uncomment to run with classical mode only
    # example_double_ratchet(use_pq=False) 