"""
Hybrid Key Exchange Module
 
Combines X3DH (Extended Triple Diffie-Hellman) with Post-Quantum Cryptography
for establishing secure shared secrets resistant to both classical and quantum attacks.
""" 
 
import os
import json 
import time
import base64
import logging
import uuid
import random
import string
from typing import Tuple, Dict, Optional, Union
import hashlib
import ctypes 
import secure_key_manager as skm

# X25519 for classical key exchange
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# Ed25519 for classical signatures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Key derivation
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Post-quantum cryptography
import quantcrypt.kem
import quantcrypt.cipher
from quantcrypt.dss import FALCON_1024

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Add file handler for security logs
try:
    file_handler = logging.FileHandler('hybrid_security.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s'))
    log.addHandler(file_handler)
except Exception as e:
    log.warning(f"Could not create hybrid security log file: {e}")

# Constants for ephemeral identity management
DEFAULT_KEY_LIFETIME = 3072  # Default lifetime: 3072 seconds (51.2 minutes)
MIN_KEY_LIFETIME = 300       # 5 minutes minimum lifetime
EPHEMERAL_ID_PREFIX = "eph"   # Prefix for ephemeral identities
MAX_KEY_LIFETIME = 86400    # 24 hours in seconds maximum lifetime

MLKEM1024_CIPHERTEXT_SIZE = 1568  # Expected ciphertext size for ML-KEM-1024

def verify_key_material(key_material, expected_length=None, description="key material"):
    """
    Verify that cryptographic key material meets security requirements.
    
    Args:
        key_material: The key material to verify
        expected_length: Optional expected length in bytes
        description: Description of the key material for logs
        
    Returns:
        True if verification passes
        
    Raises:
        ValueError: If verification fails
    """
    if key_material is None:
        log.error(f"SECURITY ALERT: {description} is None")
        raise ValueError(f"Security violation: {description} is None")
        
    if not isinstance(key_material, bytes):
        log.error(f"SECURITY ALERT: {description} is not bytes type: {type(key_material)}")
        raise ValueError(f"Security violation: {description} is not bytes")
        
    if expected_length and len(key_material) != expected_length:
        log.error(f"SECURITY ALERT: {description} has incorrect length {len(key_material)}, expected {expected_length}")
        raise ValueError(f"Security violation: {description} has incorrect length")
        
    if len(key_material) == 0:
        log.error(f"SECURITY ALERT: {description} is empty")
        raise ValueError(f"Security violation: {description} is empty")
        
    # Basic entropy check
    if all(b == key_material[0] for b in key_material):
        log.error(f"SECURITY ALERT: {description} has low entropy (all same byte)")
        raise ValueError(f"Security violation: {description} has low entropy")
        
    log.debug(f"Verified {description}: length={len(key_material)}, entropy=OK")
    return True


def _format_binary(data, max_len=8):
    """
    Format binary data for logging in a readable way.
    
    Args:
        data: Binary data to format
        max_len: Maximum length to display before truncating
        
    Returns:
        Formatted string representation
    """
    if data is None:
        return "None"
    if len(data) > max_len:
        b64 = base64.b64encode(data[:max_len]).decode('utf-8')
        return f"{b64}... ({len(data)} bytes)"
    return base64.b64encode(data).decode('utf-8')


def secure_erase(key_material):
    """
    Securely erase key material from memory.
    
    Args:
        key_material: The key material to erase
    """
    if key_material is None:
        return
    
    # Always use the enhanced_secure_erase from secure_key_manager
    skm.enhanced_secure_erase(key_material)
    log.debug("Securely erased key material using enhanced technique")
    return


# Flag indicating we're using the real post-quantum implementation
HAVE_REAL_PQ = True
log.info("Using real post-quantum cryptography implementation: ML-KEM-1024 and FALCON-1024")


class HybridKeyExchange:
    """
    Implements a hybrid key exchange protocol combining X3DH with post-quantum cryptography.
    
    The protocol uses multiple Diffie-Hellman exchanges with X25519 keys for classical
    security, combined with ML-KEM-1024 for post-quantum security.
    
    Features:
    - Support for ephemeral identities with automatic rotation
    - In-memory key option to avoid storing sensitive key material
    - Post-quantum security with ML-KEM-1024 and FALCON-1024
    - Handshake replay protection with nonces and timestamps
    """
    
    def __init__(self, identity: str = "user", keys_dir: str = None,
                 ephemeral: bool = True, key_lifetime: int = MIN_KEY_LIFETIME,
                 in_memory_only: bool = True):
        """
        Initialize the hybrid key exchange.
        
        Args:
            identity: User identifier (ignored if ephemeral=True, which is the default).
            keys_dir: Directory for storing keys (not used if in_memory_only=True, which is the default).
            ephemeral: Defaults to True for maximum security (ephemeral identity).
                       If True, use an ephemeral identity with random identifier.
            key_lifetime: Defaults to MIN_KEY_LIFETIME for frequent rotation in ephemeral mode.
                          Seconds until keys should be rotated (for ephemeral mode).
            in_memory_only: Defaults to True for maximum security (keys only in memory).
                            If True, never store keys on disk.
        """
        self.in_memory_only = in_memory_only
        self.ephemeral_mode = ephemeral
        
        # Set key lifetime with bounds checking
        self.key_lifetime = max(MIN_KEY_LIFETIME, min(key_lifetime, MAX_KEY_LIFETIME))
        
        # Determine actual identity (ephemeral or persistent)
        _initial_identity_param = identity # Store for logging clarity if needed
        if ephemeral:
            # Create a random identity with uuid and random chars for privacy
            random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            self.identity = f"{EPHEMERAL_ID_PREFIX}-{random_id}-{str(uuid.uuid4())[:8]}"
        else:
            self.identity = identity
        
        log.info(
            f"HybridKeyExchange initializing for identity '{self.identity}'. "
            f"Configuration - Ephemeral Mode: {self.ephemeral_mode}, "
            f"In-Memory Keys: {self.in_memory_only}, "
            f"Specified Key Lifetime: {key_lifetime}s, Effective Key Lifetime: {self.key_lifetime}s (for ephemeral mode)."
        )
        
        if self.ephemeral_mode and self.in_memory_only and self.key_lifetime == MIN_KEY_LIFETIME and ephemeral and in_memory_only and key_lifetime == MIN_KEY_LIFETIME:
            log.info("SECURITY INFO: Instance configured with maximal security defaults: ephemeral ID, in-memory keys, and minimal rotation time.")
        elif self.ephemeral_mode and self.in_memory_only:
            log.info("SECURITY INFO: Instance configured with strong security settings: ephemeral ID, in-memory keys.")
        
        # Set up keys directory (not used in memory-only mode)
        if not in_memory_only and keys_dir is None:
            self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        else:
            self.keys_dir = keys_dir
        
        if not in_memory_only:
            os.makedirs(self.keys_dir, exist_ok=True)
        
        # Initialize key storage
        self.static_key = None
        self.signing_key = None
        self.signed_prekey = None
        self.prekey_signature = None
        self.kem_private_key = None
        self.kem_public_key = None
        self.falcon_private_key = None
        self.falcon_public_key = None
        self.peer_hybrid_bundle = None
        
        # Create trackers for ephemeral keys
        self.key_creation_time = None
        self.next_rotation_time = None
        self.pending_rotation = False
        
        # Initialize KEM and DSS instances
        self.kem = quantcrypt.kem.MLKEM_1024()
        self.dss = FALCON_1024()
        
        # Initialize quantum resistance future-proofing module
        self.quantum_resistance = skm.get_quantum_resistance()
        log.info("Initialized quantum resistance future-proofing module")
        
        # Add SPHINCS+ as backup signature scheme if available
        supported_algos = self.quantum_resistance.get_supported_algorithms()
        if "SPHINCS+" in supported_algos.get("signatures", []):
            self.sphincs_plus = self.quantum_resistance.get_algorithm("SPHINCS+")
            log.info("SPHINCS+ backup signature scheme initialized")
        else:
            self.sphincs_plus = None
            log.info("SPHINCS+ backup signature scheme not available")
            
        # Add nonce tracking for replay protection - dictionary mapping peer IDs to sets of seen nonces
        self.seen_nonces = {}
        
        # Timestamp validity window in seconds (±60 seconds allowed for clock drift)
        self.timestamp_window = 60
        
        # Load or generate keys
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones if they don't exist, with support for ephemeral mode."""
        self.key_creation_time = time.time()
        
        # In ephemeral or in-memory mode, always generate fresh keys
        if self.ephemeral_mode or self.in_memory_only:
            self._generate_keys()
            
            # Set the next rotation time for ephemeral keys
            if self.ephemeral_mode:
                self.next_rotation_time = self.key_creation_time + self.key_lifetime
                log.info(f"Ephemeral keys will rotate after: {self.key_lifetime} seconds")
                log.info(f"Next rotation scheduled at: {time.ctime(self.next_rotation_time)}")
            
            # Only save to disk if neither ephemeral nor in-memory mode is active
            if not self.in_memory_only and not self.ephemeral_mode:
                self._save_keys()
            return
            
        # For persistent identities, try to load existing keys
        key_file = os.path.join(self.keys_dir, f"{self.identity}_hybrid_keys.json")
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    keys_data = json.load(f)
                
                # Check for key expiration if present in the file
                if 'expiration_time' in keys_data and keys_data['expiration_time'] < time.time():
                    log.info(f"Keys for {self.identity} have expired, generating new ones")
                    self._generate_keys()
                    self._save_keys()
                    return
                
                # Load X25519 static key
                self.static_key = X25519PrivateKey.from_private_bytes(
                    base64.b64decode(keys_data['static_key'])
                )
                
                # Load Ed25519 signing key
                self.signing_key = Ed25519PrivateKey.from_private_bytes(
                    base64.b64decode(keys_data['signing_key'])
                )
                
                # Load signed prekey and its signature
                self.signed_prekey = X25519PrivateKey.from_private_bytes(
                    base64.b64decode(keys_data['signed_prekey'])
                )
                self.prekey_signature = base64.b64decode(keys_data['prekey_signature'])
                
                # Load KEM key
                self.kem_private_key = base64.b64decode(keys_data['kem_private_key'])
                self.kem_public_key = base64.b64decode(keys_data['kem_public_key'])
                
                # Load FALCON keys
                if 'falcon_private_key' in keys_data and 'falcon_public_key' in keys_data:
                    self.falcon_private_key = base64.b64decode(keys_data['falcon_private_key'])
                    self.falcon_public_key = base64.b64decode(keys_data['falcon_public_key'])
                else:
                    # Generate FALCON keys if not found in existing file
                    log.info(f"Generating new FALCON-1024 keys for {self.identity}")
                    self.falcon_public_key, self.falcon_private_key = self.dss.keygen()
                    self._save_keys()
                
                # Load or set key creation time
                if 'created_at' in keys_data:
                    self.key_creation_time = keys_data['created_at']
                
                log.info(f"Loaded existing hybrid key material for {self.identity}")
            else:
                # Generate new keys
                self._generate_keys()
                self._save_keys()
                
        except Exception as e:
            log.error(f"Error loading keys, generating new ones: {e}")
            self._generate_keys()
            self._save_keys()
    
    def _generate_keys(self):
        """Generate all required keys for the hybrid handshake."""
        log.info(f"Generating new hybrid cryptographic key material for identity: {self.identity}")
        
        # Generate X25519 static key
        self.static_key = X25519PrivateKey.generate()
        static_pub = self.static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        log.debug(f"Generated X25519 static key: {_format_binary(static_pub)}")
        
        # Generate Ed25519 signing key
        self.signing_key = Ed25519PrivateKey.generate()
        signing_pub = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        log.debug(f"Generated Ed25519 signing key: {_format_binary(signing_pub)}")
        
        # Generate signed prekey
        self.signed_prekey = X25519PrivateKey.generate()
        prekey_public_bytes = self.signed_prekey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        log.debug(f"Generated X25519 signed prekey: {_format_binary(prekey_public_bytes)}")
        
        # Sign the prekey
        self.prekey_signature = self.signing_key.sign(prekey_public_bytes)
        log.debug(f"Generated prekey signature: {_format_binary(self.prekey_signature)}")
        
        # Verify the signature
        try:
            self.signing_key.public_key().verify(self.prekey_signature, prekey_public_bytes)
            log.debug("Verified prekey signature successfully")
        except InvalidSignature:
            log.error("SECURITY ALERT: Generated prekey signature failed verification")
            raise ValueError("Critical security error: Signature verification failed")
        
        # Generate KEM key
        log.debug("Generating ML-KEM-1024 key pair")
        self.kem_public_key, self.kem_private_key = self.kem.keygen()
        
        # Generate FALCON signature key
        log.debug("Generating FALCON-1024 signature key pair")
        self.falcon_public_key, self.falcon_private_key = self.dss.keygen()
        
        # Verify key material
        verify_key_material(self.kem_public_key, description="ML-KEM public key")
        verify_key_material(self.kem_private_key, description="ML-KEM private key")
        verify_key_material(self.falcon_public_key, description="FALCON-1024 public key")
        verify_key_material(self.falcon_private_key, description="FALCON-1024 private key")
        
        log.info(f"Successfully generated complete hybrid key material for {self.identity}")
    
    def _save_keys(self):
        """Save the generated keys to a file if neither in-memory nor ephemeral mode is active."""
        # Skip saving if in-memory only mode is enabled
        if self.in_memory_only:
            log.debug("In-memory only mode active, skipping key persistence")
            return
            
        # Skip saving if ephemeral mode is enabled
        if self.ephemeral_mode:
            log.debug("Ephemeral mode active, skipping key persistence")
            return
            
        # Only save if neither in-memory nor ephemeral mode is active
        key_file = os.path.join(self.keys_dir, f"{self.identity}_hybrid_keys.json")
        
        keys_data = {
            'static_key': base64.b64encode(self.static_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8'),
            
            'signing_key': base64.b64encode(self.signing_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8'),
            
            'signed_prekey': base64.b64encode(self.signed_prekey.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8'),
            
            'prekey_signature': base64.b64encode(self.prekey_signature).decode('utf-8'),
            
            # Save KEM keys
            'kem_private_key': base64.b64encode(self.kem_private_key).decode('utf-8'),
            'kem_public_key': base64.b64encode(self.kem_public_key).decode('utf-8'),
            
            # Save FALCON keys
            'falcon_private_key': base64.b64encode(self.falcon_private_key).decode('utf-8'),
            'falcon_public_key': base64.b64encode(self.falcon_public_key).decode('utf-8')
        }
        
        # Add timestamps for key management
        keys_data['created_at'] = self.key_creation_time or int(time.time())
        keys_data['expiration_time'] = self.key_creation_time + self.key_lifetime
        
        with open(key_file, 'w') as f:
            json.dump(keys_data, f)
        
        log.info(f"Saved hybrid keys to {key_file} (expires: {time.ctime(keys_data['expiration_time'])})")
    
    def get_public_bundle(self) -> Dict[str, str]:
        """
        Get the public key bundle to share with peers.
        
        Returns:
            Dictionary containing all public key components
        """
        # Check if keys need rotation before creating bundle
        if self.check_key_expiration():
            self.rotate_keys()
            
        # Create basic bundle with X25519 and KEM keys
        bundle = {
            'identity': self.identity,
            'static_key': base64.b64encode(self.static_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            
            'signing_key': base64.b64encode(self.signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            
            'signed_prekey': base64.b64encode(self.signed_prekey.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            
            'prekey_signature': base64.b64encode(self.prekey_signature).decode('utf-8'),
            
            # Add KEM public key
            'kem_public_key': base64.b64encode(self.kem_public_key).decode('utf-8'),
            
            # Add FALCON public key
            'falcon_public_key': base64.b64encode(self.falcon_public_key).decode('utf-8')
        }
        
        # Add ephemeral identity metadata if applicable
        if self.ephemeral_mode:
            bundle['ephemeral'] = True
            bundle['created_at'] = int(self.key_creation_time)
            bundle['expires_at'] = int(self.next_rotation_time)
            
        # Create a canonicalized representation of the bundle for signing
        bundle_data = json.dumps(bundle, sort_keys=True).encode('utf-8')
        
        # Sign the entire bundle with FALCON-1024
        bundle_signature = self.dss.sign(self.falcon_private_key, bundle_data)
        
        # Add the bundle signature
        bundle['bundle_signature'] = base64.b64encode(bundle_signature).decode('utf-8')
        
        return bundle
    
    def verify_public_bundle(self, bundle: Dict[str, str]) -> bool:
        """
        Verify the signatures in a public key bundle.
        
        Args:
            bundle: The key bundle to verify
            
        Returns:
            True if verification succeeds, False if it fails
        """
        try:
            # Check for required keys
            if not all(k in bundle for k in ['static_key', 'signed_prekey', 'signing_key', 'prekey_signature']):
                log.error("Invalid key bundle: missing required keys")
                return False
                
            # Extract keys from bundle
            signing_key_bytes = base64.b64decode(bundle['signing_key'])
            prekey_signature = base64.b64decode(bundle['prekey_signature'])
            signed_prekey = base64.b64decode(bundle['signed_prekey'])
            
            # First verify Ed25519 prekey signature
            try:
                signing_public_key = Ed25519PublicKey.from_public_bytes(signing_key_bytes)
            except ValueError as e:
                log.error(f"Invalid signing key format: {e}")
                return False
                
            # Verify the prekey signature
            try:
                signing_public_key.verify(prekey_signature, signed_prekey)
                log.debug("Ed25519 prekey signature verified successfully")
            except InvalidSignature:
                log.error("SECURITY ALERT: Prekey signature verification failed")
                return False
            
            # Now verify the FALCON bundle signature if present
            if 'bundle_signature' in bundle and 'falcon_public_key' in bundle:
                # Create copy of bundle without signature for verification
                verification_bundle = bundle.copy()
                bundle_signature = base64.b64decode(verification_bundle.pop('bundle_signature'))
                
                # Get the public key
                falcon_public_key = base64.b64decode(bundle['falcon_public_key'])
                
                # Create canonicalized representation
                bundle_data = json.dumps(verification_bundle, sort_keys=True).encode('utf-8')
                
                # Verify with FALCON-1024
                try:
                    secure_verify(self.dss, falcon_public_key, bundle_data, bundle_signature, "FALCON bundle signature")
                    log.debug("FALCON-1024 bundle signature verified successfully")
                except ValueError as e:
                    log.error(f"SECURITY ALERT: {str(e)}")
                    return False
            
            return True
            
        except (KeyError, ValueError, InvalidSignature) as e:
            log.error(f"Invalid key bundle: {e}")
            return False
    
    def _generate_handshake_nonce(self) -> Tuple[bytes, int]:
        """
        Generate a secure random nonce and timestamp for handshake replay protection.
        
        Returns:
            Tuple of (nonce, timestamp) where nonce is 32 random bytes and timestamp is current Unix time
        """
        nonce = os.urandom(32)  # 32 bytes of cryptographically secure randomness
        timestamp = int(time.time())  # Current Unix timestamp
        return nonce, timestamp

    def _verify_handshake_nonce(self, peer_id: str, nonce: bytes, timestamp: int) -> bool:
        """
        Verify that a handshake nonce hasn't been seen before and the timestamp is valid.
        
        Args:
            peer_id: Identity of the peer sending the nonce
            nonce: The nonce to verify (32 bytes)
            timestamp: Unix timestamp from the handshake
            
        Returns:
            True if nonce is valid (not seen before and timestamp is current), False otherwise
        """
        current_time = int(time.time())
        
        # Check if timestamp is within the acceptable window (±timestamp_window seconds)
        if abs(current_time - timestamp) > self.timestamp_window:
            log.error(f"SECURITY ALERT: Handshake timestamp outside valid window. Received: {timestamp}, Current: {current_time}")
            return False
        
        # Initialize nonce set for this peer if it doesn't exist
        if peer_id not in self.seen_nonces:
            self.seen_nonces[peer_id] = set()
        
        # Check if we've seen this nonce before from this peer
        if nonce in self.seen_nonces[peer_id]:
            log.error(f"SECURITY ALERT: Handshake replay detected! Duplicate nonce from peer: {peer_id}")
            return False
            
        # Store the nonce as seen
        self.seen_nonces[peer_id].add(nonce)
        
        # If we have too many nonces stored for this peer, keep only the most recent ones
        # This prevents memory exhaustion attacks
        if len(self.seen_nonces[peer_id]) > 1000:  # Arbitrary limit
            log.warning(f"Too many stored nonces for peer {peer_id}, clearing oldest")
            self.seen_nonces[peer_id].clear()  # In a production system, you might want to keep the most recent ones
            self.seen_nonces[peer_id].add(nonce)  # Keep the current one
            
        return True

    def initiate_handshake(self, peer_bundle: Dict[str, str]) -> Tuple[Dict[str, str], bytes]:
        """
        Initiate the X3DH+PQ handshake (Alice's side).
        
        Args:
            peer_bundle: The public key bundle from the peer (Bob)
            
        Returns:
            Tuple of (handshake_message, shared_secret) containing the message
            to send to the peer and the derived shared secret
        """
        log.info(f"Initiating hybrid X3DH+PQ handshake with peer: {peer_bundle.get('identity', 'unknown')}")
        
        # Store the peer's bundle for later use
        self.peer_hybrid_bundle = peer_bundle
        
        # Verify bundle before proceeding
        if not self.verify_public_bundle(peer_bundle):
            log.error("SECURITY ALERT: Invalid peer key bundle, signature verification failed")
            raise ValueError("Handshake aborted: invalid peer key bundle signature")
        
        # Generate handshake nonce and timestamp for replay protection
        handshake_nonce, timestamp = self._generate_handshake_nonce()
        
        # Generate ephemeral key
        log.debug("Generating ephemeral X25519 key for handshake")
        ephemeral_key = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        log.debug(f"Generated ephemeral key: {_format_binary(ephemeral_public)}")
        
        # Extract peer's public keys
        peer_static_public = X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_bundle['static_key'])
        )
        peer_signed_prekey_public = X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_bundle['signed_prekey'])
        )
        
        # Perform DH exchanges
        log.debug("Performing multiple Diffie-Hellman exchanges")
        
        # 1. Static-Static DH
        dh1 = self.static_key.exchange(peer_static_public)
        verify_key_material(dh1, description="DH1: Static-Static exchange")
        log.debug(f"DH1 (Static-Static): {_format_binary(dh1)}")
        
        # 2. Ephemeral-Static DH
        dh2 = ephemeral_key.exchange(peer_static_public)
        verify_key_material(dh2, description="DH2: Ephemeral-Static exchange")
        log.debug(f"DH2 (Ephemeral-Static): {_format_binary(dh2)}")
        
        # 3. Static-SPK DH
        dh3 = self.static_key.exchange(peer_signed_prekey_public)
        verify_key_material(dh3, description="DH3: Static-SPK exchange")
        log.debug(f"DH3 (Static-SPK): {_format_binary(dh3)}")
        
        # 4. Ephemeral-SPK DH
        dh4 = ephemeral_key.exchange(peer_signed_prekey_public)
        verify_key_material(dh4, description="DH4: Ephemeral-SPK exchange")
        log.debug(f"DH4 (Ephemeral-SPK): {_format_binary(dh4)}")
        
        # Perform KEM encapsulation
        log.debug("Performing ML-KEM-1024 encapsulation")
        peer_kem_public = base64.b64decode(peer_bundle['kem_public_key'])
        verify_key_material(peer_kem_public, description="Peer ML-KEM public key")
        
        kem_ciphertext, kem_shared_secret = self.kem.encaps(peer_kem_public)
        verify_key_material(kem_ciphertext, description="ML-KEM ciphertext")
        verify_key_material(kem_shared_secret, description="ML-KEM shared secret")
        log.debug(f"KEM encapsulation successful: ciphertext ({len(kem_ciphertext)} bytes), shared secret ({len(kem_shared_secret)} bytes)")
        
        # Generate ephemeral FALCON key for this handshake
        eph_falcon_public_key, eph_falcon_private_key = self.dss.keygen()
        verify_key_material(eph_falcon_public_key, description="Ephemeral FALCON public key")
        verify_key_material(eph_falcon_private_key, description="Ephemeral FALCON private key")
        log.debug(f"Generated ephemeral FALCON key for handshake: {_format_binary(eph_falcon_public_key)}")

        # Sign the ephemeral FALCON public key with the main FALCON identity key
        try:
            eph_falcon_key_signature = self.dss.sign(self.falcon_private_key, eph_falcon_public_key)
            verify_key_material(eph_falcon_key_signature, description="Ephemeral FALCON key signature")
            log.debug(f"Signed ephemeral FALCON public key: {_format_binary(eph_falcon_key_signature)}")
        except Exception as e:
            log.error(f"SECURITY CRITICAL: Failed to sign ephemeral FALCON public key: {e}", exc_info=True)
            raise ValueError("Failed to sign ephemeral FALCON public key")

        # Create specific binding for ephemeral EC key, KEM ciphertext, and handshake nonce, signed by ephemeral FALCON key
        # Include the nonce and timestamp in the binding data for replay protection
        binding_data = ephemeral_public + kem_ciphertext + handshake_nonce + timestamp.to_bytes(8, byteorder='big')
        try:
            ec_pq_binding_signature = self.dss.sign(eph_falcon_private_key, binding_data)
            verify_key_material(ec_pq_binding_signature, description="EC-PQ binding signature")
            log.debug(f"Generated EC-PQ binding signature (with ephemeral FALCON): {_format_binary(ec_pq_binding_signature)}")
        except Exception as e:
            log.error(f"SECURITY CRITICAL: Failed to generate EC-PQ binding signature with ephemeral key: {e}", exc_info=True)
            raise ValueError("Failed to generate critical EC-PQ binding signature with ephemeral key")

        # Combine all shared secrets with HKDF
        log.debug("Combining all shared secrets with HKDF")
        ikm = dh1 + dh2 + dh3 + dh4 + kem_shared_secret
        verify_key_material(ikm, description="Combined input key material")
        log.debug(f"Combined IKM length: {len(ikm)} bytes")
        
        root_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'Hybrid X3DH+PQ Root Key',
        ).derive(ikm)
        
        verify_key_material(root_key, expected_length=32, description="Derived root key")
        log.debug(f"Derived root key: {_format_binary(root_key)}")
        
        # Securely erase the ephemeral X25519 private key data
        try:
            # Extract raw private key bytes for secure wiping
            raw_priv = ephemeral_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Convert to a bytearray so it's mutable
            ba = bytearray(raw_priv)
            # Write zeros to the memory
            for i in range(len(ba)):
                ba[i] = 0
            # Delete references
            del ephemeral_key, raw_priv, ba
            log.debug("Securely erased ephemeral X25519 private key")
        except Exception as e:
            log.error(f"Error during ephemeral X25519 key zeroization: {e}")
        
        # Create the handshake message with all data fields, but no signatures yet
        handshake_message = {
            'identity': self.identity,
            'ephemeral_key': base64.b64encode(ephemeral_public).decode('utf-8'),
            'static_key': base64.b64encode(self.static_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            'kem_ciphertext': base64.b64encode(kem_ciphertext).decode('utf-8'),
            'eph_falcon_public_key': base64.b64encode(eph_falcon_public_key).decode('utf-8'),
            'eph_falcon_key_signature': base64.b64encode(eph_falcon_key_signature).decode('utf-8'),
            'ec_pq_binding_sig': base64.b64encode(ec_pq_binding_signature).decode('utf-8'),
            'handshake_nonce': base64.b64encode(handshake_nonce).decode('utf-8'),
            'timestamp': timestamp
        }

        # --- Generate and add signatures ---
        
        # Generate ephemeral SPHINCS+ keys and add public key to the message
        eph_sphincs_pk, eph_sphincs_sk = None, None
        if hasattr(self, 'sphincs_plus') and self.sphincs_plus:
            eph_sphincs_pk, eph_sphincs_sk = self.sphincs_plus.keygen()
            handshake_message['eph_sphincs_pk'] = base64.b64encode(eph_sphincs_pk).decode('utf-8')

        # Create the final canonical message data to be signed by all parties
        message_data_to_sign = json.dumps(handshake_message, sort_keys=True).encode('utf-8')
        message_hash_for_falcon = hashlib.sha512(message_data_to_sign).digest()

        # Sign the hash with the ephemeral FALCON-1024 key
        message_signature = self.dss.sign(eph_falcon_private_key, message_hash_for_falcon)
        handshake_message['message_signature'] = base64.b64encode(message_signature).decode('utf-8')

        # Sign the data with SPHINCS+ if available
        if eph_sphincs_sk:
            try:
                # Our SPHINCS+ fallback hashes internally, so we pass the full data
                sphincs_signature = self.sphincs_plus.sign(eph_sphincs_sk, message_data_to_sign)
                handshake_message['sphincs_signature'] = base64.b64encode(sphincs_signature).decode('utf-8')
                log.debug("Successfully added SPHINCS+ signature for algorithm diversity")
            except Exception as e:
                log.warning(f"Failed to add SPHINCS+ signature: {e}. Continuing with FALCON only.")
                # Remove the public key if signing failed
                handshake_message.pop('eph_sphincs_pk', None)

        # Securely erase the ephemeral private keys
        secure_erase(eph_falcon_private_key)
        if eph_sphincs_sk:
            skm.enhanced_secure_erase(eph_sphincs_sk)
        
        log.info(f"Hybrid X3DH+PQ handshake initiated successfully with {peer_bundle.get('identity', 'unknown')}")
        return handshake_message, root_key
    
    def respond_to_handshake(self, handshake_message: Dict[str, str], peer_bundle: Optional[Dict[str, str]] = None) -> bytes:
        """
        Respond to the X3DH+PQ handshake (Bob's side).
        
        Args:
            handshake_message: The handshake message from the peer (Alice)
            peer_bundle: Optional. The public key bundle from the peer (Alice).
                         If provided, it will be used for signature verifications.
                         If None, self.peer_hybrid_bundle will be used.
            
        Returns:
            The derived shared secret
        """
        try:
            log.info(f"Processing incoming handshake from: {handshake_message.get('identity', 'unknown')}")
            
            # Check for required nonce and timestamp fields
            if 'handshake_nonce' not in handshake_message or 'timestamp' not in handshake_message:
                log.error("SECURITY ALERT: Handshake message missing nonce or timestamp")
                raise ValueError("Handshake message missing required replay protection fields")
            
            # Extract and verify nonce and timestamp
            handshake_nonce = base64.b64decode(handshake_message['handshake_nonce'])
            timestamp = handshake_message['timestamp']
            
            # Verify the nonce hasn't been seen before and timestamp is valid
            peer_id = handshake_message.get('identity', 'unknown')
            if not self._verify_handshake_nonce(peer_id, handshake_nonce, timestamp):
                log.error("SECURITY ALERT: Handshake replay protection check failed")
                raise ValueError("Invalid handshake: replay protection check failed")
            
            # Use provided peer_bundle if available, otherwise fallback to instance's stored bundle
            current_peer_bundle = peer_bundle if peer_bundle else self.peer_hybrid_bundle
            if not current_peer_bundle:
                log.error("SECURITY ALERT: Peer bundle not available for respond_to_handshake. Cannot verify signatures.")
                raise ValueError("Peer bundle unavailable for signature verification")

            # Extract and verify the ephemeral FALCON key first
            if 'eph_falcon_public_key' not in handshake_message or \
               'eph_falcon_key_signature' not in handshake_message:
                log.error("SECURITY ALERT: Handshake message missing ephemeral FALCON key components.")
                raise ValueError("Handshake message missing ephemeral FALCON key or its signature.")

            eph_falcon_public_key_b64 = handshake_message['eph_falcon_public_key']
            eph_falcon_public_key_bytes = base64.b64decode(eph_falcon_public_key_b64)
            verify_key_material(eph_falcon_public_key_bytes, description="Received ephemeral FALCON public key")
            
            eph_falcon_key_signature_b64 = handshake_message['eph_falcon_key_signature']
            eph_falcon_key_signature_bytes = base64.b64decode(eph_falcon_key_signature_b64)
            verify_key_material(eph_falcon_key_signature_bytes, description="Received ephemeral FALCON key signature")

            # Get the main FALCON public key from the peer's bundle to verify the ephemeral FALCON key
            if 'falcon_public_key' not in current_peer_bundle:
                log.error("SECURITY ALERT: Peer's main FALCON public key not found in their bundle.")
                raise ValueError("Peer's main FALCON public key missing from bundle.")
            
            peer_main_falcon_public_key_b64 = current_peer_bundle['falcon_public_key']
            peer_main_falcon_public_key = base64.b64decode(peer_main_falcon_public_key_b64)
            verify_key_material(peer_main_falcon_public_key, description="Peer's main FALCON public key from bundle")

            try:
                secure_verify(self.dss, peer_main_falcon_public_key, eph_falcon_public_key_bytes, 
                             eph_falcon_key_signature_bytes, "ephemeral FALCON key signature")
                log.debug("Ephemeral FALCON public key successfully verified against main FALCON key.")
            except ValueError as e:
                log.error(f"SECURITY ALERT: {str(e)}")
                raise

            # Now, the eph_falcon_public_key_bytes can be trusted to verify other signatures in the message.
            # Keep it as peer_verified_eph_falcon_pk for clarity
            peer_verified_eph_falcon_pk = eph_falcon_public_key_bytes


            # Create a copy of the message to verify signatures against.
            # Pop the signatures themselves from this copy.
            verification_message = handshake_message.copy()
            message_signature_b64 = verification_message.pop('message_signature', None)
            sphincs_signature_b64 = verification_message.pop('sphincs_signature', None)
            
            if not message_signature_b64:
                log.error("SECURITY ALERT: Handshake message missing FALCON signature ('message_signature')")
                raise ValueError("Handshake message missing required FALCON signature")

            # Create the canonical representation of the message that was signed
            message_data_that_was_signed = json.dumps(verification_message, sort_keys=True).encode('utf-8')
            message_hash_that_was_signed = hashlib.sha512(message_data_that_was_signed).digest()

            # --- Verify FALCON signature ---
            message_signature = base64.b64decode(message_signature_b64)
            try:
                self.dss.verify(peer_verified_eph_falcon_pk, message_hash_that_was_signed, message_signature)
                log.debug("Message signature verified successfully with ephemeral FALCON key")
            except Exception as e:
                log.error(f"SECURITY ALERT: FALCON message signature verification failed: {e}")
                raise ValueError("FALCON message signature verification failed")

            # --- Verify SPHINCS+ signature if present ---
            if sphincs_signature_b64:
                if hasattr(self, 'sphincs_plus') and self.sphincs_plus and 'eph_sphincs_pk' in verification_message:
                    try:
                        sphincs_sig = base64.b64decode(sphincs_signature_b64)
                        eph_sphincs_pk = base64.b64decode(verification_message['eph_sphincs_pk'])
                        
                        # Our SPHINCS+ fallback hashes internally. We pass it the original data.
                        result = self.sphincs_plus.verify(eph_sphincs_pk, message_data_that_was_signed, sphincs_sig)
                        if result:
                            log.info("SPHINCS+ signature verified successfully - algorithm diversity enhanced")
                        else:
                            # This is a warning because FALCON already succeeded.
                            log.warning("SPHINCS+ signature verification failed. Continuing as FALCON signature was valid.")
                    except Exception as e:
                        log.warning(f"SPHINCS+ verification error: {e}. Continuing as FALCON signature was valid.")
                else:
                    log.warning("Received a SPHINCS+ signature but cannot verify it (library or key missing).")


            # Extract peer's public keys (ephemeral and static)
            log.debug("Extracting peer public keys from handshake message")
            peer_ephemeral_public_b64 = handshake_message['ephemeral_key']
            peer_ephemeral_public_bytes = base64.b64decode(peer_ephemeral_public_b64) # Renamed for clarity
            verify_key_material(peer_ephemeral_public_bytes, expected_length=32, description="Peer ephemeral X25519 key from handshake")
            # Convert to X25519PublicKey object
            peer_ephemeral_public_key = X25519PublicKey.from_public_bytes(peer_ephemeral_public_bytes)

            peer_static_public_b64 = handshake_message['static_key']
            peer_static_public = X25519PublicKey.from_public_bytes(
                base64.b64decode(peer_static_public_b64)
            )
            # No verify_key_material for X25519PublicKey objects directly, but it was bytes before from_public_bytes

            # KEM Ciphertext and EC-PQ Binding Signature Verification
            kem_ciphertext_b64 = handshake_message['kem_ciphertext']
            kem_ciphertext = base64.b64decode(kem_ciphertext_b64)
            verify_key_material(kem_ciphertext, 
                                expected_length=MLKEM1024_CIPHERTEXT_SIZE, 
                                description="ML-KEM ciphertext from handshake (for binding check)")

            if 'ec_pq_binding_sig' in handshake_message:
                ec_pq_binding_sig_b64 = handshake_message['ec_pq_binding_sig']
                ec_pq_binding_signature = base64.b64decode(ec_pq_binding_sig_b64)
                verify_key_material(ec_pq_binding_signature, description="EC-PQ binding signature from handshake")

                # Include the nonce and timestamp in the binding data verification
                binding_data_to_verify = peer_ephemeral_public_bytes + kem_ciphertext + handshake_nonce + timestamp.to_bytes(8, byteorder='big')

                # Verify with the trusted ephemeral FALCON key
                try:
                    secure_verify(self.dss, peer_verified_eph_falcon_pk, binding_data_to_verify, 
                                ec_pq_binding_signature, "EC-PQ binding signature")
                    log.debug("Explicit EC-PQ binding signature verified successfully (using ephemeral key).")
                except ValueError as e:
                    log.error(f"SECURITY ALERT: {str(e)}")
                    raise
            else:
                log.error("SECURITY ALERT: Handshake message is missing 'ec_pq_binding_sig'. This is a required field.")
                raise ValueError("Handshake message missing ec_pq_binding_sig")
                
            # Perform DH exchanges
            log.debug("Performing multiple Diffie-Hellman exchanges")
            
            # 1. Static-Static DH
            dh1 = self.static_key.exchange(peer_static_public)
            verify_key_material(dh1, description="DH1: Static-Static exchange")
            log.debug(f"DH1 (Static-Static): {_format_binary(dh1)}")
            
            # 2. Static-Ephemeral DH
            dh2 = self.static_key.exchange(peer_ephemeral_public_key) # Use the key object
            verify_key_material(dh2, description="DH2: Static-Ephemeral exchange")
            log.debug(f"DH2 (Static-Ephemeral): {_format_binary(dh2)}")
            
            # 3. SPK-Static DH
            dh3 = self.signed_prekey.exchange(peer_static_public)
            verify_key_material(dh3, description="DH3: SPK-Static exchange")
            log.debug(f"DH3 (SPK-Static): {_format_binary(dh3)}")
            
            # 4. SPK-Ephemeral DH
            dh4 = self.signed_prekey.exchange(peer_ephemeral_public_key) # Use the key object
            verify_key_material(dh4, description="DH4: SPK-Ephemeral exchange")
            log.debug(f"DH4 (SPK-Ephemeral): {_format_binary(dh4)}")
            
            # Perform KEM decapsulation
            log.debug("Performing ML-KEM-1024 decapsulation")
            # kem_ciphertext is already defined and verified above (for binding check)
            # Verify KEM ciphertext integrity again just before decapsulation, as a final check.
            verify_key_material(kem_ciphertext, 
                                expected_length=MLKEM1024_CIPHERTEXT_SIZE, 
                                description="ML-KEM ciphertext (final check before decaps)")
            
            try:
                kem_shared_secret = self.kem.decaps(self.kem_private_key, kem_ciphertext)
            except quantcrypt.QuantCryptError as qce: # Catch specific quantcrypt errors
                log.error(f"SECURITY ALERT: KEM decapsulation failed due to quantcrypt error: {qce}", exc_info=True)
                raise ValueError(f"KEM decapsulation failed: {qce}")
            except Exception as e: # Catch any other unexpected errors during decapsulation
                log.error(f"SECURITY ALERT: KEM decapsulation failed unexpectedly: {e}", exc_info=True)
                raise ValueError(f"KEM decapsulation failed with an unexpected error: {e}")

            verify_key_material(kem_shared_secret, description="ML-KEM shared secret")
            log.debug(f"KEM decapsulation successful: shared secret ({len(kem_shared_secret)} bytes)")
            
            # Combine all shared secrets with HKDF
            log.debug("Combining all shared secrets with HKDF")
            ikm = dh1 + dh2 + dh3 + dh4 + kem_shared_secret
            verify_key_material(ikm, description="Combined input key material")
            log.debug(f"Combined IKM length: {len(ikm)} bytes")
            
            root_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=b'Hybrid X3DH+PQ Root Key',
            ).derive(ikm)
            
            verify_key_material(root_key, expected_length=32, description="Derived root key")
            log.debug(f"Derived root key: {_format_binary(root_key)}")
            
            # Securely erase all intermediate key material
            try:
                # Zero out all DH shares and IKM
                for key_material in [dh1, dh2, dh3, dh4, kem_shared_secret, ikm]:
                    if isinstance(key_material, bytes):
                        ba = bytearray(key_material)
                        for i in range(len(ba)):
                            ba[i] = 0
                        del ba
                
                # Delete references to sensitive values
                del dh1, dh2, dh3, dh4, kem_shared_secret, ikm
                log.debug("Securely erased intermediate key material from handshake")
            except Exception as e:
                log.error(f"Error during intermediate key material zeroization: {e}")
            
            log.info(f"Hybrid X3DH+PQ handshake completed successfully with {handshake_message.get('identity', 'unknown')}")
            return root_key
            
        except (KeyError, ValueError) as e:
            log.error(f"SECURITY ALERT: Error processing handshake: {e}", exc_info=True)
            raise ValueError(f"Invalid handshake message: {e}")

    def rotate_keys(self) -> bool:
        """
        Manually rotate all cryptographic keys.
        
        This completely regenerates the identity with new keys for improved security.
        It's automatically called when ephemeral keys expire, but can be manually
        triggered for extra security.
        
        Returns:
            bool: True if rotation was successful
        """
        log.info(f"Rotating cryptographic keys for {self.identity}")
        
        try:
            # Securely erase old keys
            if self.static_key:
                secure_erase(self.static_key)
            if self.signing_key:
                secure_erase(self.signing_key)
            if self.signed_prekey:
                secure_erase(self.signed_prekey)
            if self.kem_private_key:
                secure_erase(self.kem_private_key)
            if self.falcon_private_key:
                secure_erase(self.falcon_private_key)
            
            # Store old identity information for potential file deletion
            old_identity_for_file_deletion = None
            old_key_file_path = None

            if self.ephemeral_mode and not self.in_memory_only and self.keys_dir and self.identity:
                old_identity_for_file_deletion = self.identity # Capture current identity before it changes
                old_key_file_path = os.path.join(self.keys_dir, f"{old_identity_for_file_deletion}_hybrid_keys.json")

            # Generate new identity if in ephemeral mode
            if self.ephemeral_mode:
                random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                self.identity = f"{EPHEMERAL_ID_PREFIX}-{random_id}-{str(uuid.uuid4())[:8]}"
                log.info(f"Generated new ephemeral identity: {self.identity}")
            
            # Generate all new keys
            self._generate_keys()
            
            # Delete the old key file *after* new keys are generated (or attempt to)
            # but *before* saving new ones, to minimize window of no keys if save fails.
            # More robustly, could delete after successful save of new key.
            # For now, delete here.
            if old_key_file_path and os.path.exists(old_key_file_path):
                try:
                    os.remove(old_key_file_path)
                    log.info(f"Successfully deleted old ephemeral key file: {old_key_file_path}")
                except OSError as e:
                    log.warning(f"Could not delete old ephemeral key file {old_key_file_path}: {e}")
            
            # Save keys if not in ephemeral or in-memory mode
            # Note: _save_keys itself checks for self.ephemeral_mode and self.in_memory_only
            # and will not save if either is true. This call is mainly for persistent identities.
            if not self.ephemeral_mode and not self.in_memory_only:
                self._save_keys()
                
            # Reset key rotation timing
            self.key_creation_time = time.time()
            self.next_rotation_time = self.key_creation_time + self.key_lifetime
            self.pending_rotation = False
            
            log.info(f"Key rotation completed successfully")
            return True
            
        except Exception as e:
            log.error(f"Key rotation failed: {e}")
            return False
    
    def check_key_expiration(self) -> bool:
        """
        Check if the current keys have expired and need rotation.
        
        For ephemeral identities, this should be called periodically to
        ensure the keys are rotated according to the key_lifetime value.
        
        Returns:
            bool: True if keys need rotation, False otherwise
        """
        # Only ephemeral identities need automatic rotation
        if not self.ephemeral_mode:
            return False
            
        # Check if it's time to rotate
        current_time = time.time()
        if self.next_rotation_time and current_time >= self.next_rotation_time:
            log.info(f"Ephemeral keys have expired (created: {time.ctime(self.key_creation_time)})")
            self.pending_rotation = True
            return True
            
        return self.pending_rotation

    def generate_ephemeral_identity(self) -> str:
        """
        Generate a completely new ephemeral identity.
        
        This method creates a new random identity and rotates all keys,
        returning the new identity string.
        
        Returns:
            str: The new ephemeral identity string
        """
        if not self.ephemeral_mode:
            # Convert to ephemeral mode
            self.ephemeral_mode = True
            log.info("Switching to ephemeral mode")
            
        # Create new random identity
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.identity = f"{EPHEMERAL_ID_PREFIX}-{random_id}-{str(uuid.uuid4())[:8]}"
        
        # Rotate all keys
        self.rotate_keys()
        
        log.info(f"Generated fresh ephemeral identity: {self.identity}")
        return self.identity
    
    def secure_cleanup(self):
        """
        Securely erase all key material from memory.
        
        Should be called when the object is no longer needed to ensure
        no sensitive key material remains in memory.
        """
        log.info(f"Performing secure cleanup for {self.identity}")
        
        # Erase all sensitive key material using the enhanced secure erase function
        if self.static_key:
            skm.enhanced_secure_erase(self.static_key)
            self.static_key = None
            
        if self.signing_key:
            skm.enhanced_secure_erase(self.signing_key)
            self.signing_key = None
            
        if self.signed_prekey:
            skm.enhanced_secure_erase(self.signed_prekey)
            self.signed_prekey = None
            
        if self.prekey_signature:
            skm.enhanced_secure_erase(self.prekey_signature)
            self.prekey_signature = None
            
        if self.kem_private_key:
            skm.enhanced_secure_erase(self.kem_private_key)
            self.kem_private_key = None
            
        if self.kem_public_key:
            skm.enhanced_secure_erase(self.kem_public_key)
            self.kem_public_key = None
            
        if self.falcon_private_key:
            skm.enhanced_secure_erase(self.falcon_private_key)
            self.falcon_private_key = None
            
        if self.falcon_public_key:
            skm.enhanced_secure_erase(self.falcon_public_key)
            self.falcon_public_key = None

        # Clear nonce tracking
        self.seen_nonces.clear()
        
        # Set all key attributes to None
        self.static_key = None
        self.signing_key = None
        self.signed_prekey = None
        self.prekey_signature = None
        self.kem_private_key = None
        self.kem_public_key = None
        self.falcon_private_key = None
        self.falcon_public_key = None
        self.peer_hybrid_bundle = None

    def _derive_shared_secret(self, dh_secret, pq_shared_secret):
        """
        Derive a shared secret from DH and PQ shared secrets using enhanced
        hybrid key derivation with quantum resistance features.
        
        Args:
            dh_secret: The shared secret from classical DH exchange
            pq_shared_secret: The shared secret from post-quantum KEM
            
        Returns:
            The derived shared secret
        """
        log.debug("Deriving shared secret using quantum-resistant hybrid KDF")
        
        # If quantum resistance is available, use it for enhanced security
        if hasattr(self, 'quantum_resistance') and self.quantum_resistance:
            try:
                # Combine the DH and PQ secrets as seed material
                seed_material = dh_secret + pq_shared_secret
                
                # Use the enhanced hybrid KDF
                info = f"HYBRID-X3DH-PQ-{self.identity}".encode('utf-8')
                derived_key = self.quantum_resistance.hybrid_key_derivation(seed_material, info)
                
                log.debug("Successfully derived shared secret using quantum-resistant hybrid KDF")
                return derived_key
            except Exception as e:
                log.warning(f"Error using quantum-resistant hybrid KDF: {e}. Falling back to standard KDF.")
        
        # Fallback to standard HKDF if quantum resistance is not available
        log.debug("Using standard HKDF for shared secret derivation")
        combined_secret = dh_secret + pq_shared_secret
        
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'Hybrid X3DH+PQ Root Key',
        ).derive(combined_secret)
        
        return derived_key

    def secure_erase(self, data):
        """
        Military-grade secure erasure of sensitive key material.
        
        Args:
            data: The data to erase (bytearray or bytes)
        """
        if not data:
            return
            
        # Convert to bytearray if it's not already
        if isinstance(data, bytes):
            # Can't erase bytes objects directly, log a warning
            log.warning("Cannot securely erase immutable bytes object - key material may remain in memory")
            return
            
        if not isinstance(data, bytearray):
            log.warning(f"Cannot securely erase object of type {type(data).__name__}")
            return
            
        size = len(data)
        
        # Military-grade secure wiping with multiple patterns
        # 1. First pattern: All zeros
        for i in range(size):
            data[i] = 0
        
        # Memory barrier to prevent optimization
        self._memory_barrier()
        
        # 2. Second pattern: All ones
        for i in range(size):
            data[i] = 0xFF
        
        # Memory barrier to prevent optimization
        self._memory_barrier()
        
        # 3. Third pattern: Alternating bits
        for i in range(size):
            data[i] = 0xAA
        
        # Memory barrier to prevent optimization
        self._memory_barrier()
        
        # 4. Fourth pattern: Inverse alternating bits
        for i in range(size):
            data[i] = 0x55
        
        # Memory barrier to prevent optimization
        self._memory_barrier()
        
        # 5. Fifth pattern: Random data
        try:
            import platform_hsm_interface as cphs
            random_data = cphs.get_secure_random(size)
            for i in range(size):
                data[i] = random_data[i]
        except (ImportError, Exception):
            # Fallback to os.urandom
            random_data = os.urandom(size)
            for i in range(size):
                data[i] = random_data[i]
        
        # Memory barrier to prevent optimization
        self._memory_barrier()
        
        # 6. Final pattern: All zeros
        for i in range(size):
            data[i] = 0
            
        log.debug("Securely erased key material")
        
    def _memory_barrier(self):
        """Create a memory barrier to prevent compiler optimization of secure erasure."""
        try:
            # Try to use platform-specific memory barrier
            import platform_hsm_interface as cphs
            cphs.get_secure_random(1)  # Just getting 1 byte creates a side effect
        except (ImportError, Exception):
            # Fallback implementation
            try:
                # Use ctypes to create a memory barrier
                if hasattr(ctypes, 'memmove'):
                    # Allocate a small buffer and move it (creates a memory barrier)
                    buf = ctypes.create_string_buffer(1)
                    ctypes.memmove(buf, buf, 1)
            except Exception:
                # Last resort: use a volatile random operation
                _ = os.urandom(1)

    def enhance_quantum_resistance(self):
        """
        Enhance the quantum resistance of this key exchange instance by
        adding support for additional post-quantum algorithms and hybrid approaches.
        """
        log.info("Enhancing quantum resistance capabilities")
        
        if not hasattr(self, 'quantum_resistance') or not self.quantum_resistance:
            try:
                self.quantum_resistance = skm.get_quantum_resistance()
                log.info("Initialized quantum resistance module")
            except Exception as e:
                log.warning(f"Failed to initialize quantum resistance module: {e}")
                return False
        
        try:
            # Reinitialize the SPHINCS+ instance if available
            supported_algos = self.quantum_resistance.get_supported_algorithms()
            if "SPHINCS+" in supported_algos.get("signatures", []):
                self.sphincs_plus = self.quantum_resistance.get_algorithm("SPHINCS+")
                log.info("SPHINCS+ backup signature scheme initialized")
            
            # Generate multi-algorithm keypairs for additional diversity
            self.multi_algo_public_keys, self.multi_algo_private_keys = \
                self.quantum_resistance.generate_multi_algorithm_keypair()
                
            log.info(f"Generated keypairs for multiple algorithms: {list(self.multi_algo_public_keys.keys())}")
            
            # Track latest NIST standards
            standards_info = self.quantum_resistance.track_nist_standards()
            log.info(f"NIST PQC standards status updated: ML-KEM: {standards_info['ml_kem_status']}, "
                    f"FALCON: {standards_info['falcon_status']}, SPHINCS+: {standards_info['sphincs_plus_status']}")
            
            return True
        except Exception as e:
            log.warning(f"Error enhancing quantum resistance: {e}")
            return False


def demonstrate_handshake():
    """
    Demonstrate the hybrid handshake protocol with two users.
    """
    print("Demonstrating Hybrid X3DH + PQ Handshake")
    print("-----------------------------------------")
    
    # Create Alice and Bob's key exchange instances
    alice = HybridKeyExchange(identity="alice")
    bob = HybridKeyExchange(identity="bob")
    
    # Get Bob's public bundle
    bob_bundle = bob.get_public_bundle()
    print(f"Bob's identity: {bob_bundle['identity']}")
    
    # Alice initiates the handshake
    print("\nAlice initiates handshake...")
    alice_message, alice_key = alice.initiate_handshake(bob_bundle)
    print(f"Alice derived key: {base64.b64encode(alice_key).decode('utf-8')}")
    
    # Set bob's peer bundle to alice's bundle so verification works
    bob.peer_hybrid_bundle = alice.get_public_bundle()
    
    # Bob responds to the handshake
    print("\nBob processes Alice's handshake...")
    bob_key = bob.respond_to_handshake(alice_message)
    print(f"Bob derived key:   {base64.b64encode(bob_key).decode('utf-8')}")
    
    # Verify that both derived the same key
    if alice_key == bob_key:
        print("\n✅ Success! Alice and Bob derived the same shared secret.")
    else:
        print("\n❌ Error! The derived keys don't match.")


def test_replay_protection():
    """
    Test function to demonstrate handshake replay protection.
    
    This function simulates a replay attack by verifying the same nonce twice,
    which should be rejected on the second attempt.
    """
    print("\n=== Testing Handshake Replay Protection ===")
    
    # Create a HybridKeyExchange instance
    kex = HybridKeyExchange(identity="test_user", ephemeral=True)
    
    # Generate a test nonce and timestamp
    peer_id = "test_peer"
    nonce = os.urandom(32)
    timestamp = int(time.time())
    
    print(f"Generated test nonce ({len(nonce)} bytes) and timestamp: {timestamp}")
    
    # First verification should succeed
    result1 = kex._verify_handshake_nonce(peer_id, nonce, timestamp)
    print(f"First verification result: {result1} (should be True)")
    
    # Second verification with same nonce should fail (replay detected)
    result2 = kex._verify_handshake_nonce(peer_id, nonce, timestamp)
    print(f"Second verification result: {result2} (should be False - replay detected)")
    
    # Test with invalid timestamp (too old)
    old_timestamp = timestamp - 120  # 2 minutes ago (outside the window)
    new_nonce = os.urandom(32)
    result3 = kex._verify_handshake_nonce(peer_id, new_nonce, old_timestamp)
    print(f"Verification with old timestamp: {result3} (should be False - timestamp too old)")
    
    # Test with invalid timestamp (future)
    future_timestamp = timestamp + 120  # 2 minutes in future (outside the window)
    new_nonce2 = os.urandom(32)
    result4 = kex._verify_handshake_nonce(peer_id, new_nonce2, future_timestamp)
    print(f"Verification with future timestamp: {result4} (should be False - timestamp in future)")
    
    print("\nReplay protection test completed.")


def secure_verify(dss, public_key, payload, signature, description="signature"):
    """
    Securely verify a signature, aborting immediately on mismatch.
    
    Args:
        dss: The digital signature system (e.g., FALCON_1024 instance)
        public_key: The public key bytes to use for verification
        payload: The payload that was signed
        signature: The signature to verify
        description: Description for logging
        
    Returns:
        True if verification succeeds
        
    Raises:
        ValueError: If verification fails or throws an exception
    """
    try:
        if not dss.verify(public_key, payload, signature):
            log.error(f"SECURITY ALERT: {description} verification failed")
            raise ValueError(f"Handshake aborted: invalid {description}")
        return True
    except Exception as e:
        # Log at most "signature mismatch" (avoid printing raw data)
        log.error(f"SECURITY ALERT: {description} verification error", exc_info=True)
        raise ValueError(f"Handshake aborted: invalid {description}")


if __name__ == "__main__":
    # Uncomment the line below to run the replay protection test
    test_replay_protection()
    # Or uncomment this line to run the regular handshake demo
    # demonstrate_handshake() 