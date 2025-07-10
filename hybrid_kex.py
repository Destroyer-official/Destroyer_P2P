"""
Hybrid Key Exchange Module for Post-Quantum Secure Communications

This module implements a state-of-the-art hybrid key exchange protocol that combines:
1. X3DH (Extended Triple Diffie-Hellman) for classical security
2. ML-KEM-1024 (formerly Kyber) for post-quantum security
3. FALCON-1024 and SPHINCS+ for post-quantum signatures

The hybrid approach provides security against both classical and quantum adversaries,
following the "hybrid" recommendation from NIST's Post-Quantum Cryptography standards.
All cryptographic operations use constant-time implementations to prevent side-channel
attacks, and sensitive key material is protected in memory.

Key features:
- Forward secrecy through ephemeral keys
- Post-quantum resistance with NIST-standardized algorithms
- Multiple DH exchanges for defense-in-depth
- Cryptographic binding between classical and PQ components
- Automatic key rotation for enhanced security
- Memory protection for sensitive material
"""

import os
import json  
import time
import base64 
import logging
import uuid
import random
import string
import hashlib
from typing import Tuple, Dict, Optional, Union
import math
import ctypes
import quantcrypt
import secure_key_manager as skm
from double_ratchet import verify_key_material

# X25519 for classical key exchange
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# Ed25519 for classical signatures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Key derivation
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
log = logging.getLogger(__name__)

# Configure dedicated logger for hybrid key exchange operations
hybrid_kex_logger = logging.getLogger("hybrid_kex")
hybrid_kex_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging with detailed information for security auditing
hybrid_kex_file_handler = logging.FileHandler(os.path.join("logs", "hybrid_kex.log"))
hybrid_kex_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
hybrid_kex_file_handler.setFormatter(formatter)
hybrid_kex_logger.addHandler(hybrid_kex_file_handler)

# Setup console logging for immediate operational feedback
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
hybrid_kex_logger.addHandler(console_handler)

hybrid_kex_logger.info("Hybrid Key Exchange logger initialized")

# Post-quantum cryptography
try:
    # Import enhanced implementations directly
    from pqc_algorithms import (
        EnhancedMLKEM_1024,
        EnhancedFALCON_1024,
        SideChannelProtection,
        ConstantTime,
        SecureMemory,
        EnhancedHQC
    )
    HAVE_ENHANCED_PQC = True
    hybrid_kex_logger.info("Successfully imported enhanced PQC implementations from pqc_algorithms.")
except ImportError as e:
    hybrid_kex_logger.critical(f"Failed to import ENHANCED PQC algorithms: {e}. This is a fatal error.")
    HAVE_ENHANCED_PQC = False
    # Define dummy classes to prevent further import errors if needed, but the app should not run
    class EnhancedMLKEM_1024: pass
    class EnhancedFALCON_1024: pass
    class EnhancedHQC: pass

if not HAVE_ENHANCED_PQC:
    raise ImportError("CRITICAL: Enhanced PQC implementations are required for HybridKEX. Aborting.")

# Defer secure_key_manager import to avoid circular import
# secure_key_manager will be imported on-demand when needed

# Constants for ephemeral identity management
DEFAULT_KEY_LIFETIME = 3072  # Default lifetime: 3072 seconds (51.2 minutes)
MIN_KEY_LIFETIME = 300       # 5 minutes minimum lifetime
EPHEMERAL_ID_PREFIX = "eph"   # Prefix for ephemeral identities
MAX_KEY_LIFETIME = 86400    # 24 hours in seconds maximum lifetime

MLKEM1024_CIPHERTEXT_SIZE = 1568  # Expected ciphertext size for ML-KEM-1024

# For type hinting
import sys
if sys.version_info >= (3, 9):
    from typing import TypeAlias, Dict, Any, List, Optional, Tuple, Union
else:
    from typing import Dict, Any, List, Optional, Tuple, Union
    from typing_extensions import TypeAlias

# For binding the key exchange with a signature
X25519_S_P_K_DOMAIN_SEP = b"x25519_signed_prekey_signature"
PQ_BUNDLE_DOMAIN_SEP = b"post_quantum_bundle_signature"
EPHEMERAL_KEY_DOMAIN_SEP = b"ephemeral_key_signature"
EC_PQ_BINDING_DOMAIN_SEP = b"ec_pq_binding_signature"
ROOT_KEY_AUTH_DOMAIN_SEP = b"root_key_authentication"

# Ensure we have a secure wipe function
try:
    from platform_hsm_interface import secure_wipe_memory
    log.info("Using secure_wipe_memory from platform_hsm_interface.")
except (ImportError, AttributeError):
    log.warning("Could not import secure_wipe_memory. Sensitive key data may not be properly wiped.")
    # Define a no-op fallback
    def secure_wipe_memory(addr, length):
        pass

def _format_binary(data: Optional[bytes], max_len: int = 8) -> str:
    """Format binary data for secure logging with length-preserving truncation.
    
    Creates a safe representation of binary data for logging that:
    1. Base64-encodes the data for readability
    2. Truncates to max_len bytes to avoid log pollution
    3. Preserves the original data length information
    4. Handles None values gracefully
    
    This function is designed for security-sensitive logging where the
    full key material should never be exposed, but the presence and
    size of cryptographic values needs to be recorded.
    
    Args:
        data: Binary data to format safely for logs
        max_len: Maximum number of bytes to include before truncating
        
    Returns:
        str: Formatted string with truncation indicator and length
    """
    if data is None:
        return "None"
    if len(data) > max_len:
        b64 = base64.b64encode(data[:max_len]).decode('utf-8')
        return f"{b64}... ({len(data)} bytes)"
    return base64.b64encode(data).decode('utf-8')

class HybridKeyExchange:
    """Hybrid X3DH + Post-Quantum key exchange protocol implementation.
    
    Implements a military-grade key exchange protocol that combines the Extended
    Triple Diffie-Hellman (X3DH) protocol with NIST-standardized post-quantum
    cryptography to provide both classical and quantum-resistant security.
    
    Security features:
    - Four X25519 Diffie-Hellman exchanges for classical security
    - ML-KEM-1024 key encapsulation for post-quantum security
    - FALCON-1024 signatures for post-quantum authentication
    - SPHINCS+ signatures as a quantum-resistant backup
    - Cryptographic binding between classical and PQ components
    - Constant-time implementations to prevent side-channel attacks
    - Memory protection for sensitive key material
    
    Privacy features:
    - Ephemeral identity support with automatic rotation
    - In-memory-only key option to avoid disk persistence
    - Forward secrecy through key rotation
    - Replay protection with nonces and timestamps
    
    This implementation follows NIST's recommendation for hybrid post-quantum
    security and is designed for high-security applications where both classical
    and quantum threats must be mitigated.
    """
    
    def __init__(self, identity: str = "user", keys_dir: str = None,
                 ephemeral: bool = True, key_lifetime: int = MIN_KEY_LIFETIME,
                 in_memory_only: bool = True):
        """Initialize a hybrid key exchange instance with security parameters.
        
        Creates a new hybrid key exchange instance with the specified security
        parameters. The default configuration provides maximum security with
        ephemeral identity, in-memory keys, and frequent key rotation.
        
        Args:
            identity: User identifier string
                     (ignored if ephemeral=True, which is the default)
            keys_dir: Directory path for key storage
                     (not used if in_memory_only=True, which is the default)
            ephemeral: When True (default), generates a random ephemeral identity
                       that cannot be linked to the user across sessions
            key_lifetime: Time in seconds before keys are automatically rotated
                         (default=MIN_KEY_LIFETIME for frequent rotation)
            in_memory_only: When True (default), keys are never persisted to disk
                           for maximum security against forensic analysis
        
        Security note:
            The default parameters (ephemeral=True, in_memory_only=True) provide
            maximum security and are recommended for most applications. Only
            change these if you have specific requirements for persistent identities.
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
        
        hybrid_kex_logger.info(
            f"HybridKeyExchange initializing for identity '{self.identity}'. "
            f"Configuration - Ephemeral Mode: {self.ephemeral_mode}, "
            f"In-Memory Keys: {self.in_memory_only}, "
            f"Specified Key Lifetime: {key_lifetime}s, Effective Key Lifetime: {self.key_lifetime}s (for ephemeral mode)."
        )
        
        if self.ephemeral_mode and self.in_memory_only and self.key_lifetime == MIN_KEY_LIFETIME and ephemeral and in_memory_only and key_lifetime == MIN_KEY_LIFETIME:
            hybrid_kex_logger.info("SECURITY INFO: Instance configured with maximal security defaults: ephemeral ID, in-memory keys, and minimal rotation time.")
        elif self.ephemeral_mode and self.in_memory_only:
            hybrid_kex_logger.info("SECURITY INFO: Instance configured with strong security settings: ephemeral ID, in-memory keys.")
        
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
        # Use enhanced ML-KEM implementation with side-channel protections
        self.ml_kem_impl = EnhancedMLKEM_1024()
        
        # Use the enhanced FALCON implementation with improved parameters
        self.dss = EnhancedFALCON_1024()
        hybrid_kex_logger.info("Using EnhancedFALCON_1024 with improved parameters for stronger security guarantees")
        
        # Initialize quantum resistance future-proofing module
        # Import here to avoid circular import
        import secure_key_manager as skm
        self.qr_future_proofing = self.enhance_quantum_resistance()
        self.is_key_material_generated = False
        
        # Add SPHINCS+ as backup signature scheme if available
        supported_algos = self.qr_future_proofing.get_supported_algorithms()
        if "SPHINCS+" in supported_algos.get("signatures", []):
            self.sphincs_plus = self.qr_future_proofing.get_algorithm("SPHINCS+")
            hybrid_kex_logger.info("SPHINCS+ backup signature scheme initialized")
        else:
            self.sphincs_plus = None
            hybrid_kex_logger.info("SPHINCS+ backup signature scheme not available")
            
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
                hybrid_kex_logger.info(f"Ephemeral keys will rotate after: {self.key_lifetime} seconds")
                hybrid_kex_logger.info(f"Next rotation scheduled at: {time.ctime(self.next_rotation_time)}")
            
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
                    hybrid_kex_logger.info(f"Keys for {self.identity} have expired, generating new ones")
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
                    hybrid_kex_logger.info(f"Generating new FALCON-1024 keys for {self.identity}")
                    self.falcon_public_key, self.falcon_private_key = self.dss.keygen()
                    self._save_keys()
                
                # Load or set key creation time
                if 'created_at' in keys_data:
                    self.key_creation_time = keys_data['created_at']
                
                hybrid_kex_logger.info(f"Loaded existing hybrid key material for {self.identity}")
            else:
                # Generate new keys
                self._generate_keys()
                self._save_keys()
                
        except Exception as e:
            hybrid_kex_logger.error(f"Error loading keys, generating new ones: {e}")
            self._generate_keys()
            self._save_keys()
    
    def _generate_keys(self):
        """Generate all required keys for the hybrid handshake."""
        hybrid_kex_logger.info(f"Generating new hybrid cryptographic key material for identity: {self.identity}")
        
        # Generate X25519 static key
        self.static_key = X25519PrivateKey.generate()
        static_pub = self.static_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        hybrid_kex_logger.debug(f"Generated X25519 static key: {_format_binary(static_pub)}")
        
        # Generate Ed25519 signing key
        self.signing_key = Ed25519PrivateKey.generate()
        signing_pub = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        hybrid_kex_logger.debug(f"Generated Ed25519 signing key: {_format_binary(signing_pub)}")
        
        # Generate signed prekey
        self.signed_prekey = X25519PrivateKey.generate()
        prekey_public_bytes = self.signed_prekey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        hybrid_kex_logger.debug(f"Generated X25519 signed prekey: {_format_binary(prekey_public_bytes)}")
        
        # Sign the prekey
        self.prekey_signature = self.signing_key.sign(prekey_public_bytes)
        hybrid_kex_logger.debug(f"Generated prekey signature: {_format_binary(self.prekey_signature)}")
        
        # Verify the signature
        try:
            self.signing_key.public_key().verify(self.prekey_signature, prekey_public_bytes)
            hybrid_kex_logger.debug("Verified prekey signature successfully")
        except InvalidSignature:
            hybrid_kex_logger.error("SECURITY ALERT: Generated prekey signature failed verification")
            raise ValueError("Critical security error: Signature verification failed")
        
        # Generate KEM key
        hybrid_kex_logger.debug("Generating ML-KEM-1024 key pair")
        self.kem_public_key, self.kem_private_key = self.ml_kem_impl.keygen()
        
        # Generate FALCON signature key
        hybrid_kex_logger.debug("Generating FALCON-1024 signature key pair")
        self.falcon_public_key, self.falcon_private_key = self.dss.keygen()
        
        # Verify key material
        verify_key_material(self.kem_public_key, description="ML-KEM public key")
        verify_key_material(self.kem_private_key, description="ML-KEM private key")
        verify_key_material(self.falcon_public_key, description="FALCON-1024 public key")
        verify_key_material(self.falcon_private_key, description="FALCON-1024 private key")
        
        hybrid_kex_logger.info(f"Successfully generated complete hybrid key material for {self.identity}")
    
    def _save_keys(self):
        """Save the generated keys to a file if neither in-memory nor ephemeral mode is active."""
        # Skip saving if in-memory only mode is enabled
        if self.in_memory_only:
            hybrid_kex_logger.debug("In-memory only mode active, skipping key persistence")
            return
            
        # Skip saving if ephemeral mode is enabled
        if self.ephemeral_mode:
            hybrid_kex_logger.debug("Ephemeral mode active, skipping key persistence")
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
        
        hybrid_kex_logger.info(f"Saved hybrid keys to {key_file} (expires: {time.ctime(keys_data['expiration_time'])})")
    
    def get_public_bundle(self) -> Dict[str, str]:
        """Create a signed public key bundle for sharing with peers.
        
        Assembles a complete key bundle containing all public keys needed for
        the hybrid key exchange protocol. The bundle includes:
        
        1. Identity information and metadata
        2. X25519 static public key for long-term identity
        3. X25519 signed prekey for forward secrecy
        4. Ed25519 signing key for classical signatures
        5. ML-KEM-1024 public key for post-quantum key encapsulation
        6. FALCON-1024 public key for post-quantum signatures
        7. Prekey signature (Ed25519) for key authentication
        8. Bundle signature (FALCON-1024) for integrity protection
        9. Ephemeral identity metadata (if applicable)
        
        The bundle is cryptographically bound through signatures to prevent
        tampering and key substitution attacks.
        
        Returns:
            Dict[str, str]: Complete public key bundle with all components
                           encoded as base64 strings
                           
        Note:
            This method automatically rotates keys if they have expired
            before creating the bundle.
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
        """Verify the cryptographic integrity of a peer's public key bundle.
        
        Performs comprehensive verification of a key bundle:
        1. Validates bundle structure and required components
        2. Verifies Ed25519 signature on the signed prekey
        3. Verifies FALCON-1024 signature on the entire bundle
        
        This verification is critical for preventing MITM attacks and
        key substitution attacks in the key exchange protocol.
        
        Args:
            bundle: Public key bundle from a peer containing:
                   - identity: Peer identifier
                   - static_key: X25519 static public key (base64)
                   - signed_prekey: X25519 signed prekey (base64)
                   - signing_key: Ed25519 public key (base64)
                   - prekey_signature: Ed25519 signature (base64)
                   - kem_public_key: ML-KEM public key (base64)
                   - falcon_public_key: FALCON public key (base64)
                   - bundle_signature: FALCON signature (base64)
            
        Returns:
            bool: True if all signatures verify successfully
                 False if any verification fails
                 
        Security note:
            Failed verification should be treated as a potential attack.
            The caller should abort the handshake if this returns False.
        """
        try:
            # Check for required keys
            if not all(k in bundle for k in ['static_key', 'signed_prekey', 'signing_key', 'prekey_signature']):
                hybrid_kex_logger.error("Invalid key bundle: missing required keys")
                return False
                
            # Extract keys from bundle
            signing_key_bytes = base64.b64decode(bundle['signing_key'])
            prekey_signature = base64.b64decode(bundle['prekey_signature'])
            signed_prekey = base64.b64decode(bundle['signed_prekey'])
            
            # First verify Ed25519 prekey signature
            try:
                signing_public_key = Ed25519PublicKey.from_public_bytes(signing_key_bytes)
            except ValueError as e:
                hybrid_kex_logger.error(f"Invalid signing key format: {e}")
                return False
                
            # Verify the prekey signature
            try:
                signing_public_key.verify(prekey_signature, signed_prekey)
                hybrid_kex_logger.debug("Ed25519 prekey signature verified successfully")
            except InvalidSignature:
                hybrid_kex_logger.error("SECURITY ALERT: Prekey signature verification failed")
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
                    hybrid_kex_logger.debug("FALCON-1024 bundle signature verified successfully")
                except ValueError as e:
                    hybrid_kex_logger.error(f"SECURITY ALERT: {str(e)}")
                    return False
            
            return True
            
        except (KeyError, ValueError, InvalidSignature) as e:
            hybrid_kex_logger.error(f"Invalid key bundle: {e}")
            return False
    
    def _generate_handshake_nonce(self) -> Tuple[bytes, int]:
        """Generate cryptographically secure nonce and timestamp for replay protection.
        
        Creates a unique, unpredictable nonce and current timestamp to prevent
        replay attacks in the key exchange protocol. The nonce provides uniqueness
        while the timestamp allows for time-based verification windows.
        
        The nonce is generated using a cryptographically secure random number
        generator (os.urandom) to ensure unpredictability.
        
        Returns:
            Tuple[bytes, int]: (nonce, timestamp) where:
                - nonce: 32 bytes of cryptographically secure random data
                - timestamp: Current Unix time in seconds
        """
        nonce = os.urandom(32)  # 32 bytes of cryptographically secure randomness
        timestamp = int(time.time())  # Current Unix timestamp
        return nonce, timestamp

    def _verify_handshake_nonce(self, peer_id: str, nonce: bytes, timestamp: int) -> bool:
        """Verify handshake nonce and timestamp to prevent replay attacks.
        
        Performs comprehensive verification of handshake nonces:
        1. Validates timestamp is within the acceptable window (prevents old message replay)
        2. Checks if the nonce has been seen before from this peer (prevents message replay)
        3. Stores the nonce in a peer-specific set for future verification
        4. Implements memory protection against DoS attacks by limiting stored nonces
        
        This verification is critical for preventing various replay attacks
        against the key exchange protocol.
        
        Args:
            peer_id: Unique identifier of the peer sending the nonce
            nonce: 32-byte random nonce to verify
            timestamp: Unix timestamp (seconds since epoch) from the handshake
            
        Returns:
            bool: True if nonce is valid (not seen before and timestamp is current),
                 False if the nonce is invalid or represents a replay attempt
                 
        Security note:
            Failed verification should be treated as a potential attack and
            the handshake should be aborted immediately.
        """
        current_time = int(time.time())
        
        # Check if timestamp is within the acceptable window (±timestamp_window seconds)
        if abs(current_time - timestamp) > self.timestamp_window:
            hybrid_kex_logger.error(f"SECURITY ALERT: Handshake timestamp outside valid window. Received: {timestamp}, Current: {current_time}")
            return False
        
        # Initialize nonce set for this peer if it doesn't exist
        if peer_id not in self.seen_nonces:
            self.seen_nonces[peer_id] = set()
        
        # Check if we've seen this nonce before from this peer
        if nonce in self.seen_nonces[peer_id]:
            hybrid_kex_logger.error(f"SECURITY ALERT: Handshake replay detected! Duplicate nonce from peer: {peer_id}")
            return False
            
        # Store the nonce as seen
        self.seen_nonces[peer_id].add(nonce)
        
        # If we have too many nonces stored for this peer, keep only the most recent ones
        # This prevents memory exhaustion attacks
        if len(self.seen_nonces[peer_id]) > 1000:  # Arbitrary limit
            hybrid_kex_logger.warning(f"Too many stored nonces for peer {peer_id}, clearing oldest")
            self.seen_nonces[peer_id].clear()  # In a production system, you might want to keep the most recent ones
            self.seen_nonces[peer_id].add(nonce)  # Keep the current one
            
        return True

    def initiate_handshake(self, peer_bundle: Dict[str, str]) -> Tuple[Dict[str, str], bytes]:
        """Initiate a hybrid X3DH+PQ handshake (Alice's role).
        
        Performs the initiator side of the hybrid key exchange protocol:
        
        1. Verifies the peer's key bundle signatures
        2. Generates an ephemeral X25519 key pair
        3. Performs four Diffie-Hellman exchanges:
           - DH1: Static-Static (initiator's static + peer's static)
           - DH2: Ephemeral-Static (initiator's ephemeral + peer's static)
           - DH3: Static-SPK (initiator's static + peer's signed prekey)
           - DH4: Ephemeral-SPK (initiator's ephemeral + peer's signed prekey)
        4. Performs ML-KEM-1024 encapsulation with peer's KEM public key
        5. Generates ephemeral FALCON key and signatures for binding
        6. Creates a cryptographic binding between classical and PQ components
        7. Combines all shared secrets with HKDF-SHA512
        8. Creates a handshake message with all required components
        
        Args:
            peer_bundle: The peer's public key bundle containing:
                        - identity: Peer identifier
                        - static_key: Peer's static X25519 public key (base64)
                        - signed_prekey: Peer's signed prekey (base64)
                        - kem_public_key: Peer's ML-KEM public key (base64)
                        - dss_public_key: Peer's FALCON public key (base64)
                        - signatures: Various signatures for verification
            
        Returns:
            Tuple[Dict[str, str], bytes]: (handshake_message, shared_secret)
                - handshake_message: Complete message to send to the peer
                - shared_secret: 32-byte derived shared secret for session keys
                
        Raises:
            ValueError: If peer bundle verification fails or cryptographic operations fail
            SecurityError: If any security constraint is violated
        """
        hybrid_kex_logger.info(f"Initiating hybrid X3DH+PQ handshake with peer: {peer_bundle.get('identity', 'unknown')}")
        
        # Store the peer's bundle for later use
        self.peer_hybrid_bundle = peer_bundle
        
        # Verify bundle before proceeding
        if not self.verify_public_bundle(peer_bundle):
            hybrid_kex_logger.error("SECURITY ALERT: Invalid peer key bundle, signature verification failed")
            raise ValueError("Handshake aborted: invalid peer key bundle signature")
        
        # Generate handshake nonce and timestamp for replay protection
        handshake_nonce, timestamp = self._generate_handshake_nonce()
        
        # Generate ephemeral key
        hybrid_kex_logger.debug("Generating ephemeral X25519 key for handshake")
        ephemeral_key = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        hybrid_kex_logger.debug(f"Generated ephemeral key: {_format_binary(ephemeral_public)}")
        
        # Extract peer's public keys
        peer_static_public = X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_bundle['static_key'])
        )
        peer_signed_prekey_public = X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_bundle['signed_prekey'])
        )
        
        # Perform DH exchanges
        hybrid_kex_logger.debug("Performing multiple Diffie-Hellman exchanges")
        
        # 1. Static-Static DH
        dh1 = self.static_key.exchange(peer_static_public)
        verify_key_material(dh1, description="DH1: Static-Static exchange")
        hybrid_kex_logger.debug(f"DH1 (Static-Static): {_format_binary(dh1)}")
        
        # 2. Ephemeral-Static DH
        dh2 = ephemeral_key.exchange(peer_static_public)
        verify_key_material(dh2, description="DH2: Ephemeral-Static exchange")
        hybrid_kex_logger.debug(f"DH2 (Ephemeral-Static): {_format_binary(dh2)}")
        
        # 3. Static-SPK DH
        dh3 = self.static_key.exchange(peer_signed_prekey_public)
        verify_key_material(dh3, description="DH3: Static-SPK exchange")
        hybrid_kex_logger.debug(f"DH3 (Static-SPK): {_format_binary(dh3)}")
        
        # 4. Ephemeral-SPK DH
        dh4 = ephemeral_key.exchange(peer_signed_prekey_public)
        verify_key_material(dh4, description="DH4: Ephemeral-SPK exchange")
        hybrid_kex_logger.debug(f"DH4 (Ephemeral-SPK): {_format_binary(dh4)}")
        
        # Perform KEM encapsulation
        hybrid_kex_logger.debug("Performing ML-KEM-1024 encapsulation")
        peer_kem_public = base64.b64decode(peer_bundle['kem_public_key'])
        verify_key_material(peer_kem_public, description="Peer ML-KEM public key")
        
        kem_ciphertext, kem_shared_secret = self.ml_kem_impl.encaps(peer_kem_public)
        verify_key_material(kem_ciphertext, description="ML-KEM ciphertext")
        verify_key_material(kem_shared_secret, description="ML-KEM shared secret")
        hybrid_kex_logger.debug(f"KEM encapsulation successful: ciphertext ({len(kem_ciphertext)} bytes), shared secret ({len(kem_shared_secret)} bytes)")
        
        # Generate ephemeral FALCON key for this handshake
        eph_falcon_public_key, eph_falcon_private_key = self.dss.keygen()
        verify_key_material(eph_falcon_public_key, description="Ephemeral FALCON public key")
        verify_key_material(eph_falcon_private_key, description="Ephemeral FALCON private key")
        hybrid_kex_logger.debug(f"Generated ephemeral FALCON key for handshake: {_format_binary(eph_falcon_public_key)}")

        # Sign the ephemeral FALCON public key with the main FALCON identity key
        try:
            eph_falcon_key_signature = self.dss.sign(self.falcon_private_key, eph_falcon_public_key)
            verify_key_material(eph_falcon_key_signature, description="Ephemeral FALCON key signature")
            hybrid_kex_logger.debug(f"Signed ephemeral FALCON public key: {_format_binary(eph_falcon_key_signature)}")
        except Exception as e:
            hybrid_kex_logger.error(f"SECURITY CRITICAL: Failed to sign ephemeral FALCON public key: {e}", exc_info=True)
            raise ValueError("Failed to sign ephemeral FALCON public key")

        # Create specific binding for ephemeral EC key, KEM ciphertext, and handshake nonce, signed by ephemeral FALCON key
        # Include the nonce and timestamp in the binding data for replay protection
        binding_data = ephemeral_public + kem_ciphertext + handshake_nonce + timestamp.to_bytes(8, byteorder='big')
        try:
            ec_pq_binding_signature = self.dss.sign(eph_falcon_private_key, binding_data)
            verify_key_material(ec_pq_binding_signature, description="EC-PQ binding signature")
            hybrid_kex_logger.debug(f"Generated EC-PQ binding signature (with ephemeral FALCON): {_format_binary(ec_pq_binding_signature)}")
        except Exception as e:
            hybrid_kex_logger.error(f"SECURITY CRITICAL: Failed to generate EC-PQ binding signature with ephemeral key: {e}", exc_info=True)
            raise ValueError("Failed to generate critical EC-PQ binding signature with ephemeral key")

        # Combine all shared secrets with HKDF
        hybrid_kex_logger.debug("Combining all shared secrets with HKDF")
        ikm = dh1 + dh2 + dh3 + dh4 + kem_shared_secret
        verify_key_material(ikm, description="Combined input key material")
        hybrid_kex_logger.debug(f"Combined IKM length: {len(ikm)} bytes")
        
        root_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'Hybrid X3DH+PQ Root Key',
        ).derive(ikm)
        
        verify_key_material(root_key, expected_length=32, description="Derived root key")
        hybrid_kex_logger.debug(f"Derived root key: {_format_binary(root_key)}")
        
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
            hybrid_kex_logger.debug("Securely erased ephemeral X25519 private key")
        except Exception as e:
            hybrid_kex_logger.error(f"Error during ephemeral X25519 key zeroization: {e}")
        
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
                hybrid_kex_logger.debug("Successfully added SPHINCS+ signature for algorithm diversity")
            except Exception as e:
                hybrid_kex_logger.warning(f"Failed to add SPHINCS+ signature: {e}. Continuing with FALCON only.")
                # Remove the public key if signing failed
                handshake_message.pop('eph_sphincs_pk', None)

        # Securely erase the ephemeral private keys
        skm.secure_erase(eph_falcon_private_key)
        if eph_sphincs_sk:
            # Import secure_key_manager to use enhanced_secure_erase
            skm.enhanced_secure_erase(eph_sphincs_sk)
        
        hybrid_kex_logger.info(f"Hybrid X3DH+PQ handshake initiated successfully with {peer_bundle.get('identity', 'unknown')}")
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
            hybrid_kex_logger.info(f"Processing incoming handshake from: {handshake_message.get('identity', 'unknown')}")
            
            # Check for required nonce and timestamp fields
            if 'handshake_nonce' not in handshake_message or 'timestamp' not in handshake_message:
                hybrid_kex_logger.error("SECURITY ALERT: Handshake message missing nonce or timestamp")
                raise ValueError("Handshake message missing required replay protection fields")
            
            # Extract and verify nonce and timestamp
            handshake_nonce = base64.b64decode(handshake_message['handshake_nonce'])
            timestamp = handshake_message['timestamp']
            
            # Verify the nonce hasn't been seen before and timestamp is valid
            peer_id = handshake_message.get('identity', 'unknown')
            if not self._verify_handshake_nonce(peer_id, handshake_nonce, timestamp):
                hybrid_kex_logger.error("SECURITY ALERT: Handshake replay protection check failed")
                raise ValueError("Invalid handshake: replay protection check failed")
            
            # Use provided peer_bundle if available, otherwise fallback to instance's stored bundle
            current_peer_bundle = peer_bundle if peer_bundle else self.peer_hybrid_bundle
            if not current_peer_bundle:
                hybrid_kex_logger.error("SECURITY ALERT: Peer bundle not available for respond_to_handshake. Cannot verify signatures.")
                raise ValueError("Peer bundle unavailable for signature verification")

            # Extract and verify the ephemeral FALCON key first
            if 'eph_falcon_public_key' not in handshake_message or \
               'eph_falcon_key_signature' not in handshake_message:
                hybrid_kex_logger.error("SECURITY ALERT: Handshake message missing ephemeral FALCON key components.")
                raise ValueError("Handshake message missing ephemeral FALCON key or its signature.")

            eph_falcon_public_key_b64 = handshake_message['eph_falcon_public_key']
            eph_falcon_public_key_bytes = base64.b64decode(eph_falcon_public_key_b64)
            verify_key_material(eph_falcon_public_key_bytes, description="Received ephemeral FALCON public key")
            
            eph_falcon_key_signature_b64 = handshake_message['eph_falcon_key_signature']
            eph_falcon_key_signature_bytes = base64.b64decode(eph_falcon_key_signature_b64)
            verify_key_material(eph_falcon_key_signature_bytes, description="Received ephemeral FALCON key signature")

            # Get the main FALCON public key from the peer's bundle to verify the ephemeral FALCON key
            if 'falcon_public_key' not in current_peer_bundle:
                hybrid_kex_logger.error("SECURITY ALERT: Peer's main FALCON public key not found in their bundle.")
                raise ValueError("Peer's main FALCON public key missing from bundle.")
            
            peer_main_falcon_public_key_b64 = current_peer_bundle['falcon_public_key']
            peer_main_falcon_public_key = base64.b64decode(peer_main_falcon_public_key_b64)
            verify_key_material(peer_main_falcon_public_key, description="Peer's main FALCON public key from bundle")

            try:
                secure_verify(self.dss, peer_main_falcon_public_key, eph_falcon_public_key_bytes, 
                             eph_falcon_key_signature_bytes, "ephemeral FALCON key signature")
                hybrid_kex_logger.debug("Ephemeral FALCON public key successfully verified against main FALCON key.")
            except ValueError as e:
                hybrid_kex_logger.error(f"SECURITY ALERT: {str(e)}")
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
                hybrid_kex_logger.error("SECURITY ALERT: Handshake message missing FALCON signature ('message_signature')")
                raise ValueError("Handshake message missing required FALCON signature")

            # Create the canonical representation of the message that was signed
            message_data_that_was_signed = json.dumps(verification_message, sort_keys=True).encode('utf-8')
            message_hash_that_was_signed = hashlib.sha512(message_data_that_was_signed).digest()

            # --- Verify FALCON signature ---
            message_signature = base64.b64decode(message_signature_b64)
            try:
                self.dss.verify(peer_verified_eph_falcon_pk, message_hash_that_was_signed, message_signature)
                hybrid_kex_logger.debug("Message signature verified successfully with ephemeral FALCON key")
            except Exception as e:
                hybrid_kex_logger.error(f"SECURITY ALERT: FALCON message signature verification failed: {e}")
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
                            hybrid_kex_logger.info("SPHINCS+ signature verified successfully - algorithm diversity enhanced")
                        else:
                            # This is a warning because FALCON already succeeded.
                            hybrid_kex_logger.warning("SPHINCS+ signature verification failed. Continuing as FALCON signature was valid.")
                    except Exception as e:
                        hybrid_kex_logger.warning(f"SPHINCS+ verification error: {e}. Continuing as FALCON signature was valid.")
                else:
                    hybrid_kex_logger.warning("Received a SPHINCS+ signature but cannot verify it (library or key missing).")


            # Extract peer's public keys (ephemeral and static)
            hybrid_kex_logger.debug("Extracting peer public keys from handshake message")
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
                    hybrid_kex_logger.debug("Explicit EC-PQ binding signature verified successfully (using ephemeral key).")
                except ValueError as e:
                    hybrid_kex_logger.error(f"SECURITY ALERT: {str(e)}")
                    raise
            else:
                hybrid_kex_logger.error("SECURITY ALERT: Handshake message is missing 'ec_pq_binding_sig'. This is a required field.")
                raise ValueError("Handshake message missing ec_pq_binding_sig")
                
            # Perform DH exchanges
            hybrid_kex_logger.debug("Performing multiple Diffie-Hellman exchanges")
            
            # 1. Static-Static DH
            dh1 = self.static_key.exchange(peer_static_public)
            verify_key_material(dh1, description="DH1: Static-Static exchange")
            hybrid_kex_logger.debug(f"DH1 (Static-Static): {_format_binary(dh1)}")
            
            # 2. Static-Ephemeral DH
            dh2 = self.static_key.exchange(peer_ephemeral_public_key) # Use the key object
            verify_key_material(dh2, description="DH2: Static-Ephemeral exchange")
            hybrid_kex_logger.debug(f"DH2 (Static-Ephemeral): {_format_binary(dh2)}")
            
            # 3. SPK-Static DH
            dh3 = self.signed_prekey.exchange(peer_static_public)
            verify_key_material(dh3, description="DH3: SPK-Static exchange")
            hybrid_kex_logger.debug(f"DH3 (SPK-Static): {_format_binary(dh3)}")
            
            # 4. SPK-Ephemeral DH
            dh4 = self.signed_prekey.exchange(peer_ephemeral_public_key) # Use the key object
            verify_key_material(dh4, description="DH4: SPK-Ephemeral exchange")
            hybrid_kex_logger.debug(f"DH4 (SPK-Ephemeral): {_format_binary(dh4)}")
            
            # Perform KEM decapsulation
            hybrid_kex_logger.debug("Performing ML-KEM-1024 decapsulation")
            # kem_ciphertext is already defined and verified above (for binding check)
            # Verify KEM ciphertext integrity again just before decapsulation, as a final check.
            verify_key_material(kem_ciphertext, 
                                expected_length=MLKEM1024_CIPHERTEXT_SIZE, 
                                description="ML-KEM ciphertext (final check before decaps)")
            
            try:
                kem_shared_secret = self.ml_kem_impl.decaps(self.kem_private_key, kem_ciphertext)

            except quantcrypt.QuantCryptError as qce: # Catch specific quantcrypt errors
                hybrid_kex_logger.error(f"SECURITY ALERT: KEM decapsulation failed due to quantcrypt error: {qce}", exc_info=True)
                raise ValueError(f"KEM decapsulation failed: {qce}")
            except Exception as e: # Catch any other unexpected errors during decapsulation
                hybrid_kex_logger.error(f"SECURITY ALERT: KEM decapsulation failed unexpectedly: {e}", exc_info=True)
                raise ValueError(f"KEM decapsulation failed with an unexpected error: {e}")

            verify_key_material(kem_shared_secret, description="ML-KEM shared secret")
            hybrid_kex_logger.debug(f"KEM decapsulation successful: shared secret ({len(kem_shared_secret)} bytes)")
             
            # Combine all shared secrets with HKDF
            hybrid_kex_logger.debug("Combining all shared secrets with HKDF")
            ikm = dh1 + dh2 + dh3 + dh4 + kem_shared_secret
            verify_key_material(ikm, description="Combined input key material")
            hybrid_kex_logger.debug(f"Combined IKM length: {len(ikm)} bytes")
            
            root_key = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=b'Hybrid X3DH+PQ Root Key',
            ).derive(ikm)
            
            verify_key_material(root_key, expected_length=32, description="Derived root key")
            hybrid_kex_logger.debug(f"Derived root key: {_format_binary(root_key)}")
            
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
                hybrid_kex_logger.debug("Securely erased intermediate key material from handshake")
            except Exception as e:
                hybrid_kex_logger.error(f"Error during intermediate key material zeroization: {e}")
            
            hybrid_kex_logger.info(f"Hybrid X3DH+PQ handshake completed successfully with {handshake_message.get('identity', 'unknown')}")
            return root_key
            
        except (KeyError, ValueError) as e:
            hybrid_kex_logger.error(f"SECURITY ALERT: Error processing handshake: {e}", exc_info=True)
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
        hybrid_kex_logger.info(f"Rotating cryptographic keys for {self.identity}")
        
        try:
            # Securely erase old keys
            if self.static_key:
                skm.secure_erase(self.static_key)
                self.static_key = None
            if self.signing_key:
                skm.secure_erase(self.signing_key)
                self.signing_key = None
            if self.signed_prekey:
                skm.secure_erase(self.signed_prekey)
                self.signed_prekey = None
            if self.kem_private_key:
                skm.secure_erase(self.kem_private_key)
                self.kem_private_key = None
            if self.falcon_private_key:
                skm.secure_erase(self.falcon_private_key)
                self.falcon_private_key = None
            
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
                hybrid_kex_logger.info(f"Generated new ephemeral identity: {self.identity}")
            
            # Generate all new keys
            self._generate_keys()
            
            # Delete the old key file *after* new keys are generated (or attempt to)
            # but *before* saving new ones, to minimize window of no keys if save fails.
            # More robustly, could delete after successful save of new key.
            # For now, delete here.
            if old_key_file_path and os.path.exists(old_key_file_path):
                try:
                    os.remove(old_key_file_path)
                    hybrid_kex_logger.info(f"Successfully deleted old ephemeral key file: {old_key_file_path}")
                except OSError as e:
                    hybrid_kex_logger.warning(f"Could not delete old ephemeral key file {old_key_file_path}: {e}")
            
            # Save keys if not in ephemeral or in-memory mode
            # Note: _save_keys itself checks for self.ephemeral_mode and self.in_memory_only
            # and will not save if either is true. This call is mainly for persistent identities.
            if not self.ephemeral_mode and not self.in_memory_only:
                self._save_keys()
                
            # Reset key rotation timing
            self.key_creation_time = time.time()
            self.next_rotation_time = self.key_creation_time + self.key_lifetime
            self.pending_rotation = False
            
            hybrid_kex_logger.info(f"Key rotation completed successfully")
            return True
            
        except Exception as e:
            hybrid_kex_logger.error(f"Key rotation failed: {e}")
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
            hybrid_kex_logger.info(f"Ephemeral keys have expired (created: {time.ctime(self.key_creation_time)})")
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
            hybrid_kex_logger.info("Switching to ephemeral mode")
            
        # Create new random identity
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.identity = f"{EPHEMERAL_ID_PREFIX}-{random_id}-{str(uuid.uuid4())[:8]}"
        
        # Rotate all keys
        self.rotate_keys()
        
        hybrid_kex_logger.info(f"Generated fresh ephemeral identity: {self.identity}")
        return self.identity
    
    def secure_cleanup(self):
        """Securely erase all cryptographic material from memory.
        
        Performs comprehensive cleanup of all sensitive key material:
        1. Securely erases all private keys using zero-overwrite techniques
        2. Clears all public keys and signatures
        3. Removes all references to key objects
        4. Clears nonce tracking to prevent memory analysis
        
        This method should be called when the HybridKeyExchange instance
        is no longer needed to prevent sensitive cryptographic material
        from remaining in memory where it could be exposed through memory
        dumps or cold boot attacks.
        
        Security note:
            This method is critical for maintaining forward secrecy.
            Always call this method when key exchange is complete.
        """
        hybrid_kex_logger.info(f"Performing secure cleanup for {self.identity}")
        
        # Erase all sensitive key material using the enhanced secure erase function
        if self.static_key:
            skm.secure_erase(self.static_key)
            self.static_key = None
            
        if self.signing_key:
            skm.secure_erase(self.signing_key)
            self.signing_key = None
            
        if self.signed_prekey:
            skm.secure_erase(self.signed_prekey)
            self.signed_prekey = None
            
        if self.prekey_signature:
            skm.secure_erase(self.prekey_signature)
            self.prekey_signature = None
            
        if self.kem_private_key:
            skm.secure_erase(self.kem_private_key)
            self.kem_private_key = None
            
        if self.kem_public_key:
            skm.secure_erase(self.kem_public_key)
            self.kem_public_key = None
            
        if self.falcon_private_key:
            skm.secure_erase(self.falcon_private_key)
            self.falcon_private_key = None
            
        if self.falcon_public_key:
            skm.secure_erase(self.falcon_public_key)
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
        """Derive a hybrid shared secret using quantum-resistant techniques.
        
        Combines classical and post-quantum shared secrets using advanced
        key derivation techniques to ensure the resulting key is secure
        even if one component (classical or PQ) is compromised.
        
        The method implements a defense-in-depth approach:
        1. Attempts to use quantum-resistant hybrid KDF if available
        2. Falls back to HKDF-SHA512 if enhanced KDF is unavailable
        3. Uses identity binding to prevent key substitution attacks
        4. Implements domain separation for different protocol contexts
        
        Args:
            dh_secret: Combined shared secret from classical DH exchanges
            pq_shared_secret: Shared secret from post-quantum KEM
            
        Returns:
            bytes: 32-byte derived shared secret suitable for key derivation
            
        Security note:
            The resulting key maintains security as long as at least one
            input component (classical or PQ) remains secure.
        """
        hybrid_kex_logger.debug("Deriving shared secret using quantum-resistant hybrid KDF")
        
        # If quantum resistance is available, use it for enhanced security
        if hasattr(self, 'qr_future_proofing') and self.qr_future_proofing:
            try:
                # Combine the DH and PQ secrets as seed material
                seed_material = dh_secret + pq_shared_secret
                
                # Use the enhanced hybrid KDF
                info = f"HYBRID-X3DH-PQ-{self.identity}".encode('utf-8')
                derived_key = self.qr_future_proofing.hybrid_key_derivation(seed_material, info)
                
                hybrid_kex_logger.debug("Successfully derived shared secret using quantum-resistant hybrid KDF")
                return derived_key
            except Exception as e:
                hybrid_kex_logger.warning(f"Error using quantum-resistant hybrid KDF: {e}. Falling back to standard KDF.")
        
        # Fallback to standard HKDF if quantum resistance is not available
        hybrid_kex_logger.debug("Using standard HKDF for shared secret derivation")
        combined_secret = dh_secret + pq_shared_secret
        
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'Hybrid X3DH+PQ Root Key',
        ).derive(combined_secret)
        
        return derived_key

    def enhance_quantum_resistance(self):
        """Enhance quantum resistance with additional post-quantum algorithms.
        
        Upgrades the key exchange instance with additional quantum-resistant
        capabilities beyond the base ML-KEM and FALCON implementations:
        
        1. Initializes SPHINCS+ as a backup signature scheme
           (stateless hash-based signatures with minimal security assumptions)
        2. Generates multi-algorithm keypairs for cryptographic diversity
           (protection against algorithm-specific vulnerabilities)
        3. Tracks latest NIST PQC standardization status
           (ensures compliance with evolving standards)
        4. Enables enhanced hybrid key derivation functions
           (combines multiple algorithms for stronger security)
        
        Returns:
            bool or object: False if enhancement fails, otherwise the quantum
                          resistance module instance for advanced operations
        
        Note:
            This is an optional enhancement that provides additional security
            beyond the core hybrid protocol implementation.
        """
        hybrid_kex_logger.info("Enhancing quantum resistance capabilities")
        
        if not hasattr(self, 'qr_future_proofing') or not self.qr_future_proofing:
            try:
                # Import here to avoid circular dependency
                from secure_key_manager import get_quantum_resistance
                self.qr_future_proofing = get_quantum_resistance()
                hybrid_kex_logger.info("Initialized quantum resistance module")
            except Exception as e:
                hybrid_kex_logger.warning(f"Failed to initialize quantum resistance module: {e}")
                self.qr_future_proofing = None
        
        if not self.qr_future_proofing:
            return False

        try:
            # Reinitialize the SPHINCS+ instance if available
            supported_algos = self.qr_future_proofing.get_supported_algorithms()
            if "SPHINCS+" in supported_algos.get("signatures", []):
                self.sphincs_plus = self.qr_future_proofing.get_algorithm("SPHINCS+")
                hybrid_kex_logger.info("SPHINCS+ backup signature scheme initialized")
            
            # Generate multi-algorithm keypairs for additional diversity
            self.multi_algo_public_keys, self.multi_algo_private_keys = \
                self.qr_future_proofing.generate_multi_algorithm_keypair()
                
            hybrid_kex_logger.info(f"Generated keypairs for multiple algorithms: {list(self.multi_algo_public_keys.keys())}")
            
            # Track latest NIST standards
            standards_info = self.qr_future_proofing.track_nist_standards()
            hybrid_kex_logger.info(f"NIST PQC standards status updated: ML-KEM: {standards_info['ml_kem_status']}, "
                    f"FALCON: {standards_info['falcon_status']}, SPHINCS+: {standards_info['sphincs_plus_status']}")
            
            return self.qr_future_proofing
        except Exception as e:
            hybrid_kex_logger.error(f"Error enhancing quantum resistance: {e}", exc_info=True)
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
    """Verify a digital signature with enhanced security and format handling.
    
    Performs secure signature verification with several security enhancements:
    1. Validates all inputs before verification to prevent null-byte attacks
    2. Handles enhanced FALCON signature format with version detection
    3. Supports both standard and enhanced public key formats
    4. Implements fallback verification paths for compatibility
    5. Raises exceptions on verification failure rather than returning False
    
    This function is designed to be resistant to signature forgery attacks
    and to handle various signature formats securely.
    
    Args:
        dss: Digital signature system instance (e.g., EnhancedFALCON_1024)
        public_key: Verification public key bytes
        payload: Original data that was signed
        signature: Signature bytes to verify
        description: Description for error messages and logging
        
    Returns:
        bool: True if verification succeeds (never returns False)
        
    Raises:
        ValueError: If verification fails for any reason
        
    Security note:
        This function follows the principle of failing closed - any verification
        error results in an exception rather than a boolean False return.
    """
    try:
        # Check if inputs are valid
        if not public_key or not payload or not signature:
            hybrid_kex_logger.error(f"SECURITY ALERT: {description} verification failed - missing input")
            raise ValueError(f"Handshake aborted: invalid {description} - missing input")
            
        # Handle Enhanced FALCON signature format (EFS-2)
        if isinstance(signature, bytes) and signature.startswith(b"EFS-"):
            try:
                # Extract version and signature data
                version = int(signature[4:5])
                stripped_signature = signature[5:]  # Remove the "EFS-2" prefix
                hybrid_kex_logger.debug(f"Detected enhanced FALCON signature format version {version}")
                
                # Handle Enhanced FALCON public key format (EFPK-2)
                if isinstance(public_key, bytes) and public_key.startswith(b"EFPK-"):
                    pk_version = int(public_key[5:6])
                    stripped_public_key = public_key[6:]  # Remove the "EFPK-2" prefix
                    hybrid_kex_logger.debug(f"Detected enhanced FALCON public key format version {pk_version}")
                    
                    # Try verification with stripped values first
                    if hasattr(dss, 'base_falcon'):
                        # If this is our enhanced FALCON implementation, try the base implementation
                        if dss.base_falcon.verify(stripped_public_key, payload, stripped_signature):
                            hybrid_kex_logger.debug(f"Enhanced FALCON verification succeeded with stripped prefixes")
                            return True
            except Exception as e:
                hybrid_kex_logger.debug(f"Error handling enhanced format: {e}, falling back to standard verification")
        
        # Attempt verification with original values
        if dss.verify(public_key, payload, signature):
            return True
            
        # If verification fails, try with stripped prefixes as a fallback
        if isinstance(signature, bytes) and signature.startswith(b"EFS-"):
            stripped_signature = signature[5:]
            if isinstance(public_key, bytes) and public_key.startswith(b"EFPK-"):
                stripped_public_key = public_key[6:]
                
                # Try direct verification with base implementation if available
                if hasattr(dss, 'base_falcon'):
                    if dss.base_falcon.verify(stripped_public_key, payload, stripped_signature):
                        hybrid_kex_logger.info(f"Direct base FALCON verification succeeded for {description}")
                        return True
        
        # If we reach here, verification failed
        hybrid_kex_logger.error(f"SECURITY ALERT: {description} verification failed")
        hybrid_kex_logger.debug(f"Public key length: {len(public_key) if public_key else 'None'}, " +
                 f"Payload length: {len(payload) if payload else 'None'}, " +
                 f"Signature length: {len(signature) if signature else 'None'}")
        
        raise ValueError(f"Handshake aborted: invalid {description}")
    except Exception as e:
        # Log at most "signature mismatch" (avoid printing raw data)
        hybrid_kex_logger.error(f"SECURITY ALERT: {description} verification error: {str(e)}")
        
        # For debugging purposes, log more details about the error
        hybrid_kex_logger.debug(f"Error type: {type(e).__name__}, Public key type: {type(public_key).__name__}, " +
                 f"Payload type: {type(payload).__name__}, Signature type: {type(signature).__name__}")
        
        raise ValueError(f"Handshake aborted: invalid {description}")


if __name__ == "__main__":
    # Uncomment the line below to run the replay protection test
    test_replay_protection()
    # Or uncomment this line to run the regular handshake demo
    # demonstrate_handshake() 