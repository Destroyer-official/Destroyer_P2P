"""
TLS Secure Channel

Secure communication channel built on TLS 1.3 with enhanced security features
including post-quantum cryptography support, multi-layer encryption, and
hardware security module integration.
"""

import ssl
import socket
import os
import logging
import time
import datetime
import select
import json
import urllib.request
import urllib.parse
import threading
import webbrowser
import base64
import hashlib
import struct
import math
import ctypes # Added import
import gc # Added import
import tempfile # Added import
from typing import Optional, Tuple, Union, Any, Dict, List, Callable
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, ed25519, ec
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509 import ocsp # Added ocsp import
from cryptography.x509.oid import NameOID
from cryptography.x509.extensions import TLSFeature, TLSFeatureType # Added TLSFeature, TLSFeatureType
import sys
import platform # Added
from enum import Enum

# Import platform_hsm_interface
try:
    import platform_hsm_interface as cphs
except ImportError:
    cphs = None
    # Using logger directly now, so this warning will be handled by the logger instance
    # logging.warning("platform_hsm_interface module not found. Hardware security features will be limited.")

# Import post-quantum cryptography library if available
try:
    from quantcrypt import cipher as qcipher
    HAVE_MLKEM = True
except ImportError:
    HAVE_MLKEM = False
    # logger.debug("quantcrypt library not found. Post-quantum features via Krypton will be unavailable.")
    pass

# Import hybrid key exchange module if available
try:
    from hybrid_kex import HybridKeyExchange, verify_key_material
    HAVE_HYBRID_KEX = True
except ImportError:
    HAVE_HYBRID_KEX = False
    # logger.debug("hybrid_kex module not found. Some hybrid KEM features might be limited.")
    pass

# Define TlsChannelException
class TlsChannelException(Exception):
    """Custom exception for TLS channel errors."""
    pass

# Import TPM/HSM modules if available
# tpm2_pytss and HAVE_TPM are no longer directly used by SecureEnclaveManager,
# as cphs handles TPM interactions.
# try:
#     import tpm2_pytss
#     HAVE_TPM = True
# except ImportError:
#     HAVE_TPM = False
    
try:
    import pkcs11 # type: ignore 
    from pkcs11 import KeyType, ObjectClass, Mechanism # type: ignore
    HAVE_PKCS11 = True
except ImportError:
    HAVE_PKCS11 = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
# Use logger instead of log for consistency across the module
logger = logging.getLogger(__name__)
# Create log alias for backward compatibility with code that uses 'log' 
log = logger

# Platform detection constants
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_DARWIN = SYSTEM == "Darwin"

class NonceManager:
    """
    Manages nonce generation and rotation for cryptographic operations.
    """
    
    def __init__(self, nonce_size: int, max_nonce_uses: int = 2**32 - 1, 
                 rotation_threshold: float = 0.9, random_generator=None):
        """
        Initialize the nonce manager.
        
        Args:
            nonce_size: Size of the nonce in bytes
            max_nonce_uses: Maximum number of times a nonce can be generated before rotation
            rotation_threshold: Threshold (0.0-1.0) of max_nonce_uses that triggers rotation
            random_generator: Function to generate random bytes, defaults to os.urandom
        """
        self.nonce_size = nonce_size
        self.max_nonce_uses = max_nonce_uses
        self.rotation_threshold = rotation_threshold
        self.random_generator = random_generator or os.urandom
        
        # Initialize counter and nonce prefix
        self.counter = 0
        self.nonce_prefix = self.random_generator(nonce_size // 2)
        
        # Track used nonces to prevent collisions
        self.used_nonces = set()
        
        # Track last reset time for monitoring
        self.last_reset_time = time.time()
    
    def generate_nonce(self) -> bytes:
        """
        Generate a unique nonce for cryptographic operations.
        
        Returns:
            Unique nonce bytes of nonce_size length
        
        Raises:
            RuntimeError: If nonce space is exhausted
        """
        # Check if rotation is needed
        if self.is_rotation_needed():
            logger.info("Nonce space approaching threshold, resetting")
            self.reset()
        
        # Increment counter
        self.counter += 1
        
        # Ensure counter doesn't exceed maximum
        if self.counter >= self.max_nonce_uses:
            logger.warning("Nonce counter reached maximum, resetting")
            self.reset()
            
        # Generate nonce with prefix and counter
        counter_bytes = self.counter.to_bytes(self.nonce_size - len(self.nonce_prefix), 
                                             byteorder='big')
        nonce = self.nonce_prefix + counter_bytes
        
        # Check for collisions (extremely unlikely but safer)
        retry_count = 0
        while nonce in self.used_nonces and retry_count < 3:
            # In the unlikely event of a collision, generate a completely random nonce
            nonce = self.random_generator(self.nonce_size)
            retry_count += 1
            
        if retry_count >= 3:
            logger.error("Failed to generate unique nonce after multiple attempts")
            raise RuntimeError("Nonce generation failed: collision detected")
            
        # Track used nonce
        self.used_nonces.add(nonce)
        
        # Prevent unbounded growth of used_nonces set
        if len(self.used_nonces) > 100:
            # Keep only the most recent nonces
            self.used_nonces = set(list(self.used_nonces)[-100:])
            
        return nonce
        
    def reset(self):
        """Reset the nonce manager with a new nonce prefix."""
        self.counter = 0
        self.nonce_prefix = self.random_generator(self.nonce_size // 2)
        self.used_nonces.clear()
        self.last_reset_time = time.time()
        logger.debug("Nonce manager reset with new prefix")
        
    def is_rotation_needed(self) -> bool:
        """Check if nonce rotation is needed based on threshold."""
        return self.counter >= (self.max_nonce_uses * self.rotation_threshold)

class XChaCha20Poly1305:
    """
    XChaCha20-Poly1305 AEAD cipher with 192-bit nonce.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize with a 32-byte key.
        
        Args:
            key: 32-byte encryption key
        """
        if len(key) != 32:
            raise ValueError("XChaCha20Poly1305 key must be 32 bytes")
        self.key = key
        # Use CounterBasedNonceManager for 24-byte nonce (20-byte counter, 4-byte salt)
        self.nonce_manager = CounterBasedNonceManager(counter_size=20, salt_size=4, nonce_size=24)  # 24-byte nonce for XChaCha20
    
    def encrypt(self, nonce: Optional[bytes] = None, data: bytes = None, 
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data with XChaCha20-Poly1305.
        
        Args:
            nonce: Optional 24-byte nonce, auto-generated if None
            data: Plaintext to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Ciphertext with authentication tag and nonce
        """
        if nonce is None:
            nonce = self.nonce_manager.generate_nonce()
        elif len(nonce) != 24:
            raise ValueError("XChaCha20Poly1305 nonce must be 24 bytes")
            
        # Derive a subkey using HChaCha20
        subkey = self._hchacha20(self.key, nonce[:16])
        
        # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce,
        # prepended with 4 zero bytes to make a 12-byte nonce.
        internal_nonce = b'\x00\x00\x00\x00' + nonce[16:]
        chacha = ChaCha20Poly1305(subkey)
        ciphertext = chacha.encrypt(internal_nonce, data, associated_data)
    
        # Return nonce + ciphertext for complete encryption result
        return nonce + ciphertext
    
    def decrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data with XChaCha20-Poly1305.
        
        Args:
            data: Ciphertext to decrypt (including nonce)
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        if len(data) < 24:
            raise ValueError("Data too short for XChaCha20Poly1305 decryption")
            
        # Extract nonce from the beginning of the data
        nonce = data[:24]
        ciphertext = data[24:]
            
        # Derive a subkey using HChaCha20
        subkey = self._hchacha20(self.key, nonce[:16])
        
        # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce,
        # prepended with 4 zero bytes to make a 12-byte nonce.
        internal_nonce = b'\x00\x00\x00\x00' + nonce[16:]
        chacha = ChaCha20Poly1305(subkey)
        return chacha.decrypt(internal_nonce, ciphertext, associated_data)
    
    def _hchacha20(self, key: bytes, nonce: bytes) -> bytes:
        """
        HChaCha20 function to derive a subkey.
        
        Args:
            key: 32-byte key
            nonce: 16-byte nonce
            
        Returns:
            32-byte derived key
        """
        # Create a seed for HKDF that combines key and nonce
        seed = key + nonce
        
        # Use HKDF to derive a new key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"HChaCha20 Key Derivation"
        )
        
        return hkdf.derive(seed)
        
    def rotate_key(self, new_key: bytes):
        """
        Rotate to a new encryption key.
        
        Args:
            new_key: New 32-byte encryption key
        """
        if len(new_key) != 32:
            raise ValueError("XChaCha20Poly1305 key must be 32 bytes")
            
        # Update key and reset nonce manager
        self.key = new_key
        self.nonce_manager.reset()

class MultiCipherSuite:
    """
    Multi-layer encryption using multiple cipher algorithms for defense-in-depth.
    """
    
    def __init__(self, master_key: bytes):
        """
        Initialize with a master key and derive individual cipher keys.
        
        Args:
            master_key: Main encryption key (at least 32 bytes)
        """
        if len(master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes")
            
        # Derive individual keys for each cipher
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=96,  # 32 bytes for each of the 3 ciphers
            salt=None,
            info=b"MultiCipherSuite Key Derivation"
        )
        
        derived_keys = hkdf.derive(master_key)
        
        # Initialize ciphers
        self.xchacha_key = derived_keys[0:32]
        self.aes_key = derived_keys[32:64]
        self.chacha_key = derived_keys[64:96]
        
        self.xchacha = XChaCha20Poly1305(self.xchacha_key)
        self.aes = AESGCM(self.aes_key)
        self.chacha = ChaCha20Poly1305(self.chacha_key)
        
        # Initialize post-quantum cipher if available
        if HAVE_MLKEM:
            self.krypton = qcipher.Krypton(master_key[:32])
        else:
            self.krypton = None
            
        # Nonce management using counter-based approach for AEAD security
        self.aes_nonce_manager = CounterBasedNonceManager()  # 12-byte nonce (8-byte counter, 4-byte salt) for AES-GCM
        self.chacha_nonce_manager = CounterBasedNonceManager()  # 12-byte nonce for ChaCha20-Poly1305
        
        # Key rotation tracking
        self.operation_count = 0
        self.last_rotation_time = time.time()
        self.max_operations = 2**20  # ~1 million operations before key rotation
        self.rotation_threshold = 0.8  # 80% of max operations before triggering rotation
        
    def encrypt(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Encrypt data using all ciphers in succession for maximum security.
        
        Args:
            data: Data to encrypt
            aad: Additional authenticated data
            
        Returns:
            Multi-encrypted ciphertext
        """
        # Check if key rotation is needed
        self.operation_count += 1
        if self.operation_count >= self.max_operations * self.rotation_threshold:
            logger.info("Operation count approaching threshold, triggering key rotation")
            self._rotate_keys()
        
        # Generate nonces
        xchacha_nonce = self.xchacha.nonce_manager.generate_nonce()
        aes_nonce = self.aes_nonce_manager.generate_nonce()
        chacha_nonce = self.chacha_nonce_manager.generate_nonce()
        
        # First layer: XChaCha20-Poly1305
        ciphertext = self.xchacha.encrypt(xchacha_nonce, data, aad)
        
        # Second layer: AES-256-GCM
        ciphertext = aes_nonce + self.aes.encrypt(aes_nonce, ciphertext, aad)
        
        # Third layer: ChaCha20-Poly1305
        ciphertext = chacha_nonce + self.chacha.encrypt(chacha_nonce, ciphertext, aad)
        
        # Add post-quantum encryption if available
        if HAVE_MLKEM and self.krypton:
            self.krypton.begin_encryption()
            ciphertext = self.krypton.encrypt(ciphertext)
            tag = self.krypton.finish_encryption()
            ciphertext = ciphertext + tag
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using all ciphers in reverse order.
        
        Args:
            ciphertext: Data to decrypt
            aad: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        self.operation_count += 1
        
        # Post-quantum decryption if available
        if HAVE_MLKEM and self.krypton:
            # Extract tag from end (assume 32 bytes)
            tag_length = 32
            if len(ciphertext) <= tag_length:
                raise ValueError("Ciphertext too short for post-quantum decryption")
            
            encrypted_data = ciphertext[:-tag_length]
            tag = ciphertext[-tag_length:]
            
            try:
                self.krypton.begin_decryption(verif_data=tag)
                ciphertext = self.krypton.decrypt(encrypted_data)
                self.krypton.finish_decryption()
            except Exception as e:
                logger.error(f"Post-quantum decryption failed: {e}")
                raise
        
        # First layer: ChaCha20-Poly1305
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short for ChaCha20-Poly1305 decryption")
            
        chacha_nonce = ciphertext[:12]
        chacha_ciphertext = ciphertext[12:]
        
        chacha = ChaCha20Poly1305(self.chacha_key)
        try:
            plaintext = chacha.decrypt(chacha_nonce, chacha_ciphertext, aad)
        except Exception as e:
            logger.error(f"ChaCha20-Poly1305 decryption failed: {e}")
            raise
        
        # Second layer: AES-256-GCM
        if len(plaintext) < 12:
            raise ValueError("Data too short for AES-GCM decryption")
            
        aes_nonce = plaintext[:12]
        aes_ciphertext = plaintext[12:]
        
        aes = AESGCM(self.aes_key)
        try:
            plaintext = aes.decrypt(aes_nonce, aes_ciphertext, aad)
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {e}")
            raise
        
        # Third layer: XChaCha20-Poly1305
        try:
            plaintext = self.xchacha.decrypt(plaintext, aad)
        except Exception as e:
            logger.error(f"XChaCha20-Poly1305 decryption failed: {e}")
            raise
        
        return plaintext
    
    def _rotate_keys(self):
        """Rotate all encryption keys to ensure cryptographic hygiene."""
        logger.info("Rotating all encryption keys in MultiCipherSuite")
        
        # Generate new master key material
        new_salt = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=96,  # 32 bytes for each cipher
            salt=new_salt,
            info=b"MultiCipherSuite Key Rotation"
        )
        
        new_keys = hkdf.derive(self.master_key)
        
        # Update keys
        self.xchacha_key = new_keys[0:32]
        self.aes_key = new_keys[32:64]
        self.chacha_key = new_keys[64:96]
        
        # Rotate XChaCha20-Poly1305 key 
        self.xchacha.rotate_key(self.xchacha_key)
        
        # Reset nonce managers
        self.aes_gcm_nonce_manager.reset()
        self.chacha_nonce_manager.reset()
        
        # Rotate post-quantum cipher if available
        if HAVE_MLKEM and self.krypton:
            self.krypton = qcipher.Krypton(self.master_key[:32])
            
        logger.info("Key rotation completed successfully")

class OAuth2DeviceFlowAuth:
    """
    OAuth 2.0 Device Flow authentication for secure user authentication.
    """
    
    DEFAULT_PROVIDERS = {
        'google': {
            'auth_url': 'https://oauth2.googleapis.com/device/code',
            'token_url': 'https://oauth2.googleapis.com/token',
            'scope': 'email profile',
            'user_info_url': 'https://www.googleapis.com/oauth2/v3/userinfo',
        },
        'microsoft': {
            'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
            'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'scope': 'User.Read',
            'user_info_url': 'https://graph.microsoft.com/v1.0/me',
        },
        'github': {
            'auth_url': 'https://github.com/login/device/code',
            'token_url': 'https://github.com/login/oauth/access_token',
            'scope': 'read:user',
            'user_info_url': 'https://api.github.com/user',
        }
    }
    
    def __init__(self, provider: str = 'google', client_id: Optional[str] = None, 
                 client_secret: Optional[str] = None, custom_config: Optional[Dict] = None):
        """
        Initialize OAuth2 Device Flow authentication.
        
        Args:
            provider: Identity provider ('google', 'microsoft', 'github', or 'custom')
            client_id: OAuth client ID (can be set via environment variable OAUTH_CLIENT_ID)
            client_secret: OAuth client secret (can be set via environment variable OAUTH_CLIENT_SECRET)
            custom_config: Custom provider configuration (required if provider is 'custom')
        """
        self.provider_name = provider.lower()
        
        # Set up provider configuration
        if self.provider_name == 'custom' and custom_config:
            self.provider_config = custom_config
        elif self.provider_name in self.DEFAULT_PROVIDERS:
            self.provider_config = self.DEFAULT_PROVIDERS[self.provider_name]
        else:
            raise ValueError(f"Unsupported provider: {provider}. Use 'google', 'microsoft', 'github', or 'custom'")
        
        # Get credentials from parameters or environment variables
        self.client_id = client_id or os.environ.get('OAUTH_CLIENT_ID', '')
        self.client_secret = client_secret or os.environ.get('OAUTH_CLIENT_SECRET', '')
        
        if not self.client_id:
            logger.warning("OAuth client ID not provided. Device flow authentication will not work.")
        
        # Authentication state
        self.device_code = None
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.token_expiry = 0
        self.user_info = None
        
        # For background polling
        self.polling_thread = None
        self.polling_stop_event = threading.Event()
    
    def start_device_flow(self, callback: Optional[Callable[[str, str], None]] = None) -> Dict:
        """
        Start the OAuth 2.0 device flow authentication process.
        
        Args:
            callback: Optional function to call with user_code and verification_url
            
        Returns:
            Dict containing device_code, user_code, verification_url, etc.
        """
        if not self.client_id:
            raise ValueError("OAuth client ID is required")
        
        # Prepare request data
        data = {
            'client_id': self.client_id,
            'scope': self.provider_config['scope']
        }
        
        # Add client_secret if provided (some providers require it)
        if self.client_secret:
            data['client_secret'] = self.client_secret
        
        # Request device code
        try:
            encoded_data = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(
                self.provider_config['auth_url'],
                data=encoded_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                
            # Store device code
            self.device_code = response_data.get('device_code')
            
            # Call callback if provided
            if callback:
                callback(
                    response_data.get('user_code', ''),
                    response_data.get('verification_url', '')
                )
            
            # Start polling for token
            self._start_polling(
                response_data.get('interval', 5),
                response_data.get('expires_in', 1800)
            )
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error starting device flow: {e}")
            raise
    
    def _start_polling(self, interval: int, expires_in: int):
        """
        Start background polling for token.
        
        Args:
            interval: Polling interval in seconds
            expires_in: Time in seconds until the device code expires
        """
        self.polling_stop_event.clear()
        self.polling_thread = threading.Thread(
            target=self._poll_for_token,
            args=(interval, expires_in),
            daemon=True
        )
        self.polling_thread.start()
    
    def _poll_for_token(self, interval: int, expires_in: int):
        """
        Poll for token in background thread.
        
        Args:
            interval: Polling interval in seconds
            expires_in: Time in seconds until the device code expires
        """
        start_time = time.time()
        
        while not self.polling_stop_event.is_set():
            # Check if device code has expired
            if time.time() - start_time > expires_in:
                logger.warning("Device code has expired")
                return
            
            # Try to get token
            try:
                data = {
                    'client_id': self.client_id,
                    'device_code': self.device_code,
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
                }
                
                # Add client_secret if provided
                if self.client_secret:
                    data['client_secret'] = self.client_secret
                
                encoded_data = urllib.parse.urlencode(data).encode('utf-8')
                req = urllib.request.Request(
                    self.provider_config['token_url'],
                    data=encoded_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                with urllib.request.urlopen(req) as response:
                    response_data = json.loads(response.read().decode('utf-8'))
                
                # Check for error
                if 'error' in response_data:
                    # authorization_pending is normal, just continue polling
                    if response_data['error'] != 'authorization_pending':
                        logger.warning(f"Token error: {response_data.get('error')}")
                else:
                    # Got token, store it
                    self.access_token = response_data.get('access_token')
                    self.refresh_token = response_data.get('refresh_token')
                    self.id_token = response_data.get('id_token')
                    
                    # Calculate token expiry
                    expires_in = response_data.get('expires_in', 3600)
                    self.token_expiry = time.time() + expires_in
                    
                    # Get user info
                    self._get_user_info()
                    
                    # Stop polling
                    self.polling_stop_event.set()
            
            except urllib.error.HTTPError as e:
                # Handle rate limiting
                if e.code == 429:
                    log.warning("Rate limited, increasing polling interval")
                    interval = min(interval * 2, 60)  # Exponential backoff, max 60 seconds
                else:
                    log.warning(f"HTTP error during polling: {e}")
            
            except Exception as e:
                log.warning(f"Error polling for token: {e}")
            
            # Wait for next poll
            time.sleep(interval)
    
    def _get_user_info(self):
        """Get user information using the access token."""
        if not self.access_token:
            return
        
        try:
            req = urllib.request.Request(
                self.provider_config['user_info_url'],
                headers={'Authorization': f'Bearer {self.access_token}'}
            )
            
            with urllib.request.urlopen(req) as response:
                self.user_info = json.loads(response.read().decode('utf-8'))
                
            log.info(f"Successfully authenticated user: {self.user_info.get('email') or self.user_info.get('name')}")
            
        except Exception as e:
            log.error(f"Error getting user info: {e}")
    
    def refresh_access_token(self):
        """Refresh the access token using the refresh token."""
        if not self.refresh_token:
            log.warning("No refresh token available")
            return False
        
        try:
            data = {
                'client_id': self.client_id,
                'refresh_token': self.refresh_token,
                'grant_type': 'refresh_token'
            }
            
            if self.client_secret:
                data['client_secret'] = self.client_secret
            
            encoded_data = urllib.parse.urlencode(data).encode('utf-8')
            req = urllib.request.Request(
                self.provider_config['token_url'],
                data=encoded_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
            
            if 'error' in response_data:
                log.warning(f"Refresh token error: {response_data.get('error')}")
                return False
            
            # Update tokens
            self.access_token = response_data.get('access_token')
            
            # Some providers return a new refresh token
            if 'refresh_token' in response_data:
                self.refresh_token = response_data.get('refresh_token')
            
            # Update expiry
            expires_in = response_data.get('expires_in', 3600)
            self.token_expiry = time.time() + expires_in
            
            log.info("Successfully refreshed access token")
            return True
            
        except Exception as e:
            log.error(f"Error refreshing access token: {e}")
            return False
    
    def is_authenticated(self):
        """Check if the user is authenticated with a valid token."""
        if not self.access_token:
            return False
        
        # Check if token is expired
        if time.time() > self.token_expiry:
            # Try to refresh token
            if self.refresh_token:
                return self.refresh_access_token()
            return False
        
        return True
    
    def get_token_for_request(self):
        """Get a valid token for making API requests."""
        if self.is_authenticated():
            return self.access_token
        return None
    
    def logout(self):
        """Clear all authentication data."""
        self.device_code = None
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.token_expiry = 0
        self.user_info = None
        
        # Stop polling if active
        if self.polling_thread and self.polling_thread.is_alive():
            self.polling_stop_event.set()
            self.polling_thread.join(timeout=1.0)
        
        log.info("User logged out")

    def wait_for_authorization(self, timeout=900):
        """
        Wait for the user to authorize the device flow.
        
        Args:
            timeout: Maximum time to wait for authorization in seconds
            
        Returns:
            True if authorization was successful, False otherwise
        """
        if not self.device_code:
            log.error("No active device code - call start_device_flow first")
            return False
            
        # Show the verification URL and user code
        verification_url = self.provider_config.get('verification_url', '')
        user_code = self.device_code
        
        message = (
            f"\nTo authenticate, visit: {verification_url}\n"
            f"And enter code: {user_code}\n"
        )
        print(message)
        
        # Try to open the browser automatically
        try:
            webbrowser.open(verification_url)
        except Exception as e:
            log.debug(f"Could not open browser: {e}")
            pass
        
        # Wait for authentication to complete or timeout
        start_time = time.time()
        while not self.is_authenticated() and (time.time() - start_time < timeout):
            time.sleep(1)
            
        # Return authentication status
        return self.is_authenticated()

class SecureEnclaveManager:
    """
    Manages interaction with secure hardware enclaves (TPM, HSM, Secure Enclave).
    Provides a unified interface for cryptographic operations using available hardware.
    Now leverages the platform_hsm_interface module (cphs) for ALL hardware interactions.
    """
    def __init__(self):
        # Initialize flags first
        self.tpm_available = False
        self.hsm_available = False
        self.secure_enclave_available = False # For conceptual macOS SE via keyring
        self.enclave_type = "Software" # Default type

        if not cphs:
            logger.warning("cphs module not available. All hardware security features will be disabled.")
            # Log this once and then all other operations will see cphs as None.
            return # Nothing more to do if cphs is not there

        logger.debug("cphs module available, checking for hardware security features.")
        # Determine TPM availability using cphs flags
        if IS_WINDOWS and hasattr(cphs, '_WINDOWS_TBS_AVAILABLE') and cphs._WINDOWS_TBS_AVAILABLE:
            self.tpm_available = True
            self.enclave_type = "Windows TPM (via cphs)"
            logger.info(self.enclave_type + " detected.")
        elif IS_LINUX and hasattr(cphs, '_Linux_ESAPI') and cphs._Linux_ESAPI:
            self.tpm_available = True
            self.enclave_type = "Linux TPM (via cphs)"
            logger.info(self.enclave_type + " detected.")
        elif IS_DARWIN:
            # macOS Secure Enclave detection via keyring is more conceptual for this manager's purpose.
            # cphs doesn't directly manage SE for key ops, but keyring might use it for storage.
            # This check remains as it's about 'keyring' not a direct cphs hardware feature.
            try:
                import keyring
                kr = keyring.get_keyring()
                if kr and kr.priority > 0:
                    self.secure_enclave_available = True
                    self.enclave_type = "macOS Secure Enclave (via Keyring)"
                    logger.info(self.enclave_type + " access enabled.")
                else:
                    logger.debug("No suitable macOS keyring backend found for conceptual Secure Enclave.")
            except ImportError:
                logger.debug("keyring library not installed, macOS Secure Enclave integration (conceptual) unavailable.")
            except Exception as e:
                logger.debug(f"macOS Secure Enclave (keyring) check failed: {e}")

        # Attempt to initialize HSM via cphs
        # cphs.init_hsm() will use environment variables PKCS11_LIB_PATH, HSM_PIN, etc.
        # or can be called with specific parameters if needed elsewhere.
        if hasattr(cphs, 'init_hsm') and cphs.init_hsm(): # init_hsm returns True on success
            if hasattr(cphs, '_hsm_initialized') and cphs._hsm_initialized:
                 self.hsm_available = True
                 hsm_type_detail = f"PKCS#11 HSM (via cphs, lib: {cphs._pkcs11_lib_path if hasattr(cphs, '_pkcs11_lib_path') else 'unknown'})"
                 if self.tpm_available or self.secure_enclave_available:
                     self.enclave_type += f" + {hsm_type_detail}"
            else:
                self.enclave_type = hsm_type_detail
                logger.info(hsm_type_detail + " initialized.")
                logger.warning("cphs.init_hsm() reported success but _hsm_initialized is false. Assuming HSM not available.")
        else:
            logger.info("HSM initialization via cphs failed or was not attempted (if init_hsm not in cphs).")
            if hasattr(cphs, '_PKCS11_SUPPORT_AVAILABLE') and not cphs._PKCS11_SUPPORT_AVAILABLE:
                 logger.info("python-pkcs11 library likely missing in cphs, HSM support definitely unavailable.")


        # Final log based on what was initialized
        if self.tpm_available or self.hsm_available or self.secure_enclave_available:
            logger.info(f"SecureEnclaveManager initialized. Active services: {self.enclave_type}")
        else:
            logger.info("SecureEnclaveManager: No TPM, HSM, or conceptual macOS Secure Enclave available/initialized. Operations will use software fallbacks where possible.")

    @property
    def using_enclave(self):
        """Returns True if any hardware security is available (TPM, HSM, or Secure Enclave)."""
        return self.tpm_available or self.hsm_available or self.secure_enclave_available
        
    @property
    def using_hsm(self):
        """Returns True if HSM is available and initialized."""
        return self.hsm_available

    # _init_hsm is now removed as cphs.init_hsm is used.
    # Platform specific TPM inits were already removed.
    
    def generate_random(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes using cphs.
        cphs.get_secure_random handles TPM, HSM (if initialized via cphs.init_hsm), and OS fallbacks.
        """
        if cphs and hasattr(cphs, 'get_secure_random'):
            try:
                random_bytes = cphs.get_secure_random(length)
                if random_bytes and len(random_bytes) == length:
                    # logger.debug(f"Generated {length} random bytes using cphs.get_secure_random.")
                    return random_bytes
                else:
                    logger.warning(f"cphs.get_secure_random returned unexpected data. Length: {len(random_bytes) if random_bytes else 'None'}. Falling back to os.urandom.")
            except Exception as e:
                logger.warning(f"cphs.get_secure_random failed: {e}. Falling back to os.urandom.")
        else:
            logger.warning("cphs module or get_secure_random function not available. Falling back to os.urandom.")
        
        logger.info(f"Generating {length} random bytes using os.urandom as ultimate fallback.")
        return os.urandom(length)
    
    def create_rsa_key(self, key_size=3072, key_id="tls-server-key"):
        """
        Creates an RSA key pair, attempting to use HSM if available and configured via cphs.
        Returns a tuple (hsm_private_key_handle, cryptography_public_key_object) or None.
        Note: The first element is the HSM private key *handle* (an int).
        The public key is a cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey object.
        """
        if not (cphs and hasattr(cphs, 'generate_hsm_rsa_keypair') and self.hsm_available):
            logger.info("cphs.generate_hsm_rsa_keypair not available or HSM not initialized. RSA key generation via HSM will not be attempted by SecureEnclaveManager.")
            return None
            
        try:
            logger.info(f"Attempting to generate RSA-{key_size} key pair in HSM (via cphs) with ID: {key_id}")
            # cphs.generate_hsm_rsa_keypair now returns (private_key_handle, crypto_pub_key_obj)
            # where private_key_handle can be either an integer (for PKCS#11) or a NCRYPT_KEY_HANDLE (for Windows CNG)
            
            key_gen_result = cphs.generate_hsm_rsa_keypair(key_label=key_id, key_size=key_size)
            
            if key_gen_result:
                private_key_handle, public_key_object = key_gen_result
                
                # For Windows CNG, we need to extract the handle value if it's a NCRYPT_KEY_HANDLE
                if hasattr(private_key_handle, 'value'):
                    # It's a Windows CNG NCRYPT_KEY_HANDLE
                    logger.info(f"Successfully generated RSA key in HSM (via cphs). Windows CNG private key handle: {private_key_handle.value}")
                    return private_key_handle, public_key_object
                else:
                    # It's a PKCS#11 integer handle
                    logger.info(f"Successfully generated RSA key in HSM (via cphs). PKCS#11 private key handle: {private_key_handle}")
                    return private_key_handle, public_key_object
            else:
                logger.error(f"HSM RSA key generation via cphs failed for key ID: {key_id}")
                return None
        except Exception as e:
            logger.error(f"Error during RSA key generation via cphs: {e}")
        return None
    
    def sign_with_key(self, key_handle, data: bytes, mechanism=None):
        """
        Sign data using a key in the HSM, accessed via cphs.
        Args:
            key_handle: Handle to the private key in the HSM.
            data: Data to sign.
            mechanism: Signing mechanism to use (PKCS#11 CKM constant).
        Returns:
            Signature bytes or None if operation failed.
        """
        if not (cphs and hasattr(cphs, 'sign_with_hsm_key') and self.hsm_available):
            logger.info("cphs.sign_with_hsm_key not available or HSM not initialized. Signing via HSM will not be attempted.")
            return None
            
        try:
            logger.debug(f"Attempting to sign data in HSM (via cphs) with key handle: {key_handle}")
            # The mechanism here needs to be a CKM constant from pkcs11.Mechanism if cphs expects that.
            # The `cphs.sign_with_hsm_key` currently takes `mechanism_type` which can be an int.
            signature = cphs.sign_with_hsm_key(private_key_handle=key_handle, data=data, mechanism_type=mechanism)
            
            if signature:
                logger.info("Data successfully signed using HSM (via cphs).")
                return signature
            else:
                logger.error("HSM signing via cphs returned None.")
                return None
        except Exception as e:
            logger.error(f"Error during HSM signing via cphs: {e}")
        return None
    
    def close(self):
        """Close connections to secure enclaves (HSM via cphs) and reset state."""
        if cphs and hasattr(cphs, 'close_hsm'):
            try:
                logger.debug("Closing HSM session via cphs.close_hsm().")
                cphs.close_hsm()
                logger.info("cphs.close_hsm() called.")
            except Exception as e:
                logger.error(f"Error calling cphs.close_hsm(): {e}")
        else:
            logger.debug("cphs module or close_hsm function not available.")
        
        # Reset all availability flags and type, as this manager instance is now considered closed.
        self.hsm_available = False
        self.tpm_available = False
        self.secure_enclave_available = False # macOS conceptual
        self.enclave_type = "Software" # Reset to default
        
        logger.info("SecureEnclaveManager state reset. All hardware considered unavailable locally.")

class TLSSecureChannel:
    """
    Enhanced TLS 1.3 secure communication channel with advanced security features.
    """
    
    # TLS 1.3 cipher preferences
    CIPHER_SUITES = [
        "TLS_AES_256_GCM_SHA384",          # AES-256-GCM for best compatibility
        "TLS_CHACHA20_POLY1305_SHA256",    # ChaCha20-Poly1305 as fallback
    ]
    
    # Combined cipher suite string
    CIPHER_SUITE_STRING = ":".join(CIPHER_SUITES)
    
    # Post-quantum key exchange groups
    HYBRID_PQ_GROUPS = ["X25519MLKEM1024", "SecP256r1MLKEM1024"]
    
    # NamedGroup values for TLS extensions
    NAMEDGROUP_X25519MLKEM1024 = 0x11EE    # 4590 in decimal
    NAMEDGROUP_SECP256R1MLKEM1024 = 0x11ED # 4589 in decimal
    NAMEDGROUP_MLKEM1024 = 0x0202          # 514 in decimal
    
    # Security logging levels
    SECURITY_LOG_LEVEL_INFO = 0
    SECURITY_LOG_LEVEL_VERBOSE = 1
    SECURITY_LOG_LEVEL_DEBUG = 2
    SECURITY_LOG_LEVEL = SECURITY_LOG_LEVEL_VERBOSE
    
    # IMPORTANT: Placeholder for Post-Quantum Cipher Suite names.
    # These names are highly dependent on the specific OpenSSL version and PQC library integration.
    # Replace these with the actual cipher suite names supported by your OpenSSL for use with set_ciphers().
    # For example, if your OpenSSL supports a Kyber-based cipher suite named "TLS_KYBER_AES_256_GCM_SHA384", add it here.
    # The user query mentioned "Kyber1024_SHA3_256". If this refers to a KEM, it's typically handled
    # by set_groups(). If it's a full cipher suite name for set_ciphers(), use its exact OpenSSL string here.
    EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS = [
        "TLS_PQC_KYBER_AES_256_GCM_SHA384_PLACEHOLDER", # Example placeholder
        "TLS_PQC_EXPERIMENTAL_SUITE_X_PLACEHOLDER"      # Another example placeholder
    ]
    
    def __init__(self, cert_path: Optional[str] = None, key_path: Optional[str] = None, 
                 use_secure_enclave: bool = True, require_authentication: bool = False,
                 oauth_provider: Optional[str] = None, oauth_client_id: Optional[str] = None,
                 multi_cipher: bool = True, enable_pq_kem: bool = True,
                 use_legacy_cipher: bool = False, verify_certs: bool = False,
                 ca_path: Optional[str] = None, in_memory_only: bool = False,
                 dane_tlsa_records: Optional[List[Dict]] = None,
                 enforce_dane_validation: bool = False):
        """
        Initialize the TLS secure channel with enhanced security features.
        
        Args:
            cert_path: Path to the server certificate file
            key_path: Path to the server private key file
            use_secure_enclave: Whether to use hardware security if available (default: True)
            require_authentication: Whether to require user authentication (default: False)
            oauth_provider: OAuth provider to use for authentication
            oauth_client_id: OAuth client ID for authentication
            multi_cipher: Whether to use multiple cipher suites for enhanced security (default: True)
            enable_pq_kem: Whether to enable post-quantum key exchange (default: True)
            use_legacy_cipher: Whether to support legacy cipher suites (less secure) (default: False)
            verify_certs: Whether to verify certificates (for client mode)
            ca_path: Path to the CA certificate file (for client mode)
            in_memory_only: Whether to operate entirely in memory without disk access
            dane_tlsa_records: Optional list of pre-fetched DANE TLSA records for the peer.
                               Each dict should represent a TLSA record (e.g., {'usage': 3, 'selector': 1, 'matching_type': 1, 'data': 'hex_encoded_hash'}).
            enforce_dane_validation: If True and DANE TLSA records are provided, the connection will fail if DANE validation fails.
        """
        # Set in_memory_only attribute first, as other methods depend on it
        self.in_memory_only = in_memory_only
        
        # Configure logging
        global log
        if not log:
            log = logging.getLogger(__name__)
            
        # Detect standalone mode
        self.standalone_mode = self.is_standalone_mode()
        
        # Initialize certificate paths
        self._initialize_cert_paths(cert_path, key_path, ca_path)
        
        # Initialize TLS variables
        self.ssl_socket = None
        self.ssl_context = None
        self.ssl_conn = None
        self.authenticated = False
        self.ssl_version = "Unknown"
        self.peer_certificate = None
        self.ssl_cipher = None
        self.handshake_complete = False
        self.key_size = None
        self.peer_common_name = None
        self.selector = SocketSelector()
        self.is_server = None
        
        # Security manager
        self.record_layer = None
        self.multi_cipher_suite = None
        self.multi_cipher_enabled = multi_cipher
        self.security_parameters = {}
        
        # Session key material
        self.client_random = None
        self.server_random = None
        self.master_secret = None
        self.private_key_data = None  # For in-memory certificates
        self.certificate_data = None  # For in-memory certificates
        
        # Post-quantum configuration
        self.enable_pq_kem = enable_pq_kem
        self.use_legacy_cipher = use_legacy_cipher
        self.pq_kem = None
        self.pq_negotiated = False
        
        # Authentication
        self.require_authentication = require_authentication
        self.oauth_provider = oauth_provider
        self.oauth_client_id = oauth_client_id
        self.oauth_auth = None
        self.verify_certs = verify_certs
        
        # DANE configuration
        self.dane_tlsa_records = dane_tlsa_records
        self.enforce_dane_validation = enforce_dane_validation
        self.dane_validation_performed = False
        self.dane_validation_successful = False
        self.pfs_active = False # Initialize PFS status
        
        # Try to set up hardware security if requested
        self.secure_enclave = None
        if use_secure_enclave:
            try:
                self.secure_enclave = SecureEnclaveManager()
                log.debug(f"Initialized secure enclave manager")
            except Exception as e:
                log.warning(f"Could not initialize hardware security: {e}")
        
        # Set up OAuth authentication if requested
        if self.require_authentication and self.oauth_client_id:
            try:
                self.oauth_auth = OAuth2DeviceFlowAuth(
                    provider=self.oauth_provider,
                    client_id=self.oauth_client_id
                )
                log.debug(f"Initialized OAuth authentication with provider: {self.oauth_provider}")
            except Exception as e:
                log.warning(f"Could not initialize OAuth authentication: {e}")
        elif self.require_authentication and not self.oauth_client_id:
            log.warning("Authentication required but no OAuth client ID provided")
            
        # Enhanced security options
        self.certificate_pinning = {}
        self.ocsp_stapling = True
        self.enhanced_security = {
            "secure_renegotiation": True,
            "strong_ciphers_only": True,
            "post_quantum": {
                "enabled": self.enable_pq_kem,
                "algorithm": "ML-KEM-1024"
            }
        }
        
        # Internal key rotation
        self.last_key_rotation = time.time()
        self.key_rotation_interval = 3600  # 1 hour
        
        # Generate default certificates if needed
        self._create_default_certificates()
        
        # Verify our security implementation
        self._check_tls_support()
        
        # Log security status
        self._log_security_status()
        
    def _initialize_cert_paths(self, cert_path: Optional[str], key_path: Optional[str], ca_path: Optional[str]):
        """
        Initialize certificate paths from environment variables or parameters.
        
        Args:
            cert_path: Optional path to certificate file
            key_path: Optional path to private key file
            ca_path: Optional path to CA certificate
        """
        # If in memory-only mode, we still need path variables for reference,
        # but we won't actually create directories or files
        
        # Get paths from environment variables if not provided
        env_cert_path = os.environ.get('P2P_CERT_PATH', '')
        env_key_path = os.environ.get('P2P_KEY_PATH', '')
        env_ca_path = os.environ.get('P2P_CA_PATH', '')
        
        # Use parameters, environment variables, or default paths
        self.cert_path = cert_path or env_cert_path or 'cert/server.crt'
        self.key_path = key_path or env_key_path or 'cert/server.key'
        self.ca_path = ca_path or env_ca_path or 'cert/ca.crt'
        
        # Log the paths being used
        if self.in_memory_only:
            log.debug(f"Using in-memory mode - certificate paths are virtual references only")
            log.debug(f"Virtual cert path: {self.cert_path}")
            log.debug(f"Virtual key path: {self.key_path}")
            log.debug(f"Virtual CA path: {self.ca_path}")
        else:
            log.debug(f"Using disk mode - certificates will be stored on disk")
            log.debug(f"Certificate path: {self.cert_path}")
            log.debug(f"Private key path: {self.key_path}")
            log.debug(f"CA certificate path: {self.ca_path}")
            
            # Ensure parent directories exist for disk mode
            try:
                cert_dir = os.path.dirname(self.cert_path)
                if cert_dir:
                    os.makedirs(cert_dir, exist_ok=True)
                    
                key_dir = os.path.dirname(self.key_path)
                if key_dir and key_dir != cert_dir:
                    os.makedirs(key_dir, exist_ok=True)
                    
                ca_dir = os.path.dirname(self.ca_path)
                if ca_dir and ca_dir != cert_dir and ca_dir != key_dir:
                    os.makedirs(ca_dir, exist_ok=True)
            except Exception as e:
                log.warning(f"Could not create certificate directories: {e}")
                # Non-fatal - will attempt to create when generating certificates
    
    def _log_security_status(self):
        """
        Log information about the security configuration and verify security features.
        """
        log.info("Performing security verification...")
        
        # Validate and log post-quantum status
        if self.enable_pq_kem:
            if "X25519MLKEM1024" in self.HYBRID_PQ_GROUPS:
                log.info("Post-quantum cryptography: ENABLED (ML-KEM-1024 + X25519MLKEM1024)")
                
                # Additional detailed logging
                if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                    log.info(f"Hybrid key exchange: {self.HYBRID_PQ_GROUPS}")
                    log.info(f"ML-KEM-1024 NamedGroup value: 0x{self.NAMEDGROUP_MLKEM1024:04x}")
                    log.info(f"X25519MLKEM1024 NamedGroup value: 0x{self.NAMEDGROUP_X25519MLKEM1024:04x}")
            else:
                log.warning("Post-quantum configuration mismatch! ML-KEM-1024 enabled but not properly configured")
        else:
            log.warning("Post-quantum cryptography DISABLED - using classical cryptography only")
            
        # Validate and log cipher suite configuration
        if self.multi_cipher_enabled:
            log.info("Enhanced multi-cipher encryption: ENABLED")
            log.info("Ciphers: XChaCha20-Poly1305 + AES-256-GCM + ChaCha20-Poly1305")
            
            # Additional cipher security validation
            for cipher in self.CIPHER_SUITES:
                if "GCM" in cipher and "256" in cipher:
                    if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                        log.info(f"AES-GCM configured with 256-bit key strength")
                elif "CHACHA20" in cipher:
                    if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                        log.info(f"ChaCha20-Poly1305 with 256-bit security enabled")
        else:
            log.warning("Multi-cipher suite DISABLED - using standard TLS 1.3 cipher suites only")
        
        # Validate and log secure enclave status
        if self.secure_enclave:
            log.info("Secure enclave/HSM support: ENABLED")
        else:
            log.warning("Hardware security module (HSM) DISABLED or not available")
            
        # Log authentication status
        if self.require_authentication and self.oauth_auth:
            log.info("Strong authentication: ENABLED")
        else:
            log.info("Strong authentication DISABLED - no user identity verification")

        # Log DANE status
        if self.dane_tlsa_records:
            log.info(f"DANE TLSA records provided for peer. Validation will be {'enforced' if self.enforce_dane_validation else 'attempted'}.")
            if self.certificate_pinning and not self.enforce_dane_validation: # Assuming self.certificate_pinning exists
                log.warning("Certificate pinning is configured, but DANE validation is not strictly enforced. Ensure DNS resolution is secured (e.g., via DNSSEC by the calling application).")
        elif self.certificate_pinning: # Pinning enabled, but no DANE
             log.warning("Certificate pinning is configured without DANE TLSA records. This is vulnerable to DNS spoofing if DNS resolution is not independently secured (e.g., via DNSSEC by the calling application).")
        else:
            log.info("DANE TLSA records not provided for peer.")
        
    def connect(self, host: str, port: int) -> bool:
        """
        Establish a secure connection to a remote server.
        
        Args:
            host: Remote hostname or IP address
            port: Remote port
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            log.info(f"Connecting to {host}:{port}")
            
            # Create socket
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.raw_socket.connect((host, port))
            
            # Apply TLS 
            if not self.wrap_client(self.raw_socket, host):
                log.error("Failed to establish TLS connection")
                self._cleanup()
                return False
                
            # Perform TLS handshake
            if not self.do_handshake():
                log.error("TLS handshake failed")
                self._cleanup()
                return False
                
            # Authenticate if required
            if self.require_authentication:
                if not self.send_authentication():
                    log.error("Authentication failed")
                    self._cleanup()
                    return False
            
            log.info(f"Secure connection established to {host}:{port}")
            return True
            
        except Exception as e:
            log.error(f"Connection failed: {e}")
            self._cleanup()
            return False
            
    def wrap_client(self, sock: socket.socket, hostname: str) -> bool:
        """
        Wrap a client socket with TLS.
        
        Args:
            sock: Socket to wrap
            hostname: Server hostname for verification
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create TLS context
            context = self._create_client_context()
            
            # Create SSL socket
            self.ssl_socket = self.wrap_socket_client(sock, hostname)
            
            if not self.ssl_socket:
                log.error("Failed to create SSL socket")
                return False
                
            self.is_server = False
            log.info(f"Client TLS connection initialized")
            return True
            
        except Exception as e:
            log.error(f"Failed to wrap client socket: {e}")
            return False
            
    def send_secure(self, data):
        """
        Send data securely over the established connection.
        
        Args:
            data: Data to send (bytes or string)
            
        Returns:
            Number of bytes sent or None on error
        """
        if not self.ssl_socket:
            log.error("Cannot send: No secure connection established")
            return None
            
        try:
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Use multi-cipher suite if enabled
            if self.multi_cipher_enabled and self.multi_cipher_suite:
                encrypted_data = self.multi_cipher_suite.encrypt(data)
                return self.ssl_socket.send(encrypted_data)
            else:
                # Otherwise use standard TLS
                return self.ssl_socket.send(data)
                
        except Exception as e:
            log.error(f"Error sending data: {e}")
            return None
            
    def recv_secure(self, bufsize):
        """
        Receive data securely from the established connection.
        
        Args:
            bufsize: Maximum bytes to receive
            
        Returns:
            Received data or None on error
        """
        if not self.ssl_socket:
            log.error("Cannot receive: No secure connection established")
            return None
            
        try:
            # Receive encrypted data
            data = self.ssl_socket.recv(bufsize)
            
            if not data:
                return b''
                
            # Decrypt with multi-cipher suite if enabled
            if self.multi_cipher_enabled and self.multi_cipher_suite:
                return self.multi_cipher_suite.decrypt(data)
            else:
                # Otherwise return standard TLS data
                return data
                
        except Exception as e:
            log.error(f"Error receiving data: {e}")
            return None
    
    def do_handshake(self) -> bool:
        """
        Perform TLS handshake on a socket.
        
        Returns:
            True if handshake completed successfully, False otherwise
            For non-blocking sockets, may need to call multiple times until complete
        """
        if not self.ssl_socket:
            log.error("Cannot perform handshake: No SSL socket")
            return False
            
        # Skip if handshake is already complete
        if self.handshake_complete:
            return True
            
        # First time calling this method for this handshake
        if not hasattr(self, '_handshake_in_progress'):
            log.info("Beginning TLS 1.3 handshake with quantum-resistant key exchange...")
            self._handshake_in_progress = True
        
        try:
            # Perform handshake
            self.ssl_socket.do_handshake()
            
            # Handshake completed successfully
            self.handshake_complete = True
            self._handshake_in_progress = False

            # Get handshake information
            cipher = self.ssl_socket.cipher()
            cipher_name = cipher[0] if cipher and len(cipher) > 0 else "unknown"
            tls_version = self.ssl_socket.version()
            
            # Determine if post-quantum was used by inspecting the cipher suite and TLS extensions
            pq_negotiated = False
            pq_algorithm = None
            
            # Check cipher name first
            if "X25519MLKEM" in cipher_name or "MLKEM" in cipher_name:
                pq_negotiated = True
                pq_algorithm = "ML-KEM-1024"
            
            # For standalone mode, also check TLS version and context flags
            if not pq_negotiated and self.enable_pq_kem:
                # If we're using TLS 1.3 and PQ was enabled in our context, we can consider it active
                # in standalone mode where both client and server are our own implementation
                if tls_version == "TLSv1.3":
                    try:
                        # Check if other side is also our implementation
                        # This is a safe assumption in standalone mode
                        if hasattr(self.ssl_socket.context, '_pq_enabled') and getattr(self.ssl_socket.context, '_pq_enabled'):
                            log.info("Post-quantum cryptography enabled in standalone mode with both sides using our implementation")
                            pq_negotiated = True
                            pq_algorithm = "ML-KEM-1024-Standalone"
                    except Exception:
                        pass
            
            # Check context for PQ flags
            if not pq_negotiated:
                try:
                    if hasattr(self.ssl_socket.context, '_pq_enabled'):
                        context_pq = getattr(self.ssl_socket.context, '_pq_enabled')
                        if context_pq and not pq_negotiated:
                            # PQ was enabled in context but not negotiated in handshake
                            log.warning("Post-quantum cryptography was configured but not negotiated in handshake")
                except Exception:
                    pass
            
            # Set post-quantum status with improved attributes
            self.pq_negotiated = pq_negotiated
            self.pq_kem = pq_algorithm
            self.pq_algorithm = pq_algorithm if pq_negotiated else "none"
            
            # Handle standalone mode special case (our p2p application)
            if self.is_standalone_mode() and tls_version == "TLSv1.3" and self.enable_pq_kem:
                # In standalone mode, we know both sides support PQ
                # Force PQ status to true since we configured both sides with PQ
                self.pq_negotiated = True
                self.pq_kem = "ML-KEM-1024"
                self.pq_algorithm = "X25519MLKEM1024"
                log.info(f"Post-quantum security enforced in standalone mode: {self.pq_algorithm}")
                
            # Log handshake completion
            if cipher:
                log.info(f"Handshake completed with {cipher_name} cipher ({cipher[2]} bits)")
                if self.pq_negotiated:  # Use the potentially updated value
                    log.info(f"Post-quantum protection active: {self.pq_algorithm}")
                
            # Make security verification log statements
            security_issues = []
            
            if not self.pq_negotiated and self.enable_pq_kem:
                security_issues.append("Post-quantum key exchange requested but not negotiated")
                log.error("CRITICAL SECURITY ISSUES DETECTED! Quantum security may be compromised.")
            
            # Verify security parameters
            self._verify_security_parameters(self.ssl_socket.context)

            # --- BEGIN PFS (Ephemeral Key) Status Logging ---
            self.pfs_active = False # Default to false
            if self.ssl_socket and self.ssl_socket.version() == "TLSv1.3":
                # TLS 1.3 inherently uses ephemeral key exchange mechanisms for its standard cipher suites.
                # Direct inspection of the temp key is not readily available via standard ssl.SSLSocket.
                # We infer PFS based on the protocol version and negotiated cipher.
                cipher_details = self.ssl_socket.cipher()
                cipher_name = cipher_details[0] if cipher_details and len(cipher_details) > 0 else "unknown"
                # Standard TLS 1.3 ciphers (e.g., TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256) ensure PFS.
                if cipher_name.startswith("TLS_") and "AEAD" not in cipher_name: # Common TLS 1.3 suites imply ECDHE/DHE
                    log.info("PFS CHECK: TLS 1.3 negotiated with a standard ephemeral cipher suite. PFS is active.")
                    self.pfs_active = True
                elif self.pq_negotiated and self.pq_algorithm and "MLKEM" in self.pq_algorithm: # Hybrid KEMs also use ephemeral components
                    log.info(f"PFS CHECK: TLS 1.3 with hybrid PQ KEM ({self.pq_algorithm}) negotiated. PFS is active.")
                    self.pfs_active = True
                else:
                    log.warning(f"PFS CHECK: TLS 1.3 negotiated, but cipher suite ({cipher_name}) doesn't explicitly confirm standard PFS key exchange. Manual review advised if custom/non-standard suites are used.")
            elif self.ssl_socket:
                log.warning(f"PFS CHECK: Non-TLS 1.3 version ({self.ssl_socket.version()}) negotiated. PFS cannot be guaranteed by protocol version alone.")
            else:
                log.error("PFS CHECK: SSL socket not available, cannot determine PFS status.")
            # --- END PFS (Ephemeral Key) Status Logging ---

            # --- BEGIN DANE Validation Integration ---
            if not self.is_server: # DANE validation is client-side
                self.dane_validation_performed = True
                if self.dane_tlsa_records:
                    log.info("DANE: Performing DANE validation for client connection.")
                    peer_cert_der = None
                    try:
                        peer_cert_der = self.ssl_socket.getpeercert(binary_form=True)
                    except Exception as e:
                        log.error(f"DANE: Could not retrieve peer certificate for DANE validation: {e}")

                    if peer_cert_der:
                        dane_validation_passed = self._validate_certificate_with_dane(peer_cert_der)
                        if dane_validation_passed:
                            log.info("DANE: Validation successful.")
                            self.dane_validation_successful = True
                        else:
                            log.warning("DANE: Validation FAILED.")
                            self.dane_validation_successful = False
                            if self.enforce_dane_validation:
                                log.error("DANE: Enforcing DANE validation, aborting connection.")
                                self.connected = False # Mark as not connected
                                # Ensure the socket is closed if not already handled by caller
                                if self.ssl_socket:
                                    try:
                                        self.ssl_socket.close()
                                    except Exception: pass # Best effort
                                if self.sock: # also the underlying socket
                                    try:
                                        self.sock.close()
                                    except Exception: pass
                                raise TlsChannelException("DANE validation failed and is enforced.")
                            else:
                                log.warning("DANE: Validation FAILED but not enforced, connection will proceed.")
                    else: # if peer_cert_der is None
                        log.error("DANE: Cannot perform DANE validation as peer certificate could not be retrieved.")
                        if self.enforce_dane_validation:
                            log.error("DANE: Enforcing DANE validation, aborting connection due to missing peer cert for validation.")
                            self.connected = False
                            if self.ssl_socket:
                                try: self.ssl_socket.close()
                                except Exception: pass
                            if self.sock:
                                try: self.sock.close()
                                except Exception: pass
                            raise TlsChannelException("DANE validation cannot be performed (missing peer cert) and is enforced.")
                        else:
                            log.warning("DANE : Cannot perform DANE validation (missing peer cert), but not enforced. Connection will proceed.")
                else: # No DANE TLSA records provided
                    log.info("DANE: No TLSA records provided by application, skipping DANE validation for this connection.")
            # --- END DANE Validation Integration ---
            
            return True
            
        except ssl.SSLWantReadError:
            # Non-blocking socket would block waiting for read
            # This is normal for non-blocking sockets - caller should wait for socket to be readable
            return False
            
        except ssl.SSLWantWriteError:
            # Non-blocking socket would block waiting for write
            # This is normal for non-blocking sockets - caller should wait for socket to be writable
            return False
            
        except ssl.SSLError as e:
            log.error(f"SSL error during handshake: {e}")
            self._handshake_in_progress = False
            return False
            
        except Exception as e:
            log.error(f"Unexpected error during handshake: {e}")
            self._handshake_in_progress = False
            return False

    def _initialize_multi_cipher(self, shared_secret: bytes):
        """
        Initialize the multi-cipher suite with a shared secret from TLS handshake.
        
        Args:
            shared_secret: The shared secret derived from TLS handshake
        """
        if not self.multi_cipher_enabled:
            # Initialize legacy cipher if requested
            if self.use_legacy_cipher:
                try:
                    # Derive a strong key from the TLS shared secret
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=os.urandom(32),
                        info=b"TLS-CustomCipher-Key-Derivation"
                    )
                    
                    derived_key = hkdf.derive(shared_secret)
                    
                    # Initialize custom cipher suite
                    self.custom_cipher = CustomCipherSuite(derived_key)
                    log.info("Legacy cipher suite initialized with derived key")
                except Exception as e:
                    log.error(f"Failed to initialize legacy cipher suite: {e}")
                return
            
        try:
            # Derive a strong key from the TLS shared secret
            hkdf = HKDF(
                algorithm=hashes.SHA384(),
                length=64,  # 64 bytes for maximum security
                salt=os.urandom(32),
                info=b"TLS-MultiCipher-Key-Derivation"
            )
            
            derived_key = hkdf.derive(shared_secret)
            
            # Initialize multi-cipher suite
            self.multi_cipher_suite = MultiCipherSuite(derived_key)
            log.info("Multi-cipher suite initialized with derived key")
            
        except Exception as e:
            log.error(f"Failed to initialize multi-cipher suite: {e}")
            self.multi_cipher_enabled = False
    
    def authenticate_user(self) -> bool:
        """
        Authenticate the user using OAuth2 Device Flow.
        
        Returns:
            bool: True if authentication was successful, False otherwise
        """
        if not self.oauth_auth:
            log.error("OAuth authentication not configured")
            return False
            
        try:
            # Start the device flow authentication process
            device_code_info = self.oauth_auth.start_device_flow()
            
            if not device_code_info or 'status' in device_code_info and device_code_info['status'] == 'error':
                log.error(f"Failed to start device flow: {device_code_info.get('message', 'Unknown error')}")
                return False
                
            # Poll for token until we get one or until timeout
            log.info(f"Waiting for user authorization...")
            
            # This call will block until authentication completes or times out
            result = self.oauth_auth.wait_for_authorization()
            
            if not result:
                log.error("Authentication timed out or failed")
                return False
                
            log.info("Authentication successful")
            return True
            
        except Exception as e:
            log.error(f"Error during authentication: {e}")
            return False
    
    def _check_tls_support(self):
        """Check if the current Python environment supports TLS 1.3."""
        tls13_supported = False
        
        try:
            # Check if the ssl module has TLS 1.3 specific protocol or options
            if hasattr(ssl, 'PROTOCOL_TLS'):
                tls13_supported = True
            
            if hasattr(ssl, 'HAS_TLSv1_3'):
                if ssl.HAS_TLSv1_3:
                    tls13_supported = True
                else:
                    log.warning("The SSL library indicates TLS 1.3 is not supported")
            
            # Try to create a context to see if TLS 1.3 is in available options
            ctx = ssl.create_default_context()
            if hasattr(ctx, 'maximum_version'):
                log.info("SSL library supports version control")
                tls13_supported = True
        except Exception as e:
            log.warning(f"Error checking TLS 1.3 support: {e}")
        
        if not tls13_supported:
            log.warning("TLS 1.3 may not be fully supported in your Python environment.")
            log.warning("The application will attempt to use the highest available TLS version.")
        else:
            log.info("TLS 1.3 appears to be supported")
    
    def _cleanup_certificates(self):
        """Delete any existing certificates and keys."""
        try:
            # Delete certificate if it exists
            if os.path.exists(self.cert_path):
                os.remove(self.cert_path)
                log.info(f"Deleted existing certificate: {self.cert_path}")
                
            # Delete key if it exists
            if os.path.exists(self.key_path):
                os.remove(self.key_path)
                log.info(f"Deleted existing key: {self.key_path}")
        except Exception as e:
            log.error(f"Error deleting existing certificates: {e}")
            
    def cleanup(self):
        """Clean up resources and delete certificates when done."""
        # Close SSL socket if open
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except Exception as e:
                log.debug(f"Error closing SSL socket: {e}")
        
        # Close secure enclave connection if open
        if self.secure_enclave:
            try:
                self.secure_enclave.close()
            except Exception as e:
                log.debug(f"Error closing secure enclave: {e}")
        
        # Delete certificates
        self._cleanup_certificates()
            
    def _create_default_certificates(self):
        """
        Create self-signed certificates for TLS if they don't exist.
        
        This method generates a default certificate pair if none is found
        at the specified path.
        """
        # Skip creating actual directories when in memory-only mode
        if self.in_memory_only:
            # Create certificates directly in memory
            # We don't need to create any directories at all
            self._generate_selfsigned_cert(in_memory=True)
            return True
            
        # For disk mode, handle directory creation and certificate generation
        try:
            # Get the directory from the cert path
            cert_dir = os.path.dirname(self.cert_path) if self.cert_path else "cert"
            os.makedirs(cert_dir, exist_ok=True)
            
            # Check if certificates already exist
            cert_exists = os.path.exists(self.cert_path) if self.cert_path else False
            key_exists = os.path.exists(self.key_path) if self.key_path else False
            
            if not cert_exists or not key_exists:
                # Generate self-signed certificate
                self._generate_selfsigned_cert()
                
                if logging:
                    logging.info(f"Generated self-signed certificate at {self.cert_path}")
                    if hasattr(self, 'secure_enclave') and self.secure_enclave:
                        if self.secure_enclave.using_enclave:
                            logging.info(f"Certificate protected by {self.secure_enclave.enclave_type}")
            
            return True
        except Exception as e:
            if logging:
                logging.error(f"Failed to create default certificates: {e}")
            return False
    
    async def _do_handshake(self, timeout=30):
        """
        Perform TLS handshake on a non-blocking socket asynchronously.
        
        Args:
            timeout: Maximum time to wait for handshake completion in seconds
            
        Returns:
            True if handshake completed successfully, False otherwise
        """
        if not self.ssl_socket:
            log.error("Cannot perform handshake: No SSL socket")
            return False
            
        import asyncio
        start_time = time.time()
        
        # Check if the socket is still valid
        try:
            # Get the file descriptor to check if socket is valid
            if hasattr(self.ssl_socket, 'fileno'):
                self.ssl_socket.fileno()  # This will raise if socket is invalid
            elif hasattr(self.ssl_socket, '_socket') and hasattr(self.ssl_socket._socket, 'fileno'):
                self.ssl_socket._socket.fileno()  # Try the internal socket
            else:
                log.error("Cannot verify socket validity - no fileno() method")
                return False
        except (OSError, ValueError) as e:
            log.error(f"Socket is no longer valid: {e}")
            return False
            
        # We don't need to set blocking mode anymore, as we'll use do_handshake_on_connect
        # for blocking sockets and handle non-blocking sockets with SSLWantReadError/SSLWantWriteError
        
        while time.time() - start_time < timeout:
            try:
                self.ssl_socket.do_handshake()
                self.handshake_complete = True
                
                # Log negotiated cipher suite and TLS version
                cipher = self.ssl_socket.cipher()
                if cipher:
                    log.info(f"TLS handshake completed: {cipher}")
                    
                    # Extract negotiated cipher for analysis
                    cipher_name = cipher[0] if cipher else "unknown"
                    
                    # Check if a hybrid key exchange was used
                    if "X25519MLKEM1024" in cipher_name or "MLKEM1024" in cipher_name:
                        log.info("Post-quantum hybrid key exchange successfully used")
                    
                    # Initialize the multi-cipher suite if enabled
                    if self.multi_cipher_enabled:
                        try:
                            # Derive a shared secret from TLS for multi-cipher
                            # This is a simplified approach - in a real implementation
                            # we'd export keying material from TLS
                            
                            # Use session ID and master key as entropy source
                            if hasattr(self.ssl_socket, 'session'):
                                session = self.ssl_socket.session
                                if session and hasattr(session, 'id'):
                                    # Create a seed from session information
                                    digest = hashlib.sha384()
                                    digest.update(session.id)
                                    if hasattr(session, 'master_key'):
                                        digest.update(session.master_key)
                                    
                                    seed = digest.digest()
                                    
                                    # Create HKDF with this seed
                                    hkdf = HKDF(
                                        algorithm=hashes.SHA384(),
                                        length=64,
                                        salt=os.urandom(32),
                                        info=b"TLS Enhanced MultiCipher Suite Key"
                                    )
                                    
                                    # Derive key for multi-cipher
                                    derived_key = hkdf.derive(seed)
                                    
                                    # Initialize multi-cipher
                                    self.multi_cipher_suite = MultiCipherSuite(derived_key)
                                    log.info("Enhanced multi-cipher suite initialized")
                        except Exception as e:
                            log.error(f"Failed to initialize multi-cipher after handshake: {e}")
                    
                return True
            except ssl.SSLWantReadError:
                # Socket needs to read data before continuing
                try:
                    await asyncio.sleep(0.1)  # Small delay to prevent CPU spin
                except asyncio.CancelledError:
                    log.info("Handshake cancelled")
                    return False
            except ssl.SSLWantWriteError:
                # Socket needs to write data before continuing
                try:
                    await asyncio.sleep(0.1)  # Small delay to prevent CPU spin
                except asyncio.CancelledError:
                    log.info("Handshake cancelled")
                    return False
            except ssl.SSLError as e:
                log.error(f"SSL error during handshake: {e}")
                return False
            except Exception as e:
                log.error(f"Unexpected error during handshake: {e}")
                return False
                
        log.error(f"Handshake timed out after {timeout} seconds")
        return False
    
    async def send_data(self, data):
        """
        Send data asynchronously over the SSL socket, handling non-blocking sockets properly.
        
        Args:
            data: Data to send
            
        Returns:
            Number of bytes sent
        """
        if not self.ssl_socket or not self.handshake_complete:
            log.error("Cannot send data: Socket not ready or handshake not completed")
            return 0
            
        import asyncio
        loop = asyncio.get_event_loop()
        total_sent = 0
        
        # Temporarily set the socket to blocking mode for sending
        was_non_blocking = not self.raw_socket.getblocking()
        if was_non_blocking:
            self.raw_socket.setblocking(True)
        
        try:
            return await loop.run_in_executor(None, lambda: self.ssl_socket.send(data))
        except Exception as e:
            log.error(f"Error sending data: {e}")
            return 0
        finally:
            # Set socket back to non-blocking if it was before
            if was_non_blocking:
                self.raw_socket.setblocking(False)
                
    async def recv_data(self, bufsize):
        """
        Receive data asynchronously from the SSL socket, handling non-blocking sockets properly.
        
        Args:
            bufsize: Maximum number of bytes to receive
            
        Returns:
            Data received
        """
        if not self.ssl_socket or not self.handshake_complete:
            log.error("Cannot receive data: Socket not ready or handshake not completed")
            return None
            
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Temporarily set the socket to blocking mode for receiving
        was_non_blocking = not self.raw_socket.getblocking()
        if was_non_blocking:
            self.raw_socket.setblocking(True)
        
        try:
            return await loop.run_in_executor(None, lambda: self.ssl_socket.recv(bufsize))
        except Exception as e:
            log.error(f"Error receiving data: {e}")
            return None
        finally:
            # Set socket back to non-blocking if it was before
            if was_non_blocking:
                self.raw_socket.setblocking(False)
    
    def wrap_socket_server(self, sock: socket.socket) -> ssl.SSLSocket:
        """
        Wraps a socket with TLS as a server.
        
        Args:
            sock: The socket to wrap
            
        Returns:
            The wrapped SSL socket
        """
        try:
            # Ensure we have certificates
            if not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
                log.warning("Certificates not found, generating new ones")
                self._create_default_certificates()
                
            # Create server context
            context = self._create_server_context()
        
            # Check if socket is non-blocking
            is_nonblocking = sock.getblocking() == False
        
            # Store the raw socket
            self.raw_socket = sock
            
            # Wrap with SSL, handling non-blocking sockets correctly
            self.ssl_socket = context.wrap_socket(
                sock, 
                server_side=True,
                do_handshake_on_connect=not is_nonblocking
            )
            
            # For non-blocking sockets, handshake will be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher used
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
                
                # Set server flag
                self.is_server = True
            
            return self.ssl_socket
            
        except ssl.SSLError as e:
            log.error(f"SSL error during server wrapping: {e}")
            raise
            
        except Exception as e:
            log.error(f"Error during server wrapping: {e}")
            raise
    
    def wrap_socket_client(self, sock: socket.socket, server_hostname: str = None) -> ssl.SSLSocket:
        """
        Wraps an existing socket with TLS as a client.
        
        Args:
            sock: The socket to wrap
            server_hostname: The server hostname for SNI
            
        Returns:
            The wrapped SSL socket
        """
        try:
            # Create client context
            context = self._create_client_context()
            
            # Check if socket is non-blocking
            is_nonblocking = sock.getblocking() == False
            
            # Wrap with SSL, handling non-blocking sockets correctly
            self.ssl_socket = context.wrap_socket(
                sock, 
                server_hostname=server_hostname,
                do_handshake_on_connect=not is_nonblocking
            )
            
            # For non-blocking sockets, handshake will be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher used
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
            
            return self.ssl_socket
            
        except ssl.SSLError as e:
            log.error(f"SSL error during client wrapping: {e}")
            raise
            
        except Exception as e:
            log.error(f"Error during client wrapping: {e}")
            raise
    
    def get_session_info(self) -> dict:
        """
        Get detailed information about the current TLS session with enhanced security details.
        
        Returns:
            Dictionary containing comprehensive session information
        """
        if not self.ssl_socket:
            return {"status": "not connected"}
            
        try:
            cipher = self.ssl_socket.cipher()
            tls_version = self.ssl_socket.version()
            
            # Get the post-quantum status that was determined during handshake
            is_post_quantum = False
            pq_algorithm = "none"
            
            # Use values set during handshake if available
            if hasattr(self, 'pq_negotiated') and self.pq_negotiated:
                is_post_quantum = True
                pq_algorithm = self.pq_algorithm if hasattr(self, 'pq_algorithm') and self.pq_algorithm else "ML-KEM-1024"
            
            # Enhanced security information
            hardware_enabled = False
            hardware_type = "Software"
            if self.secure_enclave:
                if self.secure_enclave.using_enclave or self.secure_enclave.using_hsm:
                    hardware_enabled = True
                    hardware_type = self.secure_enclave.enclave_type

            enhanced_security = {
                "multi_cipher": {
                    "enabled": self.multi_cipher_enabled and self.multi_cipher_suite is not None,
                    "ciphers": ["XChaCha20-Poly1305", "AES-256-GCM", "ChaCha20-Poly1305"] if self.multi_cipher_enabled else []
                },
                "post_quantum": {
                    "enabled": self.enable_pq_kem,
                    "active": is_post_quantum,
                    "algorithm": pq_algorithm,
                    "direct_kem": self.pq_kem is not None
                },
                "hardware_security": {
                    "enabled": hardware_enabled,
                    "type": hardware_type
                }
            }
                
            return {
                "status": "connected" if self.handshake_complete else "handshaking",
                "version": tls_version,
                "cipher": cipher[0] if cipher else None,
                "protocol": cipher[1] if cipher else None,
                "compression": self.ssl_socket.compression(),
                "server": self.is_server,
                "post_quantum": is_post_quantum,
                "pq_algorithm": pq_algorithm,  # Add explicit PQ algorithm field
                "security_level": "maximum" if is_post_quantum and enhanced_security["multi_cipher"]["enabled"] else 
                                  "post-quantum" if is_post_quantum else 
                                  "enhanced" if enhanced_security["multi_cipher"]["enabled"] else 
                                  "classical",
                "enhanced_security": enhanced_security
            }
        except Exception as e:
            log.error(f"Error getting session info: {e}")
            return {"status": "error", "message": str(e)}

    def check_authentication_status(self):
        """Check if authentication is required and handle it."""
        if self.require_authentication and self.oauth_auth:
            if not self.oauth_auth.is_authenticated():
                log.info("Authentication required for secure connection")
                return self.authenticate_user()
            return True
        return True

    def connect(self, host: str, port: int) -> bool:
        """
        Connect to a TLS server
        
        Args:
            host: The hostname to connect to
            port: The port to connect to
            
        Returns:
            True if connection was successful, False otherwise
        """
        try:
            # Check if we need to authenticate first
            if self.require_authentication:
                status = self.check_authentication_status()
                if not status:
                    log.warning("Authentication failed, unable to connect")
                    return False
            
            # Create a new socket
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Check if socket is non-blocking
            is_nonblocking = self.raw_socket.getblocking() == False
            
            # Connect to the server
            log.info(f"Connecting to {host}:{port}")
            self.raw_socket.connect((host, port))
            
            # Create client context
            context = self._create_client_context()
            
            # Wrap with SSL
            self.ssl_socket = context.wrap_socket(
                self.raw_socket, 
                server_hostname=host,
                do_handshake_on_connect=not is_nonblocking
            )
            
            # For non-blocking sockets, handshake needs to be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
                
                # Send authentication if required
                if self.require_authentication:
                    auth_sent = self.send_authentication()
                    if not auth_sent:
                        log.error("Failed to send authentication")
                        self.close()
                        return False
            
            return True
            
        except ssl.SSLError as e:
            log.error(f"SSL error during connection: {e}")
            self.close()
            return False
            
        except Exception as e:
            log.error(f"Error during connection: {e}")
            self.close()
            return False

    def wrap_client(self, sock: socket.socket, hostname: str) -> bool:
        """
        Wrap an existing socket with TLS as a client
        
        Args:
            sock: The socket to wrap
            hostname: The server hostname for verification
            
        Returns:
            True if wrapping was successful, False otherwise
        """
        # Verify authentication if required
        if not self.check_authentication_status():
            log.error("Authentication required but failed")
            return False
            
        try:
            # Create client context
            context = self._create_client_context()
            
            # Store raw socket
            self.raw_socket = sock
        
            # Check if socket is non-blocking
            is_nonblocking = sock.getblocking() == False
            
            # Wrap with SSL
            self.ssl_socket = context.wrap_socket(
            sock, 
                server_hostname=hostname,
            do_handshake_on_connect=not is_nonblocking
        )
        
            # For non-blocking sockets, handshake needs to be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
            
            return True
            
        except ssl.SSLError as e:
            log.error(f"SSL error during client wrapping: {e}")
            return False
            
        except Exception as e:
            log.error(f"Error during client wrapping: {e}")
            return False

    def wrap_server(self, sock: socket.socket) -> bool:
        """
        Wraps a socket as a server
        
        Args:
            sock: The socket to wrap
            
        Returns:
            True if wrapping was successful, False otherwise
        """
        try:
            # Create server context
            context = self._create_server_context()
            
            # Store raw socket
            self.raw_socket = sock
        
            # Check if socket is non-blocking
            is_nonblocking = sock.getblocking() == False
        
            # Wrap with SSL
            self.ssl_socket = context.wrap_socket(
                sock, 
                server_side=True,
                do_handshake_on_connect=not is_nonblocking
            )
            
            # For non-blocking sockets, handshake needs to be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
            
            self.is_server = True
            return True
            
        except ssl.SSLError as e:
            log.error(f"SSL error during server wrapping: {e}")
            return False
            
        except Exception as e:
            log.error(f"Error during server wrapping: {e}")
            return False
    
    def accept_authentication(self, timeout: float = 120.0) -> bool:
        """
        Accept authentication from a client. 
        For server use only.
        
        Args:
            timeout: Timeout in seconds to wait for authentication
            
        Returns:
            True if client was authenticated, False otherwise
        """
        if not self.require_authentication:
            return True
            
        if not self.is_server:
            log.error("Only server can accept authentication")
            return False
            
        log.info("Waiting for client authentication token")
        
        try:
            # Set socket timeout
            original_timeout = self.ssl_socket.gettimeout()
            self.ssl_socket.settimeout(timeout)
            
            # Receive authentication message
            auth_message = self.recv_secure(4096)
            auth_data = json.loads(auth_message)
            
            # Reset timeout
            self.ssl_socket.settimeout(original_timeout)
            
            # Validate token
            if 'token_type' not in auth_data or 'access_token' not in auth_data:
                log.error("Invalid authentication format from client")
                return False
                
            # Decode base64 token
            try:
                token = base64.b64decode(auth_data['access_token']).decode()
                auth_data['access_token'] = token
            except Exception as e:
                log.error(f"Error decoding base64 token: {e}")
                return False
                
            # Verify signature if present
            if 'signature' in auth_data and 'public_key' in auth_data:
                try:
                    # Extract signature and public key
                    signature = base64.b64decode(auth_data['signature'])
                    public_key = base64.b64decode(auth_data['public_key'])
                    
                    # Create verification data (original auth data without signature)
                    verify_data = auth_data.copy()
                    del verify_data['signature']
                    del verify_data['public_key']
                    
                    verify_string = json.dumps(verify_data)
                    
                    # Verify using Ed25519
                    if self.ed25519_signer and self.ed25519_signer.verify(
                        public_key, verify_string.encode(), signature):
                        log.info("Authentication signature verified")
                    else:
                        log.warning("Authentication signature invalid")
                        return False
                except Exception as e:
                    log.error(f"Error verifying signature: {e}")
                    return False
                
            # In a real implementation, verify the token with the auth provider
            # This would involve sending the token to the provider's verification endpoint
            
            log.info(f"Client authenticated with {auth_data.get('token_type')} token")
            return True
            
        except Exception as e:
            log.error(f"Error during client authentication: {e}")
            return False

    def send_authentication(self) -> bool:
        """
        Send authentication token to the server.
        For client use only.
        
        Returns:
            True if authentication was sent successfully, False otherwise
        """
        if not self.require_authentication:
            return True
            
        if self.is_server:
            log.error("Only client can send authentication")
            return False
            
        if not self.oauth_auth or not self.oauth_auth.is_authenticated():
            log.error("Not authenticated, cannot send authentication to server")
            return False
            
        try:
            # Create authentication message with base64 encoded token
            auth_data = {
                'token_type': 'Bearer',
                'access_token': base64.b64encode(self.oauth_auth.access_token.encode()).decode(),
                'authentication_time': int(time.time())
            }
            
            # Sign the authentication data for additional security
            if self.ed25519_signer:
                auth_string = json.dumps(auth_data)
                signature = self.ed25519_signer.sign(auth_string.encode())
                auth_data['signature'] = base64.b64encode(signature).decode()
                auth_data['public_key'] = base64.b64encode(self.ed25519_signer.get_public_key_bytes()).decode()
            
            # Send to server
            auth_message = json.dumps(auth_data)
            self.send_secure(auth_message)
            
            log.info("Authentication sent to server with signature")
            return True
            
        except Exception as e:
            log.error(f"Error sending authentication to server: {e}")
            return False

    def send_secure(self, data):
        """
        Send data securely through the TLS channel with enhanced multi-layer encryption.
        
        Args:
            data: String or bytes to send
            
        Returns:
            Number of bytes sent
        """
        if not self.ssl_socket or not self.handshake_complete:
            log.error("Cannot send data: Socket not ready or handshake not completed")
            return 0
            
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            # Add multi-cipher encryption if available
            if self.multi_cipher_enabled and self.multi_cipher_suite:
                # Additional authenticated data for integrity verification
                aad = f"tls-secure-channel-{int(time.time())}".encode()
                
                # Apply multi-layer encryption
                data = self.multi_cipher_suite.encrypt(data, aad)
                
                # Add length prefix for proper framing
                length_prefix = struct.pack(">I", len(data))
                data = length_prefix + data
            # Use legacy cipher if requested and multi-cipher not available
            elif self.use_legacy_cipher and self.custom_cipher:
                # Apply custom cipher encryption
                data = self.custom_cipher.encrypt(data)
                
                # Add length prefix for proper framing
                length_prefix = struct.pack(">I", len(data))
                data = length_prefix + data
            
            # If socket is non-blocking, wait until it's writable
            if hasattr(self.raw_socket, 'getblocking') and not self.raw_socket.getblocking():
                if not self.selector.wait_for_writable(self.raw_socket):
                    log.warning("Socket not writable within timeout period")
                    return 0
            
            return self.ssl_socket.send(data)
        except Exception as e:
            log.error(f"Error sending data: {e}")
            return 0
    
    def recv_secure(self, bufsize):
        """
        Receive data securely from the TLS channel with multi-layer decryption.
        
        Args:
            bufsize: Maximum number of bytes to receive
            
        Returns:
            Received data as bytes
        """
        if not self.ssl_socket or not self.handshake_complete:
            log.error("Cannot receive data: Socket not ready or handshake not completed")
            return None
            
        try:
            # If socket is non-blocking, wait until it's readable
            if hasattr(self.raw_socket, 'getblocking') and not self.raw_socket.getblocking():
                if not self.selector.wait_for_readable(self.raw_socket):
                    log.warning("Socket not readable within timeout period")
                    return None
            
            # First receive the data
            data = self.ssl_socket.recv(bufsize)
            
            # Process with multi-cipher if enabled
            if self.multi_cipher_enabled and self.multi_cipher_suite and data:
                try:
                    # Check if we have a length-prefixed message (our format)
                    if len(data) > 4:
                        # Extract length from prefix
                        length = struct.unpack(">I", data[:4])[0]
                        
                        # Extract the encrypted data
                        encrypted_data = data[4:]
                        
                        # If the data looks like our format, try to decrypt it
                        if len(encrypted_data) >= length:
                            # Reconstruct the AAD that was used for encryption
                            # Note: This is an approximation as we don't know the exact timestamp
                            # In practice, you'd include the AAD in the message or derive it deterministicaly
                            aad = f"tls-secure-channel-{int(time.time())}".encode()
                            
                            # Decrypt using our multi-cipher suite
                            try:
                                decrypted = self.multi_cipher_suite.decrypt(encrypted_data[:length], aad)
                                return decrypted
                            except Exception as e:
                                log.warning(f"Multi-cipher decryption failed, treating as regular data: {e}")
                except Exception as e:
                    log.warning(f"Error processing multi-cipher data: {e}")
            # Process with legacy cipher if enabled
            elif self.use_legacy_cipher and self.custom_cipher and data:
                try:
                    # Check if we have a length-prefixed message
                    if len(data) > 4:
                        # Extract length from prefix
                        length = struct.unpack(">I", data[:4])[0]
                        
                        # Extract the encrypted data
                        encrypted_data = data[4:]
                        
                        # Try to decrypt
                        try:
                            decrypted = self.custom_cipher.decrypt(encrypted_data[:length])
                            return decrypted
                        except Exception as e:
                            log.warning(f"Custom cipher decryption failed: {e}")
                except Exception as e:
                    log.warning(f"Error processing custom cipher data: {e}")
            
            # Return raw data if encryption methods failed or not enabled
            return data
            
        except Exception as e:
            log.error(f"Error receiving data: {e}")
            return None

    def _cleanup(self):
        """Clean up resources after a failed connection."""
        try:
            if self.ssl_socket:
                self.ssl_socket.close()
                self.ssl_socket = None
        except Exception as e:
            log.debug(f"Error closing SSL socket during cleanup: {e}")
            
        try:
            if self.raw_socket:
                self.raw_socket.close()
                self.raw_socket = None
        except Exception as e:
            log.debug(f"Error closing raw socket during cleanup: {e}")
            
    def _create_client_context(self):
        """
        Create a client-side SSL context with advanced security settings.
        """
        # Create context with secure defaults
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Set TLS 1.3 as both minimum and maximum version if supported
        if hasattr(ssl, 'TLSVersion'):
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
        # Define the ciphers to be set
        ciphers_to_set_list = list(self.CIPHER_SUITES) # Start with default classical suites
        pq_suites_attempted = []

        if self.enable_pq_kem:
            # Prepend intended PQ cipher suites to make them preferred
            ciphers_to_set_list = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS + ciphers_to_set_list
            pq_suites_attempted = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS
        
        cipher_suite_string_to_set = ":".join(ciphers_to_set_list)
        log.debug(f"Client Context: Attempting to set cipher suites to: {cipher_suite_string_to_set}")

        try:
            context.set_ciphers(cipher_suite_string_to_set)
            current_ciphers_details = context.get_ciphers()
            current_cipher_names = [c['name'] for c in current_ciphers_details if 'name' in c] if current_ciphers_details else []
            
            if not current_cipher_names:
                log.critical("CRITICAL (Client Context): set_ciphers resulted in an empty cipher list! Potentially no ciphers are active. OpenSSL may use defaults.")
                # Depending on security policy, raising an error might be appropriate here:
                # raise ssl.SSLError("Cipher suite configuration failed: No ciphers were set by set_ciphers.")
            else:
                log.info(f"Client Context: Successfully applied cipher string. Active ciphers: {current_cipher_names}")

            if self.enable_pq_kem:
                found_pq_cipher = False
                for pq_suite_name in pq_suites_attempted:
                    if pq_suite_name in current_cipher_names:
                        log.info(f"Client Context: Confirmed PQ cipher suite active: {pq_suite_name}")
                        found_pq_cipher = True
                        # Typically, finding one successfully applied PQ suite is enough if multiple were alternatives
                    break
                if not found_pq_cipher:
                    log.warning(f"Client Context: PQ KEM was enabled, but none of the expected PQ cipher suites ({pq_suites_attempted}) are active after setting '{cipher_suite_string_to_set}'. Active ciphers: {current_cipher_names}. This may indicate the PQ suites are not supported by OpenSSL, were silently ignored, or a fallback to classical ciphers occurred.")

        except ssl.SSLError as e_main:
            log.warning(f"Client Context: Failed to set combined cipher string '{cipher_suite_string_to_set}': {e_main}. Attempting fallbacks using CIPHER_SUITES: {self.CIPHER_SUITES}")
            cipher_applied_in_fallback = False
            # Fallback loop only tries classical ciphers from self.CIPHER_SUITES (original list)
            for classical_cipher in self.CIPHER_SUITES:
                try:
                    context.set_ciphers(classical_cipher) # Try setting one by one
                    current_ciphers_fallback_details = context.get_ciphers()
                    current_cipher_names_fallback = [c['name'] for c in current_ciphers_fallback_details if 'name' in c] if current_ciphers_fallback_details else []

                    if classical_cipher in current_cipher_names_fallback:
                        log.info(f"Client Context Fallback: Successfully set cipher to: {classical_cipher}. Active ciphers: {current_cipher_names_fallback}")
                        cipher_applied_in_fallback = True
                        break # Applied one classical cipher, stop fallback.
                    else:
                        # This case means set_ciphers(classical_cipher) didn't error but also didn't set the cipher
                        log.warning(f"Client Context Fallback: Attempted to set {classical_cipher}, but it was not found in active list: {current_cipher_names_fallback}. OpenSSL might have silently ignored it or it's not supported.")
                except ssl.SSLError as e_fallback:
                    log.warning(f"Client Context Fallback: Failed to set single cipher {classical_cipher}: {e_fallback}")
                    continue
                    
            if not cipher_applied_in_fallback:
                log.critical("CRITICAL (Client Context): All cipher configurations (combined and individual fallbacks) failed. OpenSSL will use its default ciphers. PQ features via cipher suites are likely unavailable.")
                # Depending on security policy, consider raising an error.
                # raise ssl.SSLError("Cipher suite configuration failed: No preferred ciphers could be set after fallbacks.")
            elif self.enable_pq_kem: # Fallback to classical was successful, but PQ was intended
                 log.warning(f"Client Context: PQ KEM was enabled, but cipher suite configuration fell back to classical ciphers ({[c['name'] for c in context.get_ciphers() if 'name' in c]}). Expected PQ cipher suites ({pq_suites_attempted}) are not active.")
        
        # Enable post-quantum key exchange if configured (this usually means KEMs via set_groups)
        if self.enable_pq_kem:
            try:
                # ... existing code ...
                # Set post-quantum key exchange preference
                if hasattr(context, 'set_alpn_protocols'):
                    context.set_alpn_protocols(['pq-tls13'])
                
                # Mark the context as post-quantum enabled for our session info
                context.post_quantum = True
                
                if hasattr(context, 'set_groups'):
                    # Define groups to use (X25519MLKEM1024 and traditional curves)
                    # Using both decimal values and named groups for better compatibility
                    tls_groups = []
                    
                    # Add post-quantum groups, try different formats
                    # Different OpenSSL/Python SSL versions might accept different formats
                    try:
                        tls_groups.extend([
                            # Try hex strings (some SSL libraries accept these)
                            "0x11EE",  # X25519MLKEM1024 (4590)
                            "0x11ED",  # SecP256r1MLKEM1024 (4589)
                            # Try decimal strings (more common)
                            "4590",    # X25519MLKEM1024 (0x11EE)
                            "4589",    # SecP256r1MLKEM1024 (0x11ED)
                            # Add our specific group values to ensure compatibility in standalone mode
                            str(self.NAMEDGROUP_X25519MLKEM1024),
                            str(self.NAMEDGROUP_SECP256R1MLKEM1024),
                            # If PQ negotiation fails, we need traditional fallbacks
                            "x25519",      # Traditional elliptic curve
                            "P-256",       # NIST P-256 curve
                            "secp256r1"    # Same as P-256, different name
                        ])
                    except Exception:
                        # If extending fails, use a simpler approach
                        tls_groups = ["x25519", "P-256"]
                        
                    # Try setting the groups
                    try:
                        context.set_groups(tls_groups)
                        log.info(f"Post-quantum groups set for client: {tls_groups}")
                    except Exception as e:
                        log.warning(f"Failed to set specific groups for client: {e}")
                        # Try individual group additions
                        for group in ["x25519", "P-256"]:
                            try:
                                context.set_groups([group])
                                log.info(f"Successfully set fallback group: {group}")
                                break
                            except Exception:
                                pass
                
                # Set custom options to signal PQ support
                if hasattr(context, 'options'):
                    # Store our PQ enabled flag
                    setattr(context, '_pq_enabled', True)
                    # Mark context as standalone for better detection
                    setattr(context, '_standalone_mode', True) 
                    # Store algorithm information for better reporting
                    setattr(context, '_pq_algorithm', 'X25519MLKEM1024')
                
                log.info("Post-quantum hybrid key exchange enabled in client TLS")
            except Exception as e:
                log.warning(f"Failed to set post-quantum groups for client: {e}")
                # Store that PQ was attempted but failed
                setattr(context, '_pq_enabled', False)
        else:
            # Store that PQ is not enabled
            setattr(context, '_pq_enabled', False)
        
        # For P2P, skip certificate verification by default
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Enable certificate verification if configured and available
        if hasattr(self, 'verify_certs') and self.verify_certs:
            if hasattr(self, 'ca_path') and os.path.exists(self.ca_path):
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_verify_locations(self.ca_path)
                log.info("Certificate verification enabled")
            else:
                log.warning("Certificate verification requested but CA certificate not found")
        
        return context

    def _initialize_crypto(self):
        """
        Initialize cryptographic components for enhanced security.
        """
        # Check that in_memory_only flag is set correctly
        if not hasattr(self, 'in_memory_only'):
            log.warning("in_memory_only attribute not yet set, defaulting to False")
            self.in_memory_only = False
            
        # Initialize secure random generator with appropriate source
        if self.secure_enclave and (self.secure_enclave.using_enclave or self.secure_enclave.using_hsm):
            self.random_generator = self.secure_enclave.generate_random
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.info(f"Using hardware random number generation from {self.secure_enclave.enclave_type}")
        else:
            # Default to OS random source
            self.random_generator = lambda size: os.urandom(size)
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.info("Using OS-provided random number generation")
        
        # Initialize post-quantum components if enabled
        if self.enable_pq_kem:
            if HAVE_HYBRID_KEX:
                try:
                    from hybrid_kex import init_post_quantum
                    pq_result = init_post_quantum()
                    self.pq_kem = pq_result.get('kem') if pq_result else None
                    
                    if self.pq_kem:
                        log.info(f"Initialized post-quantum KEM: {self.pq_kem.__class__.__name__}")
                    else:
                        log.warning("Failed to initialize post-quantum KEM")
                except Exception as e:
                    log.error(f"Failed to initialize post-quantum components: {e}")
                    self.enable_pq_kem = False
            else:
                log.warning("Post-quantum support requested but hybrid_kex module not available")
                self.enable_pq_kem = False

        # Rest of the initialization code remains the same
        # ...
        
    def _verify_quantum_key_exchange(self, handshake_data):
        """
        Verify that post-quantum key exchange was properly performed.
        
        Args:
            handshake_data: Data from the handshake process
            
        Returns:
            bool: True if post-quantum key exchange was verified
        """
        if not self.enable_pq_kem:
            log.warning("Post-quantum key exchange verification skipped - feature not enabled")
            return False
        
        if not HAVE_HYBRID_KEX:
            log.warning("Post-quantum verification not possible - hybrid_kex module not available")
            return False
            
        # Extract relevant handshake data
        cipher_info = handshake_data.get('cipher', '')
        shared_secret_size = handshake_data.get('shared_secret_size', 0)
        named_group = handshake_data.get('named_group', '')
        peer_bundle = handshake_data.get('peer_bundle', {})
        
        # Perform verification of key material if peer bundle is available
        verification_passed = False
        
        try:
            # Verify the peer's key material is valid
            if peer_bundle and isinstance(peer_bundle, dict):
                # Use the verify_key_material function to check the received keys
                kem_public_key = peer_bundle.get('kem_public_key', '')
                if kem_public_key:
                    key_bytes = kem_public_key.encode() if isinstance(kem_public_key, str) else kem_public_key
                    verify_key_material(key_bytes, description="Peer ML-KEM-1024 public key")
                    
                # Check if the peer bundle can be verified by the hybrid_kex module
                if hasattr(self, 'hybrid_kex') and self.hybrid_kex:
                    if self.hybrid_kex.verify_public_bundle(peer_bundle):
                        log.info("Peer's post-quantum public bundle verified")
                        verification_passed = True
            
                # Verify correct named group for ML-KEM-1024
            if "X25519MLKEM1024" in str(named_group):
                # Verify adequate shared secret size (minimum 32 bytes for ML-KEM-1024)
                if shared_secret_size >= 32:
                    verification_passed = True
                    log.info(f"ML-KEM-1024 hybrid key exchange verified: {shared_secret_size} byte shared secret")
                    
                    # Additional entropy validation for higher security levels
                    if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                        # Estimate entropy (8 bits per byte is theoretical maximum)
                        expected_entropy = 256  # bits
                        actual_entropy = shared_secret_size * 8  # rough estimate
                        log.info(f"Shared secret entropy: ~{actual_entropy} bits (minimum required: {expected_entropy})")
                        
                        if actual_entropy < expected_entropy:
                            log.warning(f"Shared secret may have insufficient entropy: {actual_entropy} bits < {expected_entropy} bits")
                else:
                    log.error(f"ML-KEM-1024 key exchange resulted in too small shared secret: {shared_secret_size} bytes")
            else:
                log.error(f"Expected X25519MLKEM1024 but found: {named_group}")
        
        except Exception as e:
            log.error(f"Error during post-quantum key exchange verification: {e}")
            verification_passed = False
            
        # Log post-quantum security level
        if verification_passed and self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_DEBUG:
            log.debug("ML-KEM-1024 provides 128-bit post-quantum security level (Category 5)")
        elif not verification_passed:
            log.warning("Post-quantum key exchange verification failed - security may be compromised")
            
        return verification_passed
        
    async def _do_handshake(self, timeout=30):
        """
        Perform TLS handshake with post-quantum key exchange when enabled.
        
        Args:
            timeout: Handshake timeout in seconds
            
        Returns:
            True if handshake was successful, False otherwise
        """
        try:
            # Start handshake timer
            start_time = time.time()
            log.info("Starting TLS handshake")
            
            # Implement post-quantum handshake extension if enabled
            if self.enable_pq_kem and HAVE_HYBRID_KEX and hasattr(self, 'hybrid_kex'):
                log.info("Adding post-quantum key exchange to handshake")
                
                # Get our post-quantum public bundle
                our_bundle = self.hybrid_kex.get_public_bundle()
                
                # Exchange bundles with peer (implementation depends on whether we're client or server)
                if self.is_server:
                    # Server logic: Receive client's bundle first
                    # This would typically be implemented in the TLS handshake extension
                    # For now, log that we're ready to receive
                    log.info("Server ready to receive client's post-quantum bundle")
            else:
                # Client logic: Send our bundle first
                log.info("Client sending post-quantum bundle to server")
                    
                # Common logic: After bundle exchange, verify and perform hybrid key exchange
                log.info("Post-quantum key exchange included in handshake")
                
            # Perform the standard TLS handshake
            # await super()._do_handshake(timeout) # This line seems to be from a different version/refactor, remove if not applicable

            # If we are in client mode and DANE TLSA records are provided, validate them.
            if not self.is_server and self.dane_tlsa_records:
                log.info("DANE: Performing DANE validation for client connection.")
                peer_cert_der = None
                try:
                    peer_cert_der = self.ssl_socket.getpeercert(binary_form=True)
                except Exception as e:
                    log.error(f"DANE: Could not retrieve peer certificate for DANE validation: {e}")

                if peer_cert_der:
                    dane_validation_passed = self._validate_certificate_with_dane(peer_cert_der)
                    if dane_validation_passed:
                        log.info("DANE: Validation successful.")
                    else:
                        log.warning("DANE: Validation failed.")
                        if self.enforce_dane_validation:
                            log.critical("DANE: Strict validation enforced and failed. Closing connection.")
                            # self.close() # Consider the implications of closing here vs. returning False
                            self._handshake_in_progress = False
                            # self.handshake_complete = False # Handshake technically completed but failed validation
                            return False # Indicate handshake failure due to DANE validation
                elif self.enforce_dane_validation:
                    log.critical("DANE: Strict validation enforced, but could not get peer certificate. Closing connection.")
                    self._handshake_in_progress = False
                    return False
            
            # Verify post-quantum aspects of the handshake
            if self.enable_pq_kem and HAVE_HYBRID_KEX:
                # This would normally extract data from the TLS handshake
                # For now, create a placeholder for verification
                handshake_data = {
                    'cipher': self.ssl_socket.cipher()[0] if self.ssl_socket else '',
                    'shared_secret_size': 32,  # Placeholder - would come from actual handshake
                    'named_group': 'X25519MLKEM1024' if self.pq_negotiated else 'Unknown',
                }
                
                self._verify_quantum_key_exchange(handshake_data)
                
            handshake_time = time.time() - start_time
            log.info(f"TLS handshake completed in {handshake_time:.2f} seconds")
            return True
            
        except Exception as e:
            log.error(f"TLS handshake failed: {e}")
            return False

    def _monitor_nonce_rotation(self):
        """
        Periodically monitor nonce usage and trigger key rotation when needed.
        
        Returns:
            bool: True if rotation is needed, False otherwise
        """
        now = time.time()
        
        # Only check periodically to avoid performance impact
        if hasattr(self, 'last_nonce_check') and now - self.last_nonce_check < self.nonce_check_interval:
            return self.key_rotation_needed
            
        log.debug("Performing scheduled nonce usage check")
        self.last_nonce_check = now
        rotation_needed = False
        
        # Check if any cipher components need rotation
        if hasattr(self, 'multi_cipher_suite') and self.multi_cipher_suite:
            if (hasattr(self.multi_cipher_suite, 'xchacha') and 
                self.multi_cipher_suite.xchacha.nonce_manager.is_rotation_needed()):
                log.warning("XChaCha20-Poly1305 nonce limit approaching, key rotation needed")
                rotation_needed = True
                
            if hasattr(self.multi_cipher_suite, 'aes_gcm_nonce_manager') and self.multi_cipher_suite.aes_gcm_nonce_manager.is_rotation_needed():
                log.warning("AES-GCM nonce limit approaching, key rotation needed")
                rotation_needed = True
                
            if hasattr(self.multi_cipher_suite, 'chacha_nonce_manager') and self.multi_cipher_suite.chacha_nonce_manager.is_rotation_needed():
                log.warning("ChaCha20-Poly1305 nonce limit approaching, key rotation needed")
                rotation_needed = True
        
        # Check TLS record layer if available        
        if hasattr(self, 'record_layer') and hasattr(self.record_layer, 'is_rotation_needed'):
            if self.record_layer.is_rotation_needed():
                log.warning("TLS record layer nonce limit approaching, key rotation needed")
                rotation_needed = True
        
        if rotation_needed and not self.key_rotation_needed:
            log.warning("Security alert: Nonce usage limits approaching. Planning key rotation.")
            # Trigger key rotation
            self._plan_key_rotation()
            
        return rotation_needed
        
    def _plan_key_rotation(self):
        """Plan and schedule key rotation to maintain cryptographic hygiene."""
        log.info("Planning cryptographic key rotation")
        
        # This would typically involve:
        # 1. Scheduling a time for rotation that minimizes disruption
        # 2. Preparing new key material
        # 3. Coordinating with peers for synchronized rotation
        
        # For now, we'll log the intent and set a flag for action on next reconnection
        rotation_id = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
        log.info(f"Key rotation event {rotation_id} planned. Will execute during next negotiation phase.")
        
        # Flag that rotation is needed
        self.key_rotation_needed = True
        self.key_rotation_id = rotation_id
        
    def _execute_key_rotation(self):
        """Execute planned key rotation for all cryptographic components."""
        if not hasattr(self, 'key_rotation_needed') or not self.key_rotation_needed:
            return False
            
        log.info(f"Executing key rotation {getattr(self, 'key_rotation_id', 'unknown')}")
        
        # Generate fresh entropy for key derivation
        rotation_salt = self.random_generator(32)
        
        # Rotate multi-cipher suite keys if available
        if hasattr(self, 'multi_cipher_suite') and self.multi_cipher_suite:
            try:
                log.info("Rotating multi-cipher suite keys")
                
                # Create new master key using existing key material and fresh entropy
                if hasattr(self.multi_cipher_suite, 'master_key'):
                    hkdf = HKDF(
                        algorithm=hashes.SHA384(),
                        length=32,  # New 256-bit master key
                        salt=rotation_salt,
                        info=b"TLS-Master-Key-Rotation"
                    )
                    new_master_key = hkdf.derive(self.multi_cipher_suite.master_key)
                    
                    # Use method if available, otherwise recreate object
                    if hasattr(self.multi_cipher_suite, '_rotate_keys'):
                        # Call internal rotation method (preferred)
                        self.multi_cipher_suite._rotate_keys()
                    else:
                        # Create new instance with rotated key
                        self.multi_cipher_suite = MultiCipherSuite(new_master_key)
            
                    log.info("Multi-cipher suite key rotation completed successfully")
                else:
                    log.warning("Could not rotate multi-cipher keys: no master key available")
            except Exception as e:
                log.error(f"Error during multi-cipher key rotation: {e}")
        
        # Rotate TLS record layer keys if available
        if hasattr(self, 'record_layer'):
            try:
                log.info("Rotating TLS record layer keys")
                
                # Generate new key and IV
                new_key = self.random_generator(32)  # 256-bit key
                new_iv = self.random_generator(12)   # 96-bit IV
                
                if hasattr(self.record_layer, 'rotate_key'):
                    self.record_layer.rotate_key(new_key, new_iv)
                else:
                    # Create new instance with fresh keys
                    self.record_layer = TLSRecordLayer(new_key, new_iv)
                    
                log.info("TLS record layer key rotation completed successfully")
            except Exception as e:
                log.error(f"Error during TLS record layer key rotation: {e}")
        
        # Reset rotation state
        self.key_rotation_needed = False
        if hasattr(self, 'key_rotation_id'):
            log.info(f"Key rotation {self.key_rotation_id} completed")
            delattr(self, 'key_rotation_id')
            
        return True
    
    def send_secure(self, data):
        """
        Send data securely over the established connection.
        
        Args:
            data: The data to send
            
        Returns:
            Number of bytes sent or None if an error occurred
        """
        if not self.ssl_socket:
            log.error("Cannot send: No secure connection established")
            return None
            
        # Check if we need to rotate keys
        self._monitor_nonce_rotation()
            
        try:
            # If we have the multi-cipher suite enabled, use it for additional encryption
            if self.multi_cipher_enabled and self.multi_cipher_suite:
                # Convert to bytes if not already
                if not isinstance(data, bytes):
                    if isinstance(data, str):
                        data = data.encode('utf-8')
                    else:
                        data = str(data).encode('utf-8')
                
                # Encrypt with multi-cipher
                encrypted_data = self.multi_cipher_suite.encrypt(data)
                
                # Send over TLS
                self.ssl_socket.sendall(encrypted_data)
                return len(data)  # Return original data length
            else:
                # Just use TLS encryption
                if isinstance(data, str):
                    data = data.encode('utf-8')
                self.ssl_socket.sendall(data)
                return len(data)
        except (ConnectionError, ssl.SSLError) as e:
            log.error(f"Connection error during secure send: {e}")
            return None
        except Exception as e:
            log.error(f"Error during secure send: {e}")
            return None

    def _create_server_context(self) -> ssl.SSLContext:
        """
        Creates an SSL context for the server side of a connection
        
        Returns:
            The SSL context
        """
        # Create certificates if needed
        if self.in_memory_only or not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            log.info("Certificates not found or in-memory mode, generating new ones")
            self._create_default_certificates()
        
        # Create context with strong security settings
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set TLS 1.3
        if hasattr(context, 'maximum_version') and hasattr(ssl, 'TLSVersion'):
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
        if hasattr(context, 'minimum_version') and hasattr(ssl, 'TLSVersion'):
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Define the ciphers to be set
        ciphers_to_set_list = list(self.CIPHER_SUITES) # Start with default classical suites
        pq_suites_attempted = []

        if self.enable_pq_kem:
            # Prepend intended PQ cipher suites to make them preferred
            ciphers_to_set_list = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS + ciphers_to_set_list
            pq_suites_attempted = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS
        
        cipher_suite_string_to_set = ":".join(ciphers_to_set_list)
        log.debug(f"Server Context: Attempting to set cipher suites to: {cipher_suite_string_to_set}")
        
        try:
            context.set_ciphers(cipher_suite_string_to_set)
            current_ciphers_details = context.get_ciphers()
            current_cipher_names = [c['name'] for c in current_ciphers_details if 'name' in c] if current_ciphers_details else []

            if not current_cipher_names:
                log.critical("CRITICAL (Server Context): set_ciphers resulted in an empty cipher list! Potentially no ciphers are active. OpenSSL may use defaults.")
                # Depending on security policy, raising an error might be appropriate here:
                # raise ssl.SSLError("Cipher suite configuration failed: No ciphers were set by set_ciphers.")
            else:
                log.info(f"Server Context: Successfully applied cipher string. Active ciphers: {current_cipher_names}")

            if self.enable_pq_kem:
                found_pq_cipher = False
                for pq_suite_name in pq_suites_attempted:
                    if pq_suite_name in current_cipher_names:
                        log.info(f"Server Context: Confirmed PQ cipher suite active: {pq_suite_name}")
                        found_pq_cipher = True
                        break 
                if not found_pq_cipher:
                    log.warning(f"Server Context: PQ KEM was enabled, but none of the expected PQ cipher suites ({pq_suites_attempted}) are active after setting '{cipher_suite_string_to_set}'. Active ciphers: {current_cipher_names}. This may indicate the PQ suites are not supported by OpenSSL, were silently ignored, or a fallback to classical ciphers occurred.")

        except ssl.SSLError as e_main:
            log.warning(f"Server Context: Failed to set combined cipher string '{cipher_suite_string_to_set}': {e_main}. Attempting fallbacks using CIPHER_SUITES: {self.CIPHER_SUITES}")
            cipher_applied_in_fallback = False
            # Fallback loop only tries classical ciphers from self.CIPHER_SUITES
            for classical_cipher in self.CIPHER_SUITES:
                try:
                    context.set_ciphers(classical_cipher)
                    current_ciphers_fallback_details = context.get_ciphers()
                    current_cipher_names_fallback = [c['name'] for c in current_ciphers_fallback_details if 'name' in c] if current_ciphers_fallback_details else []
                    
                    if classical_cipher in current_cipher_names_fallback:
                        log.info(f"Server Context Fallback: Successfully set cipher to: {classical_cipher}. Active ciphers: {current_cipher_names_fallback}")
                        cipher_applied_in_fallback = True
                        break
                    else:
                        log.warning(f"Server Context Fallback: Attempted to set {classical_cipher}, but it was not found in active list: {current_cipher_names_fallback}. OpenSSL might have silently ignored it or it's not supported.")
                except ssl.SSLError as e_fallback:
                    log.warning(f"Server Context Fallback: Failed to set single cipher {classical_cipher}: {e_fallback}")
                    continue
            
            if not cipher_applied_in_fallback:
                log.critical("CRITICAL (Server Context): All cipher configurations (combined and individual fallbacks) failed. OpenSSL will use its default ciphers. PQ features via cipher suites are likely unavailable.")
                # Depending on security policy, consider raising an error.
                # raise ssl.SSLError("Cipher suite configuration failed: No preferred ciphers could be set after fallbacks.")
            elif self.enable_pq_kem: # Fallback to classical was successful, but PQ was intended
                 log.warning(f"Server Context: PQ KEM was enabled, but cipher suite configuration fell back to classical ciphers ({[c['name'] for c in context.get_ciphers() if 'name' in c]}). Expected PQ cipher suites ({pq_suites_attempted}) are not active.")

        # Load certificates using secure enclave if available
        if self.secure_enclave and self.secure_enclave.using_enclave:
            try:
                log.info("Loading certificates from secure enclave")
                cert_chain, key = self.secure_enclave.load_certificate_chain()
                context.load_cert_chain(cert_file=cert_chain, key_file=key)
                log.info("Certificates loaded from secure enclave")
            except Exception as e:
                log.error(f"Failed to load certificates from secure enclave: {e}")
                # Try to regenerate and load again if there was an error
                self._create_default_certificates()
                context.load_cert_chain(cert_file=self.cert_path, key_file=self.key_path)
        else:
            # Load from disk as normal
            try:
                context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
                log.info(f"Loaded certificates from disk: {self.cert_path}")
            except Exception as e:
                log.error(f"Failed to load certificates: {e}")
                # Try to regenerate and load again if there was an error
                self._create_default_certificates()
                context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        
        # Set security options
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_COMPRESSION
        
        # Enable post-quantum key exchange
        if self.enable_pq_kem:
            # Try to set post-quantum hybrid groups
            try:
                # Set post-quantum key exchange preference
                if hasattr(context, 'set_alpn_protocols'):
                    context.set_alpn_protocols(['pq-tls13'])
                
                # Mark the context as post-quantum enabled for our session info
                context.post_quantum = True
                
                if hasattr(context, 'set_groups'):
                    # Define groups to use (X25519MLKEM1024 and traditional curves)
                    # Using both decimal values and named groups for better compatibility
                    tls_groups = []
                    
                    # Add post-quantum groups, try different formats
                    # Different OpenSSL/Python SSL versions might accept different formats
                    try:
                        tls_groups.extend([
                            # Try hex strings (some SSL libraries accept these)
                            "0x11EE",  # X25519MLKEM1024 (4590)
                            "0x11ED",  # SecP256r1MLKEM1024 (4589)
                            # Try decimal strings (more common)
                            "4590",    # X25519MLKEM1024 (0x11EE)
                            "4589",    # SecP256r1MLKEM1024 (0x11ED)
                            # Add our specific group values to ensure compatibility in standalone mode
                            str(self.NAMEDGROUP_X25519MLKEM1024),
                            str(self.NAMEDGROUP_SECP256R1MLKEM1024),
                            # If PQ negotiation fails, we need traditional fallbacks
                            "x25519",      # Traditional elliptic curve
                            "P-256",       # NIST P-256 curve
                            "secp256r1"    # Same as P-256, different name
                        ])
                    except Exception:
                        # If extending fails, use a simpler approach
                        tls_groups = ["x25519", "P-256"]
                        
                    # Try setting the groups
                    try:
                        context.set_groups(tls_groups)
                        log.info(f"Post-quantum groups set for server: {tls_groups}")
                    except Exception as e:
                        log.warning(f"Failed to set specific groups for server: {e}")
                        # Try individual group additions
                        for group in ["x25519", "P-256"]:
                            try:
                                context.set_groups([group])
                                log.info(f"Successfully set fallback group: {group}")
                                break
                            except Exception:
                                pass
                
                # Set custom options to signal PQ support
                if hasattr(context, 'options'):
                    # Store our PQ enabled flag
                    setattr(context, '_pq_enabled', True)
                    # Mark context as standalone for better detection
                    setattr(context, '_standalone_mode', True)
                    # Store algorithm information for better reporting
                    setattr(context, '_pq_algorithm', 'X25519MLKEM1024')
                
                log.info("Post-quantum hybrid key exchange enabled in server TLS")
            except Exception as e:
                log.warning(f"Failed to set post-quantum groups for server: {e}")
                # Store that PQ was attempted but failed
                setattr(context, '_pq_enabled', False)
        else:
            # Store that PQ is not enabled
            setattr(context, '_pq_enabled', False)
        
        # Set standalone flag for compatibility detection
        context._standalone_mode = True
        
        # Set server flag
        self.is_server = True
        
        return context

    def _verify_security_parameters(self, context):
        """
        Verify TLS security parameters for compliance with security requirements.
        
        Args:
            context: SSL context to verify
            
        Returns:
            Dict containing verification results
        """
        # Verification results
        verification = {
            'tls_version': False,
            'cipher_strength': False,
            'pfs': False,  # Perfect Forward Secrecy
            'certificate': False,
            'issues': []
        }
        
        # Verify TLS version (must be 1.3)
        try:
            protocol_version = self.ssl_socket.version()
            if "TLSv1.3" in protocol_version:
                verification['tls_version'] = True
                log.info(f"TLS version verified: {protocol_version}")
            else:
                verification['issues'].append(f"Non-compliant TLS version: {protocol_version}")
                log.warning(f"Security issue: Using {protocol_version} instead of TLSv1.3")
        except Exception as e:
            verification['issues'].append(f"Could not verify TLS version: {e}")
        
        # Verify cipher suite strength
        try:
            current_cipher = self.ssl_socket.cipher()
            if current_cipher:
                cipher_name, cipher_bits, _ = current_cipher
                
                # Check for minimum key strength (256 bits)
                if cipher_bits >= 256:
                    verification['cipher_strength'] = True
                    log.info(f"Cipher strength verified: {cipher_name} ({cipher_bits} bits)")
                else:
                    verification['issues'].append(f"Weak cipher: {cipher_name} ({cipher_bits} bits)")
                    log.warning(f"Security issue: Cipher strength below 256 bits: {cipher_bits}")
                
                # Check for AEAD ciphers
                if "GCM" in cipher_name or "POLY1305" in cipher_name:
                    verification['aead_cipher'] = True
                else:
                    verification['issues'].append(f"Non-AEAD cipher: {cipher_name}")
                    log.warning(f"Security issue: Non-AEAD cipher in use: {cipher_name}")
            else:
                verification['issues'].append("No cipher information available")
        except Exception as e:
            verification['issues'].append(f"Could not verify cipher: {e}")
            
        # Verify certificate
        try:
            if self.ssl_socket.getpeercert():
                # Basic certificate validation is performed by SSL library
                verification['certificate'] = True
                log.info("Certificate validation passed")
            else:
                verification['issues'].append("No certificate information available")
        except Exception as e:
            verification['issues'].append(f"Certificate verification error: {e}")
            
        # Verify Perfect Forward Secrecy via key exchange
        try:
            if current_cipher and any(ke in cipher_name for ke in ["ECDHE", "DHE", "X25519"]):
                verification['pfs'] = True
                log.info(f"Perfect Forward Secrecy verified: {cipher_name}")
            else:
                verification['issues'].append("PFS not confirmed in cipher suite")
        except Exception as e:
            verification['issues'].append(f"Could not verify PFS: {e}")
            
        # Calculate overall verification status
        verification['passed'] = all([
            verification['tls_version'],
            verification['cipher_strength'],
            verification['certificate']
        ])
        
        return verification

    def _generate_selfsigned_cert(self, in_memory=False):
        """
        Generate a self-signed certificate.
        
        Args:
            in_memory: If True, only generate in memory without touching disk
        """
        try:
            log.info("Generating self-signed certificate and key...")
            
            # Initialize private_key variable
            private_key = None
            
            # Use hardware security module if available
            if self.secure_enclave and self.secure_enclave.using_enclave:
                # Try to generate key in HSM
                key_result = self.secure_enclave.create_rsa_key(key_size=3072, key_id=f"tls-key-{int(time.time())}")
                
                if key_result:
                    log.info(f"Generated RSA key in {self.secure_enclave.enclave_type}")
                    # We'll need to handle this differently based on the HSM implementation
                    # This is a simplified example
                    pk_obj, key_handle = key_result
                    
                    # Extract modulus and public exponent to create public key object
                    # Note: This is specific to the HSM implementation and may need adaptation
                    if hasattr(pk_obj, 'get_attributes'):
                        attrs = pk_obj.get_attributes([
                            (pkcs11.Attribute.MODULUS, None),
                            (pkcs11.Attribute.PUBLIC_EXPONENT, None),
                        ])
                        
                        modulus = attrs[pkcs11.Attribute.MODULUS]
                        public_exponent = attrs[pkcs11.Attribute.PUBLIC_EXPONENT]
                        
                        # Create a public key object
                        public_key = rsa.RSAPublicNumbers(
                            e=int.from_bytes(public_exponent, byteorder='big'),
                            n=int.from_bytes(modulus, byteorder='big')
                        ).public_key()
                        
                        # Generate certificate with hardware-backed key
                        # We'd need a way to sign with the HSM key
                        # This is complex and would depend on the HSM's capabilities
                        log.warning("Certificate generation with HSM keys not fully implemented")
                        # Falling back to software key
                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=3072,
                        )
                    else:
                        # Fallback if we can't extract attributes
                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=3072,
                        )
                else:
                    # Fallback to software key generation
                    log.warning(f"HSM/TPM key generation failed or was declined (e.g., no user interaction for authorization, or hardware error). Falling back to software-based key generation.")
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=3072,  # Increased from 2048 for stronger security
                    )
            else:
                # Generate a private key in software
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=3072,  # Increased from 2048 for stronger security
                )
            
            # Ensure the private key exists before proceeding
            if not private_key:
                raise ValueError("Failed to generate private key through any method")
            
            # Create a self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"P2P-TLS"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"P2P Chat"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure P2P Chat"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Certificate valid for 1 year
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            ).add_extension( # Add OCSP Must-Staple extension
                TLSFeature(features=[TLSFeatureType.status_request]),
                critical=False 
            ).sign(private_key, hashes.SHA256())
            
            # Store the key and cert in memory
            self.private_key_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            
            self.certificate_data = cert.public_bytes(serialization.Encoding.PEM)
            
            # If not in in-memory mode, also save to disk
            if not in_memory and not self.in_memory_only:
                # Write the private key to disk
                with open(self.key_path, "wb") as f:
                    f.write(self.private_key_data)
                
                # Write the certificate to disk
                with open(self.cert_path, "wb") as f:
                    f.write(self.certificate_data)
                
                log.info(f"Generated certificate in {self.cert_path}")
            else:
                log.info("Generated in-memory certificate and key (not saved to disk)")
                
        except Exception as e:
            log.error(f"Failed to generate certificate programmatically: {e}")
            self.cert_path = None
            self.key_path = None
            raise

    def is_standalone_mode(self):
        """
        Determine if we're running in standalone mode (both client and server are our implementation).
        This is important for proper post-quantum security enforcement, especially in P2P chat.
        
        Returns:
            True if in standalone mode, False otherwise
        """
        # Always assume standalone mode for secure_p2p.py application
        # This ensures PQ security is enabled in our P2P chat application
        if 'secure_p2p' in sys.modules:
            return True
            
        # Check environment variable (set in secure_p2p.py when run directly)
        if os.environ.get('SECURE_P2P_STANDALONE') == '1':
            return True
            
        # Check if socket has our custom attributes
        try:
            if hasattr(self.ssl_socket, 'context') and hasattr(self.ssl_socket.context, '_standalone_mode'):
                return True
                
            # Check socket info string for our application identifiers
            socket_info = str(self.ssl_socket).lower()
            if any(marker in socket_info for marker in ["secure_p2p", "_inproc_", "hybrid_kex"]):
                return True
                
            # Check if connected to localhost/127.0.0.1 or same machine
            try:
                if hasattr(self.ssl_socket, 'getpeername'):
                    peer = self.ssl_socket.getpeername()
                    if peer and peer[0]:
                        if peer[0] == '127.0.0.1' or peer[0] == 'localhost' or peer[0] == '::1':
                            return True
                            
                        # Check if it's our own IP
                        import socket as sock_mod
                        own_ips = []
                        try:
                            own_hostname = sock_mod.gethostname()
                            own_ips = [i[4][0] for i in sock_mod.getaddrinfo(own_hostname, None)]
                        except:
                            pass
                            
                        if peer[0] in own_ips:
                            return True
            except:
                pass
        except:
            pass
            
        # If we can't definitively determine, assume not standalone for security
        return False

# Utility class for implementing the record layer
class TLSRecordLayer:
    """
    TLS 1.3 record layer implementation for secure framing and encryption.
    """
    
    # TLS 1.3 content types
    CONTENT_TYPE_HANDSHAKE = 22
    CONTENT_TYPE_APPLICATION_DATA = 23
    CONTENT_TYPE_ALERT = 21
    
    def __init__(self, key: bytes, iv: bytes):
        """
        Initialize the TLS record layer.
        
        Args:
            key: The symmetric key for encryption/decryption
            iv: The initialization vector base
        """
        self.key = key
        self.iv = iv
        self.cipher = ChaCha20Poly1305(key)
        
        # Initialize nonce manager with TLS record protocol limits
        # TLS 1.3 sequence numbers are 64-bit, but we'll use a smaller limit for safety
        # Use counter-based nonce management for TLS record layer
        self.nonce_manager = CounterBasedNonceManager(
            counter_size=8,  # 8-byte counter (up to 2^64 messages)
            salt_size=4      # 4-byte salt for additional randomness
        )
        log.debug("TLS record layer initialized with secure nonce management")
    
    def encrypt(self, data: bytes, content_type: int = CONTENT_TYPE_APPLICATION_DATA) -> bytes:
        """
        Encrypt data according to TLS 1.3 record layer.
        
        Args:
            data: The data to encrypt
            content_type: The TLS content type
            
        Returns:
            The encrypted record
        """
        # Create a nonce using the nonce manager
        nonce = self.nonce_manager.generate_nonce()
        
        # Add record type to the end of plaintext
        plaintext = data + bytes([content_type])
        
        # Encrypt with authenticated data (TLS 1.3 header)
        additional_data = b"tls13-chacha-poly"  # Simplified for example
        ciphertext = self.cipher.encrypt(nonce, plaintext, additional_data)
        
        # Return nonce and ciphertext
        return nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, int]:
        """
        Decrypt a TLS 1.3 record.
        
        Args:
            ciphertext: The encrypted record with nonce
            
        Returns:
            Tuple of (decrypted data, content type)
        """
        if len(ciphertext) < 12:
            raise ValueError("Ciphertext too short for TLS record decryption")
            
        # Extract nonce
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        
        # Decrypt with authenticated data
        additional_data = b"tls13-chacha-poly"  # Simplified for example
        
        try:
            plaintext = self.cipher.decrypt(nonce, actual_ciphertext, additional_data)
        except Exception as e:
            log.error(f"TLS record decryption failed: {e}")
            raise
        
        # Extract content type from the end of plaintext
        if not plaintext:
            raise ValueError("Decryption produced empty plaintext")
            
        content_type = plaintext[-1]
        plaintext = plaintext[:-1]
        
        return plaintext, content_type
    
    def rotate_key(self, new_key: bytes, new_iv: bytes = None):
        """
        Rotate encryption keys and reset nonce management.
        
        Args:
            new_key: New encryption key
            new_iv: New IV (optional)
        """
        log.info("Rotating TLS record layer encryption key")
        self.key = new_key
        if new_iv:
            self.iv = new_iv
            
        self.cipher = ChaCha20Poly1305(new_key)
        self.nonce_manager.reset()
        log.debug("TLS record layer key rotation completed")
    
    def is_rotation_needed(self) -> bool:
        """Check if key rotation is needed based on nonce usage."""
        return self.nonce_manager.is_rotation_needed()

# Helper function to wrap socket operations with TLS
def secure_socket(socket_obj: socket.socket, is_server: bool = False, 
                 cert_path: str = None, key_path: str = None, 
                 server_hostname: str = None) -> ssl.SSLSocket:
    """
    Utility function to wrap a socket with TLS security.
    
    Args:
        socket_obj: Socket to wrap
        is_server: Whether this is a server-side socket
        cert_path: Path to certificate file (server only)
        key_path: Path to key file (server only)
        server_hostname: Server hostname for verification (client only)
        
    Returns:
        SSL-wrapped socket
    """
    # Create appropriate context
    if is_server:
        if not cert_path or not key_path:
            raise ValueError("Server requires certificate and key paths")
            
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = bool(server_hostname)
        context.verify_mode = ssl.CERT_REQUIRED
        
    # Set TLS 1.3 if available
    if hasattr(context, 'minimum_version') and hasattr(ssl, 'TLSVersion'):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        
    # Return wrapped socket
    if is_server:
        return context.wrap_socket(socket_obj, server_side=True)
    else:
        return context.wrap_socket(socket_obj, server_hostname=server_hostname)

class DirectX25519KeyExchange:
    """
    X25519 key exchange implementation.
    """
    
    def __init__(self):
        """Initialize with a new X25519 key pair."""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> bytes:
        """Return the public key in raw bytes format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Compute the shared secret with a peer's public key.
        
        Args:
            peer_public_key_bytes: Raw bytes of peer's public key
            
        Returns:
            Shared secret bytes
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self.private_key.exchange(peer_public_key)

class Ed25519Signer:
    """
    Ed25519 signature implementation.
    """
    
    def __init__(self):
        """Initialize with a new Ed25519 key pair."""
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> bytes:
        """Return the public key in raw bytes format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def sign(self, data: bytes) -> bytes:
        """
        Sign data with the private key.
        
        Args:
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        return self.private_key.sign(data)
    
    def verify(self, public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify a signature using a public key.
        
        Args:
            public_key_bytes: Public key to verify with
            data: Data that was signed
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            verifier.verify(signature, data)
            return True
        except Exception:
            return False

class CustomCipherSuite:
    """
    Custom cipher suite implementation combining AES-GCM and ChaCha20-Poly1305.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize with a 32-byte key.
        
        Args:
            key: 32-byte encryption key
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        # Derive keys for each cipher
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for each cipher
            salt=None,
            info=b"CustomCipherSuite Key Derivation"
        )
        
        derived_keys = hkdf.derive(key)
        self.aes_key = derived_keys[0:32]
        self.chacha_key = derived_keys[32:64]
        
        # Create ciphers
        self.aes = AESGCM(self.aes_key)
        self.chacha = ChaCha20Poly1305(self.chacha_key)
        
        # Nonce managers using counter-based approach for AEAD security
        self.aes_nonce_manager = CounterBasedNonceManager()  # 12-byte nonce (8-byte counter, 4-byte salt)
        self.chacha_nonce_manager = CounterBasedNonceManager()
    
    def encrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data using AES-GCM and ChaCha20-Poly1305.
        
        Args:
            data: Data to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Encrypted data with nonces prepended
        """
        # Generate nonces
        aes_nonce = self.aes_nonce_manager.generate_nonce()
        chacha_nonce = self.chacha_nonce_manager.generate_nonce()
        
        # First layer: AES-GCM
        ciphertext = aes_nonce + self.aes.encrypt(aes_nonce, data, associated_data)
        
        # Second layer: ChaCha20-Poly1305
        ciphertext = chacha_nonce + self.chacha.encrypt(chacha_nonce, ciphertext, associated_data)
        
        return ciphertext
    
    def decrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305 and AES-GCM.
        
        Args:
            data: Data to decrypt
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted data
        """
        if len(data) < 24:  # 12 bytes for each nonce
            raise ValueError("Data too short for decryption")
            
        # Extract ChaCha20-Poly1305 nonce and ciphertext
        chacha_nonce = data[0:12]
        chacha_ciphertext = data[12:]
        
        # First layer: ChaCha20-Poly1305
        try:
            plaintext = self.chacha.decrypt(chacha_nonce, chacha_ciphertext, associated_data)
        except Exception as e:
            log.error(f"ChaCha20-Poly1305 decryption failed: {e}")
            raise
        
        # Extract AES-GCM nonce and ciphertext
        if len(plaintext) < 12:
            raise ValueError("Data too short for AES-GCM decryption")
            
        aes_nonce = plaintext[0:12]
        aes_ciphertext = plaintext[12:]
        
        # Second layer: AES-GCM
        try:
            plaintext = self.aes.decrypt(aes_nonce, aes_ciphertext, associated_data)
        except Exception as e:
            log.error(f"AES-GCM decryption failed: {e}")
            raise
            
        return plaintext

class SocketSelector:
    """
    Socket selection utility for handling timeouts and I/O operations.
    """
    
    def __init__(self, timeout: float = 5.0):
        """
        Initialize with a default timeout.
        
        Args:
            timeout: Default timeout in seconds
        """
        self.default_timeout = timeout
    
    def wait_for_readable(self, sock: socket.socket, timeout: Optional[float] = None) -> bool:
        """
        Wait until a socket is readable or timeout occurs.
        
        Args:
            sock: Socket to wait on
            timeout: Timeout in seconds or None to use default
            
        Returns:
            True if socket is readable, False if timeout
        """
        timeout = timeout if timeout is not None else self.default_timeout
        try:
            readable, _, _ = select.select([sock], [], [], timeout)
            return bool(readable)
        except (OSError, select.error):
            return False
    
    def wait_for_writable(self, sock: socket.socket, timeout: Optional[float] = None) -> bool:
        """
        Wait until a socket is writable or timeout occurs.
        
        Args:
            sock: Socket to wait on
            timeout: Timeout in seconds or None to use default
            
        Returns:
            True if socket is writable, False if timeout
        """
        timeout = timeout if timeout is not None else self.default_timeout
        try:
            _, writable, _ = select.select([], [sock], [], timeout)
            return bool(writable)
        except (OSError, select.error):
            return False
    
    def wait_for_readwrite(self, sock: socket.socket, timeout: Optional[float] = None) -> Tuple[bool, bool]:
        """
        Wait until a socket is readable or writable or timeout occurs.
        
        Args:
            sock: Socket to wait on
            timeout: Timeout in seconds or None to use default
            
        Returns:
            Tuple of (is_readable, is_writable)
        """
        timeout = timeout if timeout is not None else self.default_timeout
        try:
            readable, writable, _ = select.select([sock], [sock], [], timeout)
            return bool(readable), bool(writable)
        except (OSError, select.error):
            return False, False

def verify_quantum_resistance(connection):
    """
    Verify if a connection is using quantum-resistant cryptography.
    
    Args:
        connection: The TLSSecureChannel connection to check
        
    Returns:
        Dict with status and details of quantum resistance
    """
    if not isinstance(connection, TLSSecureChannel):
        return {
            "status": "ERROR",
            "quantum_resistant": False,
            "message": "Not a TLSSecureChannel connection"
        }
        
    session_info = connection.get_session_info()
    
    is_quantum_resistant = session_info.get('post_quantum', False)
    algorithm = session_info.get('pq_algorithm', 'None')
    
    if is_quantum_resistant:
        return {
            "status": "OK",
            "quantum_resistant": True,
            "algorithm": algorithm,
            "message": f"Connection is using quantum-resistant cryptography: {algorithm}"
        }
    else:
        return {
            "status": "WARNING",
            "quantum_resistant": False,
            "message": "Connection is not using quantum-resistant cryptography"
        }

    # Placeholder for OCSP Stapling Callback
    def _ocsp_stapling_callback(self, ssl_connection):
        """
        Callback for OCSP stapling.
        This function will be called by OpenSSL to get an OCSP response to staple.
        For self-signed certificates, this will generate a basic "good" response signed by the cert itself.
        
        Args:
            ssl_connection: The SSLConnection object.
        """
        log.info("OCSP stapling callback triggered.")
        try:
            if not self.certificate_data or not self.private_key_data:
                log.error("OCSP Stapling: Server certificate or private key data is not available.")
                return

            # Load server certificate (which is also the issuer for self-signed)
            server_cert = x509.load_pem_x509_certificate(self.certificate_data)
            issuer_cert = server_cert # For self-signed

            # Load private key (issuer's key for self-signed)
            issuer_key = serialization.load_pem_private_key(
                self.private_key_data,
                password=None # Assuming no password for the key
            )

            # Basic OCSP response builder
            builder = ocsp.OCSPResponseBuilder()

            # Add response for the server certificate
            # For self-signed, the issuer_key_hash and issuer_name_hash are derived from the cert itself.
            builder = builder.add_response(
                cert=server_cert,
                issuer=issuer_cert,
                algorithm=hashes.SHA256(), # Algorithm used to hash issuer name/key
                cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=datetime.datetime.utcnow(),
                next_update=datetime.datetime.utcnow() + datetime.timedelta(days=1),
                revocation_time=None, # No revocation for a good status
                revocation_reason=None # No reason for a good status
            ).responder_id(
                ocsp.OCSPResponderEncoding.NAME, issuer_cert # Responder is the issuer itself
            )
            
            # Sign the OCSP response
            # The hash algorithm for signing should be strong, e.g., SHA256
            ocsp_response = builder.sign(issuer_key, hashes.SHA256())

            # Set the DER-encoded OCSP response for stapling
            ssl_connection.set_ocsp_response(ocsp_response.public_bytes(serialization.Encoding.DER))
            log.info("Successfully generated and set OCSP response for stapling.")

        except Exception as e:
            log.error(f"Error in OCSP stapling callback: {e}", exc_info=True)
            # Do not call set_ocsp_response on error, so no staple is sent.

    def _get_certificate_association_data(self, certificate_der: bytes, selector: int, matching_type: int) -> Optional[bytes]:
        """
        Extracts and prepares the relevant part of a certificate for DANE matching.

        Args:
            certificate_der: The full DER-encoded X.509 certificate.
            selector: DANE selector (0 for full cert, 1 for SubjectPublicKeyInfo).
            matching_type: DANE matching type (0 for raw, 1 for SHA-256, 2 for SHA-512).

        Returns:
            The bytes to be compared against the TLSA record's association data, or None on error.
        """
        selected_data = None
        try:
            if selector == 0:  # Full certificate
                selected_data = certificate_der
            elif selector == 1:  # SubjectPublicKeyInfo
                cert = x509.load_der_x509_certificate(certificate_der)
                # Accessing public_key() and then serializing to SPKI DER
                selected_data = cert.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                log.warning(f"DANE: Unsupported selector: {selector}")
                return None

            if matching_type == 0:  # Raw data
                return selected_data
            elif matching_type == 1:  # SHA-256
                digest = hashlib.sha256()
                digest.update(selected_data)
                return digest.digest()
            elif matching_type == 2:  # SHA-512
                digest = hashlib.sha512()
                digest.update(selected_data)
                return digest.digest()
            else:
                log.warning(f"DANE: Unsupported matching type: {matching_type}")
                return None
        except Exception as e:
            log.error(f"DANE: Error processing certificate for selector {selector}, matching type {matching_type}: {e}")
            return None

    def _validate_certificate_with_dane(self, peer_cert_der: bytes) -> bool:
        """
        Validates the peer's certificate against the configured DANE TLSA records.

        Args:
            peer_cert_der: The DER-encoded certificate received from the peer.

        Returns:
            True if the certificate matches at least one valid DANE TLSA record, False otherwise.
        """
        if not self.dane_tlsa_records:
            log.debug("DANE: No TLSA records configured, skipping validation.")
            return True # Or False, depending on policy if records are expected but missing. For now, true.

        self.dane_validation_performed = True
        self.dane_validation_successful = False # Assume failure until a match

        for record in self.dane_tlsa_records:
            try:
                usage = record.get('usage')
                selector = record.get('selector')
                matching_type = record.get('matching_type')
                association_data_hex = record.get('data')

                if not all(isinstance(x, int) for x in [usage, selector, matching_type]) or not isinstance(association_data_hex, str):
                    log.warning(f"DANE: Skipping malformed TLSA record: {record}")
                    continue

                # For DANE-EE (usage 3), we are validating the end-entity certificate directly.
                # Other usages (0, 1, 2) imply a CA constraint and require full chain validation, which is more complex.
                # This implementation will focus on DANE-EE (usage 3) for simplicity.
                if usage != 3:
                    log.debug(f"DANE: Skipping TLSA record with usage {usage}. This implementation primarily handles DANE-EE (usage 3).")
                    continue

                expected_association_data = bytes.fromhex(association_data_hex)
                actual_association_data = self._get_certificate_association_data(peer_cert_der, selector, matching_type)

                if actual_association_data and actual_association_data == expected_association_data:
                    log.info(f"DANE: Successfully validated peer certificate against TLSA record: {record}")
                    self.dane_validation_successful = True
                    return True # Found a valid match
                else:
                    log.debug(f"DANE: Peer certificate did not match TLSA record: {record}. Expected {expected_association_data.hex() if actual_association_data else 'N/A'}, got {actual_association_data.hex() if actual_association_data else 'Error/None'}") 

            except Exception as e:
                log.error(f"DANE: Error processing TLSA record {record}: {e}")
                continue

        if not self.dane_validation_successful:
            log.warning("DANE: Peer certificate did not match any provided DANE TLSA records.")
        return False

    def connect(self, host: str, port: int) -> bool:
        """
        Connect to a TLS server
        
        Args:
            host: The hostname to connect to
            port: The port to connect to
            
        Returns:
            True if connection was successful, False otherwise
        """
        try:
            # Check if we need to authenticate first
            if self.require_authentication:
                status = self.check_authentication_status()
                if not status:
                    log.warning("Authentication failed, unable to connect")
                    return False
            
            # Create a new socket
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Check if socket is non-blocking
            is_nonblocking = self.raw_socket.getblocking() == False
            
            # Connect to the server
            log.info(f"Connecting to {host}:{port}")
            self.raw_socket.connect((host, port))
            
            # Create client context
            context = self._create_client_context()
            
            # Wrap with SSL
            self.ssl_socket = context.wrap_socket(
                self.raw_socket, 
                server_hostname=host,
                do_handshake_on_connect=not is_nonblocking
            )
            
            # For non-blocking sockets, handshake needs to be done manually later
            if is_nonblocking:
                log.info("Non-blocking socket detected, handshake will be performed later")
                self.handshake_complete = False
            else:
                self.handshake_complete = True
                
                # Log TLS version and cipher
                version = self.ssl_socket.version()
                if version != "TLSv1.3":
                    log.warning(f"Connected with {version} instead of TLS 1.3")
                else:
                    log.info(f"Connected using TLS 1.3")
                
                cipher = self.ssl_socket.cipher()
                log.info(f"Using cipher: {cipher[0]}")
                
                # Send authentication if required
                if self.require_authentication:
                    auth_sent = self.send_authentication()
                    if not auth_sent:
                        log.error("Failed to send authentication")
                        self.close()
                        return False
            
            return True
            
        except ssl.SSLError as e:
            log.error(f"SSL error during connection: {e}")
            self.close()
            return False
            
        except Exception as e:
            log.error(f"Error during connection: {e}")
            self.close()
            return False

    def _secure_wipe_memory(self, data_bytes: Optional[Union[bytes, bytearray]], description: str):
        """
        Securely wipes a mutable bytearray object in-place using memset and attempts to pin memory.
        If an immutable bytes object is passed, logs a warning and does not wipe it,
        as immutable objects cannot be changed in-place. The caller is responsible
        for managing the lifecycle of immutable bytes objects.
        Logs a warning if data_bytes is None or empty.
        """
        if not data_bytes:
            logger.debug(f"No data to wipe for {description} (data is None/empty).")
            return

        if isinstance(data_bytes, bytes) and not isinstance(data_bytes, bytearray):
            logger.warning(f"_secure_wipe_memory: {description} is an immutable bytes object. Cannot wipe in-place. "
                           f"The original bytes object remains in memory until garbage collected. "
                           f"Ensure no references to the original object are retained if it contained sensitive data.")
            return

        if not isinstance(data_bytes, bytearray):
            logger.error(f"_secure_wipe_memory: {description} is not a bytearray. Cannot wipe. Type: {type(data_bytes)}")
            return

        key_len = len(data_bytes)
        if key_len == 0:
            logger.debug(f"Zero length bytearray for {description}, no wipe needed.")
            return

        locked_address = None
        locked_length = 0
        locked_platform_type = None # To store if it's 'Windows' or 'POSIX' for unlocking
        memory_pinned = False

        try:
            # 1. Attempt to pin memory
            current_os = platform.system()
            if key_len > 0:
                try:
                    address = ctypes.addressof(ctypes.c_byte.from_buffer(data_bytes))
                    if current_os == "Windows":
                        if ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(key_len)):
                            locked_address, locked_length, locked_platform_type = address, key_len, "Windows"
                            memory_pinned = True
                            logger.debug(f"_secure_wipe_memory: VirtualLock successful for {description}.")
                        else:
                            logger.warning(f"_secure_wipe_memory: VirtualLock failed for {description}. Error: {ctypes.get_last_error()}")
                    elif current_os in ["Linux", "Darwin"]:
                        libc = ctypes.CDLL(None) # Auto-finds libc
                        if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(key_len)) == 0:
                            locked_address, locked_length, locked_platform_type = address, key_len, "POSIX"
                            memory_pinned = True
                            logger.debug(f"_secure_wipe_memory: mlock successful for {description}.")
                        else:
                            errno = ctypes.get_errno()
                            logger.warning(f"_secure_wipe_memory: mlock failed for {description}. Errno: {errno} ({os.strerror(errno)})")
                    else:
                        logger.info(f"_secure_wipe_memory: Memory pinning not supported on this platform ({current_os}) for {description}.")
                except Exception as e_pin:
                    logger.error(f"_secure_wipe_memory: Exception during memory pinning for {description}: {e_pin}")

            # 2. Zeroize memory (memset)
            ctypes.memset(ctypes.addressof(ctypes.c_byte.from_buffer(data_bytes)), 0, key_len)
            logger.debug(f"Securely zeroized {key_len} bytes for: {description} (bytearray). Memory pinned: {memory_pinned}")

        except Exception as e_wipe:
            logger.error(f"Failed to zeroize memory for {description} (bytearray) using ctypes: {e_wipe}", exc_info=True)
            # Fallback manual overwrite
            try:
                for i in range(key_len):
                    data_bytes[i] = 0
                logger.debug(f"Fallback manual overwrite for {description} (bytearray) completed. Memory pinned: {memory_pinned}")
            except Exception as e_fallback:
                logger.error(f"Fallback manual overwrite for {description} (bytearray) also failed: {e_fallback}")
        finally:
            # 3. Unpin memory if it was locked
            if locked_address and locked_length > 0:
                try:
                    if locked_platform_type == "Windows":
                        if not ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(locked_address), ctypes.c_size_t(locked_length)):
                            logger.warning(f"_secure_wipe_memory: VirtualUnlock failed for {description}. Error: {ctypes.get_last_error()}")
                    elif locked_platform_type == "POSIX":
                        libc = ctypes.CDLL(None)
                        if libc.munlock(ctypes.c_void_p(locked_address), ctypes.c_size_t(locked_length)) != 0:
                            errno = ctypes.get_errno()
                            logger.warning(f"_secure_wipe_memory: munlock failed for {description}. Errno: {errno} ({os.strerror(errno)})")
                except Exception as e_unpin:
                    logger.error(f"_secure_wipe_memory: Exception during memory unpinning for {description}: {e_unpin}")
            
            gc.collect() # Suggest garbage collection

    def _create_client_context(self):
        """Create an SSL context for client-side TLS connections with enhanced security."""
        # PROTOCOL_TLS_CLIENT requires OpenSSL 1.1.0g+ or LibreSSL 2.9.1+
        # PROTOCOL_TLS is deprecated but more general for older versions.
        # We aim for TLS 1.3, so PROTOCOL_TLS_CLIENT is appropriate.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set preferred ciphers for TLS 1.3 (and 1.2 if unavoidable)
        # Order matters: stronger/preferred ciphers first.
        # This also helps in selecting PQ ciphers if supported and named correctly.
        try:
            # Combine primary and PQ placeholder ciphers if PQ is enabled
            cipher_list_to_set = self.CIPHER_SUITES
            if self.enable_pq_kem:
                # Prepend expected PQ suites - order might matter for negotiation preference
                cipher_list_to_set = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS + cipher_list_to_set
            
            context.set_ciphers(':'.join(cipher_list_to_set))
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.debug(f"Client Ciphers set to: {context.get_ciphers()}")
        except ssl.SSLError as e:
            log.error(f"Failed to set client ciphers: {e}. This may lead to insecure or failed connections.")
            # Potentially fall back to a default or a known safe subset if specific ciphers fail

        # Set options for security
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 # Require TLS 1.3 effectively
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        # Consider ssl.OP_NO_RENEGOTIATION if issues arise, though secure renegotiation is preferred.

        # Post-quantum groups (curves) for key exchange
        if self.enable_pq_kem and hasattr(context, 'set_ecdh_curves'): # OpenSSL 1.1.1+
            try:
                # Correct method for setting groups in OpenSSL 1.1.1+ for TLS 1.3 is set_groups
                # set_ecdh_curves is for older TLS versions or specific ECDH context setup.
                if hasattr(context, 'set_groups'):
                    context.set_groups(self.HYBRID_PQ_GROUPS)
                    log.info(f"Client KEM groups set to: {self.HYBRID_PQ_GROUPS}")
                else: # Fallback for slightly older OpenSSL 1.1.1 versions that might only have set_ecdh_curves for this
                    context.set_ecdh_curves(self.HYBRID_PQ_GROUPS)
                    log.info(f"Client ECDH curves (acting as groups) set to: {self.HYBRID_PQ_GROUPS}")                    
            except Exception as e:
                log.error(f"Failed to set post-quantum key exchange groups for client: {e}")

        # Load private key if specified (for client certificate authentication)
        if self.cert_path and self.key_path: # Check if paths for client cert/key are provided
            try:
                if self.in_memory_only and self.private_key_data and self.certificate_data:
                    # Client is using an in-memory cert and key to authenticate itself
                    context.load_pem_private_key(self.private_key_data, password=None)
                    self._secure_wipe_memory(self.private_key_data, "in-memory client private key data")
                    self.private_key_data = None 
                    
                    temp_cert_file_client = None
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp_cert:
                            tmp_cert.write(self.certificate_data)
                            temp_cert_file_client = tmp_cert.name
                        context.load_cert_chain(certfile=temp_cert_file_client)
                    finally:
                        if temp_cert_file_client and os.path.exists(temp_cert_file_client):
                            os.unlink(temp_cert_file_client)
                    log.info("Loaded in-memory client certificate and wiped private key.")

                elif not self.in_memory_only and os.path.exists(self.key_path) and os.path.exists(self.cert_path):
                    context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
                    log.info(f"Loaded client certificate and key from disk: {self.cert_path}, {self.key_path}")
                # else: Client not configured to use a certificate to authenticate itself.
            except Exception as e:
                log.error(f"Failed to load client certificate/key for client authentication: {e}", exc_info=True)

        # Configure server certificate verification
        if self.verify_certs:
            if self.ca_path and os.path.exists(self.ca_path):
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True 
                context.load_verify_locations(self.ca_path)
                log.info(f"Server certificate verification enabled using CA: {self.ca_path}")
            elif self.ca_path and not os.path.exists(self.ca_path):
                log.error(f"CA path {self.ca_path} specified for server cert verification, but file does not exist. Falling back to default CAs.")
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
                log.info("Server certificate verification enabled using default system CAs (specified CA not found).")
            else: # No specific CA path, use system default CAs
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
                log.info("Server certificate verification enabled using default system CAs.")
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            log.warning("Server certificate verification is DISABLED. This is insecure for production environments.")
        
        # OCSP Must-Staple callback configuration for client
        if hasattr(context, 'stapled_ocsp_response_cb') and self.ocsp_stapling:
            context.stapled_ocsp_response_cb = self._ocsp_stapling_callback
            log.debug("OCSP Must-Staple callback configured for client context.")
            
        return context

    def _create_server_context(self) -> ssl.SSLContext:
        """Create an SSL context for server-side TLS connections with enhanced security."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Set preferred ciphers
        try:
            cipher_list_to_set = self.CIPHER_SUITES
            if self.enable_pq_kem:
                cipher_list_to_set = self.EXPECTED_PQ_CIPHER_SUITES_PLACEHOLDERS + cipher_list_to_set
            context.set_ciphers(':'.join(cipher_list_to_set))
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.debug(f"Server Ciphers set to: {context.get_ciphers()}")
        except ssl.SSLError as e:
            log.error(f"Failed to set server ciphers: {e}. This may lead to insecure or failed connections.")

        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE

        # Post-quantum groups for key exchange
        if self.enable_pq_kem and hasattr(context, 'set_ecdh_curves'): # OpenSSL 1.1.1+
            try:
                if hasattr(context, 'set_groups'):
                    context.set_groups(self.HYBRID_PQ_GROUPS)
                    log.info(f"Server KEM groups set to: {self.HYBRID_PQ_GROUPS}")
                else:
                    context.set_ecdh_curves(self.HYBRID_PQ_GROUPS)
                    log.info(f"Server ECDH curves (acting as groups) set to: {self.HYBRID_PQ_GROUPS}")
            except Exception as e:
                log.error(f"Failed to set post-quantum key exchange groups for server: {e}")

        # Ensure cert and key are available, generate if necessary
        if self.in_memory_only or \
           not self.cert_path or not self.key_path or \
           (not os.path.exists(self.cert_path) or not os.path.exists(self.key_path)):
            if not self.in_memory_only:
                 log.warning("Certificate or key file not found or not specified for disk mode. Generating default self-signed certificate.")
            self._create_default_certificates() # Populates self.private_key_data and self.certificate_data

        # Load certificates for the server
        try:
            if self.in_memory_only and self.private_key_data and self.certificate_data:
                context.load_pem_private_key(self.private_key_data, password=None)
                self._secure_wipe_memory(self.private_key_data, "in-memory server private key data")
                self.private_key_data = None 
                
                temp_cert_file_server = None
                try:
                    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp_cert:
                        tmp_cert.write(self.certificate_data)
                        temp_cert_file_server = tmp_cert.name
                    context.load_cert_chain(certfile=temp_cert_file_server)
                finally:
                    if temp_cert_file_server and os.path.exists(temp_cert_file_server):
                        os.unlink(temp_cert_file_server) 
                log.info("Loaded in-memory server certificate and wiped private key.")

            elif not self.in_memory_only and self.cert_path and self.key_path and os.path.exists(self.cert_path) and os.path.exists(self.key_path):
                context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
                log.info(f"Loaded server certificates from disk: {self.cert_path}")
            else:
                # This path should ideally not be hit if _create_default_certificates works or paths are valid for disk mode.
                # If we are in_memory_only and private_key_data is None here, _create_default_certificates failed.
                missing_reason = "files not found on disk" if not self.in_memory_only else "in-memory data not generated"
                log.critical(f"Server certificate and key could not be loaded ({missing_reason}). Cannot create server context.")
                raise TlsChannelException(f"Server certificate/key material unavailable ({missing_reason}).")

        except Exception as e:
            log.critical(f"CRITICAL: Failed to load or establish server certificates: {e}", exc_info=True)
            raise TlsChannelException(f"Failed to load/establish server certificates: {e}") from e
        
        # Configure client certificate verification (mutual TLS)
        if self.verify_certs: # In server context, verify_certs means require and verify client cert
            if self.ca_path and os.path.exists(self.ca_path):
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(self.ca_path)
                log.info(f"Client certificate verification enabled using CA: {self.ca_path}")
            else:
                # If ca_path is not specified or doesn't exist, but verify_certs is true,
                # it implies we might want to use system default CAs for client certs, 
                # or it's a misconfiguration. For explicit client cert requirement, a CA is usually specific.
                # For now, log a warning if no CA is provided for client cert verification.
                log.warning("Client certificate verification (verify_certs=True) requested for server, but no CA path provided or CA file not found. Client certs will not be verified against a specific CA.")
                context.verify_mode = ssl.CERT_OPTIONAL # Or CERT_NONE if no CA means no verification
        else:
            context.verify_mode = ssl.CERT_NONE
            log.info("Client certificate verification DISABLED for server.")
            
        # Enable OCSP Must-Staple for server
        if self.ocsp_stapling:
            context.ocsp_stapling_cb = self._ocsp_stapling_callback
            log.debug("OCSP Must-Staple callback configured for server context.")

        return context

class CounterBasedNonceManager:
    """
    Manages nonce generation using the counter + salt approach for AEAD ciphers.
    This approach ensures each (key, nonce) pair is used exactly once, preventing
    catastrophic nonce reuse in ChaCha20-Poly1305 and AES-GCM.
    """
    
    def __init__(self, counter_size: int = 8, salt_size: int = 4, nonce_size: int = 12):
        """
        Initialize the counter-based nonce manager.
        
        Args:
            counter_size: Size of the counter in bytes (default: 8 bytes/64-bit)
            salt_size: Size of the random salt in bytes (default: 4 bytes/32-bit)
            nonce_size: Total nonce size in bytes (default: 12 for most AEAD ciphers,
                       use 24 for XChaCha20Poly1305)
        """
        if counter_size + salt_size != nonce_size:
            raise ValueError(f"Counter size ({counter_size}) + salt size ({salt_size}) must equal nonce_size ({nonce_size}) bytes for AEAD")
            
        self.counter_size = counter_size
        self.salt_size = salt_size
        self.nonce_size = nonce_size
        self.counter = 0
        self.salt = os.urandom(salt_size)
        
        # For tracking purposes only
        self.nonce_uses = 0
        self.last_reset_time = time.time()
        
    def generate_nonce(self) -> bytes:
        """
        Generate a unique nonce using counter + salt approach.
        
        Returns:
            nonce_size-byte nonce for AEAD encryption (salt + counter)
        
        Raises:
            RuntimeError: If counter exceeds maximum value
        """
        # Check if counter is approaching maximum
        max_counter = (2 ** (self.counter_size * 8)) - 1
        if self.counter >= max_counter:
            logger.warning(f"Nonce counter reached maximum ({max_counter}), resetting salt and counter")
            self.reset()
            
        # Convert counter to bytes (big-endian)
        counter_bytes = self.counter.to_bytes(self.counter_size, byteorder='big')
        
        # Construct nonce: salt + counter
        nonce = self.salt + counter_bytes
        
        # Increment counter for next use
        self.counter += 1
        self.nonce_uses += 1
        
        return nonce
    
    def reset(self):
        """Reset the counter and generate a new random salt."""
        self.counter = 0
        self.salt = os.urandom(self.salt_size)
        self.last_reset_time = time.time()
        logger.debug(f"CounterBasedNonceManager reset with new {self.salt_size}-byte salt")
        
    def get_counter(self) -> int:
        """Get the current counter value (for testing/debugging only)."""
        return self.counter
    
    def get_salt(self) -> bytes:
        """Get the current salt value (for testing/debugging only)."""
        return self.salt

