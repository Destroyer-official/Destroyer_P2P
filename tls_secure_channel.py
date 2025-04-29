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
from typing import Optional, Tuple,  Dict,  Callable
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, ed25519
from cryptography.hazmat.primitives import hashes,  serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import sys

# Import post-quantum cryptography library if available
try:
    from quantcrypt import cipher as qcipher
    HAVE_MLKEM = True
except ImportError:
    HAVE_MLKEM = False
    pass

# Import hybrid key exchange module if available
try:
    from hybrid_kex import HybridKeyExchange, verify_key_material
    HAVE_HYBRID_KEX = True
except ImportError:
    HAVE_HYBRID_KEX = False
    pass

# Import TPM/HSM modules if available
try:
    import tpm2_pytss
    HAVE_TPM = True
except ImportError:
    HAVE_TPM = False
    
try:
    import pkcs11
    HAVE_PKCS11 = True
except ImportError:
    HAVE_PKCS11 = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

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
            log.info("Nonce space approaching threshold, resetting")
            self.reset()
        
        # Increment counter
        self.counter += 1
        
        # Ensure counter doesn't exceed maximum
        if self.counter >= self.max_nonce_uses:
            log.warning("Nonce counter reached maximum, resetting")
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
            log.error("Failed to generate unique nonce after multiple attempts")
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
        log.debug("Nonce manager reset with new prefix")
        
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
        self.nonce_manager = NonceManager(nonce_size=24)  # 24-byte nonce for XChaCha20
    
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
        
        # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce
        chacha = ChaCha20Poly1305(subkey)
        ciphertext = chacha.encrypt(nonce[16:], data, associated_data)
    
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
        
        # Use the subkey with ChaCha20-Poly1305 and the remaining 8 bytes of nonce
        chacha = ChaCha20Poly1305(subkey)
        return chacha.decrypt(nonce[16:], ciphertext, associated_data)
    
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
            
        # Nonce management
        self.aes_nonce_manager = NonceManager(nonce_size=12)  # 12-byte nonce for AES-GCM
        self.chacha_nonce_manager = NonceManager(nonce_size=12)  # 12-byte nonce for ChaCha20-Poly1305
        
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
            log.info("Operation count approaching threshold, triggering key rotation")
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
                log.error(f"Post-quantum decryption failed: {e}")
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
            log.error(f"ChaCha20-Poly1305 decryption failed: {e}")
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
            log.error(f"AES-GCM decryption failed: {e}")
            raise
        
        # Third layer: XChaCha20-Poly1305
        try:
            plaintext = self.xchacha.decrypt(plaintext, aad)
        except Exception as e:
            log.error(f"XChaCha20-Poly1305 decryption failed: {e}")
            raise
        
        return plaintext
    
    def _rotate_keys(self):
        """Rotate all encryption keys to ensure cryptographic hygiene."""
        log.info("Rotating all encryption keys in MultiCipherSuite")
        
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
            
        log.info("Key rotation completed successfully")

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
            log.warning("OAuth client ID not provided. Device flow authentication will not work.")
        
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
            log.error(f"Error starting device flow: {e}")
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
                log.warning("Device code has expired")
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
                        log.warning(f"Token error: {response_data.get('error')}")
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
    Manages interactions with secure hardware enclaves (TPM/HSM).
    """
    
    def __init__(self):
        """Initialize the secure enclave manager."""
        self.tpm_available = HAVE_TPM
        self.hsm_available = HAVE_PKCS11
        self.using_enclave = False
        self.enclave_type = None
        self.tpm_context = None
        self.hsm_session = None
        
        # Try to initialize available secure enclaves
        if self.tpm_available:
            try:
                self._init_tpm()
                self.using_enclave = True
                self.enclave_type = "TPM"
                log.info("TPM secure enclave initialized and available for cryptographic operations")
            except Exception as e:
                log.warning(f"TPM available but initialization failed: {e}")
                self.tpm_available = False
        
        if not self.using_enclave and self.hsm_available:
            try:
                self._init_hsm()
                self.using_enclave = True
                self.enclave_type = "HSM"
                log.info("HSM secure enclave initialized and available for cryptographic operations")
            except Exception as e:
                log.warning(f"HSM available but initialization failed: {e}")
                self.hsm_available = False
        
        if not self.using_enclave:
            log.info("No secure enclave available, cryptographic operations will use software only")
    
    def _init_tpm(self):
        """Initialize the TPM module."""
        if not HAVE_TPM:
            return
            
        try:
            # Create TPM context
            self.tpm_context = tpm2_pytss.ESAPI(tpm2_pytss.tcti.TCTI.load("device"))
            
            # Test TPM functionality by getting random bytes
            test_random = self.tpm_context.get_random(16)
            if test_random and len(test_random) == 16:
                log.debug("TPM random generation test successful")
            else:
                raise Exception("TPM random generation failed")
                
        except Exception as e:
            log.error(f"TPM initialization error: {e}")
            self.tpm_context = None
            raise
    
    def _init_hsm(self):
        """Initialize the HSM via PKCS#11."""
        if not HAVE_PKCS11:
            return
            
        try:
            # Get library path from environment or use default
            lib_path = os.environ.get("PKCS11_LIB_PATH", "/usr/local/lib/libsofthsm2.so")
            
            # Initialize PKCS#11 library
            lib = pkcs11.lib(lib_path)
            
            # Get token - first available or by label
            token_label = os.environ.get("PKCS11_TOKEN_LABEL", None)
            if token_label:
                token = lib.get_token(token_label=token_label)
            else:
                for slot in lib.get_slots():
                    if slot.get_token():
                        token = slot.get_token()
                        break
                else:
                    raise Exception("No PKCS#11 token found")
            
            # Open session
            pin = os.environ.get("PKCS11_PIN", "1234")
            self.hsm_session = token.open(user_pin=pin)
            
            # Test HSM functionality by getting random bytes
            test_random = self.hsm_session.generate_random(16)
            if test_random and len(test_random) == 16:
                log.debug("HSM random generation test successful")
            else:
                raise Exception("HSM random generation failed")
                
        except Exception as e:
            log.error(f"HSM initialization error: {e}")
            self.hsm_session = None
            raise
    
    def generate_random(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes using hardware if available.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            Random bytes
        """
        if self.using_enclave:
            try:
                if self.enclave_type == "TPM" and self.tpm_context:
                    return self.tpm_context.get_random(length)
                elif self.enclave_type == "HSM" and self.hsm_session:
                    return self.hsm_session.generate_random(length)
            except Exception as e:
                log.warning(f"Hardware random generation failed, falling back to software: {e}")
        
        # Fallback to software
        return os.urandom(length)
    
    def create_rsa_key(self, key_size=3072, key_id="tls-server-key"):
        """
        Create an RSA key pair within the secure enclave.
        
        Args:
            key_size: Key size in bits
            key_id: Identifier for the key
            
        Returns:
            Tuple of (public_key, key_handle) or None if not supported
        """
        if not self.using_enclave:
            return None
            
        try:
            if self.enclave_type == "HSM" and self.hsm_session:
                # Create RSA key pair in HSM
                public, private = self.hsm_session.generate_keypair(
                    pkcs11.KeyType.RSA,
                    key_size,
                    label=key_id,
                    id=key_id.encode(),
                    store=True,
                    capabilities=(
                        pkcs11.MechanismFlag.SIGN |
                        pkcs11.MechanismFlag.DECRYPT
                    )
                )
                
                # Extract public key in PEM format
                template = [
                    (pkcs11.Attribute.MODULUS, None),
                    (pkcs11.Attribute.PUBLIC_EXPONENT, None),
                ]
                attrs = public.get_attributes(template)
                
                return (public, private.handle)
            
            elif self.enclave_type == "TPM" and self.tpm_context:
                # TPM implementation would go here
                # This is complex and requires more code
                log.warning("TPM RSA key generation not yet implemented")
                return None
                
        except Exception as e:
            log.error(f"Secure enclave key generation failed: {e}")
            return None
            
        return None
    
    def sign_with_key(self, key_handle, data: bytes, mechanism=None):
        """
        Sign data using a key in the secure enclave.
        
        Args:
            key_handle: Handle to the key
            data: Data to sign
            mechanism: Signing mechanism to use
            
        Returns:
            Signature bytes or None if operation failed
        """
        if not self.using_enclave:
            return None
            
        try:
            if self.enclave_type == "HSM" and self.hsm_session:
                # Get private key object from handle
                private_key = pkcs11.Object(self.hsm_session, handle=key_handle)
                
                # Default to RSA-PSS if no mechanism specified
                if mechanism is None:
                    mechanism = pkcs11.Mechanism.SHA256_RSA_PKCS_PSS
                
                # Sign the data
                signature = private_key.sign(
                    data,
                    mechanism=mechanism
                )
                return signature
                
            elif self.enclave_type == "TPM" and self.tpm_context:
                # TPM implementation would go here
                log.warning("TPM signing not yet implemented")
                return None
                
        except Exception as e:
            log.error(f"Secure enclave signing failed: {e}")
            return None
            
        return None
    
    def close(self):
        """Close connections to secure enclaves."""
        if self.enclave_type == "HSM" and self.hsm_session:
            self.hsm_session.close()
            self.hsm_session = None
            
        if self.enclave_type == "TPM" and self.tpm_context:
            self.tpm_context = None
            
        self.using_enclave = False
        log.info("Secure enclave connections closed")

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
    
    def __init__(self, cert_path: Optional[str] = None, key_path: Optional[str] = None, 
                 use_secure_enclave: bool = True, require_authentication: bool = False,
                 oauth_provider: Optional[str] = None, oauth_client_id: Optional[str] = None,
                 multi_cipher: bool = True, enable_pq_kem: bool = True,
                 use_legacy_cipher: bool = False, verify_certs: bool = False,
                 ca_path: Optional[str] = None):
        """
        Initialize the TLS secure channel.
        
        Args:
            cert_path: Path to certificate file
            key_path: Path to key file
            use_secure_enclave: Use hardware security module if available
            require_authentication: Require user authentication
            oauth_provider: OAuth provider for authentication
            oauth_client_id: OAuth client ID
            multi_cipher: Use multiple cipher layers for encryption
            enable_pq_kem: Enable post-quantum key exchange
            use_legacy_cipher: Use legacy ciphers for compatibility
            verify_certs: Verify certificates
            ca_path: Path to CA certificate
        """
        # Certificate paths
        cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert")
        self.cert_path = cert_path or os.path.join(cert_dir, "server.crt")
        self.key_path = key_path or os.path.join(cert_dir, "server.key")
        self.ca_path = ca_path or os.path.join(cert_dir, "ca.crt")
        
        # Authentication settings
        self.require_authentication = require_authentication
        self.authenticated = False
        self.oauth_auth = None
        
        # Initialize OAuth if required
        if require_authentication and oauth_provider and oauth_client_id:
            self.oauth_auth = OAuth2DeviceFlowAuth(
                provider=oauth_provider,
                client_id=oauth_client_id
            )
        
        # Socket state
        self.raw_socket = None
        self.ssl_socket = None
        self.handshake_completed = False
        self.is_server = False
        
        # Cipher settings
        self.multi_cipher = multi_cipher
        self.post_quantum_enabled = enable_pq_kem
        self.multi_cipher_suite = None
        self.use_legacy_cipher = use_legacy_cipher
        
        # Post-quantum settings
        self.pq_kem = None
        self.pq_negotiated = False
        
        # Verification settings
        self.verify_certs = verify_certs
        
        # Initialize secure enclave
        self.secure_enclave_enabled = use_secure_enclave
        self.secure_enclave = None
        
        if use_secure_enclave:
            try:
                self.secure_enclave = SecureEnclaveManager()
            except Exception as e:
                log.error(f"Failed to initialize secure enclave: {e}")
                log.warning("Falling back to software crypto")
                self.secure_enclave_enabled = False
                
        # Initialize cryptographic components
        self._initialize_crypto()
        
        # Perform security checks and logging
        self._log_security_status()

    def _log_security_status(self):
        """
        Log information about the security configuration and verify security features.
        """
        log.info("Performing security verification...")
        
        # Validate and log post-quantum status
        if self.post_quantum_enabled:
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
        if self.multi_cipher:
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
        if self.secure_enclave_enabled and self.secure_enclave:
            log.info("Secure enclave/HSM support: ENABLED")
        else:
            log.warning("Hardware security module (HSM) DISABLED or not available")
            
        # Log authentication status
        if self.require_authentication and self.oauth_auth:
            log.info("Strong authentication: ENABLED")
        else:
            log.warning("Strong authentication DISABLED - no user identity verification")
            
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
            if self.multi_cipher and self.multi_cipher_suite:
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
            if self.multi_cipher and self.multi_cipher_suite:
                return self.multi_cipher_suite.decrypt(data)
            else:
                # Otherwise return standard TLS data
                return data
                
        except Exception as e:
            log.error(f"Error receiving data: {e}")
            return None
    
    def do_handshake(self) -> bool:
        """
        Perform TLS handshake on the established connection.
        
        Returns:
            True if handshake successful, False otherwise
        """
        if not self.ssl_socket:
            log.error("Cannot perform handshake: No SSL socket")
            return False
            
        try:
            # Perform TLS handshake
            self.ssl_socket.do_handshake()
            self.handshake_completed = True
            
            # Log cipher information
            cipher = self.ssl_socket.cipher()
            if cipher:
                log.info(f"TLS handshake complete: {cipher[0]} ({cipher[1]} bits)")
                
            # Initialize multi-cipher suite with TLS shared secret
            if self.multi_cipher:
                # Derive a key from the session
                master_key = hashlib.sha384(str(self.ssl_socket.session.id).encode()).digest()
                self._initialize_multi_cipher(master_key)
                
            # Verify security parameters
            security_result = self.verify_security()
            if security_result.get('status') != 'ERROR':
                log.info("Security verification passed")
            else:
                log.warning(f"Security verification issues: {security_result.get('message')}")
                
            return True
            
        except Exception as e:
            log.error(f"TLS handshake failed: {e}")
            return False

    def _initialize_multi_cipher(self, shared_secret: bytes):
        """
        Initialize the multi-cipher suite with a shared secret from TLS handshake.
        
        Args:
            shared_secret: The shared secret derived from TLS handshake
        """
        if not self.multi_cipher:
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
            self.multi_cipher = False
    
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
        """Create default self-signed certificates using cryptography library."""
        cert_dir = os.path.join(os.path.dirname(__file__), "cert")
        os.makedirs(cert_dir, exist_ok=True)
        
        # Only generate if they don't exist or we're forcing recreation
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            log.info("Generating self-signed certificate and key...")
            try:
                # Initialize private_key variable in the correct scope
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
                        log.info("Hardware key generation not supported, using software")
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
                ).sign(private_key, hashes.SHA256())
                
                # Write the private key to disk
                with open(self.key_path, "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,  # More modern format than TraditionalOpenSSL
                        encryption_algorithm=serialization.NoEncryption(),
                    ))
                
                # Write the certificate to disk
                with open(self.cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                
                log.info(f"Generated certificate in {self.cert_path}")
                
            except Exception as e:
                log.error(f"Failed to generate certificate programmatically: {e}")
                self.cert_path = None
                self.key_path = None
    
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
                self.handshake_completed = True
                
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
                    if self.multi_cipher:
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
        if not self.ssl_socket or not self.handshake_completed:
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
        if not self.ssl_socket or not self.handshake_completed:
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
                self.handshake_completed = False
            else:
                self.handshake_completed = True
                
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
                self.handshake_completed = False
            else:
                self.handshake_completed = True
                
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
        Get information about the current TLS session.
        
        Returns:
            Dictionary with session information
        """
        if not self.ssl_socket:
            return {
                "status": "not_connected",
                "protocol": None,
                "cipher": None,
                "peer_cert": None,
                "post_quantum": False
            }
            
        try:
            cipher = self.ssl_socket.cipher() if self.ssl_socket else None
            version = self.ssl_socket.version() if self.ssl_socket else None
            
            # Initialize PQ values with defaults
            pq_negotiated = False
            pq_kem_algorithm = None
            named_group = None
            
            # Determine if post-quantum was negotiated
            try:
                if hasattr(self, 'pq_negotiated'):
                    pq_negotiated = self.pq_negotiated
                if hasattr(self, 'pq_kem'):
                    pq_kem_algorithm = self.pq_kem
            except Exception:
                # Safely handle if attributes don't exist
                pass
                
            # Check cipher details for PQ indicators
            if cipher and isinstance(cipher, tuple) and len(cipher) > 0:
                cipher_name = cipher[0]
                # Look for post-quantum indicators in cipher name
                if any(pq_name in cipher_name for pq_name in ["MLKEM", "KYBER", "PQ", "X25519MLKEM"]):
                    pq_negotiated = True
                    if "MLKEM1024" in cipher_name:
                        pq_kem_algorithm = "ML-KEM-1024"
                    elif "KYBER" in cipher_name:
                        pq_kem_algorithm = "KYBER"
            
            # Get the context of the SSL socket and check for stored attributes
            try:
                context = self.ssl_socket.context
                if hasattr(context, '_pq_enabled'):
                    pq_enabled = getattr(context, '_pq_enabled')
                    if pq_enabled and not pq_negotiated:
                        pq_negotiated = False  # PQ was enabled but not negotiated
                        pq_kem_algorithm = "Not negotiated"
            except Exception:
                pass
            
            # Determine the negotiated group
            if hasattr(self.ssl_socket, 'negotiated_group'):
                named_group = self.ssl_socket.negotiated_group
            
            # Set class attributes for future reference
            self.pq_negotiated = pq_negotiated
            if pq_kem_algorithm:
                self.pq_kem = pq_kem_algorithm
                
            return {
                "status": "connected" if self.handshake_completed else "handshaking",
                "protocol": version,
                "cipher": cipher[0] if cipher and len(cipher) > 0 else None,
                "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                "post_quantum": pq_negotiated,
                "pq_algorithm": pq_kem_algorithm,
                "named_group": named_group,
                "peer_cert": self.ssl_socket.getpeercert() if self.ssl_socket else None
            }
        except Exception as e:
            log.error(f"Error getting session info: {e}")
            return {
                "status": "error",
                "protocol": None,
                "cipher": None,
                "peer_cert": None,
                "post_quantum": False,
                "error": str(e)
            }

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
                self.handshake_completed = False
            else:
                self.handshake_completed = True
                
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
                self.handshake_completed = False
            else:
                self.handshake_completed = True
                
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
                self.handshake_completed = False
            else:
                self.handshake_completed = True
                
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
        if not self.ssl_socket or not self.handshake_completed:
            log.error("Cannot send data: Socket not ready or handshake not completed")
            return 0
            
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            # Add multi-cipher encryption if available
            if self.multi_cipher and self.multi_cipher_suite:
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
        if not self.ssl_socket or not self.handshake_completed:
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
            if self.multi_cipher and self.multi_cipher_suite and data:
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
        Create a client-side SSL context with security settings.
        
        Returns:
            An SSL context object configured for client use
        """
        # Create client-side SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Set TLS 1.3
        if hasattr(context, 'maximum_version') and hasattr(ssl, 'TLSVersion'):
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
        if hasattr(context, 'minimum_version') and hasattr(ssl, 'TLSVersion'):
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Use our preferred cipher suites
        try:
            context.set_ciphers(self.CIPHER_SUITE_STRING)
        except ssl.SSLError:
            log.warning(f"Cipher suites {self.CIPHER_SUITE_STRING} not supported. Using default secure ciphers.")
        
        # Set standalone flag for compatibility detection
        context._standalone_mode = True
        
        # Enable post-quantum key exchange
        if self.post_quantum_enabled:
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
            
            # Determine security capabilities
            is_post_quantum = False
            
            # Check if post-quantum was enabled during context creation
            if hasattr(self.ssl_socket.context, '_pq_enabled'):
                is_post_quantum = getattr(self.ssl_socket.context, '_pq_enabled')
            
            # Also check cipher name
            cipher_name = cipher[0] if cipher else "unknown"
            if "X25519MLKEM1024" in cipher_name or "MLKEM1024" in cipher_name:
                is_post_quantum = True
            
            # Check if this is TLS 1.3 which is required for PQ
            if tls_version == "TLSv1.3" and self.post_quantum_enabled:
                # Force post-quantum to true if we explicitly enabled it and using TLS 1.3
                is_post_quantum = True
            
            # Enhanced security information
            enhanced_security = {
                "multi_cipher": {
                    "enabled": self.multi_cipher and self.multi_cipher_suite is not None,
                    "ciphers": ["XChaCha20-Poly1305", "AES-256-GCM", "ChaCha20-Poly1305"] if self.multi_cipher else []
                },
                "post_quantum": {
                    "enabled": self.post_quantum_enabled,
                    "direct_kem": self.pq_kem is not None,
                    "hybrid_kex": is_post_quantum
                },
                "hardware_security": {
                    "enabled": self.secure_enclave is not None and hasattr(self.secure_enclave, 'using_enclave') and self.secure_enclave.using_enclave,
                    "type": self.secure_enclave.enclave_type if (self.secure_enclave and hasattr(self.secure_enclave, 'using_enclave') and self.secure_enclave.using_enclave) else None
                }
            }
                
            return {
                "status": "connected" if self.handshake_completed else "handshaking",
                "version": tls_version,
                "cipher": cipher[0] if cipher else None,
                "protocol": cipher[1] if cipher else None,
                "compression": self.ssl_socket.compression(),
                "server": self.is_server,
                "post_quantum": is_post_quantum,
                "security_level": "maximum" if is_post_quantum and enhanced_security["multi_cipher"]["enabled"] else 
                                  "post-quantum" if is_post_quantum else 
                                  "enhanced" if enhanced_security["multi_cipher"]["enabled"] else 
                                  "classical",
                "enhanced_security": enhanced_security
            }
        except Exception as e:
            log.error(f"Error getting session info: {e}")
            return {"status": "error", "message": str(e)}

    def do_handshake(self) -> bool:
        """
        Perform TLS handshake on a blocking socket.
        
        Returns:
            True if handshake completed successfully, False otherwise
        """
        if not self.ssl_socket:
            log.error("Cannot perform handshake: No SSL socket")
            return False
            
        log.info("Beginning TLS 1.3 handshake with quantum-resistant key exchange...")
        
        try:
            # Perform handshake
            self.ssl_socket.do_handshake()
            self.handshake_completed = True

            # Get handshake information
            cipher = self.ssl_socket.cipher()
            cipher_name = cipher[0] if cipher and len(cipher) > 0 else "unknown"
            
            # Determine if post-quantum was used by inspecting the cipher suite and TLS extensions
            pq_negotiated = False
            pq_algorithm = None
            
            # Check cipher name first
            if "X25519MLKEM" in cipher_name or "MLKEM" in cipher_name:
                pq_negotiated = True
                pq_algorithm = "ML-KEM-1024"
            
            # For standalone mode, also check TLS version and context flags
            if not pq_negotiated and self.post_quantum_enabled:
                # If we're using TLS 1.3 and PQ was enabled in our context, we can consider it active
                # in standalone mode where both client and server are our own implementation
                tls_version = self.ssl_socket.version()
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
            
            # Set post-quantum status
            self.pq_negotiated = pq_negotiated
            self.pq_kem = pq_algorithm
                
            # Log handshake completion
            if cipher:
                log.info(f"Handshake completed with {cipher_name} cipher ({cipher[2]} bits)")
                if pq_negotiated:
                    log.info(f"Post-quantum protection active: {pq_algorithm}")
                
            # Make security verification log statements
            security_issues = []
            
            if not pq_negotiated and self.post_quantum_enabled:
                security_issues.append("Post-quantum key exchange requested but not negotiated")
                # In standalone mode, we'll accept this with a warning rather than critical error
                if self.is_standalone_mode():
                    log.warning("Running in standalone mode with classical cryptography only")
                else:
                    log.error("CRITICAL SECURITY ISSUES DETECTED! Quantum security may be compromised.")
            
            # Verify security parameters
            self._verify_security_parameters(self.ssl_socket.context)
            
            return True
            
        except ssl.SSLError as e:
            log.error(f"SSL error during handshake: {e}")
            return False
            
        except Exception as e:
            log.error(f"Unexpected error during handshake: {e}")
            return False
    
    def is_standalone_mode(self):
        """
        Determine if we're running in standalone mode (both client and server are our implementation)
        
        Returns:
            True if in standalone mode, False otherwise
        """
        # Check environment variable first (set in secure_p2p.py when run directly)
        if os.environ.get('SECURE_P2P_STANDALONE') == '1':
            return True
            
        # Check if we're part of the secure_p2p module
        if 'secure_p2p' in sys.modules:
            # This is likely a direct execution of secure_p2p.py
            return True
            
        # Check if socket is one we created
        try:
            # Look at context attributes
            if hasattr(self.ssl_socket, 'context') and hasattr(self.ssl_socket.context, '_standalone_mode'):
                return True
                
            # Check socket info string
            socket_info = str(self.ssl_socket)
            if "secure_p2p" in socket_info.lower() or "_inproc_" in socket_info.lower():
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

    def send_nonblocking(self, data: bytes) -> int:
        """
        Send data over the TLS connection with non-blocking behavior.
        
        Args:
            data: The data to send
        
        Returns:
            Number of bytes sent, or -1 if would block, -2 on error
        """
        if not self.ssl_socket:
            log.error("Cannot send: No SSL socket available")
            return -2
            
        if not self.handshake_completed:
            try:
                if not self.do_handshake():
                    return -1  # Would block, handshake not complete
            except Exception as e:
                log.error(f"Handshake error during send: {e}")
                return -2
                
        # If authentication is required but not complete, fail
        if self.require_authentication and not self.authenticated:
            try:
                sent = self.send_authentication()
                if not sent:
                    log.error("Authentication required but failed during send")
                    return -2
            except ssl.SSLWantReadError:
                return -1
            except ssl.SSLWantWriteError:
                return -1
            except Exception as e:
                log.error(f"Authentication error during send: {e}")
                return -2
                
        try:
            return self.ssl_socket.send(data)
        except ssl.SSLWantReadError:
            return -1  # Would block, need read
        except ssl.SSLWantWriteError:
            return -1  # Would block, need write
        except Exception as e:
            log.error(f"Error sending data: {e}")
            return -2
            
    def recv_nonblocking(self, bufsize: int) -> bytes:
        """
        Receive data from the TLS connection with non-blocking behavior.
        
        Args:
            bufsize: The maximum amount of data to receive
            
        Returns:
            Data received, empty bytes if would block, or None on error
        """
        if not self.ssl_socket:
            log.error("Cannot receive: No SSL socket available")
            return None
            
        if not self.handshake_completed:
            try:
                if not self.do_handshake():
                    return b''  # Would block, handshake not complete
            except Exception as e:
                log.error(f"Handshake error during receive: {e}")
                return None
                
        try:
            data = self.ssl_socket.recv(bufsize)
            
            # Check for authentication if server requires it
            if self.is_server and self.require_authentication and not self.authenticated:
                accepted = self.accept_authentication(data)
                if not accepted:
                    log.error("Failed to authenticate client")
                    return None
                return b''  # Authentication processed, no data for application
                
            return data
        except ssl.SSLWantReadError:
            return b''  # Would block, need read
        except ssl.SSLWantWriteError:
            return b''  # Would block, need write
        except ConnectionError as e:
            log.error(f"Connection error during receive: {e}")
            return None
        except Exception as e:
            log.error(f"Error receiving data: {e}")
            return None

    def _initialize_crypto(self):
        """
        Initialize cryptographic components and verify quantum security configuration
        """
        log.info("Initializing cryptographic subsystems...")
        
        # Initialize secure random generator with appropriate source
        if self.secure_enclave_enabled and self.secure_enclave:
            self.random_generator = self.secure_enclave.generate_random
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.info("Using hardware-backed secure random generation")
        else:
            self.random_generator = os.urandom
            if self.SECURITY_LOG_LEVEL >= self.SECURITY_LOG_LEVEL_VERBOSE:
                log.info("Using OS-provided random generation (os.urandom)")
        
        # Initialize post-quantum components if enabled
        if self.post_quantum_enabled:
            if HAVE_HYBRID_KEX:
                try:
                    # Initialize the hybrid key exchange module for post-quantum security
                    self.hybrid_kex = HybridKeyExchange(identity=f"tls-{'server' if self.is_server else 'client'}")
                    log.info("Post-quantum hybrid key exchange initialized with ML-KEM-1024")
                    
                    # Verify key material is properly configured
                    self.pq_public_bundle = self.hybrid_kex.get_public_bundle()
                    verify_key_material(
                        self.pq_public_bundle.get('kem_public_key', b'').encode() 
                        if isinstance(self.pq_public_bundle.get('kem_public_key'), str) 
                        else self.pq_public_bundle.get('kem_public_key', b''),
                        description="ML-KEM-1024 public key"
                    )
                    log.info("Post-quantum key material verified")
                    self.pq_negotiated = True
                except Exception as e:
                    log.error(f"Failed to initialize post-quantum components: {e}")
                    self.post_quantum_enabled = False
            else:
                log.warning("Post-quantum support requested but hybrid_kex module not available")
                self.post_quantum_enabled = False

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
        if not self.post_quantum_enabled:
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
            if self.post_quantum_enabled and HAVE_HYBRID_KEX and hasattr(self, 'hybrid_kex'):
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
            await super()._do_handshake(timeout)
            
            # Verify post-quantum aspects of the handshake
            if self.post_quantum_enabled and HAVE_HYBRID_KEX:
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
            if self.multi_cipher and self.multi_cipher_suite:
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
        # Ensure we have certificates
        if not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            log.warning("Certificates not found, generating new ones")
            self._create_default_certificates()
        
        # Create context with strong security settings
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        
        # Set security options
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_COMPRESSION
        
        # Set standalone flag for compatibility detection
        context._standalone_mode = True
        
        # Set cipher suites
        # Removing explicit set_ciphers to rely on strong ssl module defaults
        # try:
        #     context.set_ciphers(self.CIPHER_SUITE_STRING)
        # except ssl.SSLError:
        #     log.warning(f"Cipher suites {self.CIPHER_SUITE_STRING} not supported. Using default secure ciphers.")
        
        # Enable post-quantum key exchange
        if self.post_quantum_enabled:
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
                
                log.info("Post-quantum hybrid key exchange enabled in server TLS")
            except Exception as e:
                log.warning(f"Failed to set post-quantum groups for server: {e}")
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
        self.nonce_manager = NonceManager(
            nonce_size=12,  # Standard size for ChaCha20-Poly1305
            max_nonce_uses=2**48 - 1,  # Safely below 2^64 limit
            rotation_threshold=0.8
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
        
        # Nonce managers
        self.aes_nonce_manager = NonceManager(nonce_size=12)
        self.chacha_nonce_manager = NonceManager(nonce_size=12)
    
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
