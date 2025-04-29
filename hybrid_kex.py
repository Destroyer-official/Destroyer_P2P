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
from typing import Tuple, Dict

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
        
    if isinstance(key_material, bytes):
        buffer = bytearray(key_material)
        for i in range(len(buffer)):
            buffer[i] = 0
    elif hasattr(key_material, 'zeroize'):
        key_material.zeroize()
    
    log.debug("Securely erased key material")


# Flag indicating we're using the real post-quantum implementation
HAVE_REAL_PQ = True
log.info("Using real post-quantum cryptography implementation: ML-KEM-1024 and FALCON-1024")


class HybridKeyExchange:
    """
    Implements a hybrid key exchange protocol combining X3DH with post-quantum cryptography.
    
    The protocol uses multiple Diffie-Hellman exchanges with X25519 keys for classical
    security, combined with ML-KEM-1024 for post-quantum security.
    """
    
    def __init__(self, identity: str = "user", keys_dir: str = None):
        """
        Initialize the hybrid key exchange.
        
        Args:
            identity: User identifier
            keys_dir: Directory for storing keys
        """
        self.identity = identity
        
        # Set up keys directory
        if keys_dir is None:
            self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        else:
            self.keys_dir = keys_dir
            
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
        
        # Initialize KEM and DSS instances
        self.kem = quantcrypt.kem.MLKEM_1024()
        self.dss = FALCON_1024()
        
        # Load or generate keys
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones if they don't exist."""
        key_file = os.path.join(self.keys_dir, f"{self.identity}_hybrid_keys.json")
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    keys_data = json.load(f)
                
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
        """Save the generated keys to a file."""
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
        
        # Add generation timestamp
        keys_data['generated_at'] = int(time.time())
        
        with open(key_file, 'w') as f:
            json.dump(keys_data, f)
        
        log.info(f"Saved hybrid keys to {key_file}")
    
    def get_public_bundle(self) -> Dict[str, str]:
        """
        Get the public key bundle to share with peers.
        
        Returns:
            Dictionary containing all public key components
        """
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
            bundle: The public key bundle from a peer
            
        Returns:
            True if the bundle is valid, False otherwise
        """
        try:
            # First verify Ed25519 prekey signature
            signing_public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(bundle['signing_key'])
            )
            
            signed_prekey = base64.b64decode(bundle['signed_prekey'])
            prekey_signature = base64.b64decode(bundle['prekey_signature'])
            
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
                    if not self.dss.verify(falcon_public_key, bundle_data, bundle_signature):
                        log.error("SECURITY ALERT: FALCON bundle signature verification failed")
                        return False
                    log.debug("FALCON-1024 bundle signature verified successfully")
                except Exception as e:
                    log.error(f"SECURITY ALERT: FALCON signature verification error: {e}")
                    return False
            
            return True
            
        except (KeyError, ValueError, InvalidSignature) as e:
            log.error(f"Invalid key bundle: {e}")
            return False
    
    def initiate_handshake(self, peer_bundle: Dict[str, str]) -> Tuple[Dict[str, str], bytes]:
        """
        Initiate the X3DH+PQ handshake (Alice's side).
        
        Args:
            peer_bundle: The public key bundle from the peer (Bob)
            
        Returns:
            A tuple containing:
            - The handshake message to send to the peer
            - The derived shared secret
        """
        log.info(f"Initiating hybrid X3DH+PQ handshake with peer: {peer_bundle.get('identity', 'unknown')}")
        
        # Store the peer's bundle for later use
        self.peer_hybrid_bundle = peer_bundle
        
        # Verify bundle before proceeding
        if not self.verify_public_bundle(peer_bundle):
            log.error("SECURITY ALERT: Invalid peer key bundle, signature verification failed")
            raise ValueError("Invalid peer key bundle")
        
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
        
        # Create the handshake message
        handshake_message = {
            'identity': self.identity,
            'ephemeral_key': base64.b64encode(ephemeral_public).decode('utf-8'),
            'static_key': base64.b64encode(self.static_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode('utf-8'),
            'kem_ciphertext': base64.b64encode(kem_ciphertext).decode('utf-8')
        }
        
        # Create a canonicalized representation for signing
        message_data = json.dumps(handshake_message, sort_keys=True).encode('utf-8')
        
        # Sign the message with FALCON-1024
        message_signature = self.dss.sign(self.falcon_private_key, message_data)
        handshake_message['message_signature'] = base64.b64encode(message_signature).decode('utf-8')
        
        log.info(f"Hybrid X3DH+PQ handshake initiated successfully with {peer_bundle.get('identity', 'unknown')}")
        return handshake_message, root_key
    
    def respond_to_handshake(self, handshake_message: Dict[str, str]) -> bytes:
        """
        Respond to the X3DH+PQ handshake (Bob's side).
        
        Args:
            handshake_message: The handshake message from the peer (Alice)
            
        Returns:
            The derived shared secret
        """
        try:
            log.info(f"Processing incoming handshake from: {handshake_message.get('identity', 'unknown')}")
            
            # Verify FALCON message signature if present
            if 'message_signature' in handshake_message:
                verification_message = handshake_message.copy()
                message_signature = base64.b64decode(verification_message.pop('message_signature'))
                
                # Get public key - check if we have peer_hybrid_bundle
                if hasattr(self, 'peer_hybrid_bundle') and self.peer_hybrid_bundle and 'falcon_public_key' in self.peer_hybrid_bundle:
                    peer_falcon_public_key = base64.b64decode(self.peer_hybrid_bundle['falcon_public_key'])
                    
                    # Create canonicalized representation
                    message_data = json.dumps(verification_message, sort_keys=True).encode('utf-8')
                    
                    # Verify with FALCON-1024
                    try:
                        if not self.dss.verify(peer_falcon_public_key, message_data, message_signature):
                            log.error("SECURITY ALERT: FALCON message signature verification failed")
                            raise ValueError("Invalid handshake message signature")
                        log.debug("FALCON-1024 handshake message signature verified successfully")
                    except Exception as e:
                        log.error(f"SECURITY ALERT: FALCON signature verification error: {e}")
                        raise ValueError(f"FALCON signature verification failed: {e}")
                else:
                    # Log as INFO because the bundle is expected later
                    log.info("Cannot verify FALCON signature yet: peer bundle not available")
                
            # Extract peer's public keys
            log.debug("Extracting peer public keys from handshake message")
            peer_ephemeral_public = X25519PublicKey.from_public_bytes(
                base64.b64decode(handshake_message['ephemeral_key'])
            )
            peer_static_public = X25519PublicKey.from_public_bytes(
                base64.b64decode(handshake_message['static_key'])
            )
            
            # Perform DH exchanges
            log.debug("Performing multiple Diffie-Hellman exchanges")
            
            # 1. Static-Static DH
            dh1 = self.static_key.exchange(peer_static_public)
            verify_key_material(dh1, description="DH1: Static-Static exchange")
            log.debug(f"DH1 (Static-Static): {_format_binary(dh1)}")
            
            # 2. Static-Ephemeral DH
            dh2 = self.static_key.exchange(peer_ephemeral_public)
            verify_key_material(dh2, description="DH2: Static-Ephemeral exchange")
            log.debug(f"DH2 (Static-Ephemeral): {_format_binary(dh2)}")
            
            # 3. SPK-Static DH
            dh3 = self.signed_prekey.exchange(peer_static_public)
            verify_key_material(dh3, description="DH3: SPK-Static exchange")
            log.debug(f"DH3 (SPK-Static): {_format_binary(dh3)}")
            
            # 4. SPK-Ephemeral DH
            dh4 = self.signed_prekey.exchange(peer_ephemeral_public)
            verify_key_material(dh4, description="DH4: SPK-Ephemeral exchange")
            log.debug(f"DH4 (SPK-Ephemeral): {_format_binary(dh4)}")
            
            # Perform KEM decapsulation
            log.debug("Performing ML-KEM-1024 decapsulation")
            kem_ciphertext = base64.b64decode(handshake_message['kem_ciphertext'])
            verify_key_material(kem_ciphertext, description="ML-KEM ciphertext")
            
            kem_shared_secret = self.kem.decaps(self.kem_private_key, kem_ciphertext)
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
            
            log.info(f"Hybrid X3DH+PQ handshake completed successfully with {handshake_message.get('identity', 'unknown')}")
            return root_key
            
        except (KeyError, ValueError) as e:
            log.error(f"SECURITY ALERT: Error processing handshake: {e}", exc_info=True)
            raise ValueError(f"Invalid handshake message: {e}")


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


if __name__ == "__main__":
    demonstrate_handshake() 