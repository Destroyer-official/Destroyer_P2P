"""
Comprehensive Test Suite for P2P Crypto Components

Tests all cryptographic components:
- Certificate Exchange (ca_services.py)
- Hybrid Key Exchange (hybrid_kex.py)
- Double Ratchet (double_ratchet.py)
- TLS Channel Management (tls_channel_manager.py)
"""

import unittest
import os
import tempfile
import logging
import hashlib
from threading import Thread
import socket
import time
import secrets
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up test logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('crypto_test')
logger.setLevel(logging.DEBUG)

# Import the modules we're testing
from ca_services import CAExchange, SecurityError
from hybrid_kex import HybridKeyExchange, verify_key_material
from double_ratchet import DoubleRatchet
import tls_channel_manager
from tls_channel_manager import XChaCha20Poly1305, CounterBasedNonceManager

class TestCertificateExchange(unittest.TestCase):
    """Test the certificate exchange mechanism"""
    
    def setUp(self):
        self.server_ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
        self.client_ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
        
        # Generate certificates
        self.server_ca.generate_self_signed()
        self.client_ca.generate_self_signed()
        
    def test_key_size_validation(self):
        """Test that keys are properly sized for ChaCha20-Poly1305"""
        # Verify the exchange key is exactly 32 bytes (required for ChaCha20Poly1305)
        self.assertEqual(len(self.server_ca.exchange_key), 32, "Exchange key must be exactly 32 bytes")
        self.assertEqual(len(self.client_ca.exchange_key), 32, "Exchange key must be exactly 32 bytes")
    
    def test_certificate_exchange_with_aad(self):
        """Test certificate exchange with authenticated additional data"""
        # Simulate an exchange with AAD
        host = "127.0.0.1"
        port = 8800
        
        # Start server in a thread
        def run_server():
            try:
                self.server_ca.exchange_certs("server", host, port)
            except Exception as e:
                logger.error(f"Server exchange error: {e}")
        
        server_thread = Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(0.5)  # Give server time to start
        
        try:
            # Client connects and exchanges certs
            peer_cert = self.client_ca.exchange_certs("client", host, port)
            self.assertIsNotNone(peer_cert)
            self.assertTrue(b"-----BEGIN CERTIFICATE-----" in peer_cert)
            
            # Verify fingerprints match
            self.assertEqual(
                self.server_ca.local_cert_fingerprint,
                self.client_ca.peer_cert_fingerprint,
                "Certificate fingerprints should match"
            )
        except Exception as e:
            self.fail(f"Certificate exchange failed: {e}")

    def test_key_derivation(self):
        """Test proper key derivation from base shared secret"""
        # Create an instance with a custom base shared secret
        custom_secret = b"CustomSharedSecretForTesting!!"
        ca = CAExchange(secure_exchange=True, base_shared_secret=custom_secret)
        
        # Verify the key is 32 bytes and derived properly (not the raw secret)
        self.assertEqual(len(ca.exchange_key), 32)
        self.assertNotEqual(ca.exchange_key, custom_secret)
        
    def test_encryption_error_handling(self):
        """Test that encryption errors are properly handled"""
        # Create a corrupted cipher to force encryption failure
        class MockFailingCipher:
            def encrypt(self, *args, **kwargs):
                raise ValueError("Mock encryption failure")
        
        # Replace the cipher with our mock
        self.client_ca.xchacha_cipher = MockFailingCipher()
        
        # Attempt to encrypt data
        with self.assertRaises(SecurityError):
            self.client_ca._encrypt_data(b"test data", b"test aad")

class TestHybridKeyExchange(unittest.TestCase):
    """Test the hybrid key exchange mechanism"""
    
    def setUp(self):
        # Create two instances for testing exchange
        self.initiator = HybridKeyExchange(
            identity="test-initiator", 
            ephemeral=True, 
            in_memory_only=True
        )
        self.responder = HybridKeyExchange(
            identity="test-responder",
            ephemeral=True,
            in_memory_only=True
        )
    
    def test_key_material_verification(self):
        """Test verification of key material"""
        # Valid material should pass
        valid_key = secrets.token_bytes(32)
        self.assertTrue(verify_key_material(valid_key, 32, "test key"))
        
        # Test with invalid key length
        with self.assertRaises(ValueError):
            verify_key_material(valid_key, 16, "wrong size key")
            
        # Test with empty key
        with self.assertRaises(ValueError):
            verify_key_material(b"", None, "empty key")
            
        # Test with None key
        with self.assertRaises(ValueError):
            verify_key_material(None, 32, "None key")
    
    def test_complete_handshake(self):
        """Test a complete key exchange handshake"""
        # Get responder's bundle
        responder_bundle = self.responder.get_public_bundle()
        
        # Make responder aware of initiator's bundle
        initiator_bundle = self.initiator.get_public_bundle()
        self.responder.peer_hybrid_bundle = initiator_bundle
        
        # Initiator starts handshake
        handshake_msg, initiator_shared_secret = self.initiator.initiate_handshake(responder_bundle)
        
        # Responder processes handshake
        responder_shared_secret = self.responder.respond_to_handshake(handshake_msg)
        
        # Both sides should have the same shared secret
        self.assertEqual(len(initiator_shared_secret), 32)
        self.assertEqual(initiator_shared_secret, responder_shared_secret)

class TestDoubleRatchet(unittest.TestCase):
    """Test the Double Ratchet protocol"""
    
    def setUp(self):
        # Create a shared root key through the hybrid key exchange
        initiator = HybridKeyExchange(
            identity="dr-initiator", 
            ephemeral=True, 
            in_memory_only=True
        )
        responder = HybridKeyExchange(
            identity="dr-responder",
            ephemeral=True,
            in_memory_only=True
        )
        
        # Share bundles between the parties
        responder_bundle = responder.get_public_bundle()
        initiator_bundle = initiator.get_public_bundle()
        responder.peer_hybrid_bundle = initiator_bundle
        
        # Complete a handshake to get a shared root key
        handshake_msg, initiator_secret = initiator.initiate_handshake(responder_bundle)
        responder_secret = responder.respond_to_handshake(handshake_msg)
        
        # Create Double Ratchet instances
        self.alice = DoubleRatchet(
            root_key=initiator_secret,
            is_initiator=True,
            enable_pq=True
        )
        
        # Create Bob's ratchet
        self.bob = DoubleRatchet(
            root_key=responder_secret,
            is_initiator=False,
            enable_pq=True
        )
        
        # Get Alice's public keys
        alice_public_key = self.alice.get_public_key()
        alice_kem_key = self.alice.get_kem_public_key()
        alice_dss_key = self.alice.get_dss_public_key()
        
        # Get Bob's public keys
        bob_public_key = self.bob.get_public_key()
        bob_kem_key = self.bob.get_kem_public_key()
        bob_dss_key = self.bob.get_dss_public_key()
        
        # Set Alice's keys in Bob's ratchet
        self.bob.set_remote_public_key(
            alice_public_key,
            alice_kem_key,
            alice_dss_key
        )
        
        # Set Bob's keys in Alice's ratchet
        self.alice.set_remote_public_key(
            bob_public_key,
            bob_kem_key,
            bob_dss_key
        )
        
        # Exchange KEM ciphertexts for post-quantum security
        # Get the ciphertext from Alice (initiator) and process it in Bob (responder)
        alice_kem_ciphertext = self.alice.get_kem_ciphertext()
        if alice_kem_ciphertext:
            self.bob.process_kem_ciphertext(alice_kem_ciphertext)
    
    def test_encrypt_decrypt_cycle(self):
        """Test the encrypt/decrypt cycle"""
        # Alice encrypts a message for Bob
        message = b"This is a secure message from Alice to Bob"
        encrypted = self.alice.encrypt(message)
        
        # Bob decrypts Alice's message
        decrypted = self.bob.decrypt(encrypted)
        
        # Verify decryption is correct
        self.assertEqual(message, decrypted)
        
        # Now Bob responds to Alice
        response = b"This is Bob's response to Alice"
        encrypted_response = self.bob.encrypt(response)
        
        # Alice decrypts Bob's response
        decrypted_response = self.alice.decrypt(encrypted_response)
        
        # Verify decryption is correct
        self.assertEqual(response, decrypted_response)
    
    def test_message_chain(self):
        """Test sending multiple messages in a chain"""
        # Send 10 messages from Alice to Bob
        messages = []
        encrypted_messages = []
        
        for i in range(10):
            message = f"Alice message #{i}".encode('utf-8')
            messages.append(message)
            encrypted_messages.append(self.alice.encrypt(message))
        
        # Decrypt all messages with Bob
        for i in range(10):
            decrypted = self.bob.decrypt(encrypted_messages[i])
            self.assertEqual(messages[i], decrypted)

    def test_out_of_order_messages(self):
        """Test handling out-of-order messages"""
        # Skip message numbers to test out-of-order handling
        msg1 = b"Message 1"
        msg2 = b"Message 2"
        msg3 = b"Message 3"
        
        enc1 = self.alice.encrypt(msg1)
        enc2 = self.alice.encrypt(msg2)
        enc3 = self.alice.encrypt(msg3)
        
        # Decrypt out of order: 2, 1, 3
        dec2 = self.bob.decrypt(enc2)
        self.assertEqual(msg2, dec2)
        
        dec1 = self.bob.decrypt(enc1)
        self.assertEqual(msg1, dec1)
        
        dec3 = self.bob.decrypt(enc3)
        self.assertEqual(msg3, dec3)

class TestTLSChannelManager(unittest.TestCase):
    """Test TLS channel manager components"""
    
    def test_xchacha20poly1305(self):
        """Test XChaCha20Poly1305 implementation"""
        key = secrets.token_bytes(32)
        cipher = XChaCha20Poly1305(key)
        
        # Test encryption and decryption
        plaintext = b"Test message for XChaCha20Poly1305"
        aad = b"Additional authenticated data"
        
        encrypted = cipher.encrypt(data=plaintext, associated_data=aad)
        decrypted = cipher.decrypt(data=encrypted, associated_data=aad)
        
        self.assertEqual(plaintext, decrypted)
        
        # Test with manually provided nonce
        nonce = secrets.token_bytes(24)  # XChaCha20 uses 24-byte nonces
        encrypted = cipher.encrypt(nonce=nonce, data=plaintext, associated_data=aad)
        
        # First 24 bytes should be the nonce
        self.assertEqual(nonce, encrypted[:24])
        
        # Verify key rotation
        new_key = secrets.token_bytes(32)
        cipher.rotate_key(new_key)
        
        # Verify nonce validation
        with self.assertRaises(ValueError):
            cipher.encrypt(nonce=b"too_short", data=plaintext)
    
    def test_counter_based_nonce_manager(self):
        """Test the counter-based nonce manager"""
        # Create nonce manager for ChaCha20Poly1305 (12-byte nonces)
        manager = CounterBasedNonceManager(counter_size=8, salt_size=4, nonce_size=12)
        
        # Generate nonces and verify they're unique
        nonces = [manager.generate_nonce() for _ in range(10)]
        
        # Check nonce size
        for nonce in nonces:
            self.assertEqual(len(nonce), 12)
        
        # Check all nonces are unique
        self.assertEqual(len(nonces), len(set(nonces)))
        
        # Check counter increments
        self.assertEqual(manager.get_counter(), 10)
        
        # Test reset
        orig_salt = manager.get_salt()
        manager.reset()
        new_salt = manager.get_salt()
        
        self.assertEqual(manager.get_counter(), 0)
        self.assertNotEqual(orig_salt, new_salt)

if __name__ == '__main__':
    unittest.main() 