import unittest
import os
import sys
import socket
import time
import threading
import logging
from contextlib import contextmanager
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca_services import CAExchange, SecurityError

# Configure test logging
logging.basicConfig(level=logging.INFO)

class TestCertificateAuthSecurity(unittest.TestCase):
    """
    Test suite for certificate authority exchange security features
    """
    
    def setUp(self):
        """Set up test environment before each test"""
        self.ca_exchange = CAExchange(exchange_port_offset=0, secure_exchange=True)
    
    def tearDown(self):
        """Clean up after each test"""
        if hasattr(self, 'ca_exchange'):
            self.ca_exchange.secure_cleanup()
    
    def test_self_signed_certificate_generation(self):
        """Test self-signed certificate generation with enhanced security parameters"""
        key_pem, cert_pem = self.ca_exchange.generate_self_signed()
        
        # Verify key and certificate were generated
        self.assertIsNotNone(key_pem)
        self.assertIsNotNone(cert_pem)
        self.assertIsNotNone(self.ca_exchange.local_cert_fingerprint)
        
        # Verify key and certificate content
        self.assertTrue(key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"))
    
    def test_certificate_exchange(self):
        """Test secure certificate exchange between client and server"""
        # Generate certificates for both peers
        server_ca = CAExchange(exchange_port_offset=0, secure_exchange=True)
        client_ca = CAExchange(exchange_port_offset=0, secure_exchange=True)
        
        server_key, server_cert = server_ca.generate_self_signed()
        client_key, client_cert = client_ca.generate_self_signed()
        
        # Use a threading event to coordinate server-client exchange
        ready_event = threading.Event()
        
        # Start server in a separate thread
        server_thread = threading.Thread(
            target=server_ca.exchange_certs,
            args=("server", "127.0.0.1", 38444, ready_event)
        )
        server_thread.daemon = True
        server_thread.start()
        
        # Wait for server to be ready
        ready_event.wait(timeout=5.0)
        
        # Client connects and exchanges certificates
        client_peer_cert = client_ca.exchange_certs("client", "127.0.0.1", 38444)
        
        # Wait for server thread to complete
        server_thread.join(timeout=5.0)
        
        # Verify certificate exchange was successful
        self.assertIsNotNone(client_peer_cert)
        self.assertIsNotNone(server_ca.peer_cert_pem)
        
        # Verify exchanged certificates match
        self.assertEqual(client_peer_cert, server_cert)
        self.assertEqual(server_ca.peer_cert_pem, client_cert)
        
        # Clean up
        server_ca.secure_cleanup()
        client_ca.secure_cleanup()
    
    def test_wrong_aad_fails_decryption(self):
        """Test that using wrong AAD fails decryption as expected"""
        # Initialize CAExchange with secure exchange
        ca_exchange = CAExchange(secure_exchange=True)
        
        # Generate a test message
        test_data = b"This is a test message for secure exchange"
        correct_aad = b"correct-aad"
        wrong_aad = b"wrong-aad"
        
        # Encrypt with correct AAD
        encrypted_data = ca_exchange._encrypt_data(test_data, associated_data=correct_aad)
        
        # Verify decryption works with correct AAD
        decrypted = ca_exchange._decrypt_data(encrypted_data, associated_data=correct_aad)
        self.assertEqual(decrypted, test_data)
        
        # Verify decryption fails with wrong AAD
        with self.assertRaises(SecurityError):
            ca_exchange._decrypt_data(encrypted_data, associated_data=wrong_aad)
    
    def test_encryption_failure_raises_error(self):
        """Test that encryption failure raises proper error instead of returning plaintext"""
        ca_exchange = CAExchange(secure_exchange=True)
        
        # Mock the XChaCha20Poly1305 cipher with one that always fails
        class MockFailingCipher:
            def encrypt(self, data=None, associated_data=None):
                raise ValueError("Simulated encryption failure")
        
        ca_exchange.xchacha_cipher = MockFailingCipher()
        
        # Verify that encryption failure raises SecurityError
        with self.assertRaises(SecurityError):
            ca_exchange._encrypt_data(b"test data", associated_data=b"test aad")
    
    def test_decryption_failure_raises_error(self):
        """Test that decryption failure raises proper error instead of returning ciphertext"""
        ca_exchange = CAExchange(secure_exchange=True)
        
        # Mock the XChaCha20Poly1305 cipher with one that always fails
        class MockFailingCipher:
            def decrypt(self, data=None, associated_data=None):
                raise ValueError("Simulated decryption failure")
        
        ca_exchange.xchacha_cipher = MockFailingCipher()
        
        # Verify that decryption failure raises SecurityError
        with self.assertRaises(SecurityError):
            ca_exchange._decrypt_data(b"fake encrypted data", associated_data=b"test aad")

if __name__ == "__main__":
    unittest.main() 