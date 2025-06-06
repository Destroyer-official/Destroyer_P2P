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

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ca_services import CAExchange

# Configure test logging
logging.basicConfig(level=logging.ERROR)

class TestCertificateAuthSecurity(unittest.TestCase):
    """Test suite focused on certificate authentication security"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Use a different port for testing to avoid conflicts
        self.test_port = 38443
        self.host = '127.0.0.1'

    @contextmanager
    def _create_server_socket(self, host, port):
        """Helper to create and clean up test server socket"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        try:
            yield server
        finally:
            server.close()
    
    def test_key_derivation_correct_length(self):
        """Test that HKDF key derivation produces correct 32-byte key length for ChaCha20Poly1305"""
        # The original vulnerability: using a 33-byte key
        insecure_key = b'SecureP2PCertificateExchangeKey!!'  # 33 bytes - incorrect
        self.assertEqual(len(insecure_key), 33, "Test pre-condition: insecure key should be 33 bytes")
        
        # Verify that ChaCha20Poly1305 rejects 33-byte key
        with self.assertRaises(ValueError) as cm:
            ChaCha20Poly1305(insecure_key)
        self.assertIn("key must be 32 bytes", str(cm.exception))
        
        # Test the fixed implementation using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Must be 32 for ChaCha20Poly1305
            salt=None,
            info=b'chacha20poly1305-exchange-key'
        )
        secure_key = hkdf.derive(insecure_key)
        self.assertEqual(len(secure_key), 32, "Derived key should be exactly 32 bytes")
        
        # Verify that ChaCha20Poly1305 accepts this key
        try:
            cipher = ChaCha20Poly1305(secure_key)
            self.assertIsNotNone(cipher)
        except ValueError:
            self.fail("ChaCha20Poly1305 should accept a 32-byte key")
    
    def test_cert_exchange_encrypt_decrypt(self):
        """Test that certificate exchange encryption and decryption works correctly"""
        ca_exchange = CAExchange(exchange_port_offset=1, secure_exchange=True)
        ca_exchange.generate_self_signed()
        
        # Test data that simulates a certificate
        test_cert_data = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----"
        
        # Construct AAD similar to what's used in exchange_certs
        aad = b"server:127.0.0.1:38444:cert-exchange"
        
        # Encrypt the data
        encrypted_data = ca_exchange._encrypt_data(test_cert_data, associated_data=aad)
        self.assertIsNotNone(encrypted_data)
        self.assertGreater(len(encrypted_data), len(test_cert_data))
        
        # Decrypt the data
        decrypted_data = ca_exchange._decrypt_data(encrypted_data, associated_data=aad)
        self.assertEqual(decrypted_data, test_cert_data)
    
    def test_wrong_aad_fails_decryption(self):
        """Test that using wrong AAD fails decryption as expected"""
        ca_exchange = CAExchange(exchange_port_offset=1, secure_exchange=True)
        ca_exchange.generate_self_signed()
        
        test_cert_data = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----"
        
        # Encrypt with one AAD
        correct_aad = b"server:127.0.0.1:38444:cert-exchange"
        encrypted_data = ca_exchange._encrypt_data(test_cert_data, associated_data=correct_aad)
        
        # Try to decrypt with different AAD
        wrong_aad = b"client:127.0.0.1:38444:cert-exchange"
        
        # Should raise ValueError due to authentication failure
        with self.assertRaises(ValueError):
            ca_exchange._decrypt_data(encrypted_data, associated_data=wrong_aad)
    
    def test_encryption_failure_raises_error(self):
        """Test that encryption failure raises proper error instead of returning plaintext"""
        # Create a modified CAExchange with a broken xchacha_cipher that will fail
        ca_exchange = CAExchange(exchange_port_offset=1, secure_exchange=True)
        
        # Force encryption to fail by setting cipher to problematic state
        class BrokenCipher:
            def encrypt(self, *args, **kwargs):
                raise ValueError("Simulated encryption failure")
        
        ca_exchange.xchacha_cipher = BrokenCipher()
        
        # Attempt to encrypt - should raise ValueError instead of returning plaintext
        with self.assertRaises(ValueError):
            ca_exchange._encrypt_data(b"test data", associated_data=b"test aad")
    
    def test_decryption_failure_raises_error(self):
        """Test that decryption failure raises proper error instead of returning ciphertext"""
        # Create a modified CAExchange with a broken xchacha_cipher that will fail during decryption
        ca_exchange = CAExchange(exchange_port_offset=1, secure_exchange=True)
        
        # Force decryption to fail by setting cipher to problematic state
        class BrokenCipher:
            def decrypt(self, *args, **kwargs):
                raise ValueError("Simulated decryption failure")
        
        ca_exchange.xchacha_cipher = BrokenCipher()
        
        # Attempt to decrypt - should raise ValueError instead of returning ciphertext
        with self.assertRaises(ValueError):
            ca_exchange._decrypt_data(b"fake encrypted data", associated_data=b"test aad")
            
    def test_certificate_exchange_integration(self):
        """
        Test certificate exchange integration with both client and server roles
        This is a more complex test that exercises the full certificate exchange process
        """
        # Set up server exchange in a thread
        def server_exchange():
            server_ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
            server_ca.generate_self_signed()
            try:
                server_ca.exchange_certs("server", self.host, self.test_port)
                return True
            except Exception as e:
                print(f"Server exchange error: {e}")
                return False
        
        # Start server thread
        server_thread = threading.Thread(target=server_exchange)
        server_thread.daemon = True
        server_thread.start()
        
        # Give the server time to start
        time.sleep(1)
        
        # Now run client exchange
        client_ca = CAExchange(exchange_port_offset=1, secure_exchange=True)
        client_ca.generate_self_signed()
        peer_cert = client_ca.exchange_certs("client", self.host, self.test_port)
        
        # Verify we got a legitimate certificate
        self.assertIsNotNone(peer_cert)
        self.assertIn(b"-----BEGIN CERTIFICATE-----", peer_cert)
        
        # Wait for server thread to finish
        server_thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main() 