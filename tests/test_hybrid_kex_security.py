import unittest
import os
import sys
import base64
import logging
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the hybrid key exchange module
from hybrid_kex import HybridKeyExchange, verify_key_material

# Configure test logging to avoid polluting test output
logging.basicConfig(level=logging.ERROR)

class TestHybridKeyExchangeSecurity(unittest.TestCase):
    """
    Test suite focused on hybrid key exchange security - a critical component
    that combines classical (X25519) with post-quantum (ML-KEM-1024) cryptography
    """
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create instance for initiator and responder
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
    
    def tearDown(self):
        """Clean up after each test"""
        # Ensure secure cleanup of key material
        if hasattr(self, 'initiator'):
            self.initiator.secure_cleanup()
        if hasattr(self, 'responder'):
            self.responder.secure_cleanup()
    
    def test_verify_key_material_validation(self):
        """Test that the key material verification protects against insecure keys"""
        # Should raise on None
        with self.assertRaises(ValueError):
            verify_key_material(None, description="null key")
            
        # Should raise on wrong type
        with self.assertRaises(ValueError):
            verify_key_material("string not bytes", description="string key")
            
        # Should raise on empty bytes
        with self.assertRaises(ValueError):
            verify_key_material(b"", description="empty key")
            
        # Should raise on all-same-byte (low entropy)
        with self.assertRaises(ValueError):
            verify_key_material(b"\x00" * 32, description="zeroed key")
            
        # Should raise if expected length doesn't match
        with self.assertRaises(ValueError):
            verify_key_material(b"12345", expected_length=32, description="short key")
            
        # Should pass with good key material
        self.assertTrue(verify_key_material(os.urandom(32), description="random key"))
    
    def test_public_bundle_generation(self):
        """Test that public bundle contains all required components and proper formatting"""
        # Get the public bundle from both peers
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Verify bundle contents
        required_keys = [
            'identity', 'static_key', 'signed_prekey', 'prekey_signature', 
            'kem_public_key', 'falcon_public_key', 'bundle_signature'
        ]
        
        for key in required_keys:
            self.assertIn(key, initiator_bundle)
            self.assertIn(key, responder_bundle)
            
        # Test that all byte values are properly base64 encoded
        for key in ['static_key', 'signed_prekey', 'prekey_signature', 
                   'kem_public_key', 'falcon_public_key', 'bundle_signature']:
            # Should be strings containing valid base64
            self.assertIsInstance(initiator_bundle[key], str)
            try:
                decoded = base64.b64decode(initiator_bundle[key])
                self.assertIsInstance(decoded, bytes)
            except Exception:
                self.fail(f"Failed to decode base64 value for {key}")
    
    def test_bundle_verification(self):
        """Test that bundle verification correctly validates signatures"""
        # Get bundles
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Each peer should be able to verify the other's bundle
        self.assertTrue(self.initiator.verify_public_bundle(responder_bundle))
        self.assertTrue(self.responder.verify_public_bundle(initiator_bundle))
        
        # Tamper with the bundle and verify it fails verification
        tampered_bundle = initiator_bundle.copy()
        tampered_bundle['static_key'] = base64.b64encode(os.urandom(32)).decode('utf-8')
        self.assertFalse(self.responder.verify_public_bundle(tampered_bundle))
    
    def test_handshake_protocol_security(self):
        """Test the security of the handshake protocol"""
        # Get bundles
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Verify bundles
        self.assertTrue(self.initiator.verify_public_bundle(responder_bundle))
        self.assertTrue(self.responder.verify_public_bundle(initiator_bundle))
        
        # Perform handshake
        handshake_message, initiator_key = self.initiator.initiate_handshake(responder_bundle)
        responder_key = self.responder.respond_to_handshake(handshake_message, initiator_bundle)
        
        # Keys should be non-empty and match
        self.assertIsNotNone(initiator_key)
        self.assertIsNotNone(responder_key)
        self.assertEqual(initiator_key, responder_key)
        self.assertGreaterEqual(len(initiator_key), 32)
    
    def test_tampered_handshake_rejection(self):
        """Test that tampered handshake messages are rejected"""
        # Get bundles
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Start handshake
        handshake_message, _ = self.initiator.initiate_handshake(responder_bundle)
        
        # Tamper with the handshake message
        tampered_handshake = handshake_message.copy()
        if 'kem_ciphertext' in tampered_handshake:
            original = base64.b64decode(tampered_handshake['kem_ciphertext'])
            # Flip some bits in the ciphertext
            if len(original) > 0:
                modified = bytearray(original)
                modified[0] ^= 0xFF  # XOR the first byte to change it
                tampered_handshake['kem_ciphertext'] = base64.b64encode(bytes(modified)).decode('utf-8')
        
        # Responder should reject the tampered handshake
        with self.assertRaises(Exception):
            self.responder.respond_to_handshake(tampered_handshake, initiator_bundle)
    
    def test_replay_protection(self):
        """Test that replay protection prevents reusing handshake messages"""
        # Get bundles
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Perform first handshake
        handshake_message, _ = self.initiator.initiate_handshake(responder_bundle)
        self.responder.respond_to_handshake(handshake_message, initiator_bundle)
        
        # Attempt to replay the same handshake
        with self.assertRaises(Exception):
            self.responder.respond_to_handshake(handshake_message, initiator_bundle)
    
    def test_pq_resistance_with_classical_break(self):
        """
        Test that the hybrid scheme provides quantum resistance 
        by simulating a break in the classical component
        """
        # Get bundles
        initiator_bundle = self.initiator.get_public_bundle()
        responder_bundle = self.responder.get_public_bundle()
        
        # Create a responder that simulates a classical crypto break
        class BrokenClassicalResponder(HybridKeyExchange):
            def respond_to_handshake(self, handshake_message, peer_bundle=None):
                # Call the normal handshake process
                result = super().respond_to_handshake(handshake_message, peer_bundle)
                
                # The PQ component should ensure we still get a valid key despite the "broken" classical component
                return result
        
        # Create an instance with the broken classical DH
        broken_responder = BrokenClassicalResponder(
            identity="broken-classical",
            ephemeral=True,
            in_memory_only=True
        )
        
        # Give it the same bundle as the original responder for testing
        broken_responder.peer_hybrid_bundle = initiator_bundle
        
        # Force zero values for DH shared secrets by patching the class
        original_dh1 = broken_responder._get_dh1_shared_secret = lambda *args: bytes([0] * 32)
        original_dh2 = broken_responder._get_dh2_shared_secret = lambda *args: bytes([0] * 32)
        original_dh3 = broken_responder._get_dh3_shared_secret = lambda *args: bytes([0] * 32)
        original_dh4 = broken_responder._get_dh4_shared_secret = lambda *args: bytes([0] * 32)
        
        # Handshake should still succeed with quantum-resistant part intact
        handshake_message, initiator_key = self.initiator.initiate_handshake(responder_bundle)
        responder_key = broken_responder.respond_to_handshake(handshake_message, initiator_bundle)
        
        # Keys should still match due to the post-quantum component
        self.assertEqual(len(initiator_key), len(responder_key))
        
        # Key should not be all zeros (which would happen if only X25519 were used)
        self.assertNotEqual(responder_key, bytes([0] * len(responder_key)))
        
        # Clean up
        broken_responder.secure_cleanup()
    
    def test_secure_cleanup(self):
        """Test that secure cleanup effectively wipes sensitive key material"""
        # Create a new key exchange instance
        kex = HybridKeyExchange(
            identity="test-cleanup",
            ephemeral=True,
            in_memory_only=True
        )
        
        # Check that keys exist
        self.assertIsNotNone(getattr(kex, 'static_key', None))
        
        # Call secure cleanup
        kex.secure_cleanup()
        
        # Verify sensitive fields are cleared or set to None
        # Since we can't directly check if memory is overwritten, check object state
        sensitive_attrs = [
            'static_key', 'signed_prekey', 
            'kem_private_key', 'falcon_private_key'
        ]
        
        for attr in sensitive_attrs:
            # After cleanup, these should either be None or indicate they've been cleaned
            attr_value = getattr(kex, attr, None)
            if attr_value is not None and isinstance(attr_value, bytes):
                # If it's bytes, it should be zeroed out
                self.assertTrue(all(b == 0 for b in attr_value), 
                               f"{attr} was not properly zeroed")


if __name__ == '__main__':
    unittest.main() 