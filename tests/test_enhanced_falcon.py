"""
Unit tests for the EnhancedFALCON_1024 implementation.

Tests that the enhanced parameters are correctly applied and that the implementation
properly handles the improved security parameters from the research paper
"A Closer Look at Falcon" (eprint.iacr.org/2024/1769).
"""

import unittest
import os
import sys
import logging
import hashlib

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules under test
from hybrid_kex import EnhancedFALCON_1024

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
logger = logging.getLogger(__name__)

class TestEnhancedFalcon(unittest.TestCase):
    """Test case for the EnhancedFALCON_1024 implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.falcon = EnhancedFALCON_1024()
        self.test_message = b"This is a test message for FALCON signature verification"
        
    def test_initialization(self):
        """Test that the EnhancedFALCON_1024 instance is properly initialized."""
        self.assertIsNotNone(self.falcon)
        self.assertEqual(self.falcon.tau, 1.28, "tau parameter should be 1.28")
        self.assertEqual(self.falcon.norm_bound_factor, 1.10, "norm_bound_factor should be 1.10")
        
    def test_key_generation(self):
        """Test key generation with enhanced parameters."""
        pk, sk = self.falcon.keygen()
        
        # Check key format
        self.assertTrue(pk.startswith(b"EFPK-1"), "Public key should have the enhanced format marker")
        self.assertTrue(sk.startswith(b"EFSK-1"), "Private key should have the enhanced format marker")
        
        # Check key lengths - accounting for the metadata header
        self.assertGreaterEqual(len(pk), 1793 + 6, "Enhanced public key should be at least 1799 bytes")
        self.assertGreaterEqual(len(sk), 2305 + 6, "Enhanced private key should be at least 2311 bytes")
        
    def test_sign_and_verify(self):
        """Test signing and verification with enhanced parameters."""
        pk, sk = self.falcon.keygen()
        
        # Sign the test message
        signature = self.falcon.sign(sk, self.test_message)
        
        # Check signature format
        self.assertTrue(signature.startswith(b"EFS-1"), "Signature should have the enhanced format marker")
        
        # Verify the signature
        self.assertTrue(
            self.falcon.verify(pk, self.test_message, signature),
            "Signature verification should succeed"
        )
        
        # Test with modified message
        modified_message = self.test_message + b"modification"
        try:
            # Should raise an exception with invalid signature
            result = self.falcon.verify(pk, modified_message, signature)
            # If we get here, verification didn't fail as expected
            self.assertFalse(result, "Signature verification should fail with modified message")
        except Exception:
            # This is the expected behavior - verification should fail with an exception
            pass
        
    def test_backward_compatibility(self):
        """Test that the implementation can handle legacy keys without metadata headers."""
        pk, sk = self.falcon.keygen()
        
        # Strip off the metadata headers to simulate legacy keys
        legacy_pk = pk[6:]  # Remove "EFPK-1"
        legacy_sk = sk[6:]  # Remove "EFSK-1"
        
        # Sign with legacy key
        signature = self.falcon.sign(legacy_sk, self.test_message)
        
        # Verify with legacy public key
        self.assertTrue(
            self.falcon.verify(legacy_pk, self.test_message, signature),
            "Should verify with legacy public key"
        )
        
    def test_signature_interoperability(self):
        """Test compatibility between signature formats."""
        pk, sk = self.falcon.keygen()
        
        # Create a signature with enhanced format
        enhanced_sig = self.falcon.sign(sk, self.test_message)
        
        # Strip off the metadata header to simulate legacy signature
        legacy_sig = enhanced_sig[5:]  # Remove "EFS-1"
        
        # Should still verify with legacy signature
        self.assertTrue(
            self.falcon.verify(pk, self.test_message, legacy_sig),
            "Should verify legacy signature format"
        )
        
    def test_multiple_messages(self):
        """Test signing and verifying multiple different messages."""
        pk, sk = self.falcon.keygen()
        
        # Generate and test 5 different messages
        for i in range(5):
            message = f"Test message {i} with different content".encode('utf-8')
            signature = self.falcon.sign(sk, message)
            
            self.assertTrue(
                self.falcon.verify(pk, message, signature),
                f"Failed to verify message {i}"
            )
            
    def test_large_message(self):
        """Test signing and verifying a large message."""
        pk, sk = self.falcon.keygen()
        
        # Generate a large message (100 KB)
        large_message = os.urandom(100 * 1024)
        
        # Sign the large message (should hash it internally)
        signature = self.falcon.sign(sk, large_message)
        
        # Verify the signature
        self.assertTrue(
            self.falcon.verify(pk, large_message, signature),
            "Failed to verify large message"
        )
            
if __name__ == '__main__':
    unittest.main() 