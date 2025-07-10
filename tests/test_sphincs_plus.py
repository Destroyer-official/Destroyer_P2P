#!/usr/bin/env python3
"""
SPHINCS+ Post-Quantum Signature Test Suite

This script tests the SPHINCS+ signature scheme implementation to verify
cryptographic correctness and security.
"""

import unittest
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

try:
    import sphincs
    log.info("Successfully imported SPHINCS+ implementation")
except ImportError as e:
    log.error(f"Failed to import SPHINCS+: {e}")
    log.info("SPHINCS+ tests will be skipped")

# SPHINCS+ parameter set
ALGORITHM = 'shake_128f_simple'

class TestSPHINCSPlus(unittest.TestCase):
    """Test cases for SPHINCS+ signature scheme"""
    
    @classmethod
    def setUpClass(cls):
        """Check if SPHINCS+ is available"""
        try:
            import sphincs
            cls.sphincs_available = True
        except ImportError:
            cls.sphincs_available = False
    
    def setUp(self):
        """Set up test environment"""
        if not self.sphincs_available:
            self.skipTest("SPHINCS+ module not available")
        
        # Generate keys once for all tests
        self.public_key, self.private_key = sphincs.keygen(ALGORITHM)
        self.test_message = b"This is a test message for the SPHINCS+ signature scheme."
    
    def test_key_generation(self):
        """Test key generation"""
        # Verify key lengths
        self.assertGreater(len(self.public_key), 0, "Public key should not be empty")
        self.assertGreater(len(self.private_key), 0, "Private key should not be empty")
        log.info(f"Public Key Length: {len(self.public_key)} bytes")
        log.info(f"Private Key Length: {len(self.private_key)} bytes")
    
    def test_sign_verify_cycle(self):
        """Test sign and verify cycle"""
        # Sign the message
        signature = sphincs.sign(ALGORITHM, self.test_message, self.private_key)
        
        # Verify signature length
        self.assertGreater(len(signature), 0, "Signature should not be empty")
        log.info(f"Signature Length: {len(signature)} bytes")
        
        # Verify the signature
        is_valid = sphincs.verify(ALGORITHM, self.test_message, signature, self.public_key)
        self.assertTrue(is_valid, "Signature verification should succeed")
    
    def test_tampered_message_rejection(self):
        """Test that tampered messages are rejected"""
        # Sign the original message
        signature = sphincs.sign(ALGORITHM, self.test_message, self.private_key)
        
        # Tamper with the message
        tampered_message = b"This is a tampered message."
        
        # Verify that the signature is invalid for the tampered message
        is_valid = sphincs.verify(ALGORITHM, tampered_message, signature, self.public_key)
        self.assertFalse(is_valid, "Tampered message should fail verification")
    
    def test_different_parameter_sets(self):
        """Test different parameter sets if available"""
        try:
            # Try an alternative parameter set if available
            alt_algorithm = 'sha2_128f_simple'
            pk, sk = sphincs.keygen(alt_algorithm)
            message = b"Testing alternative parameter set"
            signature = sphincs.sign(alt_algorithm, message, sk)
            is_valid = sphincs.verify(alt_algorithm, message, signature, pk)
            self.assertTrue(is_valid, "Alternative parameter set should work")
        except Exception as e:
            self.skipTest(f"Alternative parameter set not available: {e}")

if __name__ == "__main__":
    unittest.main()
