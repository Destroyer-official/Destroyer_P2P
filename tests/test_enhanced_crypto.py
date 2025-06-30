#!/usr/bin/env python3
"""
Enhanced Post-Quantum Cryptography Test Suite

This script tests the enhanced implementations of FALCON-1024 and ML-KEM-1024
to verify both cryptographic correctness and security enhancements.
"""

import os
import sys
import time
import math
import hashlib
import logging
import binascii
import unittest
from typing import Tuple, Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# Import our enhanced implementations
try:
    from hybrid_kex import EnhancedFALCON_1024, EnhancedMLKEM_1024
    log.info("Successfully imported enhanced crypto implementations from hybrid_kex")
except ImportError as e:
    log.error(f"Failed to import from hybrid_kex: {e}")
    sys.exit(1)

# Import base implementations for comparison
try:
    from quantcrypt.dss import FALCON_1024
    from quantcrypt.kem import MLKEM_1024
    log.info("Successfully imported base crypto implementations from quantcrypt")
except ImportError as e:
    log.error(f"Failed to import from quantcrypt: {e}")
    sys.exit(1)

class CryptoTestUtils:
    """Utility methods for cryptographic testing"""
    
    @staticmethod
    def measure_execution_time(func, *args, **kwargs):
        """Measure execution time of a function"""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        return result, (end_time - start_time)
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * (math.log(probability) / math.log(256))
            
        return entropy * 8  # Convert to bits
    
    @staticmethod
    def verify_key_material(data: bytes, min_entropy: float = 7.0) -> bool:
        """Verify key material has sufficient entropy"""
        if not data or len(data) < 16:
            return False
            
        entropy = CryptoTestUtils.calculate_entropy(data)
        return entropy >= min_entropy
    
    @staticmethod
    def generate_test_messages(count: int = 10, min_size: int = 1, max_size: int = 1024) -> List[bytes]:
        """Generate test messages of various sizes"""
        messages = []
        
        # Fixed test cases
        messages.append(b"Hello, world!")  # Simple ASCII
        messages.append(b"\x00" * 64)  # All zeros
        messages.append(b"\xff" * 64)  # All ones
        messages.append(b"a")  # Minimum size
        
        # Random messages of various sizes
        for i in range(count - len(messages)):
            size = min_size + int(os.urandom(2)[0] / 255 * (max_size - min_size))
            messages.append(os.urandom(size))
            
        return messages

class TestEnhancedFALCON1024(unittest.TestCase):
    """Test cases for EnhancedFALCON_1024"""
    
    def setUp(self):
        """Set up test environment"""
        self.enhanced_falcon = EnhancedFALCON_1024()
        self.base_falcon = FALCON_1024()
        self.test_messages = CryptoTestUtils.generate_test_messages()
        
    def test_version_info(self):
        """Test version information"""
        self.assertEqual(self.enhanced_falcon.version, 2, "Enhanced FALCON should be version 2")
        self.assertGreaterEqual(self.enhanced_falcon.tau, 1.28, "Enhanced FALCON should have tau >= 1.28")
        
    def test_key_generation(self):
        """Test key generation"""
        # Generate keys with enhanced implementation
        pk, sk = self.enhanced_falcon.keygen()
        
        # Verify key format
        self.assertTrue(pk.startswith(b"EFPK-"), "Enhanced public key should have EFPK- prefix")
        self.assertTrue(sk.startswith(b"EFSK-"), "Enhanced private key should have EFSK- prefix")
        
        # Verify key material
        self.assertTrue(len(pk) > 1000, f"Public key too short: {len(pk)} bytes")
        self.assertTrue(len(sk) > 1000, f"Private key too short: {len(sk)} bytes")
        
        # Extract core keys (without prefix)
        core_pk = pk[6:] if pk.startswith(b"EFPK-") else pk
        core_sk = sk[6:] if sk.startswith(b"EFSK-") else sk
        
        # Verify with base implementation
        test_message = b"Test message for verification"
        base_sig = self.base_falcon.sign(core_sk, test_message)
        self.assertTrue(
            self.base_falcon.verify(core_pk, test_message, base_sig),
            "Base implementation should verify signature from enhanced keys"
        )
        
    def test_sign_verify_cycle(self):
        """Test sign and verify cycle"""
        # Generate keys
        pk, sk = self.enhanced_falcon.keygen()
        
        for i, message in enumerate(self.test_messages):
            # Skip empty message as FALCON doesn't support it
            if len(message) == 0:
                continue
                
            # Sign with enhanced implementation
            signature = self.enhanced_falcon.sign(sk, message)
            
            # Verify signature format
            self.assertTrue(signature.startswith(b"EFS-"), 
                           f"Enhanced signature should have EFS- prefix, got: {signature[:10]}")
            
            # Verify with enhanced implementation
            self.assertTrue(
                self.enhanced_falcon.verify(pk, message, signature),
                f"Failed to verify signature for message {i}"
            )
            
    def test_cross_compatibility(self):
        """Test cross-compatibility between enhanced and base implementations"""
        # Generate keys with enhanced implementation
        enh_pk, enh_sk = self.enhanced_falcon.keygen()
        
        # Generate keys with base implementation
        base_pk, base_sk = self.base_falcon.keygen()
        
        test_message = b"Cross-compatibility test message"
        
        # Sign with enhanced, verify with base (after removing prefix)
        enh_sig = self.enhanced_falcon.sign(enh_sk, test_message)
        core_sig = enh_sig[5:] if enh_sig.startswith(b"EFS-") else enh_sig
        core_pk = enh_pk[6:] if enh_pk.startswith(b"EFPK-") else enh_pk
        
        self.assertTrue(
            self.base_falcon.verify(core_pk, test_message, core_sig),
            "Base implementation should verify signature from enhanced implementation"
        )
        
        # Sign with base, verify with enhanced
        base_sig = self.base_falcon.sign(base_sk, test_message)
        enh_sig_wrapped = b"EFS-2" + base_sig
        
        self.assertTrue(
            self.enhanced_falcon.verify(b"EFPK-2" + base_pk, test_message, enh_sig_wrapped),
            "Enhanced implementation should verify signature from base implementation"
        )
        
    def test_signature_entropy(self):
        """Test signature entropy"""
        pk, sk = self.enhanced_falcon.keygen()
        message = b"Test message for entropy verification"
        
        signature = self.enhanced_falcon.sign(sk, message)
        core_sig = signature[5:] if signature.startswith(b"EFS-") else signature
        
        # Calculate entropy of signature
        entropy = CryptoTestUtils.calculate_entropy(core_sig)
        
        self.assertGreaterEqual(entropy, 7.0, 
                               f"Signature entropy should be >= 7.0 bits/byte, got {entropy:.2f}")
        
    def test_tamper_resistance(self):
        """Test resistance to signature tampering"""
        pk, sk = self.enhanced_falcon.keygen()
        message = b"Test message for tamper resistance"
        
        signature = self.enhanced_falcon.sign(sk, message)
        
        # Tamper with the signature
        tampered_sig = bytearray(signature)
        # Modify a byte in the middle of the signature
        midpoint = len(tampered_sig) // 2
        tampered_sig[midpoint] = (tampered_sig[midpoint] + 1) % 256
        
        # Set test flag to indicate this is an expected verification failure
        log.info("===== EXPECTED VERIFICATION FAILURE TEST - TAMPERED SIGNATURE =====")
        # Verify should fail
        self.assertFalse(
            self.enhanced_falcon.verify(pk, message, bytes(tampered_sig)),
            "Verification should fail with tampered signature"
        )
        log.info("===== END EXPECTED VERIFICATION FAILURE TEST =====")
        
        # Tamper with the message
        tampered_msg = bytearray(message)
        if tampered_msg:
            tampered_msg[0] = (tampered_msg[0] + 1) % 256
            
            log.info("===== EXPECTED VERIFICATION FAILURE TEST - TAMPERED MESSAGE =====")
            self.assertFalse(
                self.enhanced_falcon.verify(pk, bytes(tampered_msg), signature),
                "Verification should fail with tampered message"
            )
            log.info("===== END EXPECTED VERIFICATION FAILURE TEST =====")
            
    def test_performance(self):
        """Test performance comparison"""
        test_message = b"Performance test message" * 10
        
        # Generate keys
        _, enh_keygen_time = CryptoTestUtils.measure_execution_time(self.enhanced_falcon.keygen)
        enh_pk, enh_sk = self.enhanced_falcon.keygen()
        
        _, base_keygen_time = CryptoTestUtils.measure_execution_time(self.base_falcon.keygen)
        base_pk, base_sk = self.base_falcon.keygen()
        
        # Sign
        _, enh_sign_time = CryptoTestUtils.measure_execution_time(
            self.enhanced_falcon.sign, enh_sk, test_message
        )
        enh_sig = self.enhanced_falcon.sign(enh_sk, test_message)
        
        _, base_sign_time = CryptoTestUtils.measure_execution_time(
            self.base_falcon.sign, base_sk, test_message
        )
        base_sig = self.base_falcon.sign(base_sk, test_message)
        
        # Verify
        _, enh_verify_time = CryptoTestUtils.measure_execution_time(
            self.enhanced_falcon.verify, enh_pk, test_message, enh_sig
        )
        
        _, base_verify_time = CryptoTestUtils.measure_execution_time(
            self.base_falcon.verify, base_pk, test_message, base_sig
        )
        
        # Log performance comparison
        log.info(f"FALCON-1024 Key Generation: Enhanced: {enh_keygen_time:.6f}s, Base: {base_keygen_time:.6f}s")
        log.info(f"FALCON-1024 Signing: Enhanced: {enh_sign_time:.6f}s, Base: {base_sign_time:.6f}s")
        log.info(f"FALCON-1024 Verification: Enhanced: {enh_verify_time:.6f}s, Base: {base_verify_time:.6f}s")
        
        # Performance assertions
        # Allow for some overhead due to enhanced security features
        self.assertLess(enh_keygen_time / base_keygen_time, 2.0,
                       "Enhanced key generation should not be more than 100% slower")
        self.assertLess(enh_sign_time / base_sign_time, 2.0,
                       "Enhanced signing should not be more than 100% slower")
        self.assertLess(enh_verify_time / base_verify_time, 2.0,
                       "Enhanced verification should not be more than 100% slower")

class TestEnhancedMLKEM1024(unittest.TestCase):
    """Test cases for EnhancedMLKEM_1024"""
    
    def setUp(self):
        """Set up test environment"""
        self.enhanced_mlkem = EnhancedMLKEM_1024()
        self.base_mlkem = MLKEM_1024()
        
    def test_key_generation(self):
        """Test key generation"""
        # Generate keys with enhanced implementation
        pk, sk = self.enhanced_mlkem.keygen()
        
        # Verify key format
        self.assertTrue(pk.startswith(b"EMKPK-"), "Enhanced public key should have EMKPK- prefix")
        self.assertTrue(sk.startswith(b"EMKSK-"), "Enhanced private key should have EMKSK- prefix")
        
        # Verify key material
        self.assertTrue(len(pk) > 1000, f"Public key too short: {len(pk)} bytes")
        self.assertTrue(len(sk) > 1000, f"Private key too short: {len(sk)} bytes")
        
    def test_encaps_decaps_cycle(self):
        """Test encapsulation and decapsulation cycle"""
        # Generate keys
        pk, sk = self.enhanced_mlkem.keygen()
        
        # Encapsulate
        ciphertext, shared_secret1 = self.enhanced_mlkem.encaps(pk)
        
        # Decapsulate
        shared_secret2 = self.enhanced_mlkem.decaps(sk, ciphertext)
        
        # Verify shared secrets match
        self.assertEqual(shared_secret1, shared_secret2, 
                        "Shared secrets from encaps and decaps should match")
        
        # Verify shared secret properties
        self.assertEqual(len(shared_secret1), 32, "Shared secret should be 32 bytes")
        
    def test_domain_separation(self):
        """Test domain separation in enhanced implementation"""
        # Generate keys with both implementations
        enh_pk, enh_sk = self.enhanced_mlkem.keygen()
        base_pk, base_sk = self.base_mlkem.keygen()
        
        # Extract core keys (without prefix)
        core_enh_pk = enh_pk[7:] if enh_pk.startswith(b"EMKPK-") else enh_pk
        core_enh_sk = enh_sk[7:] if enh_sk.startswith(b"EMKSK-") else enh_sk
        
        # Encapsulate with base implementation using enhanced key
        base_ct, base_ss = self.base_mlkem.encaps(core_enh_pk)
        
        # Encapsulate with enhanced implementation
        enh_ct, enh_ss = self.enhanced_mlkem.encaps(enh_pk)
        
        # The shared secrets should be different due to domain separation
        self.assertNotEqual(base_ss, enh_ss, 
                          "Enhanced shared secret should differ from base due to domain separation")
        
        # But the enhanced decapsulation should still work with the base ciphertext
        enh_ss_from_base_ct = self.enhanced_mlkem.decaps(enh_sk, base_ct)
        
        # The domain separation should be consistent but implementation might use 
        # different methods (HMAC vs hash)
        self.assertNotEqual(enh_ss_from_base_ct, base_ss, 
                          "Enhanced secret should differ from base secret")
        self.assertEqual(len(enh_ss_from_base_ct), 32,
                        "Enhanced shared secret should be 32 bytes")
        
    def test_tamper_resistance(self):
        """Test resistance to ciphertext tampering"""
        pk, sk = self.enhanced_mlkem.keygen()
        
        # Encapsulate
        ciphertext, shared_secret = self.enhanced_mlkem.encaps(pk)
        
        # Tamper with the ciphertext
        tampered_ct = bytearray(ciphertext)
        # Modify a byte in the middle of the ciphertext
        midpoint = len(tampered_ct) // 2
        tampered_ct[midpoint] = (tampered_ct[midpoint] + 1) % 256
        
        # Decapsulate with tampered ciphertext
        tampered_ss = self.enhanced_mlkem.decaps(sk, bytes(tampered_ct))
        
        # The shared secrets should be different
        self.assertNotEqual(shared_secret, tampered_ss, 
                          "Shared secret should differ with tampered ciphertext")
        
    def test_performance(self):
        """Test performance comparison"""
        # Generate keys
        _, enh_keygen_time = CryptoTestUtils.measure_execution_time(self.enhanced_mlkem.keygen)
        enh_pk, enh_sk = self.enhanced_mlkem.keygen()
        
        _, base_keygen_time = CryptoTestUtils.measure_execution_time(self.base_mlkem.keygen)
        base_pk, base_sk = self.base_mlkem.keygen()
        
        # Extract core keys (without prefix)
        core_enh_pk = enh_pk[7:] if enh_pk.startswith(b"EMKPK-") else enh_pk
        core_enh_sk = enh_sk[7:] if enh_sk.startswith(b"EMKSK-") else enh_sk
        
        # Encapsulate
        _, enh_encaps_time = CryptoTestUtils.measure_execution_time(
            self.enhanced_mlkem.encaps, enh_pk
        )
        enh_ct, _ = self.enhanced_mlkem.encaps(enh_pk)
        
        _, base_encaps_time = CryptoTestUtils.measure_execution_time(
            self.base_mlkem.encaps, core_enh_pk
        )
        base_ct, _ = self.base_mlkem.encaps(core_enh_pk)
        
        # Decapsulate
        _, enh_decaps_time = CryptoTestUtils.measure_execution_time(
            self.enhanced_mlkem.decaps, enh_sk, enh_ct
        )
        
        _, base_decaps_time = CryptoTestUtils.measure_execution_time(
            self.base_mlkem.decaps, core_enh_sk, base_ct
        )
        
        # Log performance comparison
        log.info(f"ML-KEM-1024 Key Generation: Enhanced: {enh_keygen_time:.6f}s, Base: {base_keygen_time:.6f}s")
        log.info(f"ML-KEM-1024 Encapsulation: Enhanced: {enh_encaps_time:.6f}s, Base: {base_encaps_time:.6f}s")
        log.info(f"ML-KEM-1024 Decapsulation: Enhanced: {enh_decaps_time:.6f}s, Base: {base_decaps_time:.6f}s")
        
        # The enhanced implementation might be slightly slower due to additional security checks
        self.assertLess(enh_keygen_time / base_keygen_time, 2.0,
                       "Enhanced key generation should not be more than 100% slower")
        # Allow encapsulation to be up to 2x slower due to domain separation and additional security checks
        self.assertLess(enh_encaps_time / base_encaps_time, 2.0, 
                       "Enhanced encapsulation should not be more than 100% slower")
        self.assertLess(enh_decaps_time / base_decaps_time, 1.5, 
                       "Enhanced decapsulation should not be more than 50% slower")

class TestIntegration(unittest.TestCase):
    """Integration tests for both algorithms together"""
    
    def setUp(self):
        """Set up test environment"""
        self.falcon = EnhancedFALCON_1024()
        self.mlkem = EnhancedMLKEM_1024()
        
    def test_hybrid_key_exchange(self):
        """Test hybrid key exchange with both algorithms"""
        # Generate ML-KEM keypairs for both parties
        alice_mlkem_pk, alice_mlkem_sk = self.mlkem.keygen()
        bob_mlkem_pk, bob_mlkem_sk = self.mlkem.keygen()
        
        # Generate FALCON keypairs for both parties
        alice_falcon_pk, alice_falcon_sk = self.falcon.keygen()
        bob_falcon_pk, bob_falcon_sk = self.falcon.keygen()
        
        # Bob encapsulates to Alice
        ciphertext_to_alice, bob_shared_secret = self.mlkem.encaps(alice_mlkem_pk)
        
        # Bob signs the ciphertext
        bob_signature = self.falcon.sign(bob_falcon_sk, ciphertext_to_alice)
        
        # Alice verifies Bob's signature
        self.assertTrue(
            self.falcon.verify(bob_falcon_pk, ciphertext_to_alice, bob_signature),
            "Alice should verify Bob's signature"
        )
        
        # Alice decapsulates to get the shared secret
        alice_shared_secret = self.mlkem.decaps(alice_mlkem_sk, ciphertext_to_alice)
        
        # Verify both parties have the same shared secret
        self.assertEqual(bob_shared_secret, alice_shared_secret,
                        "Both parties should derive the same shared secret")
        
        # Use the shared secret for symmetric encryption
        message = b"Secret message from Alice to Bob"
        
        # Simple XOR encryption for demonstration (not for production use)
        def xor_encrypt(key, data):
            # Expand key if needed
            while len(key) < len(data):
                key += hashlib.sha256(key).digest()
            return bytes(a ^ b for a, b in zip(data, key[:len(data)]))
        
        # Alice encrypts a message to Bob
        ciphertext = xor_encrypt(alice_shared_secret, message)
        
        # Bob decrypts the message
        decrypted = xor_encrypt(bob_shared_secret, ciphertext)
        
        # Verify decryption worked
        self.assertEqual(message, decrypted, "Bob should be able to decrypt Alice's message")

def main():
    """Main entry point"""
    # Add import path for math module if not already available
    if 'math' not in sys.modules:
        import math
    else:
        math = sys.modules['math']
        
    # Run tests
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

if __name__ == "__main__":
    main() 