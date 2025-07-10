#!/usr/bin/env python3
"""
Test script for the cross-platform secure memory implementation.
"""

import sys
import os
import unittest
import ctypes
import gc
import platform

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secure_key_manager
import time
from secure_p2p import KeyEraser

def test_secure_memory():
    print("Testing cross-platform secure memory implementation...")
    
    # Get the secure memory instance
    mem = secure_key_manager.get_secure_memory()
    
    # Test allocation
    print("Allocating secure buffer...")
    buf = mem.allocate(32)
    print(f"Allocated buffer of {len(buf)} bytes")
    
    # Test writing data
    print("Writing sensitive data to buffer...")
    buf[:] = b'SECRET_DATA_TO_PROTECT' + b'\x00' * 12
    print(f"Buffer contains: {bytes(buf)}")
    
    # Test secure wiping
    print("Securely wiping buffer...")
    mem.wipe(buf)
    print(f"Buffer after wiping: {bytes(buf)}")
    
    print("Test completed successfully!")

class TestSecureMemoryWiping(unittest.TestCase):
    """Tests for secure memory wiping functionality to ensure sensitive data is properly erased."""
    
    def test_bytearray_wiping(self):
        """Test that bytearrays are properly wiped"""
        # Create test data
        test_data = bytearray(b"SENSITIVE_TEST_DATA_123456789")
        
        # Get memory address for checking after wiping
        addr = ctypes.addressof((ctypes.c_char * len(test_data)).from_buffer(test_data))
        
        # Ensure our test data is valid
        self.assertEqual(test_data, bytearray(b"SENSITIVE_TEST_DATA_123456789"))
        
        # Wipe the data
        secure_key_manager.secure_wipe_buffer(test_data)
        
        # Verify that test_data has been wiped
        self.assertEqual(len(test_data), 29)  # Length should be preserved
        for byte in test_data:
            self.assertEqual(byte, 0)  # All bytes should be zero
            
    def test_enhanced_secure_erase_bytearray(self):
        """Test that enhanced_secure_erase properly wipes bytearrays"""
        # Create test data
        test_data = bytearray(b"SENSITIVE_TEST_DATA_ENHANCED")
        
        # Wipe the data
        secure_key_manager.enhanced_secure_erase(test_data)
        
        # Verify that test_data has been wiped
        for byte in test_data:
            self.assertEqual(byte, 0)  # All bytes should be zero

    def test_key_eraser_bytearray(self):
        """Test that KeyEraser properly wipes bytearrays"""
        # Create test data
        test_data = bytearray(b"SENSITIVE_TEST_DATA_KEYERASER")
        
        # Use KeyEraser to manage the key
        with KeyEraser(test_data, "test key") as ke:
            # Data should be accessible during the context
            self.assertEqual(test_data, bytearray(b"SENSITIVE_TEST_DATA_KEYERASER"))
        
        # After the context exits, test_data should be wiped
        for byte in test_data:
            self.assertEqual(byte, 0)  # All bytes should be zero

    def test_immutable_bytes_best_effort(self):
        """Test that we make best effort to clear immutable bytes"""
        # Create test data - immutable bytes
        test_bytes = b"IMMUTABLE_BYTES_TEST_DATA"
        
        # Store a reference to original data
        original_bytes = test_bytes
        
        # Use KeyEraser to manage the key
        with KeyEraser(test_bytes, "immutable test bytes") as ke:
            # Data should be accessible during the context
            self.assertEqual(test_bytes, b"IMMUTABLE_BYTES_TEST_DATA")
        
        # After context, KeyEraser should have attempted to wipe test_bytes
        # But since it's immutable, we can only check that our reference is now None
        self.assertIsNone(ke.key_material)
        
        # We can't assert that original_bytes is wiped (because it's immutable)
        # But we can print a message about it for manual verification
        print(f"\nNote: Original immutable bytes still contain data: {original_bytes}")
        print("This is expected as Python strings and bytes are immutable")
        
    def test_convert_and_wipe_immutable(self):
        """Test the approach of converting immutable objects to bytearrays for wiping"""
        # Create test data - immutable bytes
        test_bytes = b"CONVERT_AND_WIPE_TEST"
        
        # Convert to bytearray which can be wiped
        test_bytearray = bytearray(test_bytes)
        
        # Wipe the bytearray
        secure_key_manager.secure_wipe_buffer(test_bytearray)
        
        # Verify the bytearray is wiped
        for byte in test_bytearray:
            self.assertEqual(byte, 0)
            
        # But the original bytes are unaffected
        self.assertEqual(test_bytes, b"CONVERT_AND_WIPE_TEST")

if __name__ == "__main__":
    test_secure_memory()
    unittest.main() 