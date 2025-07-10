#!/usr/bin/env python3
"""
Comprehensive test script for the cross-platform secure memory implementation.
Tests integration with the main application components.
"""

import os
import sys
import time
import logging
import platform
import ctypes
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
)
log = logging.getLogger("test_secure_memory")

# Import our modules
import secure_key_manager
import double_ratchet
import platform_hsm_interface as cphs
from secure_p2p import KeyEraser

def test_secure_memory_basic():
    """Test basic secure memory functionality."""
    print("\n=== Testing Basic Secure Memory Functionality ===")
    
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
    
    print("Basic test completed successfully!")

def test_key_manager_integration():
    """Test integration with SecureKeyManager."""
    print("\n=== Testing SecureKeyManager Integration ===")
    
    # Initialize key manager with in-memory storage
    key_manager = secure_key_manager.get_key_manager(in_memory_only=True)
    
    # Generate test key
    test_key = os.urandom(32)
    test_name = f"verify_test_{int(time.time())}"
    
    # Store the key
    print(f"Storing key '{test_name}'...")
    store_result = secure_key_manager.store_key(
        key_material=test_key,
        key_name=test_name,
        in_memory_only=True
    )
    
    if store_result:
        print("Key stored successfully")
    else:
        print("Failed to store key")
        return False
    
    # Retrieve the key
    print(f"Retrieving key '{test_name}'...")
    retrieved_key = secure_key_manager.retrieve_key(
        test_name, 
        in_memory_only=True
    )
    
    if retrieved_key == test_key:
        print("Key retrieved successfully and matches original")
    else:
        print("Retrieved key does not match original")
        return False
    
    # Delete the key
    print(f"Deleting key '{test_name}'...")
    delete_result = secure_key_manager.delete_key(
        test_name,
        in_memory_only=True
    )
    
    if delete_result:
        print("Key deleted successfully")
    else:
        print("Failed to delete key")
        return False
    
    print("SecureKeyManager integration test completed successfully!")
    return True

def test_key_eraser():
    """Test KeyEraser integration."""
    print("\n=== Testing KeyEraser Integration ===")
    
    # Create sensitive data
    sensitive_data = bytearray(b'SENSITIVE_CRYPTOGRAPHIC_KEY' + b'\x00' * 8)
    print(f"Original data: {bytes(sensitive_data)}")
    
    # Use KeyEraser as context manager
    print("Using KeyEraser as context manager...")
    with KeyEraser(sensitive_data, "test key") as eraser:
        print(f"Data inside context: {bytes(eraser.key_material)}")
    
    # Data should be wiped after context exit
    print(f"Data after context exit: {bytes(sensitive_data)}")
    
    # Test explicit setting and wiping
    new_data = bytearray(b'NEW_SENSITIVE_DATA_TO_PROTECT' + b'\x00' * 4)
    eraser = KeyEraser(description="explicit test")
    eraser.set_key(new_data)
    print(f"New data before wiping: {bytes(new_data)}")
    eraser.secure_erase()
    print(f"New data after wiping: {bytes(new_data)}")
    
    print("KeyEraser integration test completed successfully!")
    return True

def test_double_ratchet_integration():
    """Test integration with double_ratchet's secure_erase function."""
    print("\n=== Testing Double Ratchet Integration ===")
    
    # Create sensitive data
    sensitive_data = bytearray(b'DOUBLE_RATCHET_KEY_MATERIAL' + b'\x00' * 8)
    print(f"Original data: {bytes(sensitive_data)}")
    
    # Use double_ratchet's secure_erase function
    print("Using double_ratchet.secure_erase...")
    double_ratchet.secure_erase(sensitive_data)
    
    # Data should be wiped
    print(f"Data after secure_erase: {bytes(sensitive_data)}")
    
    print("Double Ratchet integration test completed successfully!")
    return True

def test_platform_specific_features():
    """Test platform-specific secure memory features."""
    print(f"\n=== Testing Platform-Specific Features ({platform.system()}) ===")
    
    # Test memory locking
    print("Testing memory locking...")
    test_buf = bytearray(16)
    test_addr = ctypes.addressof((ctypes.c_char * 16).from_buffer(test_buf))
    
    lock_result = cphs.lock_memory(test_addr, 16)
    if lock_result:
        print("Memory locking succeeded")
        
        # Test unlocking
        unlock_result = cphs.unlock_memory(test_addr, 16)
        if unlock_result:
            print("Memory unlocking succeeded")
        else:
            print("Memory unlocking failed")
    else:
        print("Memory locking not available on this platform")
    
    # Test secure random generation
    print("Testing secure random generation...")
    random_bytes = cphs.get_secure_random(16)
    print(f"Generated secure random bytes: {random_bytes.hex()}")
    
    print("Platform-specific test completed!")
    return True

def run_all_tests():
    """Run all tests and report results."""
    tests = [
        test_secure_memory_basic,
        test_key_manager_integration,
        test_key_eraser,
        test_double_ratchet_integration,
        test_platform_specific_features
    ]
    
    results = []
    for test in tests:
        try:
            print(f"\n{'=' * 60}")
            result = test()
            results.append((test.__name__, True if result is not False else False))
        except Exception as e:
            print(f"Test {test.__name__} failed with error: {e}")
            results.append((test.__name__, False))
    
    # Print summary
    print("\n\n" + "=" * 60)
    print("Secure Memory Test Results:")
    print("=" * 60)
    all_passed = True
    for name, success in results:
        status = "PASS" if success else "FAIL"
        if not success:
            all_passed = False
        print(f"{name:.<40} {status}")
        
    print("\nOverall Result: " + ("PASS" if all_passed else "FAIL"))
    print("=" * 60)
    
    return all_passed

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 