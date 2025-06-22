#!/usr/bin/env python3
"""
Test script for the dep_impl.py module.
"""

import logging
import sys
import platform
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("test_dep_impl")

print(f"Starting test_dep_impl.py on {platform.system()} {platform.version()}")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print("="*80)

# Import the module
print("Importing dep_impl module...")
import dep_impl
print("Import successful!")

def test_dep_implementation():
    """Test the DEP implementation."""
    print("\n=== Testing DEP Implementation ===")
    
    # Create DEP instance
    print("Creating EnhancedDEP instance...")
    dep = dep_impl.EnhancedDEP()
    
    # Check initial status
    print(f"Initial status: {dep.status()}")
    
    # Enable DEP
    print("Enabling DEP...")
    success = dep.enable_dep()
    
    # Check final status
    print(f"DEP enabled: {success}")
    print(f"Final status: {dep.status()}")
    
    # Test memory protection
    print("\n=== Testing Memory Protection ===")
    if dep.is_windows:
        # Allocate protected memory
        print("Allocating protected memory...")
        address, region_id = dep.allocate_protected_memory(1024, executable=False)
        
        if address and region_id:
            print(f"Allocated memory at {address:#x} with region ID: {region_id}")
            
            # Test marking as executable
            print("Marking memory as executable...")
            exec_result = dep.mark_as_executable(region_id)
            print(f"Mark as executable result: {exec_result}")
            
            # Test marking as non-executable
            print("Marking memory as non-executable...")
            nonexec_result = dep.mark_as_non_executable(region_id)
            print(f"Mark as non-executable result: {nonexec_result}")
            
            # Free the memory
            print("Freeing memory...")
            free_result = dep.free_memory(region_id)
            print(f"Memory freed: {free_result}")
        else:
            print("Failed to allocate protected memory")
    else:
        print("Skipping memory protection tests on non-Windows platform")
    
    print("\nDEP implementation test completed!")
    return success

def test_secure_memory_wiping():
    """Test the secure memory wiping functionality."""
    print("\n=== Testing Secure Memory Wiping ===")
    
    # Create DEP instance
    dep = dep_impl.EnhancedDEP()
    
    if not dep.is_windows:
        print("Skipping secure memory wiping tests on non-Windows platform")
        return
    
    # Check if RtlSecureZeroMemory is available
    print(f"RtlSecureZeroMemory available: {dep.RtlSecureZeroMemory is not None}")
    print(f"RtlSecureZeroMemory type: {type(dep.RtlSecureZeroMemory).__name__}")
    
    # Allocate memory to test wiping
    address, region_id = dep.allocate_protected_memory(1024, executable=False)
    
    if address and region_id:
        print(f"Allocated memory at {address:#x} with region ID: {region_id}")
        
        # Free memory (which should use secure wiping)
        print("Freeing memory with secure wiping...")
        free_result = dep.free_memory(region_id)
        print(f"Memory freed with secure wiping: {free_result}")
    else:
        print("Failed to allocate memory for wiping test")
    
    print("\nSecure memory wiping test completed!")

if __name__ == "__main__":
    print(f"Testing dep_impl.py on {dep_impl.platform.system()}")
    
    # Run the tests
    try:
        print("\n" + "="*40)
        print("TEST 1: DEP Implementation")
        print("="*40)
        dep_success = test_dep_implementation()
        
        print("\n" + "="*40)
        print("TEST 2: Secure Memory Wiping")
        print("="*40)
        test_secure_memory_wiping()
        
        print("\n" + "="*40)
        print("TEST SUMMARY")
        print("="*40)
        print(f"DEP Implementation Test: {'PASSED' if dep_success else 'FAILED'}")
        print("Secure Memory Wiping Test: COMPLETED")
        
        # Exit with appropriate status
        sys.exit(0 if dep_success else 1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 