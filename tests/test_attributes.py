#!/usr/bin/env python3
# test_attributes.py - Test for attribute initialization

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_p2p import SecureP2PChat

def test_attributes():
    """Test that all required attributes are correctly initialized"""
    print("Testing attribute initialization...")
    
    # Create SecureP2PChat instance
    chat = SecureP2PChat()
    
    # Check post_quantum_enabled attribute
    if hasattr(chat, 'post_quantum_enabled'):
        print(f"✓ post_quantum_enabled: {chat.post_quantum_enabled}")
    else:
        print("✗ post_quantum_enabled attribute not found!")
    
    # Check security_verified['secure_enclave'] key
    if 'secure_enclave' in chat.security_verified:
        print(f"✓ security_verified['secure_enclave']: {chat.security_verified['secure_enclave']}")
    else:
        print("✗ security_verified['secure_enclave'] key not found!")
        
    print("Test completed!")

if __name__ == "__main__":
    test_attributes() 