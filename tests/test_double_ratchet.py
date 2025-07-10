#!/usr/bin/env python3
# test_double_ratchet.py - Test script for double ratchet initialization and security flow

import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_p2p import SecureP2PChat

def test_double_ratchet_security_flow():
    """Test double ratchet security flow initialization and access"""
    print("Starting double ratchet security flow test...")
    
    # Configure logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
    
    # Create SecureP2PChat instance
    try:
        print("Creating SecureP2PChat instance...")
        chat = SecureP2PChat()
        
        # Verify security_flow initialized properly
        print(f"security_flow initialized: {hasattr(chat, 'security_flow')}")
        print(f"double_ratchet entry exists: {'double_ratchet' in chat.security_flow}")
        
        # Access the double_ratchet entry that was previously causing KeyError
        try:
            status = chat.security_flow['double_ratchet']['status'] 
            print(f"Successfully accessed double_ratchet status: {status}")
        except KeyError as e:
            print(f"ERROR: KeyError still exists: {e}")
            return False
        
        # Simulate the critical line that was failing
        try:
            # This line simulates the update in _exchange_hybrid_keys_client
            chat.security_flow['double_ratchet']['status'] = True
            print("Successfully updated double_ratchet status to True")
        except KeyError as e:
            print(f"ERROR: KeyError when updating status: {e}")
            return False
        
        print(f"security_flow after update: {chat.security_flow}")
        return True
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_double_ratchet_security_flow()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")
    sys.exit(0 if success else 1) 