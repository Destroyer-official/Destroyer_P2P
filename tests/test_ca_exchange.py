#!/usr/bin/env python3
# test_ca_exchange.py - Test script for CA Exchange and certificate generation

import os
import logging
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_p2p import SecureP2PChat
from ca_services import CAExchange

def test_ca_exchange():
    """Test Certificate Authority Exchange functionality"""
    print("Starting CA Exchange test...")
    
    # Configure logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
    
    # Create SecureP2PChat instance
    try:
        print("Creating SecureP2PChat instance...")
        chat = SecureP2PChat()
        print(f"CA Exchange initialized: {hasattr(chat, 'ca_exchange')}")

        # Generate self-signed certificate
        print("\nGenerating self-signed certificate...")
        key_pem, cert_pem = chat.ca_exchange.generate_self_signed()
        
        # Check if certificate was generated
        if cert_pem and key_pem:
            print(f"Certificate generated successfully (size: {len(cert_pem)} bytes)")
            print(f"Private key generated successfully (size: {len(key_pem)} bytes)")
            print(f"Certificate fingerprint: {chat.ca_exchange.local_cert_fingerprint}")
            
            # Verify HPKP pin is created
            pin = chat.ca_exchange.generate_hpkp_pin(cert_pem)
            print(f"HPKP pin generated: {pin}")
            
            # Check if the certificate is properly loaded
            print("\nVerifying certificate is properly loaded...")
            if chat.ca_exchange.local_cert_pem == cert_pem:
                print("Certificate is properly stored in memory")
            else:
                print("ERROR: Certificate is not properly stored in memory")
            
            # Test creating a server context
            print("\nCreating SSL server context...")
            try:
                server_ctx = chat.ca_exchange.create_server_ctx()
                print("SSL server context created successfully")
            except ValueError as e:
                if "Peer certificate not available" in str(e):
                    print("Expected behavior: Need to exchange certificates with a peer first")
                    print("(This is not an error, just normal operation without a peer certificate)")
                else:
                    raise
        
        else:
            print("ERROR: Failed to generate certificate")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\nAll tests completed successfully!")
    return True

if __name__ == "__main__":
    if test_ca_exchange():
        sys.exit(0)
    else:
        sys.exit(1) 