#!/usr/bin/env python3
# test_server_startup.py - Test script for server startup with certificate generation

import asyncio
import logging
import sys
import signal
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_p2p import SecureP2PChat

async def test_server_startup():
    """Test server startup with certificate generation"""
    print("Starting server startup test...")
    
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
            print(f"Certificate fingerprint: {chat.ca_exchange.local_cert_fingerprint}")
            
            # Test server startup (without actually running it)
            print("\nPreparing for server startup...")
            
            # Create a future that will be resolved when the user presses Ctrl+C
            stop_future = asyncio.Future()
            
            # Set up signal handler for graceful shutdown
            def handle_sigint():
                if not stop_future.done():
                    stop_future.set_result(None)
            
            # Test starting the server (with a small timeout)
            print("Attempting server startup (will exit after 3 seconds)...")
            try:
                # Create a task that will exit after 3 seconds
                async def delayed_exit():
                    await asyncio.sleep(3)
                    if not stop_future.done():
                        stop_future.set_result(None)
                    return True
                    
                # Start both the delayed exit and chat start concurrently
                # The first one to complete will cancel the other
                exit_task = asyncio.create_task(delayed_exit())
                start_task = asyncio.create_task(chat.start())
                
                # Wait for any of the tasks to complete or stop_future to be resolved
                done, pending = await asyncio.wait(
                    [exit_task, start_task, stop_future],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Cancel any pending tasks
                for task in pending:
                    task.cancel()
                
                # Check the result
                if exit_task in done:
                    print("Server startup test completed successfully!")
                    return True
                elif start_task in done:
                    if start_task.exception():
                        print(f"Server startup failed: {start_task.exception()}")
                        return False
                    else:
                        print("Server startup completed!")
                        return True
                else:
                    print("Test was interrupted")
                    return False
                    
            except asyncio.CancelledError:
                print("Server startup test was cancelled")
                return False
            except Exception as e:
                print(f"Server startup test failed: {e}")
                return False
        else:
            print("ERROR: Failed to generate certificate")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\nAll tests completed successfully!")
    return True

if __name__ == "__main__":
    # Run the test
    asyncio.run(test_server_startup()) 