"""
Secure Key Manager

Provides secure cryptographic key storage and management with multiple backends:
- OS-native secure storage (keyring)
- Filesystem storage with proper permissions
- Process isolation for sensitive operations
"""

import base64
import hashlib
import logging
import os
import platform
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
log = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import keyring
    HAVE_KEYRING = True
except ImportError:
    HAVE_KEYRING = False
    log.warning("keyring library not available, falling back to secure file storage")

try:
    import zmq
    HAVE_ZMQ = True
except ImportError:
    HAVE_ZMQ = False
    log.warning("pyzmq not available, process isolation not available")

# Constants
SERVICE_NAME = "secure_p2p_chat"
DEFAULT_SECURE_DIR = "secure_keys"

# Determine the best IPC path for the platform
if platform.system() != "Windows":
    IPC_PATH = "ipc:///tmp/secure_key_manager"
else:
    IPC_PATH = None  # Will be set during initialization

class KeyProtectionError(Exception):
    """Exception raised for key protection related errors."""
    pass

class SecureKeyManager:
    """Manages cryptographic keys with secure storage and access controls."""
    
    def __init__(self, app_name: str = SERVICE_NAME, secure_dir: Optional[str] = None):
        """
        Initialize the secure key manager.
        
        Args:
            app_name: Application name for keyring storage
            secure_dir: Directory for secure key storage (fallback)
        """
        self.app_name = app_name
        self.secure_dir = secure_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_SECURE_DIR)
        self.service_process = None
        self.socket = None
        
        # For Windows, find an available TCP port
        global IPC_PATH
        if platform.system() == "Windows" and IPC_PATH is None:
            IPC_PATH = self._find_available_tcp_port()
            log.info(f"Using TCP socket at {IPC_PATH}")
        
        self._initialize_storage()
        self.hw_security_available = self._initialize_hardware_security()
        
        if HAVE_ZMQ and not self._check_service_running():
            self._start_key_service()
    
    def _find_available_tcp_port(self) -> str:
        """Find an available TCP port for the key service on Windows."""
        if not HAVE_ZMQ:
            return "tcp://127.0.0.1:5555"  # Fallback
            
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REP)
            port = socket.bind_to_random_port("tcp://127.0.0.1", min_port=49152, max_port=65535)
            socket.unbind(f"tcp://127.0.0.1:{port}")
            socket.close()
            context.term()
            return f"tcp://127.0.0.1:{port}"
        except Exception as e:
            log.warning(f"Error finding available port: {e}")
            return "tcp://127.0.0.1:55555"
    
    def _initialize_storage(self) -> bool:
        """Initialize secure storage directory if using filesystem storage."""
        try:
            os.makedirs(self.secure_dir, mode=0o700, exist_ok=True)
            
            if os.name == 'posix':
                os.chmod(self.secure_dir, stat.S_IRWXU)  # 0700 - owner read/write/execute
            
            return True
        except Exception as e:
            log.error(f"Failed to initialize secure storage: {e}")
            return False
    
    def _initialize_hardware_security(self) -> bool:
        """Try to initialize hardware security (TPM/HSM)."""
        # Placeholder for hardware security implementation
        return False
    
    def _check_service_running(self) -> bool:
        """Check if the key management service is already running."""
        if not HAVE_ZMQ:
            return False
        
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REQ)
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
            socket.connect(IPC_PATH)
            socket.send_string("PING")
            response = socket.recv_string()
            socket.close()
            context.term()
            return response == "PONG"
        except zmq.error.Again:
            log.debug("Timeout waiting for key service response")
            return False
        except Exception as e:
            log.debug(f"Error checking if service is running: {e}")
            return False
    
    def _start_key_service(self):
        """Start the key management service in a separate process."""
        if not HAVE_ZMQ:
            return
        
        try:
            service_script = self._create_service_script()
            log.info(f"Starting key service at {IPC_PATH}")
            
            if platform.system() == "Windows":
                try:
                    self.service_process = subprocess.Popen(
                        ["python", service_script],
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    threading.Timer(0.5, self._verify_service).start()
                    threading.Timer(2.0, self._verify_service).start()
                except Exception as e:
                    log.error(f"Failed to start key service on Windows: {e}")
            else:
                self.service_process = subprocess.Popen(
                    ["python", service_script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                threading.Timer(0.5, self._verify_service).start()
            
        except Exception as e:
            log.error(f"Failed to start key service: {e}", exc_info=True)
    
    def _create_service_script(self) -> str:
        """Create a temporary script for the key service."""
        fd, path = tempfile.mkstemp(suffix='.py')
        
        # Fix Windows path escaping
        safe_secure_dir = self.secure_dir.replace('\\', '/')
        
        with os.fdopen(fd, 'w') as f:
            f.write('''
import os
import zmq
import logging
import sys
import signal
import base64
import hashlib
import uuid
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
log = logging.getLogger("key_service")

# Service configuration
SERVICE_NAME = "{app_name}"
IPC_PATH = "{ipc_path}"
SECURE_DIR = "{secure_dir}"

# Try to import keyring
try:
    import keyring
    HAVE_KEYRING = True
except ImportError:
    HAVE_KEYRING = False

class KeyService:
    def __init__(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        self.socket.bind(IPC_PATH)
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        
        log.info(f"Key service started on {{IPC_PATH}}")
    
    def handle_shutdown(self, *args):
        log.info("Shutting down key service...")
        self.running = False
    
    def secure_store(self, key_id, key_data):
        if HAVE_KEYRING:
            try:
                keyring.set_password(SERVICE_NAME, key_id, key_data)
                return True
            except Exception as e:
                log.error(f"Keyring storage failed: {{e}}")
        
        try:
            key_path = os.path.join(SECURE_DIR, f"{{key_id}}.key")
            os.makedirs(SECURE_DIR, mode=0o700, exist_ok=True)
            
            with open(key_path, 'w') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_path, 0o600)  # Owner read/write only
            
            return True
        except Exception as e:
            log.error(f"File storage failed: {{e}}")
            return False
    
    def secure_retrieve(self, key_id):
        if HAVE_KEYRING:
            try:
                key_data = keyring.get_password(SERVICE_NAME, key_id)
                if key_data:
                    return key_data
            except Exception as e:
                log.error(f"Keyring retrieval failed: {{e}}")
        
        try:
            key_path = os.path.join(SECURE_DIR, f"{{key_id}}.key")
            if os.path.exists(key_path):
                with open(key_path, 'r') as f:
                    return f.read()
        except Exception as e:
            log.error(f"File retrieval failed: {{e}}")
        
        return None
    
    def run(self):
        while self.running:
            try:
                message = self.socket.recv_string()
                parts = message.split(":", 1)
                command = parts[0]
                
                if command == "PING":
                    self.socket.send_string("PONG")
                
                elif command == "STORE":
                    if len(parts) < 2:
                        self.socket.send_string("ERROR:Invalid command format")
                        continue
                    
                    data_parts = parts[1].split(":", 1)
                    if len(data_parts) < 2:
                        self.socket.send_string("ERROR:Invalid data format")
                        continue
                    
                    key_id, key_data = data_parts
                    success = self.secure_store(key_id, key_data)
                    
                    if success:
                        self.socket.send_string(f"SUCCESS:{{key_id}}")
                    else:
                        self.socket.send_string("ERROR:Storage failed")
                
                elif command == "RETRIEVE":
                    if len(parts) < 2:
                        self.socket.send_string("ERROR:Invalid command format")
                        continue
                    
                    key_id = parts[1]
                    key_data = self.secure_retrieve(key_id)
                    
                    if key_data:
                        self.socket.send_string(f"DATA:{{key_data}}")
                    else:
                        self.socket.send_string("ERROR:Key not found")
                
                elif command == "DELETE":
                    if len(parts) < 2:
                        self.socket.send_string("ERROR:Invalid command format")
                        continue
                    
                    key_id = parts[1]
                    
                    if HAVE_KEYRING:
                        try:
                            keyring.delete_password(SERVICE_NAME, key_id)
                        except:
                            pass
                    
                    try:
                        key_path = os.path.join(SECURE_DIR, f"{{key_id}}.key")
                        if os.path.exists(key_path):
                            os.remove(key_path)
                    except:
                        pass
                    
                    self.socket.send_string(f"SUCCESS:{{key_id}}")
                
                else:
                    self.socket.send_string("ERROR:Unknown command")
            
            except zmq.Again:
                continue
            except Exception as e:
                log.error(f"Error processing request: {{e}}")
                try:
                    self.socket.send_string(f"ERROR:{{str(e)}}")
                except:
                    pass
        
        self.socket.close()
        self.context.term()
        log.info("Key service shutdown complete")

if __name__ == "__main__":
    service = KeyService()
    service.run()
'''.format(app_name=self.app_name, ipc_path=IPC_PATH, secure_dir=safe_secure_dir))
        return path
    
    def _verify_service(self):
        """Verify the key service is running."""
        if self._check_service_running():
            log.info("Key service started successfully")
        else:
            if self.service_process:
                if self.service_process.poll() is not None:
                    return_code = self.service_process.returncode
                    stderr = self.service_process.stderr.read().decode('utf-8', errors='replace') if self.service_process.stderr else ""
                    stdout = self.service_process.stdout.read().decode('utf-8', errors='replace') if self.service_process.stdout else ""
                    
                    log.warning(f"Key service process terminated with return code {return_code}")
                    if stderr:
                        log.warning(f"Service stderr: {stderr.strip()}")
                    if stdout:
                        log.debug(f"Service stdout: {stdout.strip()}")
                else:
                    log.warning("Key service process is running but not responding")
            else:
                log.warning("Key service failed to start")
    
    def _connect_to_service(self):
        """Connect to the key management service."""
        if not HAVE_ZMQ:
            return False
        
        if self.socket is not None:
            return True
        
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REQ)
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVTIMEO, 1000)
            socket.connect(IPC_PATH)
            
            socket.send_string("PING")
            response = socket.recv_string()
            
            if response == "PONG":
                self.socket = socket
                self.context = context
                return True
            else:
                socket.close()
                context.term()
                return False
        except zmq.error.Again:
            log.debug("Timeout connecting to key service")
            socket.close()
            context.term()
            return False
        except Exception as e:
            log.debug(f"Failed to connect to key service: {e}")
            try:
                socket.close()
                context.term()
            except:
                pass
            return False
    
    def store_key(self, key_material: Union[bytes, str], key_name: str) -> bool:
        """
        Store a cryptographic key securely.
        
        Args:
            key_material: The key material to store
            key_name: Unique name for the key
            
        Returns:
            bool: True if storage succeeded, False otherwise
        """
        if isinstance(key_material, bytes):
            key_data = base64.b64encode(key_material).decode('utf-8')
        else:
            key_data = key_material
        
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"STORE:{key_name}:{key_data}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} stored securely via service")
                    return True
                else:
                    log.warning(f"Service failed to store key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        try:
            if HAVE_KEYRING:
                keyring.set_password(self.app_name, key_name, key_data)
                log.info(f"Key {key_name} stored in OS keyring")
                return True
            
            key_path = os.path.join(self.secure_dir, f"{key_name}.key")
            
            with open(key_path, 'w') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            
            log.info(f"Key {key_name} stored in file: {key_path}")
            return True
            
        except Exception as e:
            log.error(f"Failed to store key {key_name}: {e}")
            return False
    
    def retrieve_key(self, key_name: str, as_bytes: bool = True) -> Optional[Union[bytes, str]]:
        """
        Retrieve a stored cryptographic key.
        
        Args:
            key_name: Name of the key to retrieve
            as_bytes: If True, return bytes; otherwise, return string
            
        Returns:
            Optional[Union[bytes, str]]: The key material or None if not found
        """
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"RETRIEVE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("DATA:"):
                    key_data = response[5:]
                    if as_bytes:
                        return base64.b64decode(key_data)
                    return key_data
                else:
                    log.warning(f"Service failed to retrieve key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        try:
            if HAVE_KEYRING:
                key_data = keyring.get_password(self.app_name, key_name)
                if key_data:
                    log.debug(f"Key {key_name} retrieved from OS keyring")
                    if as_bytes:
                        return base64.b64decode(key_data)
                    return key_data
            
            key_path = os.path.join(self.secure_dir, f"{key_name}.key")
            if os.path.exists(key_path):
                with open(key_path, 'r') as f:
                    key_data = f.read()
                
                log.debug(f"Key {key_name} retrieved from file")
                if as_bytes:
                    return base64.b64decode(key_data)
                return key_data
            
            log.warning(f"Key {key_name} not found")
            return None
            
        except Exception as e:
            log.error(f"Failed to retrieve key {key_name}: {e}")
            return None
    
    def delete_key(self, key_name: str) -> bool:
        """
        Delete a stored cryptographic key.
        
        Args:
            key_name: Name of the key to delete
            
        Returns:
            bool: True if deletion succeeded, False otherwise
        """
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"DELETE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} deleted via service")
                    return True
                else:
                    log.warning(f"Service failed to delete key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        success = True
        
        if HAVE_KEYRING:
            try:
                keyring.delete_password(self.app_name, key_name)
                log.debug(f"Key {key_name} deleted from OS keyring")
            except Exception as e:
                log.debug(f"Could not delete from keyring: {e}")
                success = False
        
        try:
            key_path = os.path.join(self.secure_dir, f"{key_name}.key")
            if os.path.exists(key_path):
                os.remove(key_path)
                log.debug(f"Key {key_name} deleted from file")
        except Exception as e:
            log.debug(f"Could not delete key file: {e}")
            success = False
        
        return success
    
    def verify_storage(self) -> bool:
        """
        Verify that the key storage is properly configured and secure.
        
        Returns:
            bool: True if storage is secure, False otherwise
        """
        if HAVE_KEYRING:
            try:
                test_key = f"test_key_{os.urandom(4).hex()}"
                test_data = f"test_data_{os.urandom(8).hex()}"
                
                keyring.set_password(self.app_name, test_key, test_data)
                retrieved = keyring.get_password(self.app_name, test_key)
                
                if retrieved == test_data:
                    keyring.delete_password(self.app_name, test_key)
                    log.info("OS keyring storage verified")
                    return True
            except Exception as e:
                log.warning(f"OS keyring verification failed: {e}")
        
        try:
            if not os.path.exists(self.secure_dir):
                log.warning("Secure keys directory does not exist")
                return False
            
            if os.name == 'posix':
                dir_stat = os.stat(self.secure_dir)
                if dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    log.warning("SECURITY ALERT: Secure keys directory has loose permissions")
                    return False
            
            test_file = os.path.join(self.secure_dir, f".test_write_{os.urandom(4).hex()}")
            with open(test_file, 'w') as f:
                f.write("test")
            
            if os.name == 'posix':
                file_stat = os.stat(test_file)
                if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    log.warning("SECURITY ALERT: Test file has loose permissions")
                    os.remove(test_file)
                    return False
            
            os.remove(test_file)
            
            log.info("File storage verified")
            return True
            
        except Exception as e:
            log.error(f"Storage verification failed: {e}")
            return False
    
    def cleanup(self):
        """Clean up resources when finished."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        if hasattr(self, 'context') and self.context:
            try:
                self.context.term()
            except:
                pass
            self.context = None
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()


# Singleton instance for global use
_key_manager_instance = None

def get_key_manager() -> SecureKeyManager:
    """Get the global key manager instance."""
    global _key_manager_instance
    if _key_manager_instance is None:
        _key_manager_instance = SecureKeyManager()
    return _key_manager_instance


# Module-level API for simplified access

def store_key(key_material: Union[bytes, str], key_name: str) -> bool:
    """Store a cryptographic key securely."""
    return get_key_manager().store_key(key_material, key_name)

def retrieve_key(key_name: str, as_bytes: bool = True) -> Optional[Union[bytes, str]]:
    """Retrieve a stored cryptographic key."""
    return get_key_manager().retrieve_key(key_name, as_bytes)

def delete_key(key_name: str) -> bool:
    """Delete a stored cryptographic key."""
    return get_key_manager().delete_key(key_name)

def verify_storage() -> bool:
    """Verify that the key storage is properly configured and secure."""
    return get_key_manager().verify_storage()

def cleanup():
    """Clean up resources when finished."""
    if _key_manager_instance:
        _key_manager_instance.cleanup()

# Cleanup on exit
import atexit

atexit.register(cleanup) 
