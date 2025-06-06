"""
Secure Key Manager

Provides secure cryptographic key storage and management with multiple backends:
- OS-native secure storage (keyring)
- Filesystem storage with proper permissions
- Process isolation for sensitive operations
"""

import os
import stat
import base64
import logging
import hashlib
import sys
import tempfile
import platform
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, Union, Tuple

# Import the new cross-platform hardware security module
import platform_hsm_interface as cphs

# Import secure_erase for in-memory key wiping
from double_ratchet import secure_erase

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set root logger level to DEBUG for console output
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)] # Explicitly use stdout
)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG) # Ensure DEBUG messages from this module are processed

# Create a file handler for logging
try:
    # Attempt to create a log directory if it doesn't exist, relative to the script or CWD
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file_path = log_dir / "secure_key_manager.log"
except Exception as e_log_dir:
    # Fallback to current working directory if logs subdir fails
    log_file_path = Path("secure_key_manager.log")
    log.warning(f"Could not create logs directory, saving log to current directory: {log_file_path}. Error: {e_log_dir}")

file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
file_handler.setFormatter(formatter)
log.addHandler(file_handler)
# If other modules also add handlers to the root logger, this module's logs will also go there.
# To prevent duplicate console logging if root already has StreamHandler from elsewhere,
# we can set propagate to False, but for this module, it's fine to let it propagate.
# log.propagate = False

log.info(f"SecureKeyManager logging initialized. Console level: DEBUG, File level: DEBUG. Log file: {log_file_path.resolve()}")

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

try:
    import nacl.utils
    import nacl.secret
    from nacl.exceptions import CryptoError
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    log.warning("PyNaCl library not found; falling back to standard secure memory handling")

# Constants
SERVICE_NAME = "secure_p2p_chat"
DEFAULT_SECURE_DIR = "secure_keys"

# Determine the best IPC path for the platform
if platform.system() != "Windows":
    # This global IPC_PATH will be overridden by instance-specific paths for POSIX
    # or used as a default for Windows if not already set.
    IPC_PATH = "ipc:///tmp/secure_key_manager" 
else:
    IPC_PATH = None  # Will be set during initialization for Windows

class KeyProtectionError(Exception):
    """Exception raised for key protection related errors."""
    pass

class SecureMemory:
    """
    Secure memory handler using PyNaCl/libsodium for memory protection.
    
    PyNaCl provides access to libsodium's secure memory functions, which offer:
    1. Memory locking (pinning memory to prevent it from being swapped to disk)
    2. Memory protection against reads from other processes
    3. Secure memory wiping with multiple overwrite passes
    
    This class should be used for storing sensitive key material.
    """
    
    def __init__(self):
        """Initialize secure memory handler."""
        self.has_nacl = HAS_NACL
        if not self.has_nacl:
            log.warning("PyNaCl not available; using fallback memory protection")
    
    def allocate(self, size: int) -> bytearray:
        """
        Allocate secure memory of specified size.
        
        Args:
            size: Size of the secure memory buffer in bytes
            
        Returns:
            A secured bytearray
        """
        if self.has_nacl:
            try:
                # Use nacl.utils.sodium_malloc for secure memory allocation
                # This memory is locked (prevented from swapping) and protected
                secure_buffer = nacl.utils.sodium_malloc(size)
                log.debug(f"Allocated {size} bytes of secure memory using libsodium")
                return secure_buffer
            except Exception as e:
                log.warning(f"Failed to allocate secure memory with libsodium: {e}, falling back")
        
        # Fallback to regular bytearray
        buffer = bytearray(size)
        
        # Try to manually lock the memory
        try:
            buffer_addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
            if cphs.lock_memory(buffer_addr, size):
                log.debug(f"Manually locked {size} bytes of memory")
        except Exception as e:
            log.debug(f"Failed to manually lock memory: {e}")
            
        return buffer
    
    def secure_copy(self, data):
        """
        Create a secure copy of data in protected memory.
        
        Args:
            data: The data to copy (bytes, bytearray or str)
            
        Returns:
            A secure copy of the data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        secure_buffer = self.allocate(len(data))
        for i in range(len(data)):
            secure_buffer[i] = data[i]
            
        return secure_buffer
    
    def wipe(self, buffer):
        """
        Securely wipe a memory buffer.
        
        Args:
            buffer: The buffer to wipe
        """
        if self.has_nacl and hasattr(nacl.utils, 'sodium_free'):
            try:
                nacl.utils.sodium_free(buffer)
                log.debug(f"Securely wiped and freed memory using libsodium ({len(buffer)} bytes)")
                return
            except Exception as e:
                log.warning(f"Failed to sodium_free: {e}, using fallback wiping")
        
        # Fallback to secure_erase
        secure_erase(buffer)

# Create a global instance of SecureMemory
secure_memory = SecureMemory()

class SecureKeyManager:
    """Manages cryptographic keys with secure storage and access controls."""
    
    def __init__(self, app_name: str = SERVICE_NAME, secure_dir: Optional[str] = None, in_memory_only: bool = False):
        """
        Initialize the secure key manager.
        
        Args:
            app_name: Application name for keyring storage and path generation.
            secure_dir: Specific directory for secure key storage (overrides default).
            in_memory_only: If True, store keys only in memory (never on disk).
        """
        self.app_name = app_name
        self.service_process = None
        self.socket = None
        self.in_memory_only = in_memory_only
        self.context = None # Initialize ZMQ context attribute

        # In-memory key storage (if applicable)
        self.memory_keys = {}

        # Handle storage and IPC path initialization if not in-memory only
        if not self.in_memory_only:
            if secure_dir:
                self.secure_dir = Path(secure_dir).resolve() # Resolve to absolute path
                log.info(f"Using specified secure storage directory: {self.secure_dir}")
            else:
                self.secure_dir = self._get_default_secure_storage_path(self.app_name)
            
            # IPC_PATH handling:
            # For Windows, _find_available_tcp_port() determines the path.
            # For POSIX, _get_default_ipc_path() generates a unique path.
            # The global IPC_PATH is used as a fallback or for the service script,
            # but instance-specific paths are preferred.
            global IPC_PATH 
            if platform.system() == "Windows":
                # Only find a new port if IPC_PATH hasn't been set (e.g., by another instance)
                # This global IPC_PATH will be used by the service if it starts.
                if IPC_PATH is None: 
                    IPC_PATH = self._find_available_tcp_port()
                self.ipc_path = IPC_PATH # Instance uses the determined TCP path
                log.info(f"Key service IPC for Windows (TCP): {self.ipc_path}")
            else: # POSIX systems
                self.ipc_path = self._get_default_ipc_path(self.app_name)
                IPC_PATH = self.ipc_path # Update global for service script for this instance
                log.info(f"Key service IPC for POSIX (Unix Socket): {self.ipc_path}")

            self._initialize_storage() # Creates and secures self.secure_dir
            
        self.hw_security_available = self._initialize_hardware_security()
        
        # Start key service if ZMQ is available, not in-memory, and service not running
        if not self.in_memory_only and HAVE_ZMQ:
            if not self._check_service_running(): # _check_service_running will use self.ipc_path
                self._start_key_service() # _start_key_service will use self.ipc_path for script
            else:
                log.info(f"Key service already running at {self.ipc_path}")
            
        if self.in_memory_only:
            log.info("Using in-memory only mode for key storage. Keys will not be persisted.")

    def _get_default_secure_storage_path(self, app_name: str) -> Path:
        """
        Determines the OS-appropriate default secure storage path using app_name.
        Ensures the path is absolute and user-specific.
        """
        system = platform.system()
        if system == "Windows":
            # %LOCALAPPDATA% is the standard for user-specific non-roaming app data
            base_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        elif system == "Darwin": # macOS
            # ~/Library/Application Support is standard
            base_dir = Path.home() / "Library" / "Application Support"
        else: # Linux and other POSIX-like systems
            # Adheres to XDG Base Directory Specification if XDG_DATA_HOME is set
            base_dir = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        
        # Construct the full path: <base_dir>/<app_name>/secure_keys
        storage_path = base_dir / app_name / "secure_keys"
        log.info(f"Default secure storage path for '{app_name}': {storage_path}")
        return storage_path.resolve() # Return an absolute path

    def _get_default_ipc_path(self, app_name: str) -> str:
        """
        Generates an OS-appropriate, user-specific IPC socket path for POSIX systems.
        The path is based on XDG_RUNTIME_DIR or a fallback in /run/user/<uid> or /tmp.
        The parent directory for the socket is created with 0700 permissions.
        """
        if platform.system() == "Windows":
            # This method should not be called on Windows for IPC path generation.
            # Windows uses TCP sockets determined by _find_available_tcp_port.
            log.error("IPC path generation via _get_default_ipc_path is for POSIX systems only.")
            raise KeyProtectionError("IPC path generation for POSIX systems attempted on Windows.")

        # Prefer XDG_RUNTIME_DIR for user-specific temporary files like sockets
        xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
        if xdg_runtime_dir:
            ipc_base_dir = Path(xdg_runtime_dir) / app_name
        else:
            # Fallback to /run/user/<uid>/<app_name> if XDG_RUNTIME_DIR is not set
            # This is common on systems with systemd.
            uid = os.getuid()
            ipc_base_dir = Path(f"/run/user/{uid}") / app_name
            if not ipc_base_dir.parent.exists() or not os.access(ipc_base_dir.parent, os.W_OK):
                # If /run/user/<uid> is not available or writable, fallback to a /tmp location
                # This is less ideal but provides a working alternative.
                tmp_dir = Path(tempfile.gettempdir())
                ipc_base_dir = tmp_dir / f"{app_name}_ipc_{uid}"
                log.warning(f"XDG_RUNTIME_DIR or /run/user/{uid} not available/writable. Using temporary IPC directory: {ipc_base_dir}")

        try:
            os.makedirs(ipc_base_dir, mode=0o700, exist_ok=True)
            # On some systems, especially if SUDO_USER is involved, /run/user/<uid> 
            # might be owned by root initially. Chowning is a best effort.
            # Proper setup would involve the service manager (systemd) creating this directory.
            if "SUDO_UID" in os.environ and os.geteuid() == 0:
                try:
                    uid = int(os.environ["SUDO_UID"])
                    gid = int(os.environ.get("SUDO_GID", uid)) # Fallback GID to UID
                    os.chown(ipc_base_dir, uid, gid)
                    log.info(f"Changed ownership of IPC directory {ipc_base_dir} to UID/GID {uid}/{gid}")
                except Exception as e:
                    log.warning(f"Failed to change ownership of IPC directory {ipc_base_dir}: {e}")
        except OSError as e:
            # This might happen if even the /tmp fallback cannot be created, which is unlikely.
            log.error(f"Critical error: Could not create IPC directory {ipc_base_dir}: {e}. Process isolation might fail.")
            # As a last resort, use a path directly in /tmp (less secure for multi-user systems if perms are wrong)
            # but the socket itself should be protected by its own permissions if created correctly.
            ipc_base_dir = Path(tempfile.gettempdir()) / f"generic_ipc_{app_name}_{os.urandom(4).hex()}"
            os.makedirs(ipc_base_dir, mode=0o700, exist_ok=True) # Try one last time
            log.warning(f"Fallen back to less ideal IPC path in /tmp: {ipc_base_dir}")


        socket_path = ipc_base_dir / "secure_key_manager.sock"
        return f"ipc://{socket_path.resolve()}"
    
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
            # Using a less common port range for fallback
            return "tcp://127.0.0.1:55559" 
    
    def _initialize_storage(self) -> bool:
        """Initialize secure storage directory if using filesystem storage."""
        try:
            # self.secure_dir is already a Path object and resolved
            os.makedirs(self.secure_dir, mode=0o700, exist_ok=True)
            log.info(f"Secure storage directory ensured/created at {self.secure_dir}")
            
            # On POSIX, explicitly set directory permissions to 0700 (owner rwx, no group/other)
            if os.name == 'posix':
                current_mode = stat.S_IMODE(os.stat(self.secure_dir).st_mode)
                if current_mode != 0o700:
                    os.chmod(self.secure_dir, stat.S_IRWXU)
                    log.info(f"Set permissions for {self.secure_dir} to 0700")
            
            return True
        except Exception as e:
            log.error(f"Failed to initialize secure storage at {self.secure_dir}: {e}")
            return False
    
    def _initialize_hardware_security(self) -> bool:
        """Initialize hardware security module for key protection if available."""
        try:
            import platform_hsm_interface as cphs
            
            # Check for Windows TPM via CNG
            tpm_available = False
            if cphs.IS_WINDOWS and cphs._WINDOWS_CNG_NCRYPT_AVAILABLE:
                if cphs._open_cng_provider_platform():
                    tpm_available = True
                    log.info("Hardware security (TPM via Windows CNG) initialized successfully")
                    
                    # We could further check TPM capabilities here
                    attestation = cphs.attest_device()
                    if attestation and len(attestation.get("checks", [])) > 0:
                        for check in attestation["checks"]:
                            if check.get("type") == "Win32_Tpm_Query" and check.get("status") == "Found":
                                if check.get("IsEnabled") and check.get("IsActivated"):
                                    log.info("Windows TPM is enabled and activated")
            
            # Check for Linux TPM
            elif cphs.IS_LINUX and cphs._Linux_ESAPI is not None:
                tpm_available = True
                log.info("Hardware security (TPM via tpm2-pytss) initialized successfully")
            
            # Check for PKCS#11 HSM support
            if cphs._PKCS11_SUPPORT_AVAILABLE:
                # Try to initialize HSM with environment variables
                if cphs.init_hsm():
                    tpm_available = True
                    log.info("Hardware security (PKCS#11 HSM) initialized successfully")
            
            if tpm_available:
                # Further log specific TPM details if needed, e.g., cphs.get_windows_tpm_info() or cphs.get_linux_tpm_info()
                return True
            
            log.warning("Hardware security (TPM/HSM) not detected or not fully configured by platform_hsm_interface module. "
                        "Keys are protected by OS-level keyring (if available) and filesystem permissions only.")
            return False
            
        except ImportError:
            log.warning("platform_hsm_interface module not available. Hardware security features disabled.")
            return False
        except Exception as e:
            log.error(f"Error initializing hardware security: {e}")
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
            
            current_ipc_path = getattr(self, 'ipc_path', IPC_PATH) # Use instance specific IPC path if available
            socket.connect(current_ipc_path)
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
            log.warning("Cannot start key service: pyzmq library is not available.")
            return
        
        service_script_path = None
        try:
            service_script_path = self._create_service_script() # This uses self.ipc_path
            log.info(f"Starting key service using script {service_script_path} with IPC at {self.ipc_path}")
            
            # Common Popen arguments
            popen_args = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE
            }
            if platform.system() == "Windows":
                popen_args["creationflags"] = subprocess.CREATE_NO_WINDOW
            
            self.service_process = subprocess.Popen(
                [sys.executable, service_script_path], # Use sys.executable for portability
                **popen_args
            )
            
            # Schedule verification checks
            threading.Timer(0.5, self._verify_service).start()
            threading.Timer(2.0, self._verify_service).start()
            
        except Exception as e:
            log.error(f"Failed to start key service: {e}", exc_info=True)
        finally:
            # Clean up the temporary script file if it was created and Popen failed early
            # If Popen succeeded, the service itself might delete it or it can be cleaned up later.
            # For simplicity, we might leave it for OS to clean /tmp or handle on service shutdown.
            # However, explicit deletion is better if service fails to start.
            if self.service_process is None and service_script_path and os.path.exists(service_script_path):
                try:
                    # os.remove(service_script_path) # Temporarily disabled for debugging service script
                    log.debug(f"Cleaned up temporary service script: {service_script_path}")
                except OSError as e_remove:
                    log.warning(f"Could not remove temporary service script {service_script_path}: {e_remove}")

    
    def _create_service_script(self) -> str:
        """Create a temporary script for the key service."""
        # self.secure_dir is a Path object
        safe_secure_dir = str(self.secure_dir.resolve()).replace('\\', '/')
        # self.ipc_path is instance specific
        script_ipc_path = self.ipc_path 

        # Using NamedTemporaryFile for better security and auto-cleanup (mostly on POSIX)
        # delete=False is used because the file needs to exist for Popen to execute it.
        # The caller (_start_key_service) or the service itself should handle deletion.
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                script_path = f.name
                f.write('''
import os
import zmq
import logging
import sys
import signal
import base64
import hashlib # Not used in service script, but kept for now
import uuid # Not used in service script, but kept for now
from pathlib import Path

# Configure logging for the service
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [KeyService:%(lineno)d] %(message)s')
log = logging.getLogger("key_service")

# Service configuration (passed via string formatting from SecureKeyManager)
SERVICE_APP_NAME = "{app_name}" 
IPC_PATH = "{ipc_path}"
SECURE_DIR_PATH = "{secure_dir}" # Renamed to avoid conflict with os.mkdir

# Try to import keyring (dependency for the service)
try:
    import keyring
    HAVE_KEYRING = True
    # Specific keyring errors if needed
    from keyring.errors import NoKeyringError, PasswordDeleteError
except ImportError:
    HAVE_KEYRING = False
    NoKeyringError = None # Define for except blocks
    PasswordDeleteError = None # Define for except blocks
    log.warning("Keyring library not found in service process. OS keyring backend disabled.")

class KeyService:
    def __init__(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        try:
            self.socket.bind(IPC_PATH)
        except zmq.error.ZMQError as e_bind:
            log.error(f"KeyService CRITICAL: Could not bind to IPC_PATH '{{IPC_PATH}}'. Error: {{e_bind}}")
            # Attempt to clean up socket/context before exiting to avoid resource leaks
            self.socket.close()
            self.context.term()
            sys.exit(1) # Critical failure, service cannot run

        self.running = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        # On Windows, SIGBREAK might be relevant if started from console
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, self.handle_shutdown)

        log.info(f"Key service initialized. Listening on {{IPC_PATH}} for app '{{SERVICE_APP_NAME}}'. Storing keys in {{SECURE_DIR_PATH}}.")
    
    def handle_shutdown(self, signum, frame):
        log.info(f"Shutdown signal {{signum}} received. Stopping key service...")
        self.running = False
    
    def secure_store(self, key_id, key_data):
        if HAVE_KEYRING:
            try:
                # Get keyring backend name for logging, handle potential errors if get_keyring() is None
                keyring_backend_name = "Unknown"
                if keyring.get_keyring():
                    keyring_backend_name = keyring.get_keyring().__class__.__name__
                
                log.warning(f"SECURITY NOTICE (KeyService): Storing key \'{{key_id}}\' in OS keyring for app \'{{SERVICE_APP_NAME}}\'. \"\n                            f"Backend: {{keyring_backend_name}}. \"\n                            "OS keyring security depends on user account security. Consider implications if account is compromised.")\n                keyring.set_password(SERVICE_APP_NAME, key_id, key_data)\n                log.debug(f"Key \'{{key_id}}\' stored in OS keyring for \'{{SERVICE_APP_NAME}}\'.")\n                return True\n            except NoKeyringError:\n                log.warning("No OS keyring backend found for key storage.")
            except Exception as e_keyring_set:
                log.error(f"Keyring storage failed for key '{{key_id}}': {{e_keyring_set}}")
        
        # Fallback to file storage
        try:
            secure_dir = Path(SECURE_DIR_PATH)
            os.makedirs(secure_dir, mode=0o700, exist_ok=True)
            key_file = secure_dir / f"{{key_id}}.key"
            
            with open(key_file, 'w', encoding='utf-8') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_file, 0o600)  # Owner read/write only
            
            log.debug(f"Key '{{key_id}}' stored in file: {{key_file}}")
            return True
        except Exception as e_file_store:
            log.error(f"File storage failed for key '{{key_id}}': {{e_file_store}}")
            return False
    
    def secure_retrieve(self, key_id):
        if HAVE_KEYRING:
            try:
                key_data = keyring.get_password(SERVICE_APP_NAME, key_id)
                if key_data:
                    log.debug(f"Key '{{key_id}}' retrieved from OS keyring for '{{SERVICE_APP_NAME}}'.")
                    return key_data
            except NoKeyringError:
                log.warning("No OS keyring backend found for key retrieval.")
            except Exception as e_keyring_get:
                log.error(f"Keyring retrieval failed for key '{{key_id}}': {{e_keyring_get}}")
        
        # Fallback to file retrieval
        try:
            key_file = Path(SECURE_DIR_PATH) / f"{{key_id}}.key"
            if key_file.exists():
                # Basic permission check on POSIX before reading
                if os.name == 'posix':
                    mode = key_file.stat().st_mode
                    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH | stat.S_IXUSR):
                        log.warning(f"Key file {{key_file}} has insecure permissions: {{oct(mode)}}. Expected 0600 or 0400.")
                
                with open(key_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                log.debug(f"Key '{{key_id}}' retrieved from file: {{key_file}}")
                return content
        except Exception as e_file_retrieve:
            log.error(f"File retrieval failed for key '{{key_id}}': {{e_file_retrieve}}")
        
        log.debug(f"Key '{{key_id}}' not found in any storage.")
        return None
    
    def delete_key_from_storage(self, key_id):
        deleted_keyring = False
        deleted_file = False

        if HAVE_KEYRING:
            try:
                keyring.delete_password(SERVICE_APP_NAME, key_id)
                log.debug(f"Key '{{key_id}}' deleted from OS keyring for '{{SERVICE_APP_NAME}}'.")
                deleted_keyring = True
            except PasswordDeleteError:
                log.debug(f"Key '{{key_id}}' not found in OS keyring for deletion (app: {{SERVICE_APP_NAME}})")
                # This isn't an error if the key was only in file storage
            except NoKeyringError:
                log.debug("No OS keyring backend to delete from.")
            except Exception as e_keyring_del:
                log.warning(f"Error deleting key '{{key_id}}' from keyring: {{e_keyring_del}}")
        
        try:
            key_file = Path(SECURE_DIR_PATH) / f"{{key_id}}.key"
            if key_file.exists():
                os.remove(key_file)
                log.debug(f"Key '{{key_id}}' deleted from file: {{key_file}}")
                deleted_file = True
            else:
                log.debug(f"Key file '{{key_file}}' not found for deletion.")
        except Exception as e_file_del:
            log.warning(f"Error deleting key file '{{key_file}}': {{e_file_del}}")
        
        return deleted_keyring or deleted_file # Return True if deleted from at least one place

    def run(self):
        log.info("Key service run loop started.")
        self.socket.setsockopt(zmq.RCVTIMEO, 500) # Poll every 500ms

        while self.running:
            try:
                message = self.socket.recv_string()
                parts = message.split(":", 1)
                command = parts[0]
                payload = parts[1] if len(parts) > 1 else ""
                
                log.debug(f"Received command: {{command}}, payload: {{payload[:30]}}...")

                if command == "PING":
                    self.socket.send_string("PONG")
                
                elif command == "STORE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for STORE")
                        continue
                    
                    store_parts = payload.split(":", 1)
                    if len(store_parts) < 2:
                        self.socket.send_string("ERROR:Invalid data format for STORE (key_id:key_data)")
                        continue
                    
                    key_id, key_data_b64 = store_parts
                    # key_data is already base64 encoded by SecureKeyManager
                    success = self.secure_store(key_id, key_data_b64)
                    
                    if success:
                        self.socket.send_string(f"SUCCESS:{{key_id}}")
                    else:
                        self.socket.send_string("ERROR:Storage failed")
                
                elif command == "RETRIEVE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for RETRIEVE")
                        continue
                    
                    key_id = payload
                    key_data_b64 = self.secure_retrieve(key_id)
                    
                    if key_data_b64:
                        self.socket.send_string(f"DATA:{{key_data_b64}}")
                    else:
                        self.socket.send_string("ERROR:Key not found")
                
                elif command == "DELETE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for DELETE")
                        continue
                    
                    key_id = payload
                    deleted = self.delete_key_from_storage(key_id)
                    if deleted:
                        self.socket.send_string(f"SUCCESS:{{key_id}} deleted")
                    else:
                        # This could mean it wasn't found or an error occurred. Client needs to know.
                        self.socket.send_string(f"INFO:Key {{key_id}} not found or not deleted from any backend")
                
                elif command == "SHUTDOWN":
                    log.info("Received SHUTDOWN command. Terminating service.")
                    self.running = False
                    self.socket.send_string("SUCCESS:Shutting down")
                else:
                    self.socket.send_string("ERROR:Unknown command")
            
            except zmq.Again: # Timeout on recv
                continue
            except Exception as e_loop:
                log.error(f"Error processing request in service loop: {{e_loop}}", exc_info=True)
                try:
                    # Avoid sending error if socket is already closed or in bad state
                    if not self.socket.closed:
                         self.socket.send_string(f"ERROR:Internal service error: {{str(e_loop)}}")
                except Exception as e_send_err:
                    log.error(f"Failed to send error response to client: {{e_send_err}}")
        
        log.info("Key service run loop ended. Cleaning up...")
        self.socket.close()
        self.context.term()
        log.info("Key service shutdown complete.")
        # Attempt to remove self (temporary script)
        # try:
        #     if os.path.exists(__file__):
        #        os.remove(__file__)
        #        log.info(f"Temporary service script {{__file__}} removed.")
        # except OSError as e_remove_self:
        #    log.warning(f"Could not remove self (service script {{__file__}}): {{e_remove_self}}")

if __name__ == "__main__":
    # This script is intended to be run as a standalone process.
    # It receives configuration (app_name, ipc_path, secure_dir) via the formatted string.
    key_service_instance = KeyService()
    key_service_instance.run()
'''.format(app_name=self.app_name, ipc_path=script_ipc_path, secure_dir=safe_secure_dir))
            
            # Set secure permissions for the temporary script file on POSIX (owner rw)
            if os.name == 'posix':
                os.chmod(script_path, stat.S_IRUSR | stat.S_IWUSR) # 0600
            log.debug(f"Temporary key service script created at: {script_path}")

        except Exception as e_create_script:
            log.error(f"Failed to create temporary service script: {e_create_script}")
            if 'script_path' in locals() and os.path.exists(script_path):
                try: # Best effort to clean up partially created script
                    os.remove(script_path)
                except OSError:
                    pass
            raise KeyProtectionError(f"Could not create key service script: {e_create_script}") from e_create_script
        
        return script_path
    
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
    
    def _connect_to_service(self) -> bool:
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
            
            current_ipc_path = getattr(self, 'ipc_path', IPC_PATH) # Use instance specific IPC path
            socket.connect(current_ipc_path)
            
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
            
        # In-memory mode: use enhanced memory protection
        if self.in_memory_only:
            # Use secure memory if PyNaCl is available
            if HAS_NACL:
                try:
                    # Convert key_data to bytearray in secure memory
                    self.memory_keys[key_name] = secure_memory.secure_copy(key_data)
                    log.info(f"Key {key_name} stored in protected memory using PyNaCl (not persisted)")
                    return True
                except Exception as e:
                    log.warning(f"Failed to use PyNaCl secure memory for {key_name}: {e}. Falling back to bytearray.")
            
            # Fall back to using a mutable bytearray for better memory hygiene
            self.memory_keys[key_name] = _convert_to_bytearray(key_data)
            log.info(f"Key {key_name} stored in memory only (not persisted)")
            return True
        
        # Otherwise use persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"STORE:{key_name}:{key_data}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} stored securely via service using app_name '{self.app_name}'")
                    return True
                else:
                    log.warning(f"Service failed to store key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        # Fallback to direct OS keyring or file storage if ZMQ service fails or is not used
        log.warning(f"Attempting fallback storage for key '{key_name}' (OS keyring or file). ZMQ service might be unavailable or failed.")
        try:
            if HAVE_KEYRING:
                log.warning(f"SECURITY NOTICE: Storing key '{key_name}' in OS keyring for app '{self.app_name}'. "
                            f"Backend: {keyring.get_keyring().__class__.__name__ if HAVE_KEYRING and keyring.get_keyring() else 'Unknown'}. "
                            "OS keyring security depends on user account security. Consider implications if account is compromised.")
                keyring.set_password(self.app_name, key_name, key_data)
                log.info(f"Key {key_name} stored in OS keyring under app_name '{self.app_name}' (fallback).")
                return True
            
            # Fallback to file storage if keyring is not available or fails (this part is simplified)
            key_path = self.secure_dir / f"{key_name}.key"
            
            # Ensure the parent directory exists with correct permissions before writing
            os.makedirs(self.secure_dir, mode=0o700, exist_ok=True)
            if os.name == 'posix': # Re-assert parent dir permissions
                os.chmod(self.secure_dir, stat.S_IRWXU)

            with open(key_path, 'w') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR) # 0600
            
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
        # In-memory mode: retrieve from memory dictionary
        if self.in_memory_only:
            key_data = self.memory_keys.get(key_name)
            if key_data:
                log.debug(f"Key {key_name} retrieved from memory")
                if as_bytes:
                    return base64.b64decode(key_data)
                return key_data
            else:
                log.warning(f"Key {key_name} not found in memory")
                return None
                
        # Otherwise use persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"RETRIEVE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("DATA:"):
                    log.debug(f"Key {key_name} retrieved via service using app_name '{self.app_name}'")
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
                    log.debug(f"Key {key_name} retrieved from OS keyring under app_name '{self.app_name}'")
                    if as_bytes:
                        return base64.b64decode(key_data)
                    return key_data
            
            key_path = self.secure_dir / f"{key_name}.key"
            if key_path.exists():
                # Permission check before reading (optional, as read would fail anyway)
                if os.name == 'posix':
                    file_stat = os.stat(key_path)
                    # Check if only owner has read access (0400 or 0600)
                    if not (file_stat.st_mode & stat.S_IRUSR and not (file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH))):
                        log.warning(f"Key file {key_path} has insecure read permissions. Expected owner-read only.")
                        # Depending on policy, could raise error or refuse to read
                
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
        # In-memory mode: delete from memory dictionary
        if self.in_memory_only:
            if key_name in self.memory_keys:
                key_data = self.memory_keys.get(key_name)
                if key_data:
                    # Use the appropriate method for secure erasure based on the type
                    try:
                        if HAS_NACL and hasattr(nacl.utils, 'sodium_free'):
                            # If it's a PyNaCl secure buffer, use sodium_free
                            try:
                                secure_memory.wipe(key_data)
                                log.debug(f"Securely erased in-memory key data for {key_name} using libsodium")
                            except Exception as e:
                                log.warning(f"Failed to use PyNaCl for secure erasure: {e}. Falling back to secure_erase.")
                                # Fall back to secure_erase if sodium_free fails
                                secure_erase(key_data)
                        else:
                            # For regular bytearrays or strings, use secure_erase
                            if isinstance(key_data, str):
                                secure_erase(key_data.encode('utf-8'))
                            else:
                                secure_erase(key_data)
                            log.debug(f"Securely erased in-memory key data for {key_name}")
                    except Exception as e:
                        log.warning(f"Failed to securely erase in-memory key data for {key_name}: {e}")
                
                del self.memory_keys[key_name]
                log.debug(f"Key {key_name} deleted from memory")
                return True
            return False
            
        # Otherwise delete from persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"DELETE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} deleted via service for app_name '{self.app_name}'")
                    return True
                else:
                    log.warning(f"Service failed to delete key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        success = True
        
        if HAVE_KEYRING:
            try:
                keyring.delete_password(self.app_name, key_name)
                log.debug(f"Key {key_name} deleted from OS keyring under app_name '{self.app_name}'")
            except keyring.errors.PasswordDeleteError:
                log.debug(f"Key {key_name} not found in keyring for app_name '{self.app_name}' or other deletion error.")
                success = False # If keyring was expected to have it and failed, it might be an issue
            except Exception as e:
                log.warning(f"Could not delete key {key_name} from keyring for app_name '{self.app_name}': {e}")
                success = False
        
        try:
            key_path = self.secure_dir / f"{key_name}.key"
            if key_path.exists():
                os.remove(key_path)
                log.debug(f"Key {key_name} deleted from file: {key_path}")
        except Exception as e:
            log.warning(f"Could not delete key file {key_path}: {e}")
            success = False
        
        return success
    
    def verify_storage(self) -> bool:
        """
        Verify that the key storage is properly configured and secure.
        
        Returns:
            bool: True if storage is secure, False otherwise
        """
        # In-memory mode is always considered secure
        if self.in_memory_only:
            log.info("In-memory key storage verified (no disk persistence)")
            return True
        
        if HAVE_KEYRING:
            try:
                test_key = f"test_key_{os.urandom(4).hex()}"
                test_data = f"test_data_{os.urandom(8).hex()}"
                
                keyring.set_password(self.app_name, test_key, test_data)
                retrieved = keyring.get_password(self.app_name, test_key)
                
                if retrieved == test_data:
                    keyring.delete_password(self.app_name, test_key)
                    log.info(f"OS keyring storage verified for app_name '{self.app_name}'")
                    return True
            except Exception as e:
                log.warning(f"OS keyring verification failed for app_name '{self.app_name}': {e}")
        
        try:
            if not self.secure_dir.exists(): # Changed to use Path.exists()
                # Attempt to create it if it doesn't exist during verification
                log.warning(f"Secure keys directory {self.secure_dir} does not exist. Attempting to create.")
                self._initialize_storage() # This will create with 0700
                if not self.secure_dir.exists():
                    log.error(f"Failed to create secure keys directory {self.secure_dir} during verification.")
                    return False
            
            if os.name == 'posix':
                dir_stat = os.stat(self.secure_dir)
                if dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO): # Check for group/other permissions
                    log.warning(f"SECURITY ALERT: Secure keys directory {self.secure_dir} has insecure permissions: {oct(dir_stat.st_mode)}. Expected 0700.")
                    # Attempt to fix permissions
                    try:
                        os.chmod(self.secure_dir, stat.S_IRWXU)
                        log.info(f"Attempted to correct permissions for {self.secure_dir} to 0700.")
                        dir_stat = os.stat(self.secure_dir) # Re-check
                        if dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                            log.error(f"SECURITY ALERT: Failed to correct permissions for {self.secure_dir}.")
                            return False
                    except Exception as e_chmod:
                        log.error(f"SECURITY ALERT: Could not correct permissions for {self.secure_dir}: {e_chmod}")
                        return False
            
            test_file_name = f".test_write_{os.urandom(4).hex()}"
            test_file = self.secure_dir / test_file_name
            with open(test_file, 'w') as f:
                f.write("test")
            
            if os.name == 'posix':
                os.chmod(test_file, stat.S_IRUSR | stat.S_IWUSR) # Set to 0600
                file_stat = os.stat(test_file)
                if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO | stat.S_IXUSR): # Check for group/other/execute bits
                    log.warning(f"SECURITY ALERT: Test file {test_file} created with insecure permissions: {oct(file_stat.st_mode)}. Expected 0600.")
                    os.remove(test_file)
                    return False
            
            os.remove(test_file)
            
            log.info(f"File storage at {self.secure_dir} verified")
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

        # Securely erase any keys remaining in memory_keys
        if self.in_memory_only and hasattr(self, 'memory_keys') and self.memory_keys:
            log.debug(f"Cleaning up {len(self.memory_keys)} in-memory keys.")
            # Iterate over a copy of items in case secure_erase modifies the dict or list during iteration (though unlikely here)
            for key_name, key_data_b64_str in list(self.memory_keys.items()):
                if key_data_b64_str:
                    try:
                        secure_erase(key_data_b64_str.encode('utf-8'))
                        log.debug(f"Securely erased in-memory key data for {key_name} during cleanup.")
                    except Exception as e:
                        log.warning(f"Failed to securely erase in-memory key data for {key_name} during cleanup: {e}")
            self.memory_keys.clear()
            log.info("All in-memory keys securely erased and cleared.")

    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()


# Singleton instance for global use
_key_manager_instance = None

def get_key_manager(in_memory_only: bool = False) -> SecureKeyManager:
    """
    Get the global key manager instance.
    
    Args:
        in_memory_only: If True, use in-memory key storage with no disk persistence
        
    Returns:
        The global SecureKeyManager instance
    """
    global _key_manager_instance
    if _key_manager_instance is None:
        _key_manager_instance = SecureKeyManager(in_memory_only=in_memory_only)
    return _key_manager_instance


# Module-level API for simplified access

def store_key(key_material: Union[bytes, str], key_name: str, in_memory_only: bool = False) -> bool:
    """
    Store a cryptographic key securely.
    
    Args:
        key_material: The key material to store
        key_name: Name to identify the key
        in_memory_only: If True, store in memory only (no disk persistence)
    """
    return get_key_manager(in_memory_only).store_key(key_material, key_name)

def retrieve_key(key_name: str, as_bytes: bool = True, in_memory_only: bool = False) -> Optional[Union[bytes, str]]:
    """
    Retrieve a stored cryptographic key.
    
    Args:
        key_name: Name of the key to retrieve
        as_bytes: If True, return bytes; otherwise, return string
        in_memory_only: If True, retrieve from memory only (no disk access)
    """
    return get_key_manager(in_memory_only).retrieve_key(key_name, as_bytes)

def delete_key(key_name: str, in_memory_only: bool = False) -> bool:
    """
    Delete a stored cryptographic key.
    
    Args:
        key_name: Name of the key to delete
        in_memory_only: If True, delete from memory only (no disk access)
    """
    return get_key_manager(in_memory_only).delete_key(key_name)

def verify_storage(in_memory_only: bool = False) -> bool:
    """
    Verify that the key storage is properly configured and secure.
    
    Args:
        in_memory_only: If True, verify memory storage only (no disk access)
    """
    return get_key_manager(in_memory_only).verify_storage()

def cleanup():
    """Clean up resources when finished."""
    if _key_manager_instance:
        _key_manager_instance.cleanup()

# Cleanup on exit
import atexit
atexit.register(cleanup)

def _convert_to_bytearray(key_data):
    """
    Convert immutable key data to a mutable bytearray for secure wiping.
    
    Args:
        key_data: The key data to convert, either bytes or str
        
    Returns:
        A bytearray containing the key data
    """
    if isinstance(key_data, bytearray):
        return key_data
    elif isinstance(key_data, bytes):
        return bytearray(key_data)
    elif isinstance(key_data, str):
        return bytearray(key_data.encode('utf-8'))
    else:
        raise TypeError(f"Cannot convert key data of type {type(key_data)} to bytearray") 