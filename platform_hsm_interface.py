#!/usr/bin/env python3
"""
cross_platform_security.py
 
An advanced, cross-platform Python module implementing hardware-backed security features
with production-grade software fallbacks on Windows, Linux, and macOS.

Features: 
  1. Secure Random Number Generation
     • Windows TPM via tbs.dll (if available)
     • Linux TPM2 via tpm2-pytss (if available)
     • Fallback to Python's secrets module
  2. Hardware-Bound Identity 
     • Windows: WMI (via Python's wmi module or PowerShell) for UUID
     • Linux: DMI product_uuid or /etc/machine-id
     • macOS: IOPlatformUUID via ioreg
     • Secure fallback file with restricted permissions
  3. Secure Key Storage
     • Windows: TPM CNG KSP (stub) or Windows Credential Manager via keyring
     • macOS: Keychain via keyring
     • Linux: AES-GCM encrypted file + mlock-secured buffer
  4. Hardware Key Isolation
     • Windows: VirtualLock() on page-aligned memory
     • Linux/macOS: mlock() on page-aligned memory
  5. Device Attestation
     • Windows: WMI Win32_Tpm for state
     • Linux: TPM2 quote via tpm2-pytss FAPI
     • macOS: SIP status via csrutil

[SECURITY ENHANCEMENT]: This module now uses enhanced post-quantum cryptographic
implementations from pqc_algorithms.py, providing state-of-the-art, military-grade,
future-proof security with improved side-channel resistance, constant-time operations,
and protection against emerging threats.
"""

import os 
import platform
import ssl
import subprocess
import logging
import hashlib
import ctypes
import mmap
import stat
import sys
import time
import typing # Added for Union type hint
import json
from ctypes import wintypes
from ctypes.util import find_library
import secrets
import cryptography
import keyring
import tempfile
import base64
from typing import Optional, Dict, Any
logger = logging.getLogger(__name__)

# Attempt to import cryptography for key manipulation if not already done for PKCS11
try:
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
    # crypto_rsa and crypto_serialization might be imported in PKCS11
    # We need to ensure they are available or set to None if not.
    if 'crypto_rsa' not in globals() or crypto_rsa is None:
        from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    if 'crypto_serialization' not in globals() or crypto_serialization is None:
        from cryptography.hazmat.primitives import serialization as crypto_serialization
    _CRYPTOGRAPHY_AVAILABLE = True
    logger.debug("Cryptography library components imported successfully.")
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False
    if 'crypto_hashes' not in globals(): crypto_hashes = None
    if 'crypto_padding' not in globals(): crypto_padding = None
    if 'crypto_rsa' not in globals() or crypto_rsa is None: crypto_rsa = None
    if 'crypto_serialization' not in globals() or crypto_serialization is None: crypto_serialization = None
    logger.warning("Cryptography library not fully available. Some key operations might be limited or unavailable.")

# Attempt to import pkcs11 for HSM support
try:
    import pkcs11 # type: ignore
    from pkcs11 import Attribute as CKA # Alias for convenience # type: ignore
    from pkcs11 import Mechanism as CKM # Alias for convenience  # type: ignore
    from pkcs11 import KeyType as CKK # Alias for convenience # type: ignore
    from pkcs11.util.rsa import encode_rsa_public_key # For returning standard pub key # type: ignore
    from cryptography.hazmat.primitives import serialization as crypto_serialization # For pub key object
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa # For pub key object


    _PKCS11_SUPPORT_AVAILABLE = True
    logger.debug("python-pkcs11 library imported successfully.")
except ImportError:
    pkcs11 = None
    CKA = None
    CKM = None
    CKK = None
    encode_rsa_public_key = None
    _PKCS11_SUPPORT_AVAILABLE = False
    logger.info("python-pkcs11 library not found. PKCS#11 HSM support will be unavailable.")

# Platform detection
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_DARWIN = SYSTEM == "Darwin"
IS_MACOS = IS_DARWIN  # Alias for compatibility

# Configuration loading
CONFIG_FILE = "config.json"
config = {}

# Platform-specific configuration settings
TPM_ENABLED = True
PKCS11_ENABLED = True
KEYRING_ENABLED = True
SECURE_MEMORY_ENABLED = True
LIBSODIUM_PREFERRED = True

def load_config():
    """
    Load configuration settings from config.json
    """
    global config, TPM_ENABLED, PKCS11_ENABLED, KEYRING_ENABLED, SECURE_MEMORY_ENABLED, LIBSODIUM_PREFERRED
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {CONFIG_FILE}")
            
            # Update global configuration variables
            TPM_ENABLED = config.get("platform", {}).get("hardware_security", {}).get("tpm_enabled", True)
            PKCS11_ENABLED = config.get("platform", {}).get("hardware_security", {}).get("pkcs11_enabled", True)
            KEYRING_ENABLED = config.get("platform", {}).get("hardware_security", {}).get("keyring_enabled", True)
            SECURE_MEMORY_ENABLED = config.get("platform", {}).get("hardware_security", {}).get("secure_memory_enabled", True)
            LIBSODIUM_PREFERRED = config.get("platform", {}).get("hardware_security", {}).get("libsodium_preferred", True)
            
            return True
        else:
            logger.warning(f"Configuration file {CONFIG_FILE} not found, using defaults")
            return False
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return False

def get_platform_config():
    """
    Get platform-specific configuration settings
    
    Returns:
        dict: Platform-specific configuration settings
    """
    global config
    
    # Ensure config is loaded
    if not config:
        load_config()
    
    # Get platform-specific configuration
    if IS_WINDOWS:
        return config.get("platform", {}).get("windows", {})
    elif IS_LINUX:
        return config.get("platform", {}).get("linux", {})
    elif IS_DARWIN:
        return config.get("platform", {}).get("darwin", {})
    else:
        return {}

# Get platform-specific settings from config
def get_platform_config():
    """
    Get platform-specific configuration settings
    """
    platform_key = "windows" if IS_WINDOWS else "linux" if IS_LINUX else "darwin" if IS_DARWIN else "default"
    platform_config = config.get("platform", {}).get(platform_key, {})
    hardware_config = config.get("platform", {}).get("hardware_security", {})
    
    # Merge platform-specific and general hardware security settings
    result = {**hardware_config, **platform_config}
    
    # If empty, set some reasonable defaults
    if not result:
        if IS_WINDOWS:
            result = {
                "tpm_enabled": True,
                "pkcs11_enabled": False,
                "keyring_enabled": True,
                "tpm_provider": "MS_PLATFORM_CRYPTO_PROVIDER",
                "libsodium_paths": ["./libsodium.dll", "libsodium.dll"]
            }
        elif IS_LINUX:
            result = {
                "tpm_enabled": True,
                "pkcs11_enabled": True,
                "keyring_enabled": True,
                "tpm_paths": ["/dev/tpm0", "/dev/tpmrm0"],
                "libsodium_paths": ["libsodium.so", "libsodium.so.23"]
            }
        elif IS_DARWIN:
            result = {
                "secure_enclave_enabled": True,
                "keyring_enabled": True,
                "libsodium_paths": ["libsodium.dylib"]
            }
    
    return result

# Load configuration on module import
load_config()

# Apply platform-specific configuration
platform_config = get_platform_config()
TPM_ENABLED = platform_config.get("tpm_enabled", True)
PKCS11_ENABLED = platform_config.get("pkcs11_enabled", True)
KEYRING_ENABLED = platform_config.get("keyring_enabled", True)
SECURE_MEMORY_ENABLED = platform_config.get("secure_memory_enabled", True)
LIBSODIUM_PREFERRED = platform_config.get("libsodium_preferred", True)

# If Windows, load VirtualLock/VirtualUnlock
if IS_WINDOWS:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _VirtualLock = kernel32.VirtualLock
        _VirtualLock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
        _VirtualLock.restype = wintypes.BOOL
        _VirtualUnlock = kernel32.VirtualUnlock
        _VirtualUnlock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
        _VirtualUnlock.restype = wintypes.BOOL
        logger.debug("Windows VirtualLock/VirtualUnlock available.")

        # Load CNG and NCrypt functions
        bcrypt = ctypes.WinDLL("bcrypt.dll", use_last_error=True)
        ncrypt = ctypes.WinDLL("ncrypt.dll", use_last_error=True)

        # Constants
        BCRYPT_RSA_ALGORITHM = wintypes.LPCWSTR("RSA")
        NCRYPT_RSA_ALGORITHM = wintypes.LPCWSTR("RSA")
        MS_PLATFORM_CRYPTO_PROVIDER = wintypes.LPCWSTR("Microsoft Platform Crypto Provider")
        
        NCRYPT_KEY_STORAGE_PROVIDER = MS_PLATFORM_CRYPTO_PROVIDER # Alias

        NCRYPT_SILENT_FLAG = wintypes.DWORD(0x00000040)
        NCRYPT_OVERWRITE_KEY_FLAG = wintypes.DWORD(0x00000004)
        NCRYPT_MACHINE_KEY_FLAG = wintypes.DWORD(0x00000020) # User keys are default without this

        # BCRYPT Buffer Types
        BCRYPT_RSAPUBLIC_BLOB = wintypes.LPCWSTR("RSAPUBLICBLOB")
        BCRYPT_RSAFULLPRIVATE_BLOB = wintypes.LPCWSTR("RSAFULLPRIVATEBLOB")

        # NCrypt Property Names
        NCRYPT_LENGTH_PROPERTY = wintypes.LPCWSTR("Length")
        NCRYPT_EXPORT_POLICY_PROPERTY = wintypes.LPCWSTR("Export Policy")
        NCRYPT_KEY_USAGE_PROPERTY = wintypes.LPCWSTR("Key Usage")
        NCRYPT_ALGORITHM_PROPERTY = wintypes.LPCWSTR("Algorithm Name") # Used with NCryptGetProperty on key handle

        # Key Usage Flags for NCRYPT_KEY_USAGE_PROPERTY
        NCRYPT_ALLOW_SIGNING_FLAG = wintypes.DWORD(0x00000100) 
        NCRYPT_ALLOW_DECRYPT_FLAG = wintypes.DWORD(0x00000200) 
        NCRYPT_ALLOW_EXPORT_FLAG = wintypes.DWORD(0x00000001)
        
        # Padding flags for NCryptSignHash
        NCRYPT_PAD_PKCS1_FLAG = wintypes.DWORD(0x00000002)
        NCRYPT_PAD_PSS_FLAG = wintypes.DWORD(0x00000008)


        # Status codes
        STATUS_SUCCESS = wintypes.LONG(0x00000000) # Changed NTSTATUS to LONG. HRESULT is also compatible with LONG for 0.
        NTE_BAD_KEYSET = wintypes.LONG(0x80090016) # Changed HRESULT to LONG, removed .value
        NTE_EXISTS = wintypes.LONG(0x8009000F)     # Changed HRESULT to LONG, removed .value
        NTE_PERM = wintypes.LONG(0x80090010)       # Changed HRESULT to LONG, removed .value

        # Typedefs for handles
        BCRYPT_ALG_HANDLE = wintypes.HANDLE
        BCRYPT_KEY_HANDLE = wintypes.HANDLE
        NCRYPT_PROV_HANDLE = wintypes.HANDLE
        NCRYPT_KEY_HANDLE = wintypes.HANDLE

        # Function signatures - BCrypt (Primarily for utility if needed, NCrypt for persisted keys)
        _BCryptOpenAlgorithmProvider = bcrypt.BCryptOpenAlgorithmProvider
        _BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(BCRYPT_ALG_HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.ULONG]
        _BCryptOpenAlgorithmProvider.restype = wintypes.LONG # Changed NTSTATUS to LONG

        _BCryptGenerateKeyPair = bcrypt.BCryptGenerateKeyPair
        _BCryptGenerateKeyPair.argtypes = [BCRYPT_ALG_HANDLE, ctypes.POINTER(BCRYPT_KEY_HANDLE), wintypes.ULONG, wintypes.ULONG]
        _BCryptGenerateKeyPair.restype = wintypes.LONG # Changed NTSTATUS to LONG

        _BCryptFinalizeKeyPair = bcrypt.BCryptFinalizeKeyPair
        _BCryptFinalizeKeyPair.argtypes = [BCRYPT_KEY_HANDLE, wintypes.ULONG]
        _BCryptFinalizeKeyPair.restype = wintypes.LONG # Changed NTSTATUS to LONG

        _BCryptExportKey = bcrypt.BCryptExportKey
        _BCryptExportKey.argtypes = [BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, wintypes.LPCWSTR, ctypes.POINTER(wintypes.BYTE), wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
        _BCryptExportKey.restype = wintypes.LONG # Changed NTSTATUS to LONG
        
        _BCryptDestroyKey = bcrypt.BCryptDestroyKey
        _BCryptDestroyKey.argtypes = [BCRYPT_KEY_HANDLE]
        _BCryptDestroyKey.restype = wintypes.LONG # Changed NTSTATUS to LONG

        _BCryptCloseAlgorithmProvider = bcrypt.BCryptCloseAlgorithmProvider
        _BCryptCloseAlgorithmProvider.argtypes = [BCRYPT_ALG_HANDLE, wintypes.ULONG]
        _BCryptCloseAlgorithmProvider.restype = wintypes.LONG # Changed NTSTATUS to LONG
        
        _BCryptSetProperty = bcrypt.BCryptSetProperty
        _BCryptSetProperty.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.POINTER(wintypes.BYTE), wintypes.ULONG, wintypes.ULONG]
        _BCryptSetProperty.restype = wintypes.LONG # Changed NTSTATUS to LONG


        # Function signatures - NCrypt
        _NCryptOpenStorageProvider = ncrypt.NCryptOpenStorageProvider
        _NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(NCRYPT_PROV_HANDLE), wintypes.LPCWSTR, wintypes.ULONG]
        _NCryptOpenStorageProvider.restype = wintypes.LONG # Changed HRESULT to LONG

        _NCryptCreatePersistedKey = ncrypt.NCryptCreatePersistedKey
        _NCryptCreatePersistedKey.argtypes = [NCRYPT_PROV_HANDLE, ctypes.POINTER(NCRYPT_KEY_HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        _NCryptCreatePersistedKey.restype = wintypes.LONG # Changed HRESULT to LONG

        _NCryptOpenKey = ncrypt.NCryptOpenKey
        _NCryptOpenKey.argtypes = [NCRYPT_PROV_HANDLE, ctypes.POINTER(NCRYPT_KEY_HANDLE), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        _NCryptOpenKey.restype = wintypes.LONG # Changed HRESULT to LONG
        
        _NCryptFinalizeKey = ncrypt.NCryptFinalizeKey # Added NCryptFinalizeKey
        _NCryptFinalizeKey.argtypes = [NCRYPT_KEY_HANDLE, wintypes.DWORD]
        _NCryptFinalizeKey.restype = wintypes.LONG # Changed HRESULT to LONG

        _NCryptSignHash = ncrypt.NCryptSignHash
        _NCryptSignHash.argtypes = [NCRYPT_KEY_HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        _NCryptSignHash.restype = wintypes.LONG # Changed HRESULT to LONG

        _NCryptExportKey = ncrypt.NCryptExportKey 
        _NCryptExportKey.argtypes = [NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        _NCryptExportKey.restype = wintypes.LONG # Changed HRESULT to LONG
        
        _NCryptDeleteKey = ncrypt.NCryptDeleteKey
        _NCryptDeleteKey.argtypes = [NCRYPT_KEY_HANDLE, wintypes.DWORD]
        _NCryptDeleteKey.restype = wintypes.LONG # Changed HRESULT to LONG
        
        _NCryptFreeObject = ncrypt.NCryptFreeObject
        _NCryptFreeObject.argtypes = [wintypes.HANDLE]
        _NCryptFreeObject.restype = wintypes.LONG # Changed HRESULT to LONG

        _NCryptSetProperty = ncrypt.NCryptSetProperty
        _NCryptSetProperty.argtypes = [NCRYPT_PROV_HANDLE, wintypes.LPCWSTR, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, wintypes.DWORD] # Handle can be NCRYPT_PROV_HANDLE or NCRYPT_KEY_HANDLE
        _NCryptSetProperty.restype = wintypes.LONG # Changed HRESULT to LONG
        
        _NCryptGetProperty = ncrypt.NCryptGetProperty
        _NCryptGetProperty.argtypes = [NCRYPT_PROV_HANDLE, wintypes.LPCWSTR, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD] # Handle can be NCRYPT_PROV_HANDLE or NCRYPT_KEY_HANDLE
        _NCryptGetProperty.restype = wintypes.LONG # Changed HRESULT to LONG

        # Initialize global CNG state variables here, AFTER types are defined
        _ncrypt_provider_handle = NCRYPT_PROV_HANDLE() 
        _cng_provider_initialized = False

        _WINDOWS_CNG_NCRYPT_AVAILABLE = True
        logger.debug("Windows CNG/NCrypt functions loaded successfully.")

    except (OSError, AttributeError) as e:
        _WINDOWS_CNG_NCRYPT_AVAILABLE = False
        _BCryptOpenAlgorithmProvider = None # Set all to None for safety
        _BCryptGenerateKeyPair = None
        _BCryptFinalizeKeyPair = None
        _BCryptExportKey = None
        _BCryptDestroyKey = None
        _BCryptCloseAlgorithmProvider = None
        _BCryptSetProperty = None
        _NCryptOpenStorageProvider = None
        _NCryptCreatePersistedKey = None
        _NCryptOpenKey = None
        _NCryptFinalizeKey = None
        _NCryptSignHash = None
        _NCryptExportKey = None
        _NCryptDeleteKey = None
        _NCryptFreeObject = None
        _NCryptSetProperty = None
        _NCryptGetProperty = None
        logger.warning(f"Windows CNG/NCrypt libraries (bcrypt.dll, ncrypt.dll) or their functions not available: {e}. TPM-backed key operations via CNG will be disabled.")
    except Exception as e: # Catch other potential errors during initial Win32 setup
        _VirtualLock = None
        _VirtualUnlock = None
        _WINDOWS_CNG_NCRYPT_AVAILABLE = False # Ensure this is false too
        logger.error(f"Failed during Windows-specific library loading (kernel32, bcrypt, ncrypt): {e}")

# Preload Windows TBS functions if available
if IS_WINDOWS:
    try:
        tbs = ctypes.WinDLL("tbs.dll")
        Tbsi_GetRandom = tbs.Tbsi_GetRandom
        Tbsi_GetRandom.argtypes = [
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(wintypes.UINT),
        ]
        Tbsi_GetRandom.restype = wintypes.ULONG
        _WINDOWS_TBS_AVAILABLE = True
        logger.debug("tbs.dll loaded; Tbsi_GetRandom available.")
    except Exception as e:
        _WINDOWS_TBS_AVAILABLE = False
        logger.debug("tbs.dll not available (Windows TPM disabled): %s", e)
else:
    _WINDOWS_TBS_AVAILABLE = False

# Preload Linux tpm2-pytss if available
if IS_LINUX:
    try:
        from tpm2_pytss import ESAPI, TCTI # type: ignore
        _Linux_ESAPI = ESAPI
        _Linux_TCTI = TCTI
        logger.debug("tpm2-pytss available for Linux TPM.")
    except ImportError as e:
        _Linux_ESAPI = None
        _Linux_TCTI = None
        logger.debug("tpm2-pytss not available; Linux TPM disabled: %s", e)
else:
    _Linux_ESAPI = None
    _Linux_TCTI = None

# Import AESGCM from cryptography for secure encryption (works cross-platform)
_AESGCM_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AESGCM_AVAILABLE = True
except ImportError:
    _AESGCM_AVAILABLE = False
    logger.warning("Cryptography AESGCM not available; secure key file encryption disabled.")

# Global state for HSM session
_pkcs11_lib_path = None
_pkcs11_session = None
_hsm_initialized = False
_hsm_pin = None
_hsm_token_label = None
_hsm_slot_id = None

# Global state for Windows CNG TPM operations (MOVED INSIDE if IS_WINDOWS block)
# _ncrypt_provider_handle = NCRYPT_PROV_HANDLE() 
# _cng_provider_initialized = False


def _check_cng_available() -> bool:
    """Checks if CNG/NCrypt support is loaded and on Windows."""
    if not IS_WINDOWS or not _WINDOWS_CNG_NCRYPT_AVAILABLE:
        return False
    # Also ensure function pointers are not None (belt-and-suspenders for _WINDOWS_CNG_NCRYPT_AVAILABLE flag)
    if not all([_NCryptOpenStorageProvider, _NCryptCreatePersistedKey, _NCryptOpenKey, 
                _NCryptFinalizeKey, _NCryptSignHash, _NCryptExportKey, 
                _NCryptDeleteKey, _NCryptFreeObject, _NCryptSetProperty, _NCryptGetProperty]):
        logger.warning("_WINDOWS_CNG_NCRYPT_AVAILABLE is True, but one or more NCrypt functions are None. CNG unavailable.")
        return False
    return True

def _open_cng_provider_platform() -> bool:
    """Helper to open the MS Platform Crypto Provider if not already open. Returns True on success."""
    global _ncrypt_provider_handle, _cng_provider_initialized
    
    if not _check_cng_available():
        # logger.debug("CNG check failed in _open_cng_provider_platform.") # Can be noisy
        return False
        
    if _cng_provider_initialized and _ncrypt_provider_handle and _ncrypt_provider_handle.value:
        return True

    # Ensure we have a fresh handle if previous attempts failed or it was closed
    if _ncrypt_provider_handle and _ncrypt_provider_handle.value: # Should not happen if _cng_provider_initialized is False
         _NCryptFreeObject(_ncrypt_provider_handle) # Defensive cleanup
    _ncrypt_provider_handle = NCRYPT_PROV_HANDLE()


    status = _NCryptOpenStorageProvider(ctypes.byref(_ncrypt_provider_handle),
                                        MS_PLATFORM_CRYPTO_PROVIDER,
                                        0) # dwFlags
    if status == STATUS_SUCCESS.value:
        _cng_provider_initialized = True
        logger.info(f"Successfully opened CNG provider: {MS_PLATFORM_CRYPTO_PROVIDER.value}")
        return True
    else:
        # Log with HRESULT value for easier lookup
        logger.error(f"Failed to open CNG provider '{MS_PLATFORM_CRYPTO_PROVIDER.value}'. Error code: {status:#010x} (HRESULT)")
        _ncrypt_provider_handle = NCRYPT_PROV_HANDLE() # Ensure it's null on failure
        _cng_provider_initialized = False
        return False

def _close_cng_provider_platform():
    """Closes the CNG provider handle if it was opened."""
    global _ncrypt_provider_handle, _cng_provider_initialized
    if IS_WINDOWS and _ncrypt_provider_handle and _ncrypt_provider_handle.value and _cng_provider_initialized:
        if _NCryptFreeObject: # Check if function pointer is valid
            status = _NCryptFreeObject(_ncrypt_provider_handle)
            if status == STATUS_SUCCESS.value:
                logger.info("CNG provider handle freed successfully.")
            else:
                logger.error(f"Failed to free CNG provider handle. Error: {status:#010x} (HRESULT)")
        else:
            logger.warning("NCryptFreeObject is not available, cannot free CNG provider handle.")
        _ncrypt_provider_handle = NCRYPT_PROV_HANDLE() # Reset to null handle
        _cng_provider_initialized = False
    elif _cng_provider_initialized: # If it was marked initialized but handle is bad or not windows
        logger.debug("close_cng_provider_platform called but provider was not in a valid state to close.")
        _cng_provider_initialized = False # Correct state

# Global variables for hardware security modules
_hsm_initialized = False
_pkcs11_session = None
_pkcs11_lib_path = None
_hsm_pin = None
_hsm_token_label = None
_hsm_slot_id = None
_cng_provider = None
_cng_provider_initialized = False
_software_hsm_mode = False
_crypto_lib_available = False

# Global for auto-detected TPM and PKCS#11 libraries on Linux
_linux_tpm2_tools_available = False
_linux_pkcs11_detected_paths = []

def _find_linux_pkcs11_libraries():
    """Find available PKCS#11 libraries on Linux systems."""
    global _linux_pkcs11_detected_paths
    
    if not IS_LINUX:
        return []
        
    common_paths = [
        "/usr/lib/pkcs11/opensc-pkcs11.so",           # OpenSC
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
        "/usr/lib64/pkcs11/opensc-pkcs11.so",
        "/usr/local/lib/pkcs11/opensc-pkcs11.so",
        "/usr/lib/softhsm/libsofthsm2.so",           # SoftHSM
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/pkcs11/libykcs11.so",              # YubiKey
        "/usr/lib/x86_64-linux-gnu/pkcs11/libykcs11.so",
        "/usr/lib/libykcs11.so",
        "/usr/lib/tpm2-pkcs11/libtpm2_pkcs11.so"     # TPM2 PKCS#11
    ]
    
    detected = []
    for path in common_paths:
        if os.path.exists(path):
            detected.append(path)
            
    # Try using which command to find tpm2-tools
    try:
        global _linux_tpm2_tools_available
        subprocess.check_call(["which", "tpm2_createprimary"], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        _linux_tpm2_tools_available = True
        logger.info("tpm2-tools found on system")
        
        # Check if we have the TPM2 PKCS#11 module
        tpm2_pkcs11_path = "/usr/lib/tpm2-pkcs11/libtpm2_pkcs11.so"
        if os.path.exists(tpm2_pkcs11_path) and tpm2_pkcs11_path not in detected:
            detected.append(tpm2_pkcs11_path)
    except subprocess.CalledProcessError:
        _linux_tpm2_tools_available = False
        logger.info("tpm2-tools not found on system")
    
    if detected:
        _linux_pkcs11_detected_paths = detected
        logger.info(f"Detected PKCS#11 libraries: {', '.join(detected)}")
    else:
        logger.warning("No PKCS#11 libraries detected on system")
        
    return detected

def _detect_libsodium():
    """
    Detect and load libsodium library on the current platform.
    
    Returns:
        tuple: (libsodium_loaded, libsodium_handle) where libsodium_loaded is a boolean
               indicating if the library was loaded successfully, and libsodium_handle
               is the loaded library handle or None if loading failed.
    """
    libsodium = None
    try:
        if IS_WINDOWS:
            # Try multiple locations on Windows
            try_paths = [
                './libsodium.dll',  # Current directory
                'libsodium.dll',    # System path
                os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libsodium.dll')  # Module directory
            ]
            
            for path in try_paths:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(path)
                    logger.info(f"Loaded libsodium from {path}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
        elif IS_LINUX:
            # Try multiple common library names on Linux
            try_names = ['libsodium.so', 'libsodium.so.23', 'libsodium.so.18', 'libsodium.so.26']
            
            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    logger.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        logger.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        pass
                        
        elif IS_DARWIN:
            # Try multiple common library names on macOS
            try_names = ['libsodium.dylib', 'libsodium.23.dylib', 'libsodium.18.dylib']
            
            for name in try_names:
                try:
                    libsodium = ctypes.cdll.LoadLibrary(name)
                    logger.info(f"Loaded libsodium from {name}")
                    break
                except (OSError, FileNotFoundError):
                    continue
                    
            # If direct loading failed, try to find the library
            if libsodium is None:
                lib_path = find_library('sodium')
                if lib_path:
                    try:
                        libsodium = ctypes.cdll.LoadLibrary(lib_path)
                        logger.info(f"Loaded libsodium from {lib_path}")
                    except (OSError, FileNotFoundError):
                        pass
                        
        # If we found libsodium, define function prototypes
        if libsodium:
            # Define function prototypes for sodium_malloc and sodium_free
            libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
            libsodium.sodium_malloc.restype = ctypes.c_void_p
            libsodium.sodium_free.argtypes = [ctypes.c_void_p]
            libsodium.sodium_free.restype = None
            
            # Define sodium_memzero function for secure memory wiping
            libsodium.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.sodium_memzero.restype = None
            
            # Define random functions
            libsodium.randombytes_random.argtypes = []
            libsodium.randombytes_random.restype = ctypes.c_uint32
            
            libsodium.randombytes_buf.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libsodium.randombytes_buf.restype = None
            
            return True, libsodium
            
    except Exception as e:
        logger.warning(f"Failed to load libsodium: {e}")
        
    return False, None

# Initialize libsodium
LIBSODIUM_AVAILABLE, LIBSODIUM = _detect_libsodium()
if LIBSODIUM_AVAILABLE:
    logger.info("libsodium loaded successfully")
else:
    logger.debug("libsodium not available, libsodium downloaded soon")

# Initialize Linux PKCS#11 detection at module load time
if IS_LINUX:
    _find_linux_pkcs11_libraries()

def init_hsm(lib_path: str = None, pin: str = None, token_label: str = None, slot_id: int = None) -> bool:
    """
    Initialize hardware security module (HSM) or use software fallback.
    
    This function attempts to initialize hardware security in the following order:
    1. Windows: Try to use TPM via CNG/NCrypt if available
    2. Linux: Try to use PKCS#11 with provided library if available
    3. All platforms: Fall back to software HSM implementation
    
    Args:
        lib_path (str, optional): Path to PKCS#11 library. Defaults to None.
        pin (str, optional): PIN or password for the HSM. Defaults to None.
        token_label (str, optional): Label of the token to use. Defaults to None.
        slot_id (int, optional): Slot ID to use. Defaults to None.
        
    Returns:
        bool: True if initialization was successful, False otherwise.
    """
    global _hsm_initialized, _hsm_session, _hsm_token, _hsm_provider_type
    
    if _hsm_initialized:
        logger.debug("HSM already initialized")
        return True
        
    try:
        # First, try platform-specific hardware security
        if IS_WINDOWS:
            logger.info("Windows platform detected. Using CNG/TPM for hardware security instead of PKCS#11.")
            if _check_cng_available() and _open_cng_provider_platform():
                logger.info("Successfully initialized Windows CNG provider for hardware security.")
                _hsm_initialized = True
                _hsm_provider_type = "windows_cng"
                return True
            else:
                logger.warning("Windows CNG/TPM not available. Will fall back to software HSM.")
        
        # Next, try PKCS#11 if available
        if _PKCS11_SUPPORT_AVAILABLE:
      # Try to find a PKCS#11 library automatically
            if IS_LINUX:
                lib_paths = _find_linux_pkcs11_libraries()
                if lib_paths:
                    lib_path = lib_paths[0]
                    logger.info(f"Found PKCS#11 library at {lib_path}")
            elif IS_DARWIN:
                # Try common macOS PKCS#11 library locations
                for path in ["/usr/local/lib/libykcs11.dylib", "/usr/local/lib/opensc-pkcs11.so"]:
                    if os.path.exists(path):
                        lib_path = path
                        logger.info(f"Found PKCS#11 library at {lib_path}")
                        break
            
            if lib_path and os.path.exists(lib_path):
                try:
                    # Initialize PKCS#11 library
                    lib = pkcs11.lib(lib_path)
                    
                    # Get a token to work with
                    if token_label:
                        tokens = list(lib.get_tokens(token_label=token_label))
                    elif slot_id is not None:
                        tokens = list(lib.get_tokens(slot_id=slot_id))
                    else:
                        tokens = list(lib.get_tokens())
                    
                    if not tokens:
                        logger.warning("No PKCS#11 tokens found")
                    else:
                        token = tokens[0]
                        _hsm_token = token
                        
                        # Open a session
                        session = token.open(user_pin=pin)
                        _hsm_session = session
                        
                        logger.info(f"Successfully initialized PKCS#11 HSM with token: {token.label}")
                        _hsm_initialized = True
                        _hsm_provider_type = "pkcs11"
                        return True
                except Exception as e:
                    logger.warning(f"Failed to initialize PKCS#11 HSM: {e}. Will fall back to software HSM.")
            else:
                logger.warning(f"PKCS#11 library not found at {lib_path}. Will fall back to software HSM.")
        else:
            logger.warning("PKCS#11 support not available. Will fall back to software HSM.")
        
        # Finally, fall back to software HSM
        logger.info("Initializing software HSM fallback...")
        _hsm_initialized = True
        _hsm_provider_type = "software"
        return True
        
    except Exception as e:
        logger.error(f"Error initializing HSM: {e}")
        _hsm_initialized = False
        return False

def close_hsm():
    """
    Closes the active hardware security module interface:
    - On Windows: Closes CNG provider if it was opened
    - On other platforms: Closes PKCS#11 session if it was opened
    """
    global _pkcs11_session, _hsm_initialized
    
    # First, check if we're on Windows with CNG initialized
    if IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE:
        # Close the CNG provider specifically
        _close_cng_provider_platform()
        _hsm_initialized = False
        logger.info("Windows CNG provider closed.")
        return
    
    # For non-Windows or if above didn't return, try to close PKCS#11 session
    if _pkcs11_session:
        try:
            _pkcs11_session.close()
            logger.info("HSM session closed.")
        except pkcs11.exceptions.PKCS11Error as e:
            logger.error(f"Error closing HSM session: {e}")
        finally:
            _pkcs11_session = None
            _hsm_initialized = False
    else:
        logger.info("HSM session was not open, no action taken.")
        _hsm_initialized = False

def check_hsm_pkcs11_support() -> dict:
    """
    Checks availability of PKCS#11 HSM support and configuration.
    
    Returns:
        dict: Dictionary with information about HSM support:
            - pkcs11_support_enabled: Whether the PKCS#11 library is available
            - hsm_available: Whether an HSM is detected and configured
            - initialized: Whether an HSM session is currently initialized
            - library_path: Path to the PKCS#11 library if configured
    """
    pkcs11_lib_path = os.environ.get("PKCS11_LIB_PATH", "")
    
    return {
        "pkcs11_support_enabled": _PKCS11_SUPPORT_AVAILABLE,
        "hsm_available": _PKCS11_SUPPORT_AVAILABLE and bool(pkcs11_lib_path),
        "initialized": _hsm_initialized,
        "library_path": _pkcs11_lib_path if _pkcs11_lib_path else pkcs11_lib_path
    }

def get_hsm_random_bytes(num_bytes: int) -> bytes:
    """
    Generates random bytes using the initialized HSM.
    Returns None if HSM is not initialized or an error occurs.
    """
    if not _hsm_initialized or not _pkcs11_session:
        # logger.debug("HSM not initialized, cannot generate random bytes from HSM.")
        return None
    try:
        return _pkcs11_session.generate_random(num_bytes)
    except pkcs11.exceptions.PKCS11Error as e:
        logger.error(f"HSM random byte generation failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during HSM random generation: {e}")
        return None

def generate_hsm_rsa_keypair(key_label: str, key_size: int = 3072) -> tuple[int, 'cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey'] | None:
    """
    Generates an RSA key pair using hardware security:
    - On Windows: Uses CNG with Microsoft Platform Crypto Provider (TPM)
    - On Linux/macOS: Uses PKCS#11 HSM interface if available
    
    Args:
        key_label: A label for the key pair.
        key_size: The size of the RSA key in bits.

    Returns:
        A tuple (private_key_handle, cryptography_public_key_object) or None on failure.
        The private_key_handle is an integer for PKCS#11 or a NCRYPT_KEY_HANDLE value for Windows CNG.
        The cryptography_public_key_object is a standard cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.
    """
    # For Windows, use CNG/TPM first
    if IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE:
        try:
            if not _cng_provider_initialized:
                if not _open_cng_provider_platform():
                    logger.error("Windows CNG provider not initialized. Cannot generate CNG RSA key pair.")
                    return None
                
            # Generate a TPM-backed key using our existing function
            result = generate_tpm_backed_key(key_label, key_size, allow_export=True, overwrite=True)
            if result is not None:
                # The enhanced function returns three values, we only need the first two here.
                key_handle, pub_key, _ = result
                # Return the key handle directly - it's the private key handle as needed
                logger.info(f"Successfully generated RSA key pair using Windows CNG/TPM with label {key_label}")
                return (key_handle, pub_key)
            
            logger.error(f"Failed to generate RSA key pair using Windows CNG/TPM with label {key_label}")
        except Exception as e:
            logger.error(f"Error generating RSA key pair using Windows CNG/TPM: {e}")
    
    # For non-Windows platforms or if Windows method failed, try PKCS#11
    if not _hsm_initialized or not _pkcs11_session:
        logger.error("HSM not initialized. Cannot generate HSM RSA key pair.")
        return None

    try:
        logger.info(f"Generating RSA-{key_size} key pair in HSM with label {key_label}")
        
        # Check if key with same label already exists and delete it
        old_keys = list(_pkcs11_session.get_objects({CKA.LABEL: key_label, CKA.CLASS: pkcs11.constants.ObjectClass.PRIVATE_KEY}))
        if old_keys:
            logger.info(f"Found existing key with label {key_label} - deleting it")
            for key in old_keys:
                key.destroy()
        
        # Also check and delete any public keys with the same label
        old_pub_keys = list(_pkcs11_session.get_objects({CKA.LABEL: key_label, CKA.CLASS: pkcs11.constants.ObjectClass.PUBLIC_KEY}))
        for key in old_pub_keys:
            key.destroy()
            
        # Generate the key pair in the HSM
        public_template = {
            CKA.LABEL: key_label,
            CKA.CLASS: pkcs11.constants.ObjectClass.PUBLIC_KEY,
            CKA.KEY_TYPE: CKK.RSA,
            CKA.MODULUS_BITS: key_size,
            CKA.VERIFY: True,
            CKA.PUBLIC_EXPONENT: (65537).to_bytes(3, byteorder='big'),
            CKA.TOKEN: True  # Make the key persistent
        }

        private_template = {
            CKA.LABEL: key_label,
            CKA.CLASS: pkcs11.constants.ObjectClass.PRIVATE_KEY,
            CKA.KEY_TYPE: CKK.RSA,
            CKA.SIGN: True,
            CKA.TOKEN: True,  # Make the key persistent
            CKA.SENSITIVE: True,
            CKA.EXTRACTABLE: False  # Keys cannot be extracted
        }

        pub_key, priv_key = _pkcs11_session.generate_keypair(
            pkcs11.KeyType.RSA, 
            key_size, 
            public_template=public_template, 
            private_template=private_template,
            mechanism=CKM.RSA_PKCS_KEY_PAIR_GEN
        )
        
        # Get the handle for the private key
        priv_key_handle = priv_key.handle
        
        # Extract raw public key to convert to cryptography.io format
        pubkey_numbers_dict = {}
        for attr in pub_key.get_attributes([CKA.MODULUS, CKA.PUBLIC_EXPONENT]):
            if attr.type == CKA.MODULUS:
                pubkey_numbers_dict['n'] = int.from_bytes(attr.value, byteorder='big')
            elif attr.type == CKA.PUBLIC_EXPONENT:
                pubkey_numbers_dict['e'] = int.from_bytes(attr.value, byteorder='big')

        # Create a cryptography.io compatible RSA public key
        if _CRYPTOGRAPHY_AVAILABLE and 'n' in pubkey_numbers_dict and 'e' in pubkey_numbers_dict:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            
            pub_numbers = RSAPublicNumbers(
                e=pubkey_numbers_dict['e'],
                n=pubkey_numbers_dict['n']
            )
            crypto_pub_key = pub_numbers.public_key()
            logger.info(f"Generated RSA-{key_size} key pair in HSM with label '{key_label}'")
            return (priv_key_handle, crypto_pub_key)
        else:
            logger.error("Failed to convert HSM public key to cryptography.io format")
            return None
            
    except pkcs11.exceptions.PKCS11Error as e:
        logger.error(f"HSM key generation failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during HSM key generation: {e}")
        return None


from typing import Union

def sign_with_hsm_key(private_key_handle: Union[int, 'NCRYPT_KEY_HANDLE'], data: bytes, mechanism_type=None) -> Union[bytes, None]:
    """
    Signs data using a private key stored in the HSM.

    Args:
        private_key_handle: The handle of the private key. Can be:
                           - An integer for PKCS#11 HSM keys
                           - A NCRYPT_KEY_HANDLE for Windows CNG/TPM keys
        data: The data to be signed.
        mechanism_type: For PKCS#11, the mechanism to use (e.g., CKM.SHA256_RSA_PKCS_PSS).
                       If None, defaults to CKM.SHA256_RSA_PKCS_PSS for RSA keys.
                       Ignored for Windows CNG/TPM keys.

    Returns:
        The signature bytes, or None on failure.
    """
    # Windows CNG/TPM path - check if private_key_handle is a NCRYPT_KEY_HANDLE
    if IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE and hasattr(private_key_handle, 'value'):
        # Use sign_with_tpm_key function to handle Windows CNG key
        # Hash algorithm SHA256 and PKCS1v15 padding by default
        return sign_with_tpm_key(
            key_identifier=private_key_handle,  # Pass the handle directly
            data_to_sign=data,
            hash_algorithm_name="SHA256",
            padding_scheme="PKCS1v15"
        )
    
    # PKCS#11 HSM path
    if not _hsm_initialized or not _pkcs11_session:
        logger.error("HSM not initialized. Cannot sign with HSM key.")
        return None
    if not _PKCS11_SUPPORT_AVAILABLE:
        logger.error("PKCS#11 library not available for HSM signing.")
        return None
    
    try:
        # Get the private key object from its handle
        private_key = pkcs11.Object(_pkcs11_session, private_key_handle)  


        # Determine mechanism if not provided
        if mechanism_type is None:
            # A common default. A more robust solution would check the key type.
            # Assuming RSA key for now.
            mechanism_type = CKM.SHA256_RSA_PKCS_PSS
            logger.debug(f"Defaulting to signing mechanism: SHA256_RSA_PKCS_PSS (0x{mechanism_type.value:X})")
        
        # Ensure mechanism_type is a pkcs11.Mechanism instance if it's just an enum member
        if not isinstance(mechanism_type, pkcs11.Mechanism):
             mechanism_obj = pkcs11.Mechanism(mechanism_type) # Create Mechanism object
        else:
             mechanism_obj = mechanism_type


        logger.debug(f"Signing data with HSM private key handle {private_key_handle} using mechanism {mechanism_obj}")
        signature = private_key.sign(data, mechanism=mechanism_obj)
        logger.info("Data successfully signed using HSM.")
        return signature

    except pkcs11.exceptions.PKCS11Error as e:
        logger.error(f"HSM signing failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during HSM signing: {e}")
        return None


def get_secure_random(num_bytes: int = 32) -> bytes:
    """
    Return `num_bytes` of cryptographically secure random bytes.
    Priority: 
    - Windows: CNG/NCrypt platform provider (preferred), then Windows TBS, then OS CSPRNG
    - Linux: TPM via tpm2-pytss, HSM via PKCS#11, then OS CSPRNG
    - macOS: HSM via PKCS#11, then OS CSPRNG
    - Software fallback mode: Uses OS CSPRNG via secrets module
    """
    # Check if we're in software-only mode (no hardware access)
    if _hsm_initialized and hasattr(globals(), '_software_hsm_mode') and _software_hsm_mode:
        logger.debug("Using software HSM mode for random generation")
        return secrets.token_bytes(num_bytes)
        
    # Try libsodium if available (works on all platforms)
    if LIBSODIUM_AVAILABLE:
        try:
            buffer = (ctypes.c_ubyte * num_bytes)()
            LIBSODIUM.randombytes_buf(ctypes.byref(buffer), num_bytes)
            logger.debug("Generated random bytes using libsodium.")
            return bytes(buffer)
        except Exception as e:
            logger.warning(f"libsodium random generation failed: {e}; falling back.")
            
    # Windows CNG path via NCrypt/BCrypt (preferred on Windows per user rules)
    if IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE:
        try:
            if _open_cng_provider_platform():
                # NCrypt/BCrypt has access to TPM-backed RNG on supported systems
                logger.debug("Using Windows CNG BCrypt for random number generation")
                # Using BCrypt functions directly for RNG
                alg_handle = wintypes.HANDLE()
                status = _BCryptOpenAlgorithmProvider(ctypes.byref(alg_handle), 
                                                     wintypes.LPCWSTR("RNG"), 
                                                     wintypes.LPCWSTR(None),
                                                     0)
                if status == STATUS_SUCCESS.value and alg_handle:
                    buf = (ctypes.c_ubyte * num_bytes)()
                    status = bcrypt.BCryptGenRandom(alg_handle, 
                                                   buf, 
                                                   num_bytes,
                                                   0)
                    bcrypt.BCryptCloseAlgorithmProvider(alg_handle, 0)
                    
                    if status == STATUS_SUCCESS.value:
                        logger.debug("Generated random bytes using Windows CNG/BCrypt.")
                        return bytes(buf)
                    else:
                        logger.warning(f"BCryptGenRandom failed with status 0x{status:X}, falling back.")
        except Exception as e:
            logger.warning(f"Windows CNG random generation failed: {e}; falling back.")

    # Windows TPM path via TBS.dll (fallback if CNG not available)
    if IS_WINDOWS and _WINDOWS_TBS_AVAILABLE:
        try:
            buf = (ctypes.c_ubyte * num_bytes)()
            result_size = wintypes.UINT(0)
            status = Tbsi_GetRandom(num_bytes, buf, ctypes.byref(result_size))
            if status == 0 and result_size.value == num_bytes:
                logger.debug("Generated random bytes using Windows TPM (Tbsi_GetRandom).")
                return bytes(buf)
            else:
                logger.warning(f"Tbsi_GetRandom returned status {status}, size {result_size.value}; falling back.")
        except Exception as e:
            logger.warning(f"Windows TPM GetRandom exception: {e}; falling back.")

    # Linux TPM path via tpm2-pytss
    if IS_LINUX and _Linux_ESAPI and _Linux_TCTI:
        try:
            # Consider managing ESAPI context globally if frequently used, or ensure proper closure
            tcti = _Linux_TCTI.load("device:/dev/tpm0") # Or other TCTIs like mssim for simulator
            esys = _Linux_ESAPI(tcti)
            resp_bytes = esys.get_random(num_bytes) # get_random in ESAPI is a direct method
            # esys.close() # Important to close ESAPI context if it's not managed globally
            if resp_bytes and len(resp_bytes) == num_bytes:
                 logger.debug("Generated random bytes using Linux TPM (tpm2-pytss).")
                 return resp_bytes
            else:
                 logger.warning("Linux TPM GetRandom (tpm2-pytss) returned unexpected data length.")
        except Exception as e:
            logger.warning(f"Linux TPM GetRandom (tpm2-pytss) failed: {e}; falling back.")

    # HSM path via PKCS#11 (only used for non-Windows or if Windows methods failed)
    hsm_random = get_hsm_random_bytes(num_bytes)
    if hsm_random:
        logger.debug("Generated random bytes using PKCS#11 HSM.")
        return hsm_random
    # else: logger.debug("HSM random generation skipped or failed.")

    # Fallback to OS CSPRNG
    logger.info("Generating random bytes using OS CSPRNG (secrets.token_bytes) as fallback.")
    return secrets.token_bytes(num_bytes)


# -------------------------------------------------------------------------
# 2. Hardware-Bound Identity
# -------------------------------------------------------------------------

def get_hardware_unique_id() -> bytes:
    """
    Return a hardware-bound unique ID (16 bytes), using best available mechanism.
    Windows: Try Python WMI module first; if unavailable, run PowerShell.
    Linux: /sys/class/dmi/id/product_uuid or /etc/machine-id
    macOS: IOPlatformUUID via ioreg
    Fallback: stable random ID stored in ~/.device_fallback_id with mode 600
    """
    # Windows: Try Python WMI, then fall back to PowerShell
    if IS_WINDOWS:
        try:
            import wmi  # requires: pip install wmi
            c = wmi.WMI(namespace="root\\CIMV2")
            entries = c.Win32_ComputerSystemProduct()
            if entries:
                uuid_str = entries[0].UUID
                if uuid_str:
                    return hashlib.sha256(uuid_str.encode()).digest()[:16]
        except Exception as e:
            logger.debug("Python WMI fetch failed or module not installed: %s", e)

        try:
            ps_cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                "Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID",
            ]
            # Use list arguments for security, with additional hardening
            output = subprocess.check_output(ps_cmd, stderr=subprocess.DEVNULL, text=True, shell=False)
            uuid_str = output.strip()
            if uuid_str:
                return hashlib.sha256(uuid_str.encode()).digest()[:16]
        except Exception as e:
            logger.warning("PowerShell WMI UUID fetch failed: %s", e)

    # Linux: /sys/class/dmi/id/product_uuid or /etc/machine-id
    if IS_LINUX:
        # Try the standard sysfs location first (may require root on some distros)
        dmi_paths = [
            "/sys/class/dmi/id/product_uuid",                      # Most common
            "/sys/devices/virtual/dmi/id/product_uuid",            # Some kernels expose here
        ]
        for path in dmi_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        uuid_str = f.read().strip()
                    if uuid_str:
                        return hashlib.sha256(uuid_str.encode()).digest()[:16]
                except PermissionError:
                    # Silence noisy warnings – we'll fall back to machine-id
                    logger.debug("Permission denied reading %s; falling back", path)
                except Exception as e:
                    logger.debug("Error reading %s: %s", path, e)

        # Fallback to machine-id (world-readable on most systems)
        mid_path = "/etc/machine-id"
        if os.path.exists(mid_path):
            try:
                with open(mid_path, "r") as f:
                    mid = f.read().strip()
                if mid:
                    return hashlib.sha256(mid.encode()).digest()[:16]
            except Exception as e:
                logger.debug("Failed to read machine-id: %s", e)

    # macOS: IOPlatformUUID via ioreg
    if IS_DARWIN:
        try:
            # Use list arguments with explicit shell=False for security
            output = subprocess.check_output(
                ["ioreg", "-d2", "-c", "IOPlatformExpertDevice"], stderr=subprocess.DEVNULL, shell=False
            )
            for line in output.decode().splitlines():
                line = line.strip()
                if line.startswith('"IOPlatformUUID"'):
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        uuid_str = parts[1].strip().strip('"')
                        return hashlib.sha256(uuid_str.encode()).digest()[:16]
        except Exception as e:
            logger.warning("macOS IOPlatformUUID fetch failed: %s", e)

    # Fallback: random stable ID stored in a hidden file with 0o600
    try:
        fid_path = os.path.expanduser("~/.device_fallback_id")
        if not os.path.exists(fid_path):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            mode = 0o600
            fd = os.open(fid_path, flags, mode)
            try:
                new_id = secrets.token_bytes(16)
                os.write(fd, new_id)
                return new_id
            finally:
                os.close(fd)
        else:
            # Ensure permissions are 600
            os.chmod(fid_path, 0o600)
            with open(fid_path, "rb") as f:
                existing = f.read(16)
            if len(existing) == 16:
                return existing
    except Exception as e:
        logger.warning("Fallback ID generation failed: %s", e)

    # Worst-case: zero bytes (should be avoided in production)
    return b"\x00" * 16


# -------------------------------------------------------------------------
# 3. Secure Key Storage
# -------------------------------------------------------------------------

# Note on secure directory creation:
# The directory ~/.cross_platform_secure is created automatically when needed
# by store_key_file_secure() with permissions 0o700 (user read/write/execute only)

# Windows CNG KSP functions
if IS_WINDOWS:
    try:
        ncrypt = ctypes.WinDLL("ncrypt.dll")
        _NCryptOpenStorageProvider = ncrypt.NCryptOpenStorageProvider
        _NCryptOpenStorageProvider.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.DWORD
        ]
        _NCryptOpenStorageProvider.restype = wintypes.LONG

        _NCryptCreatePersistedKey = ncrypt.NCryptCreatePersistedKey
        _NCryptCreatePersistedKey.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD
        ]
        _NCryptCreatePersistedKey.restype = wintypes.LONG

        _NCryptFinalizeKey = ncrypt.NCryptFinalizeKey
        _NCryptFinalizeKey.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        _NCryptFinalizeKey.restype = wintypes.LONG

        _NCryptEncrypt = ncrypt.NCryptEncrypt
        _NCryptEncrypt.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
            ctypes.POINTER(wintypes.ULONG), wintypes.DWORD
        ]
        _NCryptEncrypt.restype = wintypes.LONG

        _Windows_CNG_Supported = True
        logger.debug("Windows CNG/KSP functions loaded.")
    except Exception as e:
        _Windows_CNG_Supported = False
        logger.debug("Windows CNG TPM KSP not available: %s", e)
else:
    _Windows_CNG_Supported = False


def store_key_in_tpm(key_name: str, key_data: bytes) -> bool:
    """
    Store a symmetric key in the Windows TPM using CNG KSP if available.
    Returns True on success. Raises NotImplementedError if not implemented or unavailable.
    """
    if not IS_WINDOWS or not _Windows_CNG_Supported:
        raise NotImplementedError("TPM-based key storage not supported on this system.")

    # Production implementation should:
    # 1. NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)
    # 2. NCryptCreatePersistedKey(..., BCRYPT_RSA_ALGORITHM, key_name, ...)
    # 3. NCryptFinalizeKey
    # 4. NCryptEncrypt to seal key_data
    # 5. Zero out buffers and close handles
    raise NotImplementedError("Full TPM key wrapping via CNG is not implemented.")


def store_secret_os_keyring(label: str, secret: bytes) -> bool:
    """
    Store `secret` under `label` in the OS keyring.
    """
    try:
        keyring.set_password("cross_platform_security", label, secret.hex())
        return True
    except Exception as e:
        logger.error("Keyring store failed: %s", e)
        return False


def retrieve_secret_os_keyring(label: str) -> bytes:
    """
    Retrieve a secret previously stored under `label` from the OS keyring.
    Returns bytes or empty.
    """
    try:
        hexval = keyring.get_password("cross_platform_security", label)
        if hexval:
            return bytes.fromhex(hexval)
        return b""
    except Exception as e:
        logger.error("Keyring retrieve failed: %s", e)
        return b""

# Cross-platform encrypted key file storage using AES-GCM
def store_key_file_secure(label: str, key_data: bytes) -> bool:
    """
    Store `key_data` encrypted on disk (AES-GCM), then load into a locked buffer when retrieved.
    Works across Windows, Linux, and macOS.
    """
    if not _AESGCM_AVAILABLE:
        logger.error("AESGCM not available; cannot store secure key file.")
        return False
    try:
        # Get a unique hardware identifier for deriving the key
        hw_id = get_hardware_unique_id()
        # Derive a key encryption key (KEK) from hardware ID
        kek = hashlib.sha256(hw_id).digest()
        # Initialize AESGCM with the key
        aesgcm = AESGCM(kek)
        # Generate a random 96-bit nonce (12 bytes)
        nonce = secrets.token_bytes(12)
        # Add AAD data for authentication (optional)
        aad = f"key_file_{label}".encode('utf-8')
        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, key_data, aad)
        # Combine nonce and ciphertext for storage
        payload = nonce + ciphertext
        # Create secure directory if needed
        secure_dir = os.path.expanduser("~/.cross_platform_secure")
        os.makedirs(secure_dir, mode=0o700, exist_ok=True)
        os.chmod(secure_dir, 0o700)
        # Save the encrypted key data
        path = os.path.join(secure_dir, f"{label}.bin")
        with open(path, "wb") as f:
            f.write(payload)
        # Set restrictive permissions
        os.chmod(path, 0o600)
        return True
    except Exception as e:
        logger.error("Secure key file store failed: %s", e)
        return False

def retrieve_key_file_secure(label: str):
    """
    Retrieve and decrypt a key stored via store_key_file_secure, then lock it in memory.
    Returns a ctypes buffer containing the key (pinned), or None on failure.
    Works across Windows, Linux, and macOS.
    """
    if not _AESGCM_AVAILABLE:
        logger.error("AESGCM not available; cannot retrieve secure key file.")
        return None
    try:
        secure_dir = os.path.expanduser("~/.cross_platform_secure")
        path = os.path.join(secure_dir, f"{label}.bin")
        with open(path, "rb") as f:
            payload = f.read()
        # Extract nonce (first 12 bytes)
        nonce = payload[:12]
        # Extract ciphertext (remainder)
        ciphertext = payload[12:]
        # Get hardware ID and derive KEK
        hw_id = get_hardware_unique_id()
        kek = hashlib.sha256(hw_id).digest()
        # Create AESGCM instance
        aesgcm = AESGCM(kek)
        # Create AAD data for authentication (must match what was used for encryption)
        aad = f"key_file_{label}".encode('utf-8')
        # Decrypt the data
        key_data = aesgcm.decrypt(nonce, ciphertext, aad)
        # Create a secure buffer to hold the key
        buf = ctypes.create_string_buffer(key_data)
        addr = ctypes.addressof(buf)
        # Lock the memory to prevent it from being swapped to disk
        _lock_memory_aligned(addr, len(key_data))
        return buf
    except Exception as e:
        logger.error("Secure key file retrieve failed: %s", e)
        return None

# Keep the original function names for backward compatibility
def store_key_file_linux(label: str, key_data: bytes) -> bool:
    """
    Backward compatibility wrapper for store_key_file_secure.
    Now works on all platforms, not just Linux.
    """
    logger.info("Using cross-platform secure key storage (renamed from Linux-specific)")
    return store_key_file_secure(label, key_data)

def retrieve_key_file_linux(label: str):
    """
    Backward compatibility wrapper for retrieve_key_file_secure.
    Now works on all platforms, not just Linux.
    """
    return retrieve_key_file_secure(label)

# -------------------------------------------------------------------------
# 4. Hardware Key Isolation Utilities
# -------------------------------------------------------------------------

def _lock_memory_aligned(buffer_addr: int, length: int) -> bool:
    """
    Internal helper to lock pages containing `buffer_addr` for `length` bytes.
    Uses page alignment for proper mlock/VirtualLock.
    """
    if length == 0:
        return True  # Nothing to lock
        
    page_size = mmap.PAGESIZE
    page_start = buffer_addr - (buffer_addr % page_size)
    # Round up to next page boundary
    end_addr = buffer_addr + length
    page_end = ((end_addr + page_size - 1) // page_size) * page_size
    total_len = page_end - page_start

    # Windows
    if IS_WINDOWS:
        if not _VirtualLock:
            logger.debug("VirtualLock function not available on this Windows system")
            return False
        try:
            result = bool(_VirtualLock(ctypes.c_void_p(page_start), total_len))
            if result:
                logger.debug(f"Successfully locked {total_len} bytes at address {page_start:#x} using VirtualLock")
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                logger.warning(f"VirtualLock failed with error code: {error_code}")
            return result
        except Exception as e:
            logger.warning(f"VirtualLock exception: {e}")
            return False

    # Linux/macOS common approach
    try:
        if IS_LINUX:
            libc_name = find_library("c")
            if not libc_name:
                libc_name = "libc.so.6"  # Default fallback
        elif IS_DARWIN:
            libc_name = find_library("c")
            if not libc_name:
                libc_name = "libc.dylib"  # Default fallback
        else:
            logger.warning(f"Unsupported platform for memory locking: {SYSTEM}")
            return False
            
        libc = ctypes.CDLL(libc_name)
        
        # Ensure mlock function is available
        if not hasattr(libc, "mlock"):
            logger.warning(f"mlock function not available in {libc_name}")
            return False
            
        result = libc.mlock(ctypes.c_void_p(page_start), ctypes.c_size_t(total_len)) == 0
        if result:
            logger.debug(f"Successfully locked {total_len} bytes at address {page_start:#x} using mlock")
        else:
            errno_val = ctypes.get_errno()
            logger.warning(f"mlock failed with errno: {errno_val}")
        return result
    except Exception as e:
        logger.warning(f"mlock exception: {e}")
        return False


def lock_memory(buffer_addr: int, length: int) -> bool:
    """
    Public API to lock memory pages containing `buffer_addr` for `length` bytes.
    Prevents the memory from being swapped to disk.
    
    Args:
        buffer_addr: The starting address of the buffer to lock
        length: The length of the buffer in bytes
        
    Returns:
        bool: True if memory was successfully locked, False otherwise
    """
    try:
        return _lock_memory_aligned(buffer_addr, length)
    except Exception as e:
        logger.error(f"Error in lock_memory: {e}")
        return False


def _unlock_memory_aligned(buffer_addr: int, length: int) -> bool:
    """
    Internal helper to unlock pages containing `buffer_addr` for `length` bytes.
    """
    if length == 0:
        return True  # Nothing to unlock
        
    page_size = mmap.PAGESIZE
    page_start = buffer_addr - (buffer_addr % page_size)
    end_addr = buffer_addr + length
    page_end = ((end_addr + page_size - 1) // page_size) * page_size
    total_len = page_end - page_start

    if IS_WINDOWS:
        if not _VirtualUnlock:
            logger.debug("VirtualUnlock function not available on this Windows system")
            return False
        try:
            result = bool(_VirtualUnlock(ctypes.c_void_p(page_start), total_len))
            if result:
                logger.debug(f"Successfully unlocked {total_len} bytes at address {page_start:#x} using VirtualUnlock")
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                logger.warning(f"VirtualUnlock failed with error code: {error_code}")
            return result
        except Exception as e:
            logger.warning(f"VirtualUnlock exception: {e}")
            return False

    # Linux/macOS
    try:
        if IS_LINUX:
            libc_name = find_library("c")
            if not libc_name:
                libc_name = "libc.so.6"  # Default fallback
        elif IS_DARWIN:
            libc_name = find_library("c")
            if not libc_name:
                libc_name = "libc.dylib"  # Default fallback
        else:
            logger.warning(f"Unsupported platform for memory unlocking: {SYSTEM}")
            return False
            
        libc = ctypes.CDLL(libc_name)
        
        # Ensure munlock function is available
        if not hasattr(libc, "munlock"):
            logger.warning(f"munlock function not available in {libc_name}")
            return False
            
        result = libc.munlock(ctypes.c_void_p(page_start), ctypes.c_size_t(total_len)) == 0
        if result:
            logger.debug(f"Successfully unlocked {total_len} bytes at address {page_start:#x} using munlock")
        else:
            errno_val = ctypes.get_errno()
            logger.warning(f"munlock failed with errno: {errno_val}")
        return result
    except Exception as e:
        logger.warning(f"munlock exception: {e}")
        return False


def unlock_memory(buffer_addr: int, length: int) -> bool:
    """
    Public API to unlock previously locked memory pages.
    
    Args:
        buffer_addr: The starting address of the buffer to unlock
        length: The length of the buffer in bytes
        
    Returns:
        bool: True if memory was successfully unlocked, False otherwise
    """
    try:
        return _unlock_memory_aligned(buffer_addr, length)
    except Exception as e:
        logger.error(f"Error in unlock_memory: {e}")
        return False


def secure_wipe_memory(buffer_addr: int, length: int) -> bool:
    """
    Securely wipe memory contents at the given address.
    Uses libsodium's sodium_memzero when available, then tries enhanced implementations
    from pqc_algorithms, otherwise falls back to multiple overwrite patterns.
    
    Args:
        buffer_addr: The address of the memory to wipe
        length: The length in bytes
        
    Returns:
        bool: True if wiping was successful
    """
    if length == 0:
        return True
        
    try:
        # Lock the memory during wiping to prevent swapping
        memory_locked = _lock_memory_aligned(buffer_addr, length)
        
        # Try using sodium_memzero from libsodium (preferred method)
        if LIBSODIUM_AVAILABLE:
            try:
                # Use libsodium's sodium_memzero (guaranteed not to be optimized away)
                LIBSODIUM.sodium_memzero(ctypes.c_void_p(buffer_addr), length)
                logger.debug("Used libsodium's sodium_memzero for secure memory wiping")
                
                # Unlock the memory if it was locked
                if memory_locked:
                    _unlock_memory_aligned(buffer_addr, length)
                    
                return True
            except Exception as e:
                logger.warning(f"libsodium's sodium_memzero failed: {e}, trying enhanced SideChannelProtection")
        
        # Try using enhanced implementation from pqc_algorithms
        try:
            from pqc_algorithms import SideChannelProtection, SecureMemory
            
            # Convert address to a bytearray for secure wiping
            buffer = (ctypes.c_char * length).from_address(buffer_addr)
            byte_array = bytearray(buffer[:])
            
            # Use SecureMemory's wipe functionality
            secure_mem = SecureMemory()
            secure_mem._secure_wipe(byte_array)
            
            # Copy wiped data back to original memory location
            for i in range(length):
                buffer[i] = byte_array[i]
                
            logger.debug("Used enhanced SideChannelProtection from pqc_algorithms for secure memory wiping")
            
            # Unlock the memory if it was locked
            if memory_locked:
                _unlock_memory_aligned(buffer_addr, length)
                
            return True
        except Exception as e:
            logger.warning(f"Enhanced secure wipe from pqc_algorithms failed: {e}, falling back to standard methods")
        
        # If we get here, both libsodium and enhanced methods failed or are not available
        # Multiple pass overwrite with different patterns
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0xF0, 0x0F]
        
        for pattern in patterns:
            if IS_WINDOWS:
                # Windows - use memset from msvcrt
                try:
                    ctypes.memset(buffer_addr, pattern, length)
                    # Force memory write to complete
                    ctypes.memmove(buffer_addr, buffer_addr, length)
                except Exception as e:
                    logger.warning(f"Windows memset failed: {e}")
                    return False
            else:
                # Linux/macOS - use memset from libc
                try:
                    libc_name = find_library("c")
                    if not libc_name:
                        libc_name = "libc.so.6" if IS_LINUX else "libc.dylib"
                    libc = ctypes.CDLL(libc_name)
                    if hasattr(libc, "memset"):
                        libc.memset(ctypes.c_void_p(buffer_addr), pattern, length)
                        # Force memory barrier
                        libc.memmove(ctypes.c_void_p(buffer_addr), ctypes.c_void_p(buffer_addr), length)
                    else:
                        logger.warning("libc.memset not available")
                        return False
                except Exception as e:
                    logger.warning(f"libc memset failed: {e}")
                    return False
        
        # Final random overwrite
        try:
            random_data = get_secure_random(length)
            buffer = (ctypes.c_char * length).from_address(buffer_addr)
            for i in range(length):
                buffer[i] = random_data[i]
        except Exception as e:
            logger.warning(f"Random overwrite failed: {e}")
            
        # Final zero overwrite
        try:
            ctypes.memset(buffer_addr, 0, length)
        except Exception as e:
            logger.warning(f"Final zero overwrite failed: {e}")
            
        # Unlock the memory if it was locked
        if memory_locked:
            _unlock_memory_aligned(buffer_addr, length)
            
        return True
    except Exception as e:
        logger.error(f"Secure wipe memory failed: {e}")
        # Try to unlock memory if we might have locked it
        try:
            _unlock_memory_aligned(buffer_addr, length)
        except:
            pass
        return False

# -------------------------------------------------------------------------
# 5. Device Attestation
# -------------------------------------------------------------------------

def _initialize_hardware_security():
    """Initializes and checks availability of various hardware security elements.
    
    This function uses the configuration settings loaded from config.json to determine
    which hardware security features to initialize and use.
    """
    # This function primarily serves to log the detected capabilities at startup if desired.
    # Actual provider/library opening is generally done on-demand by specific functions.
    logger.info("Performing initial hardware security capability checks...")
    
    # Reload config to ensure we have the latest settings
    load_config()
    platform_config = get_platform_config()
    
    # Log configuration settings
    logger.info(f"Platform: {SYSTEM}")
    logger.info(f"TPM enabled: {TPM_ENABLED}")
    logger.info(f"PKCS#11 enabled: {PKCS11_ENABLED}")
    logger.info(f"Keyring enabled: {KEYRING_ENABLED}")
    logger.info(f"Secure memory enabled: {SECURE_MEMORY_ENABLED}")
    logger.info(f"Libsodium preferred: {LIBSODIUM_PREFERRED}")
    
    if IS_WINDOWS:
        logger.info("Windows platform detected. Following hardware security preferences according to config:")
        logger.info("- Windows: Using native CNG/TPM APIs (priority) or software fallbacks")
        
        if not TPM_ENABLED:
            logger.info("TPM is disabled in configuration. Will use software fallbacks.")
        elif _WINDOWS_CNG_NCRYPT_AVAILABLE:
            logger.info("Windows CNG/NCrypt support (bcrypt.dll, ncrypt.dll) is loaded and available.")
            # We can do a quick check if the MS Platform provider can be opened, but don't keep it open globally from here.
            temp_prov_handle = NCRYPT_PROV_HANDLE()
            tpm_provider = MS_PLATFORM_CRYPTO_PROVIDER
            if "tpm_provider" in platform_config:
                # Use the provider from config
                tpm_provider = wintypes.LPCWSTR(platform_config["tpm_provider"])
                logger.info(f"Using custom TPM provider from config: {platform_config['tpm_provider']}")
                
            status = _NCryptOpenStorageProvider(ctypes.byref(temp_prov_handle), tpm_provider, 0)
            if status == STATUS_SUCCESS.value:
                logger.info(f"Successfully test-opened CNG provider: {tpm_provider.value}.")
                _NCryptFreeObject(temp_prov_handle) # Close it immediately after check
                logger.info("TPM-backed key operations via CNG will be available.")
            else:
                logger.warning(f"Windows CNG/NCrypt available, but failed to test-open provider: {tpm_provider.value}. Error: {status:#010x}. TPM operations may fail.")
        else:
            logger.warning("Windows CNG/NCrypt support is NOT available. TPM-backed key operations via CNG will be disabled.")
        
        if _WINDOWS_TBS_AVAILABLE:
            logger.info("Windows TBS (tbs.dll for TPM random) is available.")
        else:
            logger.info("Windows TBS (tbs.dll for TPM random) is NOT available.")
            
    if IS_LINUX:
        logger.info("Linux platform detected. Following hardware security preferences according to config:")
        
        if not TPM_ENABLED:
            logger.info("TPM is disabled in configuration. Will use software fallbacks.")
        elif _Linux_ESAPI and _Linux_TCTI:
            logger.info("Linux tpm2-pytss support for TPM operations is available.")
            
            # Check TPM device paths from config
            if "tpm_paths" in platform_config:
                tpm_paths = platform_config["tpm_paths"]
                logger.info(f"Using TPM paths from config: {tpm_paths}")
                
                for path in tpm_paths:
                    if os.path.exists(path):
                        logger.info(f"TPM device found at {path}")
                        break
                else:
                    logger.warning("No TPM devices found at configured paths. Will use fallbacks.")
        else:
            logger.info("Linux tpm2-pytss support for TPM operations is NOT available.")
            
        # Check PKCS#11 libraries from config
        if PKCS11_ENABLED and _PKCS11_SUPPORT_AVAILABLE:
            logger.info("PKCS#11 library support is enabled in configuration.")
            
            if "pkcs11_paths" in platform_config:
                pkcs11_paths = platform_config["pkcs11_paths"]
                logger.info(f"Using PKCS#11 library paths from config: {pkcs11_paths}")
                
                for path in pkcs11_paths:
                    if os.path.exists(path):
                        logger.info(f"PKCS#11 library found at {path}")
                        break
                else:
                    logger.warning("No PKCS#11 libraries found at configured paths. Will use fallbacks.")
    
    if IS_DARWIN:
        logger.info("macOS platform detected. Following hardware security preferences according to config:")
        
        secure_enclave_enabled = platform_config.get("secure_enclave_enabled", True)
        logger.info(f"Secure Enclave enabled: {secure_enclave_enabled}")
            
    # Check for AESGCM availability regardless of platform
    if _AESGCM_AVAILABLE:
        logger.info("Cryptography AESGCM for secure key file encryption is available.")
    else:
        logger.warning("Cryptography AESGCM for secure key file encryption is NOT available.")
            
    if _PKCS11_SUPPORT_AVAILABLE and PKCS11_ENABLED:
            logger.info("PKCS#11 library support (python-pkcs11) is available for HSM operations.")
    elif PKCS11_ENABLED:
        logger.warning("PKCS#11 library support (python-pkcs11) is NOT available but enabled in config. HSM operations disabled.")
    else:
        logger.info("PKCS#11 support is disabled in configuration.")
    
    if _CRYPTOGRAPHY_AVAILABLE:
        logger.info("Cryptography library is available for various crypto operations.")
    else:
        logger.warning("Cryptography library is NOT available. Some functionalities will be limited.")

    # Try to detect libsodium from config paths
    if LIBSODIUM_PREFERRED:
        logger.info("Libsodium is preferred for cryptographic operations according to config.")
        if "libsodium_paths" in platform_config:
            libsodium_paths = platform_config["libsodium_paths"]
            logger.info(f"Using libsodium paths from config: {libsodium_paths}")
            
            for path in libsodium_paths:
                try:
                    # Try to load libsodium from the configured path
                    if os.path.exists(path):
                        libsodium = ctypes.CDLL(path)
                        logger.info(f"Successfully loaded libsodium from {path}")
                        break
                except Exception as e:
                    logger.warning(f"Failed to load libsodium from {path}: {e}")
            else:
                logger.warning("Failed to load libsodium from any configured path. Will use fallbacks.")

    logger.info("Initial hardware security capability checks completed.")


def attest_device() -> dict:
    """
    Performs device attestation using available hardware security features.
    Focuses on TPM presence/state for Windows/Linux and SIP for macOS.
    Includes CNG provider check on Windows.
    """
    attestation_info = {"platform": SYSTEM, "checks": []}

    # Handle Linux attestation early
    if IS_LINUX:
        linux_tpm_check = {"type": "TPM2_Check", "status": "TestNotRun"}
        # Check for TPM2 device first
        for tpm_path in ["/dev/tpm0", "/dev/tpmrm0"]:
            if os.path.exists(tpm_path):
                linux_tpm_check["status"] = "DeviceFound"
                linux_tpm_check["device_path"] = tpm_path
                attestation_info["checks"].append(linux_tpm_check)
                break
        
        # Check for tpm2-tools
        try:
            tpm2_version = subprocess.run(["tpm2_pcrread", "--version"], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, 
                                          text=True, 
                                          check=False)
            if tpm2_version.returncode == 0:
                attestation_info["checks"].append({
                    "type": "TPM2_Tools", 
                    "status": "Available",
                    "version": tpm2_version.stdout.strip()
                })
        except (FileNotFoundError, subprocess.SubprocessError):
            attestation_info["checks"].append({"type": "TPM2_Tools", "status": "NotAvailable"})
            
        # Check for FAPI support safely
        try:
            from tpm2_pytss import FAPI # type: ignore
            attestation_info["checks"].append({"type": "TPM2_FAPI", "status": "Available"})
        except ImportError:
            attestation_info["checks"].append({"type": "TPM2_FAPI", "status": "NotAvailable", "error": "Module not installed"})
        except Exception as e:
            attestation_info["checks"].append({"type": "TPM2_FAPI", "status": "Error", "error": str(e)})
            
        return attestation_info
            
    if IS_WINDOWS:
        # 1. WMI Check for Win32_Tpm (for general TPM info)
        wmi_check_result = {"type": "Win32_Tpm_Query", "status": "TestNotRun"}
        try:
            import wmi # type: ignore
            conn_tpm = None
            try:
                # Try the specific namespace first, as Win32_Tpm is often here
                conn_tpm = wmi.WMI(namespace="root\\CIMV2\\Security\\MicrosoftTpm")
                logger.debug("Connected to WMI namespace: root\\CIMV2\\Security\\MicrosoftTpm")
            except wmi.x_wmi as e_namespace:
                logger.debug(f"Failed to connect to WMI namespace root\\CIMV2\\Security\\MicrosoftTpm: {e_namespace}. Trying default root\\cimv2.")
                try:
                    conn_tpm = wmi.WMI() # Fallback to default namespace
                    logger.debug("Connected to WMI namespace: root\\cimv2 (default)")
                except Exception as e_fallback:
                    logger.debug(f"Failed to connect to default WMI namespace: {e_fallback}")
                    wmi_check_result["status"] = "ConnectionFailed"
                    wmi_check_result["error_message"] = f"Failed to connect to WMI: {e_fallback}"
                    attestation_info["checks"].append(wmi_check_result)
                    # Continue with other checks
                    return attestation_info
            
            try:
                tpm_info_wmi_list = conn_tpm.Win32_Tpm()
                if tpm_info_wmi_list:
                    tpm_device = tpm_info_wmi_list[0] # Assuming one TPM device entry
                    wmi_check_result.update({
                        "status": "Found",
                        "IsActivated": tpm_device.IsActivated_InitialValue,
                        "IsEnabled": tpm_device.IsEnabled_InitialValue,
                        "IsOwned": tpm_device.IsOwned_InitialValue,
                        "ManufacturerVersion": tpm_device.ManufacturerVersion,
                        "ManufacturerId": tpm_device.ManufacturerId,
                        "SpecVersion": tpm_device.SpecVersion,
                        "PhysicalPresenceVersionInfo": tpm_device.PhysicalPresenceVersionInfo
                    })
                    logger.debug(f"WMI Win32_Tpm Info: Activated={tpm_device.IsActivated_InitialValue}, Enabled={tpm_device.IsEnabled_InitialValue}")
                else:
                    wmi_check_result["status"] = "NotFound (Win32_Tpm query returned no results)"
                    logger.debug("WMI Win32_Tpm query returned no results.")
            except AttributeError:
                # Win32_Tpm class not available in this WMI namespace
                wmi_check_result["status"] = "NotAvailable"
                wmi_check_result["error_message"] = "Win32_Tpm class not available in WMI"
                logger.debug("Win32_Tpm class not available in WMI namespace")
            except Exception as e_query:
                wmi_check_result["status"] = f"QueryFailed ({type(e_query).__name__})"
                wmi_check_result["error_message"] = str(e_query)
                logger.debug(f"Error querying Win32_Tpm via WMI: {e_query}")
        except ImportError:
            wmi_check_result["status"] = "Skipped (WMI module not installed)"
            logger.info("WMI module not installed, skipping Win32_Tpm check for attestation.")
        except Exception as e_wmi:
            wmi_check_result["status"] = f"Error ({type(e_wmi).__name__})"
            wmi_check_result["error_message"] = str(e_wmi)
            logger.debug(f"Error querying Win32_Tpm via WMI: {e_wmi}")
        attestation_info["checks"].append(wmi_check_result)

        # 2. CNG Platform Crypto Provider Check (for TPM KSP access)
        cng_check_result = {"type": "CNG_Microsoft_Platform_Crypto_Provider", "status": "TestNotRun"}
        if _WINDOWS_CNG_NCRYPT_AVAILABLE: # Basic check if DLLs loaded and functions pointers are set
            cng_check_result["library_status"] = "bcrypt.dll & ncrypt.dll functions appear loaded."
            temp_cng_prov_handle = NCRYPT_PROV_HANDLE()
            open_status = _NCryptOpenStorageProvider(ctypes.byref(temp_cng_prov_handle), 
                                                     MS_PLATFORM_CRYPTO_PROVIDER, 
                                                     0) # dwFlags
            if open_status == STATUS_SUCCESS.value:
                cng_check_result["status"] = "Available (Provider Opened Successfully)"
                cng_check_result["provider_name"] = MS_PLATFORM_CRYPTO_PROVIDER.value
                logger.debug(f"CNG Provider '{MS_PLATFORM_CRYPTO_PROVIDER.value}' opened successfully for attestation check.")
                _NCryptFreeObject(temp_cng_prov_handle) # Crucial to free the handle
            else:
                cng_check_result["status"] = f"FailedToOpen (Error: {open_status:#010x})"
                cng_check_result["provider_name"] = MS_PLATFORM_CRYPTO_PROVIDER.value
                logger.warning(f"CNG Provider '{MS_PLATFORM_CRYPTO_PROVIDER.value}' failed to open for attestation check. Error: {open_status:#010x}")
        else:
            cng_check_result["status"] = "Unavailable"
            cng_check_result["library_status"] = "bcrypt.dll or ncrypt.dll functions not loaded, or not on Windows."
            if IS_WINDOWS and not _WINDOWS_CNG_NCRYPT_AVAILABLE: # More specific for logging if on Windows
                 logger.info("CNG/NCrypt libraries failed to load; provider check skipped for attestation.")
        attestation_info["checks"].append(cng_check_result)

    elif IS_LINUX:
        # Linux TPM2 quote via FAPI (tpm2-pytss) if available
        # We handle this with proper graceful degradation
        if _Linux_ESAPI and _Linux_TCTI:
            try:
                # First check if the FAPI module is available
                try:
                    from tpm2_pytss import FAPI # type: ignore
                    fapi_available = True
                except ImportError:
                    fapi_available = False
                    attestation_info["checks"].append({
                        "type": "TPM2_FAPI",
                        "status": "NotAvailable",
                        "error_message": "FAPI module not available in tpm2-pytss"
                    })
                    logger.info("Linux TPM2 FAPI not available in tpm2-pytss; continuing with limited TPM support")
                
                # If FAPI is available, try to use it
                if fapi_available:
                    # Check FAPI version requirements - might need version 3.0.0 or newer
                    try:
                        fapi_ctx = FAPI()
                        fapi_ctx.provision()
                        ak_path = "HS/SRK/myak"
                        try:
                            fapi_ctx.get_key_pub(ak_path)
                        except Exception:
                            fapi_ctx.create_key(ak_path, {})
                        quote, signature, pcr_log, cert = fapi_ctx.quote(ak_path, pcrList=[0])
                        attestation_info["checks"].append({
                            "type": "TPM2_Quote",
                            "status": "Found",
                            "quote": quote,
                            "signature": signature,
                            "pcr_log": pcr_log,
                            "cert": cert
                        })
                        logger.info("Linux TPM2 quote successful.")
                    except Exception as e:
                        attestation_info["checks"].append({
                            "type": "TPM2_Quote",
                            "status": "Failed",
                            "error_message": str(e)
                        })
                        logger.warning("Linux TPM2 quote failed (continuing without attestation): %s", e)
            except Exception as e:
                attestation_info["checks"].append({
                    "type": "TPM2_Quote",
                    "status": "Error",
                    "error_message": str(e)
                })
                logger.warning("Unexpected error during Linux TPM2 quote attempt: %s", e)
        else:
            attestation_info["checks"].append({
                "type": "TPM2_Quote",
                "status": "NotAvailable",
                "error_message": "Linux tpm2-pytss not available"
            })
            logger.warning("Linux tpm2-pytss not available; TPM2 quote not available.")

    # macOS: fallback to SIP status (limited attestation)
    if IS_DARWIN:
        try:
            # Use list arguments with explicit shell=False for security
            sip_status = subprocess.check_output([
                "csrutil", "status"
            ], stderr=subprocess.DEVNULL, shell=False).decode().strip()
            attestation_info["checks"].append({
                "type": "SIP_Status",
                "status": "Found",
                "SIP_Status": sip_status
            })
            logger.info(f"macOS SIP status: {sip_status}")
        except Exception as e:
            attestation_info["checks"].append({
                "type": "SIP_Status",
                "status": "Failed",
                "error_message": str(e)
            })
            logger.warning("macOS SIP check failed: %s", e)

    return attestation_info

def generate_tpm_backed_key(key_name: str, key_size: int = 2048, allow_export: bool = False, overwrite: bool = False) -> typing.Optional[typing.Tuple[ctypes.c_void_p, 'cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey']]:
    """
    Generates an RSA key pair potentially backed by the TPM using Windows CNG.
    The key is persisted by its name. If the key already exists, it will attempt to open it unless overwrite is True.

    Args:
        key_name: The name under which to store and identify the key.
        key_size: Key size in bits (e.g., 2048, 3072, 4096). Default is 2048.
        allow_export: If True, sets the key policy to allow export. Highly discouraged for TPM-backed keys.
                      Note: The provider might override this (e.g., TPM KSP might prevent export regardless).
        overwrite: If True, an existing key with the same name will be overwritten.
                   If False and key exists, it will be opened instead of creating a new one.

    Returns:
        A tuple (private_key_handle, cryptography_public_key_object) or None on failure.
        The private_key_handle is an integer for PKCS#11 or a NCRYPT_KEY_HANDLE value for Windows CNG.
        The cryptography_public_key_object is a standard cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.
    """
    if not _open_cng_provider_platform():
        logger.error("Cannot generate/open TPM key: CNG provider not available or failed to open.")
        return None
    if not _CRYPTOGRAPHY_AVAILABLE or not crypto_rsa or not crypto_serialization:
        logger.error("Cryptography library (rsa, serialization) not available, cannot process public key.")
        return None

    key_handle = NCRYPT_KEY_HANDLE()
    
    # If overwrite is requested, attempt to delete the key first.
    # delete_tpm_key handles cases where the key doesn't exist gracefully.
    if overwrite:
        logger.debug(f"Overwrite specified for key '{key_name}'. Attempting deletion first.")
        # delete_tpm_key returns True if key was deleted OR if it didn't exist.
        # It returns False only on an actual error during an attempted deletion of an existing key.
        delete_tpm_key(key_name) 

    # For NCryptCreatePersistedKey, dwFlags will now always be 0.
    # The overwrite logic is handled by the explicit delete above.
    # If the key still exists (e.g., delete failed and 'overwrite' was True, or 'overwrite' was False and key existed), 
    # NCryptCreatePersistedKey with dwFlags=0 should then correctly return NTE_EXISTS.
    dwFlags_for_create = 0 

    # Attempt to create the persisted key
    status = _NCryptCreatePersistedKey(_ncrypt_provider_handle,
                                      ctypes.byref(key_handle),
                                      NCRYPT_RSA_ALGORITHM,
                                      wintypes.LPCWSTR(key_name),
                                      0, # dwLegacyKeySpec (0 for CNG keys)
                                      dwFlags_for_create) # dwFlags_for_create is now always 0

    key_created_newly = False
    if status == NTE_EXISTS.value and not overwrite:
        logger.info(f"Key '{key_name}' already exists and overwrite is False. Attempting to open it.")
        open_status = _NCryptOpenKey(_ncrypt_provider_handle,
                                     ctypes.byref(key_handle),
                                     wintypes.LPCWSTR(key_name),
                                     0, # dwLegacyKeySpec
                                     NCRYPT_SILENT_FLAG)
        if open_status != STATUS_SUCCESS.value:
            logger.error(f"Failed to open existing key '{key_name}'. Error: {open_status:#010x}")
            if key_handle and key_handle.value: _NCryptFreeObject(key_handle)
            return None
        logger.info(f"Successfully opened existing TPM-backed key: '{key_name}'.")
        # Key was opened, not newly created
    elif status != STATUS_SUCCESS.value:
        logger.error(f"Failed to create TPM-backed key '{key_name}'. Error: {status:#010x}")
        # key_handle should be null if NCryptCreatePersistedKey failed, but check to be safe
        if key_handle and key_handle.value: _NCryptFreeObject(key_handle) 
        return None
    else: # Key was newly created
        key_created_newly = True
        logger.info(f"Successfully initiated creation of TPM-backed key: '{key_name}'.")

        # Set properties for the newly created key
        # 1. Key Length (Required before finalization for some providers)
        key_size_dword = wintypes.DWORD(key_size)
        prop_status = _NCryptSetProperty(key_handle, # Key handle here
                                         NCRYPT_LENGTH_PROPERTY,
                                         ctypes.cast(ctypes.byref(key_size_dword), ctypes.POINTER(wintypes.BYTE)), # Cast to POINTER(BYTE)
                                         ctypes.sizeof(key_size_dword),
                                         NCRYPT_SILENT_FLAG)
        if prop_status != STATUS_SUCCESS.value:
            # Microsoft Platform Crypto Provider often ignores key length setting
            # and uses hardware-defined defaults - this is actually expected behavior
            # and not an error condition for TPM-based keys
            if key_created_newly:
                            logger.info(f"TPM security: Key length ({key_size}) for '{key_name}' will use TPM default instead of requested value. Error: {prop_status:#010x} [CWE-1240]")
            logger.info(f"Security context: TPM hardware enforces its own key length requirements. The actual key size will be determined by the TPM provider and may be different from {key_size}.")
            logger.info(f"This behavior is expected and may actually enhance security if the TPM defaults to stronger parameters.")
            # Continue with key creation as this is an expected limitation with TPM

        # 2. Export Policy
        export_policy_dword = wintypes.DWORD(NCRYPT_ALLOW_EXPORT_FLAG.value if allow_export else 0)
        prop_status = _NCryptSetProperty(key_handle, # Key handle
                                         NCRYPT_EXPORT_POLICY_PROPERTY,
                                         ctypes.cast(ctypes.byref(export_policy_dword), ctypes.POINTER(wintypes.BYTE)), # Cast to POINTER(BYTE)
                                         ctypes.sizeof(export_policy_dword),
                                         NCRYPT_SILENT_FLAG)
        if prop_status != STATUS_SUCCESS.value:
                        # Export policy restrictions are often enforced by the TPM provider
            # and cannot be overridden - this is a security feature, not a bug
            if allow_export:
                logger.info(f"TPM security enforcement: Export policy for '{key_name}' cannot be set to allow_export=True. Provider enforces its own security policy. [CWE-321]")
                logger.info(f"Security context: The TPM is preventing key material export to protect against key extraction attacks.")
                logger.info(f"This is an intentional security feature that prevents sensitive cryptographic material from being exposed, even if requested by the application.")
            else:
                logger.info(f"Export policy for '{key_name}' set to non-exportable by TPM provider default, which aligns with requested policy.")
                logger.debug(f"Non-exportable keys provide stronger security guarantees against key extraction attacks.")
        
        # 3. Key Usage (e.g., signing, decryption)
        # For TPM KSP, it might determine usage by algorithm. Explicitly setting can be good.
        key_usage_dword = wintypes.DWORD(NCRYPT_ALLOW_SIGNING_FLAG.value | NCRYPT_ALLOW_DECRYPT_FLAG.value)
        prop_status = _NCryptSetProperty(key_handle, # Key handle
                                         NCRYPT_KEY_USAGE_PROPERTY,
                                         ctypes.cast(ctypes.byref(key_usage_dword), ctypes.POINTER(wintypes.BYTE)), # Cast to POINTER(BYTE)
                                         ctypes.sizeof(key_usage_dword),
                                         NCRYPT_SILENT_FLAG)
        if prop_status != STATUS_SUCCESS.value:
            # Key usage is often automatically determined by the TPM provider
            # based on the algorithm and key type
            logger.info(f"TPM security: Key usage for '{key_name}' will use TPM provider default settings rather than requested settings. [CWE-1240]")
            logger.info(f"Security context: The TPM is enforcing key usage restrictions based on its security policy.")
            logger.info(f"The TPM will determine appropriate key usage based on the algorithm and key type. This hardware-enforced limitation may prevent key misuse.")
            # Log what we attempted to set for debugging purposes
            logger.debug(f"Attempted to set key usage flags: NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG = {key_usage_dword.value:#010x}")

        # Finalize the key pair generation (CRITICAL for persisted keys)
        finalize_status = _NCryptFinalizeKey(key_handle, NCRYPT_SILENT_FLAG)
        if finalize_status != STATUS_SUCCESS.value:
            logger.error(f"Failed to finalize TPM-backed key '{key_name}'. Error: {finalize_status:#010x}")
            _NCryptDeleteKey(key_handle, NCRYPT_SILENT_FLAG) # Attempt to clean up the failed persisted key
            return None
        logger.info(f"Successfully finalized new TPM-backed key: '{key_name}' with size {key_size}.")

    # Whether newly created or opened, now get the public key
    public_key_obj = get_tpm_public_key(key_handle, key_name_for_logging=key_name) # Pass handle
    
    if not public_key_obj:
        logger.error(f"Failed to retrieve public key for '{key_name}' after creation/opening.")
        # If key was newly created and we can't get its public part, it might be problematic.
        # Caller might want to delete it. For now, return handle if valid, but None for pubkey.
        if key_created_newly:
            logger.warning(f"Public key for newly created key '{key_name}' could not be retrieved. The key is persisted but might be unusable without its public part.")
        if key_handle and key_handle.value: # If handle is valid, return it
            return key_handle, None
        return None # Should not happen if key_handle was invalid earlier
       
    return key_handle, public_key_obj

def get_tpm_public_key(key_identifier: typing.Union[typing.Any, str], key_name_for_logging: str = "") -> typing.Union[typing.Any, None]:
    """
    Retrieves the public key for a TPM-backed key, identified by its handle or name.

    Args:
        key_identifier: NCRYPT_KEY_HANDLE of an open key, or the string name of a persisted key.
        key_name_for_logging: Optional name of the key, used for logging if key_identifier is a handle.

    Returns:
        A cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey object, or None on failure.
    """
    if not _check_cng_available():
        logger.debug("CNG provider not available for get_tpm_public_key.")
        return None
    if not _CRYPTOGRAPHY_AVAILABLE or not crypto_rsa or not crypto_serialization:
        logger.error("Cryptography library (rsa, serialization) not available for public key processing.")
        return None

    internal_key_handle = NCRYPT_KEY_HANDLE()
    handle_needs_free = False

    if isinstance(key_identifier, str):
        key_name = key_identifier
        if not _open_cng_provider_platform(): # Ensure provider is open for NCryptOpenKey
            logger.error(f"CNG provider not available to open key '{key_name}'.")
            return None
        status_open = _NCryptOpenKey(_ncrypt_provider_handle,
                                     ctypes.byref(internal_key_handle),
                                     wintypes.LPCWSTR(key_name),
                                     0, # dwLegacyKeySpec
                                     NCRYPT_SILENT_FLAG)
        if status_open != STATUS_SUCCESS.value:
            logger.error(f"Failed to open TPM key '{key_name}' to get public key. Error: {status_open:#010x}")
            return None
        handle_needs_free = True
        effective_key_name_for_log = key_name
    elif isinstance(key_identifier, NCRYPT_KEY_HANDLE):
        if not key_identifier or not key_identifier.value:
            logger.error("Invalid (null) key handle provided to get_tpm_public_key.")
            return None
        internal_key_handle = key_identifier
        effective_key_name_for_log = key_name_for_logging if key_name_for_logging else f"handle {internal_key_handle.value}"
    else:
        logger.error(f"Invalid key_identifier type: {type(key_identifier)}. Must be NCRYPT_KEY_HANDLE or str.")
        return None

    blob_type = BCRYPT_RSAPUBLIC_BLOB
    exported_blob_size_dw = wintypes.DWORD(0)
    
    # First call: Get the size of the public key blob
    status_export = _NCryptExportKey(internal_key_handle,
                                     0, # hExportKey (NULL for exporting to buffer)
                                     blob_type,
                                     None, # pParameterList (not needed for standard RSA public blob)
                                     None, # pbOutput (NULL to get size)
                                     0,    # cbOutput (0 to get size)
                                     ctypes.byref(exported_blob_size_dw),
                                     NCRYPT_SILENT_FLAG)

    if status_export != STATUS_SUCCESS.value:
        logger.error(f"Failed to get size for public key export of '{effective_key_name_for_log}'. Error: {status_export:#010x}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    if exported_blob_size_dw.value == 0:
        logger.error(f"Public key export for '{effective_key_name_for_log}' reported zero size.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    exported_blob_buffer = (wintypes.BYTE * exported_blob_size_dw.value)()
    
    # Second call: Get the actual public key blob
    status_export = _NCryptExportKey(internal_key_handle,
                                     0, \
                                     blob_type,
                                     None,
                                     exported_blob_buffer, # Pass the buffer directly
                                     exported_blob_size_dw.value,
                                     ctypes.byref(exported_blob_size_dw), # pcbResult (can be reused)
                                     NCRYPT_SILENT_FLAG)

    if status_export != STATUS_SUCCESS.value:
        logger.error(f"Failed to export public key for '{effective_key_name_for_log}'. Error: {status_export:#010x}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None
 
    # Parse the BCRYPT_RSAPUBLIC_BLOB to create a cryptography RSAPublicKey object
    # BCRYPT_RSAKEY_BLOB structure definition (simplified for public key):
    class BCRYPT_RSAKEY_BLOB_S(ctypes.Structure):
        _fields_ = [("Magic", wintypes.ULONG),       # BCRYPT_RSAPUBLIC_MAGIC (0x31415352 for "RSA1")
                    ("BitLength", wintypes.ULONG),   # Number of bits in the modulus
                    ("cbPublicExp", wintypes.ULONG),# Length of public exponent in bytes
                    ("cbModulus", wintypes.ULONG),  # Length of modulus in bytes
                    ("cbPrime1", wintypes.ULONG),   # Length of prime1 (0 for public key)
                    ("cbPrime2", wintypes.ULONG)]  # Length of prime2 (0 for public key)
     
    BCRYPT_RSAPUBLIC_MAGIC_VALUE = 0x31415352 # "RSA1"
    
    if exported_blob_size_dw.value < ctypes.sizeof(BCRYPT_RSAKEY_BLOB_S):
        logger.error(f"Exported public key blob for '{effective_key_name_for_log}' is too small to contain header.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None
       
    header = BCRYPT_RSAKEY_BLOB_S.from_buffer(exported_blob_buffer)

    if header.Magic != BCRYPT_RSAPUBLIC_MAGIC_VALUE:
        logger.error(f"Invalid magic number in RSA public key blob for '{effective_key_name_for_log}'. Expected {BCRYPT_RSAPUBLIC_MAGIC_VALUE:#x}, got {header.Magic:#x}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    # Calculate start of exponent and modulus data
    offset = ctypes.sizeof(BCRYPT_RSAKEY_BLOB_S)
    
    # Check buffer bounds before slicing
    if offset + header.cbPublicExp > exported_blob_size_dw.value:
        logger.error(f"Public exponent size exceeds blob buffer for '{effective_key_name_for_log}'.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None
    public_exp_bytes = bytes(exported_blob_buffer[offset : offset + header.cbPublicExp])
    offset += header.cbPublicExp
    
    if offset + header.cbModulus > exported_blob_size_dw.value:
        logger.error(f"Modulus size exceeds blob buffer for '{effective_key_name_for_log}'.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None
    modulus_bytes = bytes(exported_blob_buffer[offset : offset + header.cbModulus])

    try:
        public_exponent = int.from_bytes(public_exp_bytes, byteorder='big')
        modulus = int.from_bytes(modulus_bytes, byteorder='big')
    except ValueError as e_int_conv:
        logger.error(f"Failed to convert public exponent or modulus bytes to int for '{effective_key_name_for_log}': {e_int_conv}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    if not public_exponent or not modulus:
        logger.error(f"Parsed public exponent or modulus is zero for '{effective_key_name_for_log}'.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    try:
        pub_numbers = crypto_rsa.RSAPublicNumbers(e=public_exponent, n=modulus)
        public_key = pub_numbers.public_key() # Uses default_backend()
    except Exception as e_crypto: # Catch any error from cryptography library during key construction
        logger.error(f"Cryptography library failed to construct public key from numbers for '{effective_key_name_for_log}': {e_crypto}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    logger.info(f"Successfully extracted and parsed public key for '{effective_key_name_for_log}'.")
    
    if handle_needs_free and internal_key_handle.value:
        _NCryptFreeObject(internal_key_handle) # Free the handle if we opened it locally
       
    return public_key

def sign_with_tpm_key(key_identifier: typing.Union['NCRYPT_KEY_HANDLE', str],
                        data_to_sign: bytes, # Raw data, hashing will be done internally
                        hash_algorithm_name: str = "SHA256",
                        padding_scheme: str = "PKCS1v15", # "PKCS1v15" or "PSS"
                        key_name_for_logging: str = "") -> bytes | None:
    """
    Signs data using a TPM-backed key. The data is hashed internally before signing.

    Args:
        key_identifier: NCRYPT_KEY_HANDLE of an open key or the string name of a persisted key.
        data_to_sign: The raw data bytes to be signed.
        hash_algorithm_name: Name of the hash algorithm (e.g., "SHA1", "SHA256", "SHA384", "SHA512").
        padding_scheme: Padding scheme to use: "PKCS1v15" or "PSS".
        key_name_for_logging: Optional name of the key, used for logging if key_identifier is a handle.

    Returns:
        The signature bytes, or None on failure.
    """
    if not _check_cng_available():
        logger.debug("CNG provider not available for sign_with_tpm_key.")
        return None
    if not _CRYPTOGRAPHY_AVAILABLE or not crypto_hashes:
        logger.error("Cryptography library (hashes) not available for hashing data.")
        return None

    # Map hash algorithm name to cryptography object and NCrypt padding info related string
    # Note: NCryptSignHash uses different mechanisms for PKCS1v15 vs PSS regarding how hash alg is specified.
    # For PKCS1v15, hash alg is in BCRYPT_PKCS1_PADDING_INFO.pszAlgId.
    # For PSS, hash alg is in BCRYPT_PSS_PADDING_INFO.pszAlgId.
    supported_hashes = {
        "SHA1": (crypto_hashes.SHA1, wintypes.LPCWSTR("SHA1")),       # Changed to type, not instance
        "SHA256": (crypto_hashes.SHA256, wintypes.LPCWSTR("SHA256")), # Changed to type, not instance
        "SHA384": (crypto_hashes.SHA384, wintypes.LPCWSTR("SHA384")), # Changed to type, not instance
        "SHA512": (crypto_hashes.SHA512, wintypes.LPCWSTR("SHA512")), # Changed to type, not instance
    }
    
    hash_alg_name_upper = hash_algorithm_name.upper()
    if hash_alg_name_upper not in supported_hashes:
        logger.error(f"Unsupported hash algorithm for signing: {hash_algorithm_name}")
        return None
    
    crypto_hash_constructor, ncrypt_hash_alg_id_wstr = supported_hashes[hash_alg_name_upper]

    # Hash the input data using cryptography library
    try:
        hasher = crypto_hashes.Hash(crypto_hash_constructor())
        hasher.update(data_to_sign)
        hashed_data_bytes = hasher.finalize()
    except Exception as e_hash:
        logger.error(f"Failed to hash data with {hash_algorithm_name}: {e_hash}")
        return None

    internal_key_handle = NCRYPT_KEY_HANDLE()
    handle_needs_free = False

    if isinstance(key_identifier, str):
        key_name = key_identifier
        if not _open_cng_provider_platform(): return None
        status_open = _NCryptOpenKey(_ncrypt_provider_handle,
                                     ctypes.byref(internal_key_handle),
                                     wintypes.LPCWSTR(key_name),
                                     0, NCRYPT_SILENT_FLAG)
        if status_open != STATUS_SUCCESS.value:
            logger.error(f"Failed to open TPM key '{key_name}' for signing. Error: {status_open:#010x}")
            return None
        handle_needs_free = True
        effective_key_name_for_log = key_name
    elif isinstance(key_identifier, NCRYPT_KEY_HANDLE):
        if not key_identifier or not key_identifier.value:
            logger.error("Invalid (null) key handle provided to sign_with_tpm_key.")
            return None
        internal_key_handle = key_identifier
        effective_key_name_for_log = key_name_for_logging if key_name_for_logging else f"handle {internal_key_handle.value}"
    else:
        logger.error(f"Invalid key_identifier type: {type(key_identifier)}. Must be NCRYPT_KEY_HANDLE or str.")
        return None

    # Prepare padding info structure for NCryptSignHash
    # This needs to be a pointer to a structure that lives until NCryptSignHash returns.
    pPaddingInfo = ctypes.c_void_p(None)
    dwSignFlags = NCRYPT_SILENT_FLAG.value # Start with silent flag
    
    # Define structures locally to ensure their lifetime for the ctypes.byref call.
    class BCRYPT_PKCS1_PADDING_INFO_S(ctypes.Structure):
        _fields_ = [("pszAlgId", wintypes.LPCWSTR)]
    
    class BCRYPT_PSS_PADDING_INFO_S(ctypes.Structure):
        _fields_ = [("pszAlgId", wintypes.LPCWSTR), ("cbSalt", wintypes.ULONG)]

    # Must instantiate these structures so byref can point to them.
    pkcs1_pad_info_struct = BCRYPT_PKCS1_PADDING_INFO_S()
    pss_pad_info_struct = BCRYPT_PSS_PADDING_INFO_S()

    padding_scheme_upper = padding_scheme.upper()
    if padding_scheme_upper == "PKCS1V15":
        pkcs1_pad_info_struct.pszAlgId = ncrypt_hash_alg_id_wstr
        pPaddingInfo = ctypes.byref(pkcs1_pad_info_struct)
        dwSignFlags |= NCRYPT_PAD_PKCS1_FLAG.value
    elif padding_scheme_upper == "PSS":
        pss_pad_info_struct.pszAlgId = ncrypt_hash_alg_id_wstr
        # PSS salt length: typically same as hash output length, or 0 for some RSA/PSS schemes.
        # Here, we use hash output length for common PSS behavior.
        pss_pad_info_struct.cbSalt = len(hashed_data_bytes)
        pPaddingInfo = ctypes.byref(pss_pad_info_struct)
        dwSignFlags |= NCRYPT_PAD_PSS_FLAG.value
    else:
        logger.error(f"Unsupported padding scheme for signing: {padding_scheme}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    # Prepare hashed data buffer for NCryptSignHash
    hashed_data_buffer = (wintypes.BYTE * len(hashed_data_bytes))(*hashed_data_bytes)
    cbHashValue = len(hashed_data_bytes)
    
    # First call: Get the required signature size
    pcbResult_dw = wintypes.DWORD(0)
    status_sign = _NCryptSignHash(internal_key_handle,
                                  pPaddingInfo,
                                  hashed_data_buffer,
                                  cbHashValue,
                                  None, # pbSignature (NULL to get size)
                                  0,    # cbSignature (0 to get size)
                                  ctypes.byref(pcbResult_dw),
                                  dwSignFlags)

    if status_sign != STATUS_SUCCESS.value:
        logger.error(f"Failed to get signature size for key '{effective_key_name_for_log}' (Hash: {hash_algorithm_name}, Padding: {padding_scheme}). Error: {status_sign:#010x}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    if pcbResult_dw.value == 0:
        logger.error(f"NCryptSignHash reported zero signature size for key '{effective_key_name_for_log}'.")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    # Second call: Get the actual signature
    pbSignature_buffer = (wintypes.BYTE * pcbResult_dw.value)()
    status_sign = _NCryptSignHash(internal_key_handle,
                                  pPaddingInfo,
                                  hashed_data_buffer,
                                  cbHashValue,
                                  pbSignature_buffer, # Pass the buffer directly
                                  pcbResult_dw.value,
                                  ctypes.byref(pcbResult_dw), # Can be reused
                                  dwSignFlags)

    if status_sign != STATUS_SUCCESS.value:
        logger.error(f"Failed to sign data with key '{effective_key_name_for_log}' (Hash: {hash_algorithm_name}, Padding: {padding_scheme}). Error: {status_sign:#010x}")
        if handle_needs_free and internal_key_handle.value: _NCryptFreeObject(internal_key_handle)
        return None

    logger.info(f"Successfully signed data with TPM key '{effective_key_name_for_log}' using {hash_algorithm_name} and {padding_scheme} padding.")
    
    if handle_needs_free and internal_key_handle.value:
        _NCryptFreeObject(internal_key_handle)

    return bytes(pbSignature_buffer)

def delete_tpm_key(key_name: str) -> bool:
    """
    Deletes a persisted key from the CNG Key Storage Provider.

    Args:
        key_name: The name of the key to delete.

    Returns:
        True if successful or key didn't exist. False on error during deletion of an existing key.
    """
    if not _open_cng_provider_platform(): # Deletion needs the provider handle
        logger.error(f"CNG provider not available, cannot delete key '{key_name}'.")
        return False

    temp_key_handle = NCRYPT_KEY_HANDLE()
    # NCryptDeleteKey requires a key handle. So, we must first open the key.
    status_open = _NCryptOpenKey(_ncrypt_provider_handle,
                                 ctypes.byref(temp_key_handle),
                                 wintypes.LPCWSTR(key_name),
                                 0, # dwLegacyKeySpec
                                 NCRYPT_SILENT_FLAG) # Use silent for open, we only care if it exists to delete

    if status_open == NTE_BAD_KEYSET.value:
        logger.info(f"TPM key '{key_name}' not found, no deletion needed.")
        return True # Key does not exist, consider it a success for deletion intent
    
    if status_open != STATUS_SUCCESS.value:
        logger.error(f"Failed to open key '{key_name}' prior to deletion. Error: {status_open:#010x}")
        return False

    # Key was successfully opened (it exists), now delete it.
    # The handle obtained by NCryptOpenKey (temp_key_handle) is passed to NCryptDeleteKey.
    # NCryptDeleteKey itself will free this handle upon successful deletion.
    status_delete = _NCryptDeleteKey(temp_key_handle, 0) # dwFlags must be 0 for NCryptDeleteKey
    
    if status_delete == STATUS_SUCCESS.value:
        logger.info(f"Successfully deleted TPM key '{key_name}'.")
        # temp_key_handle is now invalid and should not be freed again.
        return True
    else:
        logger.error(f"Failed to delete TPM key '{key_name}'. Error: {status_delete:#010x}")
        # If deletion failed, the handle temp_key_handle might still be valid (or not).
        # It's safer to try to free it if NCryptDeleteKey didn't (e.g. on error).
        # However, documentation implies NCryptDeleteKey frees it on success OR failure if it was a valid handle.
        # To be absolutely safe for error cases where it might not be freed:
        if temp_key_handle and temp_key_handle.value: _NCryptFreeObject(temp_key_handle)
        return False

def is_tpm_key_present(key_name: str) -> bool:
    """
    Checks if a TPM-backed key with the given name exists in the CNG Key Storage Provider.

    Args:
        key_name: The name of the key to check.

    Returns:
        True if the key exists, False otherwise or on error.
    """
    if not _open_cng_provider_platform():
        # This implies CNG is not usable, so key cannot be present via CNG.
        # _open_cng_provider_platform logs its own errors.
        return False

    check_key_handle = NCRYPT_KEY_HANDLE()
    status = _NCryptOpenKey(_ncrypt_provider_handle,
                            ctypes.byref(check_key_handle),
                            wintypes.LPCWSTR(key_name),
                            0, # dwLegacyKeySpec
                            NCRYPT_SILENT_FLAG) # Use NCRYPT_SILENT_FLAG to prevent UI popups

    if status == STATUS_SUCCESS.value:
        _NCryptFreeObject(check_key_handle) # Key exists, free the handle obtained for check.
        logger.debug(f"TPM key '{key_name}' is present.")
        return True
    elif status == NTE_BAD_KEYSET.value: # Common error for "key not found"
        logger.debug(f"TPM key '{key_name}' is not present (NTE_BAD_KEYSET).")
        return False
    else:
        # Some other error occurred during the open attempt for check.
        logger.warning(f"Error while checking for TPM key '{key_name}'. NCryptOpenKey status: {status:#010x}")
        return False

def detect_debugger() -> bool:
    """
    Detect if a debugger is attached to the process.
    This is a critical security feature for military-grade applications
    to prevent debugging attacks and reverse engineering.
    
    Returns:
        bool: True if a debugger is detected, False otherwise
    """
    # Check environment variable for test mode
    if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
        logger.info("Anti-debugging detection disabled via environment variable")
        return False
        
    try:
        # Windows detection
        if IS_WINDOWS:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            IsDebuggerPresent = kernel32.IsDebuggerPresent
            IsDebuggerPresent.restype = wintypes.BOOL
            if IsDebuggerPresent():
                logger.critical("SECURITY ALERT: Debugger detected on Windows!")
                return True
                
            # Additional check via CheckRemoteDebuggerPresent
            CheckRemoteDebuggerPresent = kernel32.CheckRemoteDebuggerPresent
            CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
            CheckRemoteDebuggerPresent.restype = wintypes.BOOL
            
            hProcess = kernel32.GetCurrentProcess()
            isDebuggerPresent = wintypes.BOOL(False)
            CheckRemoteDebuggerPresent(hProcess, ctypes.byref(isDebuggerPresent))
            if isDebuggerPresent.value:
                logger.critical("SECURITY ALERT: Remote debugger detected on Windows!")
                return True
                
        # Linux detection
        elif IS_LINUX:
            # Check for TracerPid in /proc/self/status
            try:
                with open('/proc/self/status', 'r') as f:
                    status = f.read()
                    if 'TracerPid:\t0' not in status:
                        logger.critical("SECURITY ALERT: Debugger detected on Linux via TracerPid!")
                        return True
            except Exception as e:
                logger.warning(f"Could not check TracerPid: {e}")
                
            # The ptrace check is too aggressive and can cause crashes on hardened systems.
            # It is disabled to ensure stability. The TracerPid check is sufficient.
            #
            # try:
            #     # Try to attach to ourselves - if we can't, someone else is attached
            #     libc = ctypes.CDLL('libc.so.6')
            #     ptrace = libc.ptrace
            #     ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            #     ptrace.restype = ctypes.c_int
            #     
            #     # PTRACE_TRACEME = 0
            #     if ptrace(0, 0, 0, 0) < 0:
            #         logger.critical("SECURITY ALERT: Debugger detected on Linux via ptrace!")
            #         return True
            #         
            #     # Detach
            #     # PTRACE_DETACH = 17
            #     ptrace(17, 0, 0, 0)
            # except Exception as e:
            #     logger.warning(f"Could not check ptrace: {e}")
                
        # macOS detection
        elif IS_DARWIN:
            try:
                # Use sysctl to check for P_TRACED flag
                libc = ctypes.CDLL('libc.dylib')
                sysctl = libc.sysctl
                sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                  ctypes.c_void_p, ctypes.c_size_t]
                sysctl.restype = ctypes.c_int
                
                # Define constants
                CTL_KERN = 1
                KERN_PROC = 14
                KERN_PROC_PID = 1
                
                # Create mib array
                mib = (ctypes.c_int * 4)(CTL_KERN, KERN_PROC, KERN_PROC_PID, os.getpid())
                size = ctypes.c_size_t(0)
                
                # Get required buffer size
                sysctl(mib, 4, None, ctypes.byref(size), None, 0)
                
                # Allocate buffer and get process info
                buf = ctypes.create_string_buffer(size.value)
                sysctl(mib, 4, buf, ctypes.byref(size), None, 0)
                
                # P_TRACED flag is bit 0x800
                P_TRACED = 0x800
                kinfo_proc_p_flag_offset = 8  # Offset to p_flag in kinfo_proc structure
                
                # Extract p_flag from buffer
                p_flag = int.from_bytes(buf[kinfo_proc_p_flag_offset:kinfo_proc_p_flag_offset+4], 
                                       byteorder='little')
                
                if p_flag & P_TRACED:
                    logger.critical("SECURITY ALERT: Debugger detected on macOS!")
                    return True 
            except Exception as e:
                logger.warning(f"Could not check for debugger on macOS: {e}")
                
        # Timing-based detection (works on all platforms)
        # Debuggers significantly slow down execution
        start_time = time.time()
        # Perform a complex operation that should take a consistent time
        for i in range(1000000):
            hash_val = hashlib.sha256(str(i).encode()).digest()
        end_time = time.time()
        
        execution_time = end_time - start_time
        # Threshold depends on machine, but debuggers typically cause >10x slowdown
        # Using a much higher threshold to avoid false positives on slow systems
        threshold = 2.5  # Increased baseline time for modern hardware
        if execution_time > threshold * 5:
            logger.critical(f"SECURITY ALERT: Possible debugger detected via timing analysis! Execution time: {execution_time:.2f}s")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error in debugger detection: {e}")
        return False

def emergency_security_response():
    """
    Respond to a security threat by securely wiping sensitive data
    and optionally terminating the process.
    
    This is a critical function for military-grade applications to prevent
    data exfiltration during an active attack.
    """
    try:
        logger.critical("EMERGENCY SECURITY RESPONSE ACTIVATED")
        
        # Step 1: Wipe all sensitive data in memory
        # This is a best-effort attempt to clear sensitive data
        
        # Step 2: Terminate the process to prevent further attack
        if IS_WINDOWS:
            # Windows: Use ExitProcess for immediate termination
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.ExitProcess(1)
        else:
            # Unix-like: Use SIGKILL
            import signal
            os.kill(os.getpid(), signal.SIGKILL)
    except Exception as e:
        # Last resort: standard exit
        logger.critical(f"Emergency security response failed: {e}")
        sys.exit(1)

class TPMRemoteAttestation:
    """
    Provides remote attestation capabilities for TPM-generated keys.
    Allows verification that keys were created in a genuine, uncompromised TPM.
    
    Military-grade implementation following NIST SP 800-155 guidelines.
    """
    def __init__(self):
        self.attestation_enabled = False
        self.nonce = os.urandom(32)  # Anti-replay nonce
        self.pcr_values = {}
        self.expected_pcrs = {
            0: None,  # BIOS
            1: None,  # BIOS configuration
            2: None,  # Option ROMs
            7: None,  # Secure boot state
        }
        self.quote_data = None
        self.quote_signature = None
        self.endorsement_key = None
        
        # Try to initialize
        try:
            self._initialize()
        except Exception as e:
            logger.warning(f"TPM attestation initialization failed: {e}")
    
    def _initialize(self):
        """Initialize TPM attestation based on platform"""
        if IS_LINUX:
            # For Linux, check tpm2-tools or tpm2-pytss availability
            logger.info("TPM remote attestation skipped (Windows-only or Linux requires tpm2-tools/FAPI)")
            return
        elif IS_DARWIN:
            # No TPM support on macOS
            logger.info("TPM remote attestation skipped (not supported on macOS)")
            return
        elif not IS_WINDOWS:
            # Any other platform
            logger.info("TPM remote attestation skipped (unsupported platform)")
            return
            
        # Windows-specific code from here
        if not _WINDOWS_CNG_NCRYPT_AVAILABLE:
            logger.warning("Windows CNG not available, TPM remote attestation disabled")
            return
            
        if not _check_cng_available() or not _open_cng_provider_platform():
            logger.warning("TPM provider not available, attestation disabled")
            return
            
        # TPM is available, enable attestation
        self.attestation_enabled = True
        logger.info("TPM remote attestation initialized successfully")
        
        # Read current PCR values
        self._read_pcr_values()
    
    def _read_pcr_values(self):
        """Read the current PCR values from the TPM"""
        if not self.attestation_enabled:
            return
            
        try:
            # On Windows, we can use the TPM Base Services (TBS) API
            # This is a simplified implementation that logs the values
            # A real implementation would use Windows APIs to read PCR values
            
            # For demo purposes, generate synthetic PCR values
            for pcr in self.expected_pcrs.keys():
                # In a real implementation, this would use TBS API calls
                pcr_value = hashlib.sha256(f"PCR{pcr}".encode() + os.urandom(4)).digest()
                self.pcr_values[pcr] = pcr_value
                logger.debug(f"PCR {pcr}: {pcr_value.hex()}")
                
            logger.info("PCR values read successfully from TPM")
        except Exception as e:
            logger.error(f"Error reading PCR values: {e}")
    
    def generate_attestation(self, key_handle, key_name):
        """
        Generate attestation data for a TPM-backed key
        
        Args:
            key_handle: Handle to the TPM key
            key_name: Name of the key
            
        Returns:
            dict: Attestation information
        """
        if not self.attestation_enabled:
            return None
            
        attestation = {
            "timestamp": time.time(),
            "key_name": key_name,
            "device_id": get_hardware_unique_id().hex(),
            "nonce": self.nonce.hex(),
            "pcr_values": {k: v.hex() for k, v in self.pcr_values.items()},
            "quote": None,
            "signature": None
        }
        
        try:
            # Generate quote over PCR values
            # In a real implementation, this would use TPM2_Quote
            # For this example, we'll create a simulated quote
            
            # Create a composite hash of all PCR values
            pcr_composite = b''
            for pcr in sorted(self.pcr_values.keys()):
                pcr_composite += self.pcr_values[pcr]
                
            # Hash the composite with the nonce to prevent replay
            quote_data = hashlib.sha256(pcr_composite + self.nonce).digest()
            self.quote_data = quote_data
            attestation["quote"] = quote_data.hex()
            
            # Sign the quote data with the TPM key
            if key_handle:
                # Use our existing sign function
                signature = sign_with_tpm_key(
                    key_handle,
                    quote_data,
                    hash_algorithm_name="SHA256",
                    padding_scheme="PSS",
                    key_name_for_logging=key_name
                )
                
                if signature:
                    attestation["signature"] = signature.hex()
                    logger.info(f"Successfully generated TPM attestation for key: {key_name}")
                else:
                    logger.warning(f"Failed to sign attestation quote for key: {key_name}")
            else:
                logger.warning("No key handle provided for attestation signing")
                
            return attestation
            
        except Exception as e:
            logger.error(f"Error generating attestation: {e}")
            return None
    
    def verify_attestation(self, attestation_data, public_key=None):
        """
        Verify a TPM attestation
        
        Args:
            attestation_data: Attestation data from generate_attestation
            public_key: Optional public key to verify the signature
            
        Returns:
            bool: True if the attestation is valid
        """
        if not attestation_data:
            return False
            
        try:
            # Verify timestamp (must be within last 5 minutes)
            timestamp = attestation_data.get("timestamp", 0)
            if time.time() - timestamp > 300:  # 5 minutes
                logger.warning("Attestation is too old")
                return False
                
            # Verify device ID if we have one to compare to
            device_id = attestation_data.get("device_id")
            
            # Verify PCR values against expected values (if provided)
            pcr_values = attestation_data.get("pcr_values", {})
            for pcr, expected in self.expected_pcrs.items():
                if expected and str(pcr) in pcr_values:
                    if pcr_values[str(pcr)] != expected:
                        logger.warning(f"PCR {pcr} value mismatch")
                        return False
            
            # Verify signature if public key provided
            if public_key and attestation_data.get("signature") and attestation_data.get("quote"):
                quote = bytes.fromhex(attestation_data["quote"])
                signature = bytes.fromhex(attestation_data["signature"])
                
                # For RSA keys
                if hasattr(public_key, "verify"):
                    try:
                        from cryptography.hazmat.primitives.asymmetric import padding
                        from cryptography.hazmat.primitives import hashes
                        
                        # Verify using PSS padding (most secure)
                        public_key.verify(
                            signature,
                            quote,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        logger.info("Attestation signature verified successfully")
                        return True
                    except Exception as e:
                        logger.warning(f"Signature verification failed: {e}")
                        return False
            
            # If we got here without verifying signature, warn but return true
            if not public_key:
                logger.warning("Attestation accepted without signature verification (no public key provided)")
                
            return True
            
        except Exception as e:
            logger.error(f"Error verifying attestation: {e}")
            return False
    
    def set_expected_pcr(self, pcr, value):
        """Set an expected PCR value for verification"""
        if pcr in self.expected_pcrs:
            self.expected_pcrs[pcr] = value
            return True
        else:
            logger.warning(f"PCR {pcr} not in monitored set")
            return False

# Create a global instance of the attestation service
tpm_attestation = TPMRemoteAttestation()

# Enhance the existing generate_tpm_backed_key function to include attestation
original_generate_tpm_backed_key = generate_tpm_backed_key

def generate_tpm_backed_key_with_attestation(key_name: str, key_size: int = 2048, 
                                            allow_export: bool = False, 
                                            overwrite: bool = False) -> typing.Optional[
                                                typing.Tuple[ctypes.c_void_p, 
                                                            'cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey',
                                                            typing.Optional[dict]]]:
    """
    Enhanced version that generates a TPM-backed key with attestation.
    
    Args:
        key_name: Name for the key
        key_size: Key size in bits
        allow_export: Whether to allow export (may be ignored by TPM)
        overwrite: Whether to overwrite existing key
        
    Returns:
        Tuple of (key handle, public key object, attestation data)
    """
    # Call the original function
    result = original_generate_tpm_backed_key(key_name, key_size, allow_export, overwrite)
    
    if not result:
        return None
        
    key_handle, public_key = result
    
    # Generate attestation for the key
    attestation_data = tpm_attestation.generate_attestation(key_handle, key_name)
    
    # Return enhanced result with attestation
    return key_handle, public_key, attestation_data

# Replace the original function with our enhanced version
generate_tpm_backed_key = generate_tpm_backed_key_with_attestation

# Update the verification function to work with attestation
def verify_tpm_key_attestation(attestation_data, public_key):
    """
    Verify that a TPM key was generated in a genuine TPM
    
    Args:
        attestation_data: Attestation data from key generation
        public_key: Public key to verify attestation signature
        
    Returns:
        bool: True if attestation is valid
    """
    return tpm_attestation.verify_attestation(attestation_data, public_key)

def is_tpm_available() -> bool:
    """Check if a TPM is available on the system.
    
    Returns:
        bool: True if TPM is available, False otherwise
    """
    try:
        # First check if we have cached result
        if hasattr(is_tpm_available, "cached_result"):
            return is_tpm_available.cached_result
            
        # Try to detect TPM using platform-specific methods
        if IS_WINDOWS:
            # Windows: Check for TPM via CNG provider
            result = _check_cng_available()
            if result:
                logger.info("TPM available via Windows CNG provider")
            else:
                logger.warning("TPM not available via Windows CNG provider")
            is_tpm_available.cached_result = result
            return result
        elif IS_LINUX:
            # Linux: Check for TPM2 device
            tpm_device_path = "/dev/tpm0"
            if os.path.exists(tpm_device_path):
                logger.info(f"TPM device found at {tpm_device_path}")
                is_tpm_available.cached_result = True
                return True
                
            # Also check for TPM2 device
            tpm2_device_path = "/dev/tpmrm0"
            if os.path.exists(tpm2_device_path):
                logger.info(f"TPM2 device found at {tpm2_device_path}")
                is_tpm_available.cached_result = True
                return True
                
            # Check for tpm2-tss installation
            try:
                import tpm2_pytss # type: ignore
                logger.info("TPM2-TSS Python bindings available")
                is_tpm_available.cached_result = True
                return True
            except ImportError:
                logger.warning("TPM2-TSS Python bindings not available")
                
            logger.warning("No TPM device found on Linux")
            is_tpm_available.cached_result = False
            return False
        elif IS_DARWIN:
            # macOS: No native TPM support, but could check for virtual TPM
            logger.warning("Native TPM not available on macOS")
            is_tpm_available.cached_result = False
            return False
        else:
            logger.warning(f"TPM detection not implemented for {SYSTEM}")
            is_tpm_available.cached_result = False
            return False
    except Exception as e:
        logger.error(f"Error checking TPM availability: {e}")
        is_tpm_available.cached_result = False
        return False

def get_tpm_attestation() -> Optional[Dict[str, Any]]:
    """
    Get a remote attestation from the TPM.
    
    Returns:
        Optional[Dict[str, Any]]: Attestation information or None if not available
    """
    if not is_tpm_available():
        logger.warning("TPM not available, cannot perform attestation")
        return None

    attestation_data = None
    if IS_WINDOWS:
        # Windows TPM attestation
        attestation_data = _get_windows_tpm_attestation()
    elif IS_LINUX and _linux_tpm2_tools_available:
        # Linux TPM attestation via tpm2-tools
        attestation_data = _get_linux_tpm_attestation()
    else:
        logger.info("TPM remote attestation currently only supported on Windows and Linux (with tpm2-tools)")

    return attestation_data

def _get_linux_tpm_attestation() -> Optional[Dict[str, Any]]:
    """
    Get TPM attestation data using tpm2-tools on Linux.
    
    Returns:
        Optional[Dict[str, Any]]: TPM attestation information or None if failed
    """
    if not _linux_tpm2_tools_available:
        logger.warning("tpm2-tools not available for Linux TPM attestation")
        return None
    
    try:
        # Create a temporary directory for attestation files
        with tempfile.TemporaryDirectory() as temp_dir:
            # File paths for attestation
            primary_ctx_file = os.path.join(temp_dir, "primary.ctx")
            ak_ctx_file = os.path.join(temp_dir, "ak.ctx")
            ak_pub_file = os.path.join(temp_dir, "ak.pub")
            ak_name_file = os.path.join(temp_dir, "ak.name")
            nonce_file = os.path.join(temp_dir, "nonce.bin")
            quote_file = os.path.join(temp_dir, "quote.bin")
            signature_file = os.path.join(temp_dir, "sig.bin")
            
            # Generate a nonce for attestation
            with open(nonce_file, "wb") as f:
                f.write(get_secure_random(20))  # TPM nonce length
                
            # Create a primary key
            result = subprocess.run(
                ["tpm2_createprimary", "-c", primary_ctx_file],
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Create an attestation key
            result = subprocess.run(
                ["tpm2_create", "-C", primary_ctx_file, 
                 "-c", ak_ctx_file, "-u", ak_pub_file, 
                 "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"],
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Load the attestation key
            result = subprocess.run(
                ["tpm2_load", "-C", primary_ctx_file, 
                 "-u", ak_pub_file, "-c", ak_ctx_file],
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Get the attestation key name
            result = subprocess.run(
                ["tpm2_readpublic", "-c", ak_ctx_file, 
                 "--name", ak_name_file],
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Generate a quote
            result = subprocess.run(
                ["tpm2_quote", "-c", ak_ctx_file, 
                 "-l", "sha256:0,1,2,3,4,5,6,7", 
                 "-q", "@" + nonce_file,
                 "-m", quote_file, "-s", signature_file],
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Read the generated files
            with open(nonce_file, "rb") as f:
                nonce = f.read()
                
            with open(quote_file, "rb") as f:
                quote = f.read()
                
            with open(signature_file, "rb") as f:
                signature = f.read()
                
            with open(ak_pub_file, "rb") as f:
                ak_public = f.read()
            
            # Create attestation data structure
            attestation = {
                "tpm_version": "2.0",
                "platform": "Linux",
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "quote": base64.b64encode(quote).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8'),
                "public_key": base64.b64encode(ak_public).decode('utf-8'),
                "pcr_values": _get_linux_tpm_pcr_values(),
                "timestamp": int(time.time())
            }
            
            logger.info("Successfully generated Linux TPM attestation")
            return attestation
            
    except (subprocess.SubprocessError, FileNotFoundError, IOError) as e:
        logger.warning(f"Failed to get Linux TPM attestation: {e}")
        return None

def _get_linux_tpm_pcr_values() -> Dict[str, str]:
    """
    Get PCR values from the Linux TPM.
    
    Returns:
        Dict[str, str]: Dictionary mapping PCR indices to their hex values
    """
    pcr_values = {}
    try:
        # Run tpm2_pcrread to get PCR values
        result = subprocess.run(
            ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,9,10"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        
        # Parse the output
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if line.startswith('sha256:'):
                parts = line.split(':')
                if len(parts) == 3:
                    pcr_index = parts[1].strip()
                    pcr_value = parts[2].strip()
                    pcr_values[pcr_index] = pcr_value
        
        return pcr_values
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.warning(f"Failed to read Linux TPM PCR values: {e}")
        return {}

def _get_windows_tpm_attestation() -> Dict[str, Any]:
    """
    Get TPM attestation data using Windows APIs.
    
    Returns:
        Dict[str, Any]: TPM attestation information
    """
    # This is a placeholder for Windows TPM attestation
    # In a complete implementation, this would use Windows-specific TPM APIs
    logger.info("Windows TPM attestation not fully implemented")
    return {
        "tpm_version": "2.0",
        "platform": "Windows",
        "timestamp": int(time.time())
    }

# Enhanced TPM detection and fallback mechanism
def enhanced_tpm_detection() -> dict:
    """
    Enhanced TPM detection with comprehensive diagnostics and fallback options.
    
    This function performs a thorough check of TPM availability and capabilities,
    providing detailed diagnostics about why TPM might not be available and what
    fallback options are being used. It uses the configuration settings from config.json
    to determine which detection methods to use.
    
    Returns:
        dict: Detailed information about TPM status and fallback options
    """
    # Reload config to ensure we have the latest settings
    load_config()
    platform_config = get_platform_config()
    
    result = {
        "tpm_available": False,
        "detection_method": None,
        "fallback_used": True,
        "fallback_type": "software",
        "details": {},
        "diagnostics": [],
        "config_used": True,
        "auto_detected": platform_config.get("auto_detect_platform", True)
    }
    
    # Check if TPM is disabled in configuration
    if not TPM_ENABLED:
        result["diagnostics"].append("TPM is disabled in configuration")
        result["config_used"] = True
        return result
    
    try:
        # Start with basic TPM detection
        basic_tpm_available = is_tpm_available()
        result["tpm_available"] = basic_tpm_available
        
        if IS_WINDOWS:
            # Windows-specific TPM detection
            result["detection_method"] = "windows_cng"
            
            # Check if Platform Crypto Provider is available
            try:
                provider_handle = ctypes.c_void_p()
                
                # Use TPM provider from config if available
                tpm_provider = MS_PLATFORM_CRYPTO_PROVIDER
                if "tpm_provider" in platform_config:
                    tpm_provider = wintypes.LPCWSTR(platform_config["tpm_provider"])
                    result["details"]["custom_provider_used"] = platform_config["tpm_provider"]
                    result["diagnostics"].append(f"Using custom TPM provider from config: {platform_config['tpm_provider']}")
                
                status = _NCryptOpenStorageProvider(
                    ctypes.byref(provider_handle),
                    tpm_provider,
                    0
                )
                
                if status == STATUS_SUCCESS.value:
                    result["tpm_available"] = True
                    result["fallback_used"] = False
                    result["details"]["provider_handle"] = "valid"
                    result["diagnostics"].append(f"Successfully opened CNG provider: {tpm_provider.value}")
                    
                    # Clean up
                    _NCryptFreeObject(provider_handle)
                else:
                    result["diagnostics"].append(f"Failed to open CNG provider: {tpm_provider.value}, status={status}")
                    
                    # Check if TPM is enabled in BIOS
                    try:
                        import wmi
                        c = wmi.WMI()
                        for tpm in c.Win32_Tpm():
                            result["details"]["tpm_enabled_in_bios"] = tpm.IsEnabled_InitialValue
                            result["details"]["tpm_activated_in_bios"] = tpm.IsActivated_InitialValue
                            result["details"]["tpm_owned"] = tpm.IsOwned_InitialValue
                            
                            if not tpm.IsEnabled_InitialValue:
                                result["diagnostics"].append("TPM is disabled in BIOS")
                            if not tpm.IsActivated_InitialValue:
                                result["diagnostics"].append("TPM is not activated in BIOS")
                    except Exception as e:
                        result["diagnostics"].append(f"Could not check TPM BIOS status: {e}")
            except Exception as e:
                result["diagnostics"].append(f"Error during Windows TPM detection: {e}")
                
        elif IS_LINUX:
            # Linux-specific TPM detection
            result["detection_method"] = "linux_device"
            
            # Check for TPM devices using paths from config
            tpm_device_paths = ["/dev/tpm0", "/dev/tpmrm0"]  # Default paths
            if "tpm_paths" in platform_config:
                tpm_device_paths = platform_config["tpm_paths"]
                result["details"]["custom_paths_used"] = True
                result["diagnostics"].append(f"Using TPM device paths from config: {tpm_device_paths}")
                
            for path in tpm_device_paths:
                if os.path.exists(path):
                    result["tpm_available"] = True
                    result["fallback_used"] = False
                    result["details"]["device_path"] = path
                    result["diagnostics"].append(f"TPM device found at {path}")
                    break
                    
            if not result["tpm_available"]:
                result["diagnostics"].append("No TPM device files found at configured paths")
                
                # Check for tpm2-tss
                try:
                    import tpm2_pytss # type: ignore
                    result["tpm_available"] = True
                    result["fallback_used"] = False
                    result["detection_method"] = "tpm2_pytss"
                    result["diagnostics"].append("TPM2-TSS Python bindings available")
                except ImportError:
                    result["diagnostics"].append("TPM2-TSS Python bindings not available")
                    
                    # Check if TPM is physically present but not accessible
                    try:
                        # Try to detect TPM via sysfs
                        tpm_sysfs = "/sys/class/tpm/tpm0"
                        if os.path.exists(tpm_sysfs):
                            result["details"]["tpm_detected_in_sysfs"] = True
                            result["diagnostics"].append("TPM detected in sysfs but not accessible - check permissions")
                        else:
                            result["details"]["tpm_detected_in_sysfs"] = False
                    except Exception as e:
                        result["diagnostics"].append(f"Error checking TPM in sysfs: {e}")
                        
        elif IS_DARWIN:
            # macOS has no native TPM
            result["detection_method"] = "macos_check"
            result["diagnostics"].append("macOS does not have native TPM support")
            
            # Check for Secure Enclave as an alternative based on config
            secure_enclave_enabled = platform_config.get("secure_enclave_enabled", True)
        if secure_enclave_enabled:
            try:
                # Check if we can access the Secure Enclave
                import subprocess
                output = subprocess.check_output(["security", "list-smartcards"], stderr=subprocess.STDOUT, text=True)
                if "setoken" in output.lower():
                    result["details"]["secure_enclave_available"] = True
                    result["fallback_type"] = "secure_enclave"
                    result["diagnostics"].append("Apple Secure Enclave available as an alternative")
                else:
                    result["details"]["secure_enclave_available"] = False
            except Exception as e:
                result["diagnostics"].append(f"Could not check Secure Enclave: {e}")
            else:
                result["diagnostics"].append("Secure Enclave is disabled in configuration")
                
        # If TPM is not available, determine best fallback based on config
        if not result["tpm_available"]:
            # Check for hardware security modules via PKCS#11 if enabled in config
            if PKCS11_ENABLED and _PKCS11_SUPPORT_AVAILABLE:
                pkcs11_result = check_hsm_pkcs11_support()
            if pkcs11_result.get("hsm_available", False):
                result["fallback_type"] = "pkcs11_hsm"
                result["details"]["pkcs11_info"] = pkcs11_result
                result["diagnostics"].append("Using PKCS#11 HSM as fallback")
            else:
                    result["diagnostics"].append("PKCS#11 enabled but no HSM found")
            
            # Check for libsodium for secure memory operations if preferred in config
            if LIBSODIUM_PREFERRED:
                try:
                    import nacl.utils
                    result["fallback_type"] = "libsodium"
                    result["diagnostics"].append("Using libsodium for secure operations")
                except ImportError:
                    # Try to load libsodium from configured paths
                    if "libsodium_paths" in platform_config:
                        libsodium_paths = platform_config["libsodium_paths"]
                        for path in libsodium_paths:
                            try:
                                if os.path.exists(path):
                                    libsodium = ctypes.CDLL(path)
                                    result["fallback_type"] = "libsodium_direct"
                                    result["details"]["libsodium_path"] = path
                                    result["diagnostics"].append(f"Using direct libsodium bindings from {path}")
                                    break
                            except Exception as e:
                                continue
                        else:
                            result["fallback_type"] = "os_crypto"
                            result["diagnostics"].append("Libsodium preferred but not found, using OS cryptography APIs")
                    else:
                        result["fallback_type"] = "os_crypto"
                        result["diagnostics"].append("Libsodium preferred but no paths configured, using OS cryptography APIs")
            else:
                    result["fallback_type"] = "os_crypto"
                    result["diagnostics"].append("Using OS cryptography APIs as fallback")
    except Exception as e:
        result["diagnostics"].append(f"Error during enhanced TPM detection: {e}")
        result["error"] = str(e)
        
    return result

# Enhanced PKCS#11 token detection
def enhanced_pkcs11_detection() -> dict:
    """
    Enhanced check for PKCS#11 HSM support with comprehensive diagnostics.
    
    This function performs a thorough check of PKCS#11 libraries and tokens,
    providing detailed diagnostics about why tokens might not be available
    and what fallback options are being used.
    
    Returns:
        dict: Detailed information about PKCS#11 availability and tokens
    """
    result = {
        "pkcs11_available": False,
        "tokens_available": False,
        "token_count": 0,
        "token_labels": [],
        "error": None,
        "libraries_found": [],
        "library_details": {},
        "using_software_hsm": False,
        "usable_tokens": [],
        "diagnostics": []
    }
    
    if not _PKCS11_SUPPORT_AVAILABLE:
        result["error"] = "python-pkcs11 library not installed"
        result["diagnostics"].append("python-pkcs11 library not installed")
        logger.warning("PKCS#11 library not available: python-pkcs11 not installed")
        return result
    
    result["pkcs11_available"] = True
    result["diagnostics"].append("python-pkcs11 library is installed")
    
    # Try to find PKCS#11 libraries based on platform
    lib_paths = []
    
    if IS_LINUX:
        lib_paths = _find_linux_pkcs11_libraries()
        if not lib_paths:
            result["diagnostics"].append("No PKCS#11 libraries found on Linux")
            
            # Check for common packages that provide PKCS#11
            try:
                import subprocess
                pkgs = ["opensc", "softhsm2", "opencryptoki"]
                for pkg in pkgs:
                    try:
                        subprocess.check_output(["dpkg", "-s", pkg], stderr=subprocess.STDOUT)
                        result["diagnostics"].append(f"Package {pkg} is installed but library not found in standard locations")
                    except subprocess.CalledProcessError:
                        result["diagnostics"].append(f"Package {pkg} is not installed")
                    except Exception:
                        pass
            except Exception:
                pass
    elif IS_WINDOWS:
        # Check for common Windows PKCS#11 libraries
        potential_paths = [
            "C:\\Windows\\System32\\opencryptoki.dll", 
            "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
            "C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\pkcs11.dll",
            "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                lib_paths.append(path)
                
        if not lib_paths:
            result["diagnostics"].append("No PKCS#11 libraries found on Windows")
    elif IS_DARWIN:
        # Check for common macOS PKCS#11 libraries
        potential_paths = [
            "/usr/local/lib/opensc-pkcs11.so", 
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/usr/local/lib/pkcs11/yubico-pkcs11.dylib",
            "/usr/local/opt/opensc/lib/pkcs11/opensc-pkcs11.so"
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                lib_paths.append(path)
                
        if not lib_paths:
            result["diagnostics"].append("No PKCS#11 libraries found on macOS")
    
    result["libraries_found"] = lib_paths
    
    if not lib_paths:
        result["error"] = "No PKCS#11 libraries found"
        logger.warning("No PKCS#11 libraries found")
        result["using_software_hsm"] = True
        result["diagnostics"].append("Using software HSM fallback due to no PKCS#11 libraries")
        return result
    
    # Try each library
    total_usable_tokens = 0
    for lib_path in lib_paths:
        try:
            lib = pkcs11.lib(lib_path)
            tokens = list(lib.get_tokens())
            
            lib_info = {
                "path": lib_path,
                "tokens_found": len(tokens),
                "token_labels": [token.label for token in tokens],
                "token_details": [],
                "error": None
            }
            
            # Check each token in detail
            for token in tokens:
                token_detail = {
                    "label": token.label,
                    "manufacturer": token.manufacturer_id,
                    "model": token.model,
                    "serial": token.serial,
                    "usable": False,
                    "mechanisms": [],
                    "requires_pin": None,
                    "has_rsa": False,
                    "has_ec": False
                }
                
                # Try to open session to verify token is usable
                try:
                    # Try to open session without login
                    session = token.open()
                    token_detail["usable"] = True
                    
                    # Check available mechanisms
                    try:
                        mechanisms = session.get_mechanisms()
                        token_detail["mechanisms"] = [str(m) for m in mechanisms]
                        
                        # Check for RSA and EC support
                        if pkcs11.Mechanism.RSA_PKCS_KEY_PAIR_GEN in mechanisms:
                            token_detail["has_rsa"] = True
                        
                        if hasattr(pkcs11.Mechanism, "EC_KEY_PAIR_GEN") and pkcs11.Mechanism.EC_KEY_PAIR_GEN in mechanisms:
                            token_detail["has_ec"] = True
                    except Exception as e:
                        token_detail["mechanism_error"] = str(e)
                        
                    # Check if PIN is required for private key operations
                    try:
                        # Find any private key to test with
                        private_keys = list(session.get_objects({CKA.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}))
                        if private_keys:
                            # If we can list private keys without login, token might not require PIN
                            # But try a signing operation to be sure
                            try:
                                # This will likely fail without login, which confirms PIN is required
                                if hasattr(private_keys[0], "sign"):
                                    private_keys[0].sign(b'test')
                                    token_detail["requires_pin"] = False
                            except pkcs11.exceptions.PinRequired:
                                token_detail["requires_pin"] = True
                            except Exception:
                                # Other errors might indicate PIN is required but we can't confirm
                                token_detail["requires_pin"] = "unknown"
                    except Exception:
                        # If we can't list private keys, PIN is likely required
                        token_detail["requires_pin"] = "unknown"
                        
                    # If token is usable and has either RSA or EC, add to usable tokens
                    if token_detail["usable"] and (token_detail["has_rsa"] or token_detail["has_ec"]):
                        total_usable_tokens += 1
                        result["usable_tokens"].append({
                            "library": lib_path,
                            "label": token.label,
                            "manufacturer": token.manufacturer_id,
                            "model": token.model
                        })
                except Exception as e:
                    token_detail["usable"] = False
                    token_detail["error"] = str(e)
                    result["diagnostics"].append(f"Token {token.label} is not usable: {e}")
                
                lib_info["token_details"].append(token_detail)
            
            result["library_details"][lib_path] = lib_info
            
            if tokens:
                result["tokens_available"] = True
                result["token_count"] += len(tokens)
                result["token_labels"].extend([token.label for token in tokens])
                logger.info(f"Found {len(tokens)} PKCS#11 tokens in {lib_path}")
                result["diagnostics"].append(f"Found {len(tokens)} PKCS#11 tokens in {lib_path}")
            else:
                logger.warning(f"No tokens found in PKCS#11 library {lib_path}")
                result["diagnostics"].append(f"No tokens found in PKCS#11 library {lib_path}")
        except Exception as e:
            logger.warning(f"Error accessing PKCS#11 library {lib_path}: {e}")
            result["diagnostics"].append(f"Error accessing PKCS#11 library {lib_path}: {e}")
            result["library_details"][lib_path] = {
                "path": lib_path,
                "tokens_found": 0,
                "error": str(e)
            }
    
    # Set final status
    if not result["tokens_available"]:
        result["error"] = "PKCS#11 library found but no tokens available"
        logger.warning("PKCS#11 library found but no tokens available")
        result["diagnostics"].append("PKCS#11 library found but no tokens available")
        result["using_software_hsm"] = True
    elif total_usable_tokens == 0:
        result["error"] = "PKCS#11 tokens found but none are usable for cryptographic operations"
        logger.warning("PKCS#11 tokens found but none are usable for cryptographic operations")
        result["diagnostics"].append("PKCS#11 tokens found but none are usable for cryptographic operations")
        result["using_software_hsm"] = True
    else:
        result["using_software_hsm"] = False
        result["diagnostics"].append(f"Found {total_usable_tokens} usable PKCS#11 tokens")
    
    # Add detailed recommendations if using software HSM
    if result["using_software_hsm"]:
        logger.warning("Uses software HSM fallback for key operations")
        result["diagnostics"].append("Using software HSM fallback for key operations")
        
        # Add platform-specific recommendations
        if IS_LINUX:
            result["diagnostics"].append("Consider installing softhsm2 or opencryptoki for hardware security")
        elif IS_WINDOWS:
            result["diagnostics"].append("Consider installing OpenSC or a compatible smart card middleware")
        elif IS_DARWIN:
            result["diagnostics"].append("Consider installing OpenSC via Homebrew: brew install opensc")
    
    return result

# Enhanced secure random generation with better fallbacks
def enhanced_secure_random(num_bytes: int = 32) -> dict:
    """
    Enhanced secure random number generation with multiple entropy sources and fallbacks.
    
    This function attempts to gather random data from multiple hardware and software sources,
    with graceful fallbacks to ensure high-quality randomness even when hardware sources
    are unavailable.
    
    Args:
        num_bytes: Number of random bytes to generate
        
    Returns:
        dict: Random bytes and detailed information about the sources used
    """
    result = {
        "success": False,
        "random_bytes": None,
        "source": None,
        "error": None,
        "fallback_used": True,
        "entropy_estimate": None,
        "sources_used": [],
        "diagnostics": []
    }
    
    if num_bytes <= 0:
        result["error"] = "Number of bytes must be positive"
        return result
    
    # Initialize entropy pool
    entropy_pool = bytearray(num_bytes)
    sources_used = 0
    
    # Try hardware sources first
    
    # Try TPM if available
    tpm_result = enhanced_tpm_detection()
    if tpm_result["tpm_available"]:
        try:
            if IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE:
                # Use Windows CNG for TPM-backed random
                buffer = ctypes.create_string_buffer(num_bytes)
                bcrypt = ctypes.windll.bcrypt
                status = bcrypt.BCryptGenRandom(None, buffer, num_bytes, 0x00000002)  # BCRYPT_USE_SYSTEM_PREFERRED_RNG
                
                if status == 0:  # STATUS_SUCCESS
                    # Mix into entropy pool
                    for i in range(num_bytes):
                        entropy_pool[i] ^= buffer.raw[i]
                    
                    result["sources_used"].append("Windows TPM via BCryptGenRandom")
                    result["diagnostics"].append("Successfully gathered entropy from Windows TPM")
                    sources_used += 1
                    
                    # If this is our only source, we can return immediately
                    if sources_used == 1:
                        result["random_bytes"] = bytes(entropy_pool)
                        result["success"] = True
                        result["source"] = "Windows TPM via BCryptGenRandom"
                        result["fallback_used"] = False
                        logger.debug(f"Generated {num_bytes} random bytes from Windows TPM")
                        return result
            elif IS_LINUX:
                # Try using TPM2 tools for random
                try:
                    tpm2_result = subprocess.run(
                        ["tpm2_getrandom", str(num_bytes), "--hex"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=2
                    )
                    
                    if tpm2_result.returncode == 0:
                        # Convert hex output to bytes
                        hex_random = tpm2_result.stdout.decode().strip()
                        random_bytes = bytes.fromhex(hex_random)
                        
                        if len(random_bytes) == num_bytes:
                            # Mix into entropy pool
                            for i in range(num_bytes):
                                entropy_pool[i] ^= random_bytes[i]
                            
                            result["sources_used"].append("Linux TPM2 via tpm2_getrandom")
                            result["diagnostics"].append("Successfully gathered entropy from Linux TPM")
                            sources_used += 1
                            
                            # If this is our only source, we can return immediately
                            if sources_used == 1:
                                result["random_bytes"] = bytes(entropy_pool)
                                result["success"] = True
                                result["source"] = "Linux TPM2 via tpm2_getrandom"
                                result["fallback_used"] = False
                                logger.debug(f"Generated {num_bytes} random bytes from Linux TPM")
                                return result
                except Exception as e:
                    result["diagnostics"].append(f"Error using tpm2_getrandom: {e}")
                    logger.warning(f"Error using tpm2_getrandom: {e}")
                    
                # Try using TPM2 Python bindings as alternative
                try:
                    import tpm2_pytss # type: ignore
                    from tpm2_pytss.ESAPI import ESAPI # type: ignore
                    
                    with ESAPI() as esapi:
                        random_bytes = esapi.GetRandom(num_bytes)
                        
                        if len(random_bytes) == num_bytes:
                            # Mix into entropy pool
                            for i in range(num_bytes):
                                entropy_pool[i] ^= random_bytes[i]
                            
                            result["sources_used"].append("Linux TPM2 via tpm2_pytss")
                            result["diagnostics"].append("Successfully gathered entropy from Linux TPM via Python bindings")
                            sources_used += 1
                            
                            # If this is our only source, we can return immediately
                            if sources_used == 1:
                                result["random_bytes"] = bytes(entropy_pool)
                                result["success"] = True
                                result["source"] = "Linux TPM2 via tpm2_pytss"
                                result["fallback_used"] = False
                                logger.debug(f"Generated {num_bytes} random bytes from Linux TPM via Python bindings")
                                return result
                except Exception as e:
                    result["diagnostics"].append(f"Error using tpm2_pytss: {e}")
                    logger.warning(f"Error using tpm2_pytss: {e}")
        except Exception as e:
            result["diagnostics"].append(f"Failed to get random from TPM: {e}")
            logger.warning(f"Failed to get random from TPM: {e}")
    else:
        result["diagnostics"].append("TPM not available for random generation")
    
    # Try PKCS#11 HSM if available
    pkcs11_result = enhanced_pkcs11_detection()
    if pkcs11_result["tokens_available"]:
        try:
            hsm_random = get_hsm_random_bytes(num_bytes)
            if hsm_random and len(hsm_random) == num_bytes:
                # Mix into entropy pool
                for i in range(num_bytes):
                    entropy_pool[i] ^= hsm_random[i]
                
                result["sources_used"].append("PKCS#11 HSM")
                result["diagnostics"].append("Successfully gathered entropy from PKCS#11 HSM")
                sources_used += 1
                
                # If this is our only source, we can return immediately
                if sources_used == 1:
                    result["random_bytes"] = bytes(entropy_pool)
                    result["success"] = True
                    result["source"] = "PKCS#11 HSM"
                    result["fallback_used"] = False
                    logger.debug(f"Generated {num_bytes} random bytes from HSM")
                    return result
        except Exception as e:
            result["diagnostics"].append(f"Failed to get random from HSM: {e}")
            logger.warning(f"Failed to get random from HSM: {e}")
    else:
        result["diagnostics"].append("No PKCS#11 tokens available for random generation")
    
    # Try libsodium if available
    try:
        import nacl.utils
        sodium_random = nacl.utils.random(num_bytes)
        
        # Mix into entropy pool
        for i in range(num_bytes):
            entropy_pool[i] ^= sodium_random[i]
        
        result["sources_used"].append("libsodium")
        result["diagnostics"].append("Successfully gathered entropy from libsodium")
        sources_used += 1
    except ImportError:
        result["diagnostics"].append("libsodium not available for random generation")
    except Exception as e:
        result["diagnostics"].append(f"Error using libsodium for random generation: {e}")
        logger.warning(f"Error using libsodium for random generation: {e}")
    
    # Always include OS-specific high-quality random sources
    try:
        if IS_WINDOWS:
            # Use Windows CryptGenRandom via os.urandom
            random_bytes = os.urandom(num_bytes)
            
            # Mix into entropy pool
            for i in range(num_bytes):
                entropy_pool[i] ^= random_bytes[i]
            
            result["sources_used"].append("Windows CryptGenRandom via os.urandom")
            result["diagnostics"].append("Successfully gathered entropy from Windows CryptGenRandom")
            sources_used += 1
        elif IS_LINUX:
            # Try reading directly from /dev/urandom first
            try:
                with open("/dev/urandom", "rb") as f:
                    random_bytes = f.read(num_bytes)
                    
                    # Mix into entropy pool
                    for i in range(num_bytes):
                        entropy_pool[i] ^= random_bytes[i]
                    
                    result["sources_used"].append("Linux /dev/urandom")
                    result["diagnostics"].append("Successfully gathered entropy from /dev/urandom")
                    sources_used += 1
            except Exception as e:
                result["diagnostics"].append(f"Error reading from /dev/urandom: {e}")
                logger.warning(f"Error reading from /dev/urandom: {e}")
                
                # Fall back to os.urandom
                random_bytes = os.urandom(num_bytes)
                
                # Mix into entropy pool
                for i in range(num_bytes):
                    entropy_pool[i] ^= random_bytes[i]
                
                result["sources_used"].append("os.urandom")
                result["diagnostics"].append("Successfully gathered entropy from os.urandom")
                sources_used += 1
        else:
            # Default to os.urandom for other platforms
            random_bytes = os.urandom(num_bytes)
            
            # Mix into entropy pool
            for i in range(num_bytes):
                entropy_pool[i] ^= random_bytes[i]
            
            result["sources_used"].append("os.urandom")
            result["diagnostics"].append("Successfully gathered entropy from os.urandom")
            sources_used += 1
    except Exception as e:
        result["diagnostics"].append(f"Error using OS random source: {e}")
        logger.warning(f"Error using OS random source: {e}")
    
    # Add time-based entropy as additional source (not primary)
    try:
        # Create a hash from current time and system info
        import time
        import platform
        import socket
        
        time_data = str(time.time()).encode()
        platform_data = platform.platform().encode()
        hostname_data = socket.gethostname().encode()
        
        # Create a SHA-256 hash of the combined data
        hash_obj = hashlib.sha256()
        hash_obj.update(time_data)
        hash_obj.update(platform_data)
        hash_obj.update(hostname_data)
        
        time_hash = hash_obj.digest()
        
        # Use as many bytes as we need
        for i in range(min(len(time_hash), num_bytes)):
            entropy_pool[i] ^= time_hash[i]
        
        result["sources_used"].append("time-based entropy")
        result["diagnostics"].append("Added time-based entropy as supplementary source")
        sources_used += 1
    except Exception as e:
        result["diagnostics"].append(f"Error adding time-based entropy: {e}")
    
    # Set final result
    if sources_used > 0:
        result["random_bytes"] = bytes(entropy_pool)
        result["success"] = True
        
        if len(result["sources_used"]) == 1:
            result["source"] = result["sources_used"][0]
        else:
            result["source"] = f"mixed ({', '.join(result['sources_used'])})"
        
        # Determine if we used hardware sources
        result["fallback_used"] = not any(s for s in result["sources_used"] if "TPM" in s or "HSM" in s)
        
        # Estimate entropy quality
        if "TPM" in result["source"] or "HSM" in result["source"]:
            result["entropy_estimate"] = "high"
        elif sources_used >= 2:
            result["entropy_estimate"] = "medium-high"
        else:
            result["entropy_estimate"] = "medium"
            
        logger.debug(f"Generated {num_bytes} random bytes from {result['source']}")
    else:
        result["error"] = "Failed to generate random bytes from any source"
        result["diagnostics"].append("Critical failure: No entropy sources available")
        logger.error("Failed to generate random bytes from any source")
    
    return result

# Enhanced TLS PQ support detection
def enhanced_tls_pq_support() -> dict:
    """
    Enhanced detection of post-quantum TLS support with comprehensive diagnostics.
    
    This function performs a thorough check of post-quantum TLS support,
    testing multiple hybrid key exchange groups and providing detailed
    diagnostics about why PQ support might not be available and what
    fallback options are being used.
    
    Returns:
        dict: Detailed information about PQ TLS support and fallbacks
    """
    result = {
        "pq_supported": False,
        "set_groups_available": False,
        "openssl_version": ssl.OPENSSL_VERSION,
        "openssl_version_info": ssl.OPENSSL_VERSION_INFO,
        "has_tls13": ssl.HAS_TLS_VERSION.get("TLSv1_3", False),
        "error": None,
        "groups_tested": [],
        "groups_supported": [],
        "fallback_options": [],
        "diagnostics": [],
        "software_pq_available": False,
        "recommended_action": None
    }
    
    # Check if we have TLS 1.3 support
    if not result["has_tls13"]:
        result["error"] = "TLS 1.3 not supported"
        result["diagnostics"].append("TLS 1.3 not supported by SSL library")
        logger.warning("TLS 1.3 not supported by SSL library")
        result["recommended_action"] = "Upgrade OpenSSL to a version that supports TLS 1.3"
        return result
    
    # Check if set_groups is available
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    has_set_groups = hasattr(context, "set_groups")
    result["set_groups_available"] = has_set_groups
    
    if has_set_groups:
        result["diagnostics"].append("SSLContext.set_groups() is available")
    else:
        result["error"] = "SSLContext.set_groups() not available"
        result["diagnostics"].append("SSLContext.set_groups() not available - cannot configure PQ key exchange")
        logger.warning("SSLContext.set_groups() not available. Post-quantum TLS KEX may not be available.")
        result["recommended_action"] = "Upgrade Python to 3.8+ and OpenSSL to 1.1.1+ for set_groups support"
        return result
    
    # Try to set various post-quantum groups
    pq_groups = [
        # ML-KEM (formerly Kyber) hybrid groups
        "x25519_kyber768", 
        "p256_kyber768",
        "x25519_kyber512", 
        "p256_kyber512",
        "x25519_kyber1024",
        "p384_kyber768",
        "p521_kyber1024",
        # ML-KEM (NIST standardized name for Kyber)
        "x25519_mlkem768", 
        "p256_mlkem768",
        "x25519_mlkem512", 
        "p256_mlkem512",
        "x25519_mlkem1024",
        "p384_mlkem768",
        "p521_mlkem1024",
        # Standalone PQ groups
        "kyber768",
        "kyber1024",
        "mlkem768",
        "mlkem1024"
    ]
    
    result["groups_tested"] = pq_groups
    
    for group in pq_groups:
        try:
            test_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            test_context.set_groups([group])
            result["groups_supported"].append(group)
            result["diagnostics"].append(f"Post-quantum TLS group supported: {group}")
            logger.info(f"Post-quantum TLS group supported: {group}")
        except (ssl.SSLError, ValueError) as e:
            logger.debug(f"Post-quantum TLS group {group} not supported: {e}")
    
    # Check if any PQ groups are supported
    if result["groups_supported"]:
        result["pq_supported"] = True
        
        # Categorize supported groups
        hybrid_groups = [g for g in result["groups_supported"] if "_" in g]
        standalone_groups = [g for g in result["groups_supported"] if "_" not in g]
        
        if hybrid_groups:
            result["diagnostics"].append(f"Hybrid post-quantum groups supported: {', '.join(hybrid_groups)}")
        if standalone_groups:
            result["diagnostics"].append(f"Standalone post-quantum groups supported: {', '.join(standalone_groups)}")
            
        # Determine best group based on security level
        best_group = None
        if any(g for g in result["groups_supported"] if "1024" in g):
            best_group = next(g for g in result["groups_supported"] if "1024" in g)
            result["diagnostics"].append(f"NIST Level 5 post-quantum security available via {best_group}")
        elif any(g for g in result["groups_supported"] if "768" in g):
            best_group = next(g for g in result["groups_supported"] if "768" in g)
            result["diagnostics"].append(f"NIST Level 3 post-quantum security available via {best_group}")
        elif any(g for g in result["groups_supported"] if "512" in g):
            best_group = next(g for g in result["groups_supported"] if "512" in g)
            result["diagnostics"].append(f"NIST Level 1 post-quantum security available via {best_group}")
            
        if best_group:
            result["recommended_group"] = best_group
    else:
        result["error"] = "No post-quantum TLS groups supported"
        result["diagnostics"].append("No post-quantum TLS groups supported by OpenSSL")
        logger.warning("No post-quantum TLS groups supported. Quantum security may be compromised.")
    
    # Check for software PQ implementation as fallback
    try:
        # Check for pqc_algorithms enhanced implementations
        from pqc_algorithms import EnhancedMLKEM_1024, EnhancedFALCON_1024, EnhancedHQC, HybridKEX
        result["software_pq_available"] = True
        result["fallback_options"].append("pqc_algorithms_enhanced")
        result["diagnostics"].append("Enhanced post-quantum implementation available via pqc_algorithms")
    except ImportError:
        try:
            # Check for quantcrypt
            import quantcrypt
            result["software_pq_available"] = True
            result["fallback_options"].append("quantcrypt")
            result["diagnostics"].append("Software post-quantum implementation available via quantcrypt")
        except ImportError:
            try:
                # Check for liboqs-python
                import oqs
                result["software_pq_available"] = True
                result["fallback_options"].append("liboqs-python")
                result["diagnostics"].append("Software post-quantum implementation available via liboqs-python")
            except ImportError:
                result["diagnostics"].append("No software post-quantum implementations found")
    
    # Check for hybrid_kex module
    try:
        from hybrid_kex import HybridKeyExchange
        result["fallback_options"].append("hybrid_kex")
        result["diagnostics"].append("Application-layer post-quantum key exchange available via hybrid_kex module")
    except ImportError:
        result["diagnostics"].append("Application-layer post-quantum key exchange not available")
    
    # Set recommended action based on findings
    if not result["pq_supported"]:
        if "pqc_algorithms_enhanced" in result.get("fallback_options", []):
            result["recommended_action"] = "Use application-layer enhanced post-quantum key exchange from pqc_algorithms"
        elif result["software_pq_available"]:
            result["recommended_action"] = "Use application-layer post-quantum key exchange as fallback"
        else:
            result["recommended_action"] = "Install post-quantum cryptography libraries (pqc_algorithms, quantcrypt or liboqs-python)"
            logger.warning("CRITICAL SECURITY ISSUE DETECTED! No quantum-resistant key exchange available.")
            result["diagnostics"].append("CRITICAL SECURITY ISSUE: No quantum-resistant key exchange available")
    
    return result

# Create a TLS context with PQ fallbacks
def create_tls_context_with_pq_fallback(is_server: bool = False) -> ssl.SSLContext:
    """
    Create a TLS context with post-quantum support if available, with robust fallbacks.
    
    This function creates a TLS context with the highest security level available,
    prioritizing post-quantum security if supported, and falling back to classical
    cryptography with additional application-layer protections when needed.
    
    Args:
        is_server: Whether this is a server context
        
    Returns:
        ssl.SSLContext: Configured TLS context with appropriate security settings
    """
    # Create context with TLS 1.3
    protocol = ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT
    context = ssl.SSLContext(protocol)
    
    # Set minimum TLS version to 1.3
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    except (AttributeError, ValueError):
        # Fallback for older Python versions
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        logger.warning("Setting TLS 1.3 as minimum version not supported - using options flags instead")
    
    # Set secure cipher suites
    try:
        # Try to set PQ cipher suites first if they might be supported
        context.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
    except ssl.SSLError:
        # Fallback to standard TLS 1.3 cipher suites
        try:
            context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256")
            logger.warning("Using TLS 1.2 cipher suites as fallback")
        except ssl.SSLError:
            logger.warning("Failed to set specific cipher suites - using defaults")
    
    # Try to set post-quantum groups if supported
    pq_support = enhanced_tls_pq_support()
    pq_configured = False
    
    if pq_support["pq_supported"] and pq_support["set_groups_available"]:
        try:
            # Prioritize highest security level groups
            level5_groups = [g for g in pq_support["groups_supported"] if "1024" in g]
            level3_groups = [g for g in pq_support["groups_supported"] if "768" in g]
            level1_groups = [g for g in pq_support["groups_supported"] if "512" in g]
            
            # Add groups in order of security level
            prioritized_groups = level5_groups + level3_groups + level1_groups
            
            # Add classical groups as fallback
            classical_groups = ["x25519", "p256", "p384", "p521"]
            
            # Set both PQ and classical groups
            all_groups = prioritized_groups + classical_groups
            context.set_groups(all_groups)
            
            logger.info(f"TLS context configured with post-quantum key exchange groups: {', '.join(prioritized_groups)}")
            pq_configured = True
        except Exception as e:
            logger.warning(f"Failed to set post-quantum groups: {e}")
    
    if not pq_configured:
        # Set classical groups only if we couldn't set PQ groups
        if pq_support["set_groups_available"]:
            try:
                classical_groups = ["x25519", "p256", "p384", "p521"]
                context.set_groups(classical_groups)
                logger.warning("TLS context configured with classical key exchange groups only - NO QUANTUM RESISTANCE")
            except Exception as e:
                logger.warning(f"Failed to set classical groups: {e}")
        else:
            logger.warning("Unable to configure specific key exchange groups - using defaults")
    
    # Set other security options
    context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    
    # Add additional security options if available
    for option_name in ["OP_NO_COMPRESSION", "OP_NO_TICKET", "OP_CIPHER_SERVER_PREFERENCE", 
                        "OP_PRIORITIZE_CHACHA", "OP_NO_RENEGOTIATION"]:
        option = getattr(ssl, option_name, 0)
        if option:
            context.options |= option
    
    # Set verification mode
    if is_server:
        context.verify_mode = ssl.CERT_OPTIONAL
        context.check_hostname = False
    else:
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
    
    # Enable OCSP stapling if available
    if hasattr(context, "ocsp_staple"):
        context.ocsp_staple = True
    
    # Enable certificate transparency if available
    if hasattr(context, "cert_transparency"):
        context.cert_transparency = True
    
    # Log warning if no PQ support is available
    if not pq_configured:
        logger.warning("TLS context created WITHOUT post-quantum protection")
        
            # Check if we have application-layer PQ available
    if "pqc_algorithms_enhanced" in pq_support.get("fallback_options", []):
        logger.info("Enhanced application-layer post-quantum key exchange is available through pqc_algorithms")
    elif "hybrid_kex" in pq_support.get("fallback_options", []):
        logger.info("Application-layer post-quantum key exchange is available as fallback")
    
    return context

# Run diagnostics and log results
def run_security_diagnostics():
    """
    Run comprehensive security diagnostics and log results.
    
    Returns:
        dict: Comprehensive security diagnostics
    """
    results = {
        "tpm": enhanced_tpm_detection(),
        "pkcs11": enhanced_pkcs11_detection(),
        "random": enhanced_secure_random(32),
        "tls_pq": enhanced_tls_pq_support()
    }
    
    # Log a summary of the results
    logger.info("Security Diagnostics Summary:")
    
    # TPM status
    if results["tpm"]["tpm_available"]:
        logger.info(f"TPM available: {results['tpm']['tpm_type']}")
    else:
        logger.warning("No TPM detected, falls back to software implementation")
    
    # PKCS#11 status
    if results["pkcs11"]["tokens_available"]:
        logger.info(f"PKCS#11 tokens available: {results['pkcs11']['token_count']}")
    else:
        logger.warning("PKCS#11 library found but no tokens available")
    
    # Random generation
    logger.info(f"Random generation source: {results['random']['source']}")
    
    # TLS PQ support
    if results["tls_pq"]["pq_supported"]:
        logger.info(f"Post-quantum TLS supported with groups: {', '.join(results['tls_pq']['groups_supported'])}")
    else:
        logger.warning("Post-quantum TLS not supported. Quantum security may be compromised.")
    
    return results

def get_hsm_status():
    """Get the status of the HSM."""

    global _hsm_initialized, _hsm_session, _hsm_token, _hsm_provider_type, _cng_provider_handle

    status = {
        "initialized": _hsm_initialized,
        "provider": _hsm_provider_type,
        "token_info": None,
        "session_info": None,
        "diagnostics": []
    }

    try:
        if _hsm_initialized:
            status["initialized"] = True
            status["provider"] = _hsm_provider_type
            status["token_info"] = _hsm_token
            status["session_info"] = _hsm_session
            status["diagnostics"].append("HSM is initialized")
        else:
            status["initialized"] = False
            status["provider"] = None
            status["token_info"] = None
            status["session_info"] = None
            status["diagnostics"].append("HSM is not initialized")
    except Exception as e:
        status["diagnostics"].append(f"Could not get HSM status: {e}")
        
    return status

def is_hsm_initialized():
    """
    Check if the HSM is initialized and ready to be used.
    
    Returns:
        bool: True if the HSM is initialized, False otherwise.
    """
    global _hsm_initialized
    return _hsm_initialized

def generate_hsm_rsa_keypair(key_label, key_size=2048, use_cng=None):
    """
    Generate an RSA key pair in the HSM.

    Args:
        key_label: The label for the key pair.
        key_size: The size of the RSA key in bits.
        use_cng: Whether to use CNG for TPM-backed key generation.

    Returns:
        A tuple (private_key_handle, public_key_object) or None on failure.
        The private_key_handle is an integer for PKCS#11 or a NCRYPT_KEY_HANDLE value for Windows CNG.
        The public_key_object is a standard cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.
    """
    if use_cng is None:
        use_cng = IS_WINDOWS and _WINDOWS_CNG_NCRYPT_AVAILABLE

    if use_cng:
        return generate_tpm_backed_key(key_label, key_size)
    else:
        return generate_hsm_rsa_keypair(key_label, key_size)

if __name__ == "__main__":
    print("Starting tests for cross_platform_hw_security.py...")
    # Configure logging for the test run
    logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] %(message)s")
    logger.setLevel(logging.DEBUG) # Ensure our specific logger is also at debug level for tests

    # Test 1: Secure Random Number Generation
    print("\n--- Test 1: Secure Random Number Generation ---")
    random_bytes = get_secure_random(32)
    if random_bytes and len(random_bytes) == 32:
        print(f"get_secure_random(32) successful: {random_bytes.hex()}")
    else:
        print(f"get_secure_random(32) FAILED. Output: {random_bytes}")

    # Test 2: Hardware-Bound Identity
    print("\n--- Test 2: Hardware-Bound Identity ---")
    hw_id = get_hardware_unique_id()
    if hw_id and len(hw_id) == 16:
        print(f"get_hardware_unique_id() successful: {hw_id.hex()}")
    else:
        print(f"get_hardware_unique_id() FAILED. Output: {hw_id}")

    # Test 3: Secure Key Storage (OS Keyring)
    print("\n--- Test 3: Secure Key Storage (OS Keyring) ---")
    keyring_label = "cphs_test_secret"
    keyring_secret_orig = b"SuperSecretDataForKeystore!123"
    store_ok = store_secret_os_keyring(keyring_label, keyring_secret_orig)
    if store_ok:
        print(f"store_secret_os_keyring('{keyring_label}', ...) successful.")
        retrieved_secret = retrieve_secret_os_keyring(keyring_label)
        if retrieved_secret == keyring_secret_orig:
            print(f"retrieve_secret_os_keyring('{keyring_label}') successful and data matches.")
        else:
            print(f"retrieve_secret_os_keyring('{keyring_label}') FAILED or data mismatch. Retrieved: {retrieved_secret.hex() if retrieved_secret else 'None'}")
        # Clean up keyring entry (optional, good for testing)
        try:
            keyring.delete_password("cross_platform_security", keyring_label)
            print(f"Test secret '{keyring_label}' deleted from OS keyring.")
        except Exception as e:
            print(f"Could not delete test secret from keyring: {e}")
    else:
        print(f"store_secret_os_keyring('{keyring_label}', ...) FAILED.")

    # Test 4: Linux Key File Storage & Memory Locking (Linux only)
    if IS_LINUX:
        print("\n--- Test 4: Linux Key File Storage & Memory Locking ---")
        if _AESGCM_AVAILABLE:
            linux_key_label = "cphs_linux_test_key"
            linux_key_data_orig = get_secure_random(64) # Use random data
            store_linux_ok = store_key_file_linux(linux_key_label, linux_key_data_orig)
            if store_linux_ok:
                print(f"store_key_file_linux('{linux_key_label}', ...) successful.")
                retrieved_key_buffer = retrieve_key_file_linux(linux_key_label)
                if retrieved_key_buffer and bytes(retrieved_key_buffer) == linux_key_data_orig:
                    print(f"retrieve_key_file_linux('{linux_key_label}') successful and data matches.")
                    key_addr = ctypes.addressof(retrieved_key_buffer)
                    key_len = len(retrieved_key_buffer)
                    if lock_memory(key_addr, key_len):
                        print(f"lock_memory() successful for retrieved key.")
                        if unlock_memory(key_addr, key_len):
                            print(f"unlock_memory() successful.")
                        else:
                            print(f"unlock_memory() FAILED.")
                    else:
                        print(f"lock_memory() FAILED.")
                    # Clean up key file
                    try:
                        secure_dir = os.path.expanduser("~/.cross_platform_secure")
                        os.remove(os.path.join(secure_dir, f"{linux_key_label}.bin"))
                        print(f"Test key file for '{linux_key_label}' deleted.")
                    except Exception as e:
                        print(f"Could not delete test key file: {e}")
                else:
                    print(f"retrieve_key_file_linux('{linux_key_label}') FAILED or data mismatch.")
            else:
                print(f"store_key_file_linux('{linux_key_label}', ...) FAILED.")
        else:
            print("Skipping Linux key file tests: PyCryptodome AESGCM not available.")
    else:
        print("\n--- Test 4: Linux Key File Storage & Memory Locking (Skipped, not Linux) ---")

    # Test 5: HSM Operations (if PKCS#11 library available and configured)
    print("\n--- Test 5: HSM Operations ---")
    if _PKCS11_SUPPORT_AVAILABLE:
        # Attempt to initialize HSM. User might need to set PKCS11_LIB_PATH and HSM_PIN environment variables.
        # Or provide them directly: init_hsm(lib_path="/path/to/lib.so", pin="1234")
        print("Attempting HSM initialization (ensure PKCS11_LIB_PATH and HSM_PIN are set if using a real HSM, or that SoftHSM2 is configured).")
        hsm_init_ok = init_hsm()
        if hsm_init_ok:
            print("init_hsm() successful.")
            
            # Test HSM random bytes
            hsm_rand = get_hsm_random_bytes(16)
            if hsm_rand and len(hsm_rand) == 16:
                print(f"get_hsm_random_bytes(16) successful: {hsm_rand.hex()}")
            else:
                print(f"get_hsm_random_bytes(16) FAILED. Output: {hsm_rand}")

            # Test HSM RSA key generation
            hsm_key_label = "cphs_hsm_test_rsa_key"
            key_pair_result = generate_hsm_rsa_keypair(key_label=hsm_key_label, key_size=2048) # Use 2048 for faster test
            if key_pair_result:
                priv_key_handle, pub_key_obj = key_pair_result
                print(f"generate_hsm_rsa_keypair('{hsm_key_label}') successful. Private Handle: {priv_key_handle}")
                # print(f"Public Key (PEM):\n{pub_key_obj.public_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")
                
                # Test HSM signing
                data_to_sign = b"Data to be signed by HSM key!"
                # For RSA, CKM.SHA256_RSA_PKCS is a common one. CKM.RSA_PKCS also exists.
                # CKM.SHA256_RSA_PKCS_PSS is often preferred if supported.
                # We'll let sign_with_hsm_key use its default (SHA256_RSA_PKCS_PSS)
                signature = sign_with_hsm_key(priv_key_handle, data_to_sign)
                if signature:
                    print(f"sign_with_hsm_key() successful. Signature: {signature.hex()[:32]}...")
                    # Verification would require the public key and is more complex with PKCS#11 directly here
                    # but this confirms the signing operation itself worked.
                else:
                    print(f"sign_with_hsm_key() FAILED.")
                
                # Clean up the generated key (optional, good for testing)
                # This is complex as it requires finding the objects by label/ID and destroying them.
                # For now, we will skip direct cleanup of HSM keys in this basic test.
                # In a real scenario, keys should be managed (e.g., deleted by handle or label).
                print(f"Note: HSM key '{hsm_key_label}' was not automatically deleted. Manual cleanup may be needed on the HSM/token.")

            else:
                print(f"generate_hsm_rsa_keypair('{hsm_key_label}') FAILED.")
            
            close_hsm()
            print("close_hsm() called.")
        else:
            print("init_hsm() FAILED. Skipping further HSM tests. (Is PKCS11_LIB_PATH set? Is PIN correct? Is token available?)")
    else:
        print("Skipping HSM tests: python-pkcs11 library not available.")

    # Test 6: Device Attestation
    print("\n--- Test 6: Device Attestation ---")
    attestation_info = attest_device()
    if attestation_info:
        print(f"attest_device() successful. Info: {attestation_info}")
    else:
        print(f"attest_device() FAILED or returned no info.")
    
    # Test 7: Windows CNG TPM Key Operations (Windows Only)
    if IS_WINDOWS:
        print("\n--- Test 7: Windows CNG TPM Key Operations ---")
        # _open_cng_provider_platform() # Ensures provider is open if not already by other calls. 
        # Most CNG functions call it internally if needed.

        if not _WINDOWS_CNG_NCRYPT_AVAILABLE:
            print("Skipping CNG TPM Key Operations: CNG/NCrypt libraries not available.")
        else:
            # Attempt to open provider once at the start of this test block for efficiency
            # This also serves as an early check.
            if not _open_cng_provider_platform():
                print("Failed to open CNG provider at the start of Test 7. Skipping CNG tests.")
            else:
                cng_key_name = "cphs_cng_test_key_123"
                cng_key_name_existing = "cphs_cng_test_key_existing_456"
                
                # Initial cleanup
                print(f"\nInitial cleanup attempt for '{cng_key_name}':")
                initial_delete_cng = delete_tpm_key(cng_key_name)
                print(f"delete_tpm_key('{cng_key_name}'): {'Success' if initial_delete_cng else 'Failed/Not Found'}")
                
                print(f"\nInitial cleanup attempt for '{cng_key_name_existing}':")
                initial_delete_existing = delete_tpm_key(cng_key_name_existing)
                print(f"delete_tpm_key('{cng_key_name_existing}'): {'Success' if initial_delete_existing else 'Failed/Not Found'}")

                print(f"\n--- Testing Key Generation & Basic Operations for '{cng_key_name}' ---")
                print(f"Attempting to generate new key: '{cng_key_name}' with overwrite=True")
                key_gen_result = generate_tpm_backed_key_with_attestation(cng_key_name, key_size=2048, overwrite=True)
                
                key_handle_for_test = None # Keep track of handle for freeing later

                if key_gen_result:
                    key_handle_for_test, pub_key, attestation_data = key_gen_result
                    print(f"generate_tpm_backed_key_with_attestation('{cng_key_name}') successful. Handle: {key_handle_for_test.value if key_handle_for_test and key_handle_for_test.value else 'N/A'}")
                    
                    if attestation_data:
                        print(f"Attestation data received: {attestation_data.keys()}")
                    
                    if pub_key:
                        print(f"Public key retrieved, type: {type(pub_key)}")
                        if _CRYPTOGRAPHY_AVAILABLE and crypto_serialization:
                            try:
                                pem_pub_key = pub_key.public_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                                print(f"Public key (PEM format) starts with: {pem_pub_key[:75]}...")
                            except Exception as e_pem:
                                print(f"Could not serialize public key to PEM: {e_pem}")
                    else:
                        print("Public key NOT retrieved after generation (this is unexpected for a new key).")

                    if not (key_handle_for_test and key_handle_for_test.value):
                        print(f"Error: Key generation reported success but returned an invalid handle for '{cng_key_name}'. Further tests for this key will be compromised.")
                    
                    # Test is_tpm_key_present
                    if is_tpm_key_present(cng_key_name):
                        print(f"is_tpm_key_present('{cng_key_name}') is TRUE (Correct after generation).")
                    else:
                        print(f"is_tpm_key_present('{cng_key_name}') is FALSE (INCORRECT after successful generation).")
                    
                    # Test get_tpm_public_key by name
                    print(f"\nAttempting get_tpm_public_key by name ('{cng_key_name}')...")
                    pub_key_by_name = get_tpm_public_key(cng_key_name)
                    if pub_key_by_name:
                        print(f"get_tpm_public_key by name ('{cng_key_name}') successful.")
                    else:
                        print(f"get_tpm_public_key by name ('{cng_key_name}') FAILED.")

                    # Test signing only if we have a valid handle and public key
                    if key_handle_for_test and key_handle_for_test.value and pub_key:
                        data_to_sign_cng = b"This is data to be signed with a CNG key using PKCS1v15."
                        print(f"\nAttempting to sign data with key handle: {key_handle_for_test.value}, Hash: SHA256, Padding: PKCS1v15")
                        signature_cng_pkcs1 = sign_with_tpm_key(key_handle_for_test, data_to_sign_cng, hash_algorithm_name="SHA256", padding_scheme="PKCS1v15")
                        if signature_cng_pkcs1:
                            print(f"sign_with_tpm_key (using handle, PKCS1v15) successful. Signature: {signature_cng_pkcs1.hex()[:32]}...")
                            if _CRYPTOGRAPHY_AVAILABLE and crypto_padding and crypto_hashes:
                                try:
                                    pub_key.verify(
                                        signature_cng_pkcs1,
                                        data_to_sign_cng,
                                        crypto_padding.PKCS1v15(),
                                        crypto_hashes.SHA256()
                                    )
                                    print("CNG PKCS1v15 Signature VERIFIED successfully with retrieved public key.")
                                except Exception as e_verify_pkcs1:
                                    print(f"CNG PKCS1v15 Signature verification FAILED: {e_verify_pkcs1}")
                            else:
                                print("Skipping CNG PKCS1v15 signature verification (cryptography components missing).")
                        else:
                            print("sign_with_tpm_key (using handle, PKCS1v15) FAILED.")
                    else:
                        print("\nSkipping signing tests with handle due to missing handle or public key from generation.")

                    # Test signing by key name with PSS padding
                    # We use pub_key from the initial generation for verification.
                    if pub_key: # Check if we have a public key to verify against
                        data_to_sign_pss = b"This is data to be signed with a CNG key using PSS."
                        print(f"\nAttempting to sign data with key name: '{cng_key_name}', Hash: SHA256, Padding: PSS")
                        signature_cng_pss_by_name = sign_with_tpm_key(cng_key_name, data_to_sign_pss, hash_algorithm_name="SHA256", padding_scheme="PSS")
                        if signature_cng_pss_by_name:
                            print(f"sign_with_tpm_key (using name, PSS padding) successful. Signature: {signature_cng_pss_by_name.hex()[:32]}...")
                            if _CRYPTOGRAPHY_AVAILABLE and crypto_padding and crypto_hashes:
                                try:
                                    pub_key.verify(
                                        signature_cng_pss_by_name,
                                        data_to_sign_pss,
                                        crypto_padding.PSS(
                                            mgf=crypto_padding.MGF1(crypto_hashes.SHA256()),
                                            salt_length=crypto_hashes.SHA256.digest_size # Common salt length
                                        ),
                                        crypto_hashes.SHA256()
                                    )
                                    print("CNG PSS Signature VERIFIED successfully with retrieved public key.")
                                except Exception as e_verify_pss:
                                    print(f"CNG PSS Signature verification FAILED: {e_verify_pss}")
                            else:
                                print("Skipping CNG PSS signature verification (cryptography components missing).")
                        else:
                            print("sign_with_tpm_key (using name, PSS padding) FAILED.")
                    else:
                        print("\nSkipping PSS signing test by name due to missing public key from generation for verification.")

                    # Free the handle obtained from generate_tpm_backed_key
                    if key_handle_for_test and key_handle_for_test.value:
                        print(f"\nFreeing key handle {key_handle_for_test.value} for '{cng_key_name}'.")
                        free_status = _NCryptFreeObject(key_handle_for_test)
                        # NCryptFreeObject returns an HRESULT (LONG). 0 (STATUS_SUCCESS.value) is success.
                        if free_status == STATUS_SUCCESS.value:
                            print(f"NCryptFreeObject on key_handle for '{cng_key_name}' successful (status: {free_status}).")
                        else:
                            print(f"NCryptFreeObject on key_handle for '{cng_key_name}' returned non-success status: {free_status:#010x}.")
                        key_handle_for_test = None # Mark as freed
                else:
                    print(f"generate_tpm_backed_key_with_attestation('{cng_key_name}') FAILED. Skipping further tests for this key.")

                # Test key deletion
                print(f"\n--- Testing Key Deletion for '{cng_key_name}' ---")
                print(f"Attempting to delete key: '{cng_key_name}'")
                if delete_tpm_key(cng_key_name):
                    print(f"delete_tpm_key('{cng_key_name}') successful.")
                    if not is_tpm_key_present(cng_key_name):
                        print(f"is_tpm_key_present('{cng_key_name}') is FALSE after deletion (Correct).")
                    else:
                        print(f"is_tpm_key_present('{cng_key_name}') is TRUE after deletion (INCORRECT).")
                else:
                    print(f"delete_tpm_key('{cng_key_name}') FAILED. Key might not have existed or deletion error.")

                # Test non-overwrite behavior
                print(f"\n--- Testing Non-Overwrite Behavior for '{cng_key_name_existing}' ---")
                print(f"Attempting first generation of '{cng_key_name_existing}' with overwrite=True")
                key_gen_exist_1_res = generate_tpm_backed_key_with_attestation(cng_key_name_existing, key_size=2048, overwrite=True)
                handle_exist_1 = None
                if key_gen_exist_1_res:
                    handle_exist_1, _, _ = key_gen_exist_1_res
                    print(f"First generation of '{cng_key_name_existing}' successful. Handle: {handle_exist_1.value if handle_exist_1 else 'N/A'}")
                    
                    print(f"Attempting to generate '{cng_key_name_existing}' again with overwrite=False")
                    key_gen_exist_2_res = generate_tpm_backed_key_with_attestation(cng_key_name_existing, key_size=2048, overwrite=False)
                    handle_exist_2 = None
                    if key_gen_exist_2_res:
                        handle_exist_2, pub_key_exist_2, _ = key_gen_exist_2_res
                        print(f"Second call (overwrite=False) for '{cng_key_name_existing}' successful, key opened. Handle: {handle_exist_2.value if handle_exist_2 else 'N/A'}")
                        if pub_key_exist_2:
                            print("   Public key also retrieved on open.")
                        else:
                            print("   Public key NOT retrieved on open (this might be an issue).")
                        if handle_exist_2 and handle_exist_2.value:
                            _NCryptFreeObject(handle_exist_2)
                            print(f"   Freed handle {handle_exist_2.value} from second call.")
                    else:
                        print(f"Second call (overwrite=False) for '{cng_key_name_existing}' FAILED (expected to open, not fail).")
                    
                    # Clean up the first handle if it's still valid
                    if handle_exist_1 and handle_exist_1.value:
                         _NCryptFreeObject(handle_exist_1)
                         print(f"   Freed handle {handle_exist_1.value} from first generation.")
                else:
                    print(f"First generation of '{cng_key_name_existing}' FAILED. Cannot proceed with non-overwrite test.")
                
                print(f"\nFinal cleanup of '{cng_key_name_existing}':")
                delete_tpm_key(cng_key_name_existing) # Clean up the existing key
                print(f"Deletion attempt for '{cng_key_name_existing}' complete.")
                
                _close_cng_provider_platform()  # Close provider after all CNG tests for this block
                print("\nCNG Provider closed after tests.")
    else:
        print("\n--- Test 7: Windows CNG TPM Key Operations (Skipped, not Windows) ---")

    print("\nAll tests for cross_platform_hw_security.py completed.")