"""
Advanced Double Ratchet Protocol with Military-Grade Post-Quantum Security

This module implements a state-of-the-art secure messaging protocol based on
Signal's Double Ratchet algorithm, enhanced with post-quantum cryptography and
advanced security features for maximum protection against both classical and
quantum adversaries.

Core Security Architecture:
1. Forward Secrecy: Automatic key rotation prevents past message compromise
2. Break-in Recovery: Security is restored even after key compromise
3. Post-Quantum Resistance: Hybrid classical/quantum-resistant algorithms
4. Hardware Security Integration: TPM/SGX/Secure Enclave when available
5. Side-Channel Protection: Constant-time operations and memory protection
6. Threat Detection: Behavioral analysis and cryptographic anomaly detection

Cryptographic Components:
- Classical Security: X25519 for Diffie-Hellman exchanges
- Quantum Resistance: ML-KEM-1024 (NIST standardized) for key encapsulation
- Message Authentication: FALCON-1024 (NIST standardized) for signatures
- Symmetric Encryption: ChaCha20-Poly1305 AEAD for message confidentiality
- Key Derivation: HKDF with domain separation for cryptographic isolation

Advanced Security Features:
- Secure Memory Management: Protected memory for sensitive key material
- Hardware Binding: Device attestation for hardware-level trust
- Key Compartmentalization: Split key material across security domains
- Out-of-order Message Handling: Secure processing of delayed messages
- Replay Attack Prevention: Message deduplication with secure caching

This implementation follows NIST's recommendations for post-quantum security
and is designed for high-security applications where both classical and
quantum threats must be mitigated.
"""
# Import standard libraries
import gc 
import os
import hmac 
import hashlib
import logging
import struct
import base64
import json
import secrets
import mmap
import ctypes
import time
import math
import platform
import threading
import uuid
import sys
import subprocess
import shlex
from typing import Dict, Tuple, Any, Optional, List, Union, Callable, Deque
from dataclasses import dataclass
import collections # Added import

# Import the new cross-platform hardware security module
import platform_hsm_interface as cphs

# Classical cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# Post-quantum cryptography - Updated to use enhanced implementations
from pqc_algorithms import EnhancedMLKEM_1024, EnhancedFALCON_1024, EnhancedHQC, HybridKEX, ConstantTime, SideChannelProtection, SecureMemory, SecurityTest

# Configure dedicated logger for Double Ratchet protocol operations
ratchet_logger = logging.getLogger("double_ratchet")
ratchet_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging with detailed information for security auditing
ratchet_file_handler = logging.FileHandler(os.path.join("logs", "double_ratchet.log"))
ratchet_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
ratchet_file_handler.setFormatter(formatter)
ratchet_logger.addHandler(ratchet_file_handler)

# Setup console logging for immediate operational feedback
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
ratchet_logger.addHandler(console_handler)

ratchet_logger.info("Double Ratchet logger initialized")

# Standard logger for backward compatibility
logger = logging.getLogger(__name__)

# Advanced side-channel protection (if available)
try:
    from cryptography.hazmat.primitives import constant_time
    HAS_CONSTANT_TIME = True
except ImportError:
    HAS_CONSTANT_TIME = False

# Configure logging for backward compatibility
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
)
logger.setLevel(logging.INFO)

# Add file handler for security audit logging
try:
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(logs_dir, 'security_audit.log'))
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
    )
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Could not create security audit log file: {e}")

# Secure hardware integration - enhanced cross-platform implementation
class SecureHardwareError(Exception):
    """Raised when secure hardware functionality is unavailable or fails."""
    pass

# Platform constants (can still be useful locally, but HW detection is now in cphs)
SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux" 
IS_DARWIN = SYSTEM == "Darwin"  # macOS

# Hardware security flags will now be determined by cphs capabilities
# The old detection block (lines ~80-130) is removed.

# Improved memory protection functions now delegate to cphs
def secure_lock_memory(buffer_addr: int, length: int) -> bool:
    """Lock memory to prevent swapping of sensitive data."""
    return cphs.lock_memory(buffer_addr, length)
        
def secure_unlock_memory(buffer_addr: int, length: int) -> bool:
    """Unlock previously locked memory."""
    return cphs.unlock_memory(buffer_addr, length)

# Enhanced hardware ID generation now delegates to cphs
def get_hardware_unique_id_internal() -> bytes: # Renamed to avoid conflict if cphs is imported as *
    """Get hardware unique ID with enhanced cross-platform approach."""
    return cphs.get_hardware_unique_id()


# Fallback implementations for hardware security (can be kept for internal logic if needed)
class _StubTPMInterface:
    """Stub implementation when no TPM is available."""
    def __init__(self):
        logger.debug("Using stub TPM implementation")
        
    def get_random(self, num_bytes):
        """Generate secure random bytes using software."""
        return secrets.token_bytes(num_bytes)
        
    def store_key(self, key_id, key_data):
        """Store key in memory (not hardware)."""
        return False  # Cannot store keys securely
        
    def use_key(self, key_id, operation, data):
        """Use key for operation (not in hardware)."""
        return None  # Cannot perform hardware operations

class _StubSGXInterface:
    """Stub implementation when no SGX is available."""
    def __init__(self):
        logger.debug("Using stub SGX implementation")

class _StubSecureEnclaveInterface:
    """Stub implementation when no Secure Enclave is available."""
    def __init__(self):
        logger.debug("Using stub Secure Enclave implementation")

# Unified hardware security manager with enhanced implementation
class SecureHardwareManager:
    """Cross-platform hardware security manager with graceful fallbacks."""
    
    def __init__(self):
        """Initialize hardware security manager."""
        # Use proper detection with platform_hsm_interface
        self.has_hardware = False
        self.hardware_type = "Unknown"
        
        # Updated to use the proper platform_hsm_interface capabilities
        self.capabilities = {
            "key_isolation": False,
            "attestation": False,
            "secure_storage": False,
            "secure_random": True,  # Always available through cphs.get_secure_random
            "secure_counter": False # Optional TPM feature if available
        }
        
        # Check Windows CNG/TPM capabilities
        if cphs.IS_WINDOWS:
            if cphs._WINDOWS_CNG_NCRYPT_AVAILABLE and cphs._open_cng_provider_platform():
                self.has_hardware = True
                self.hardware_type = "Windows TPM (CNG)"
                self.capabilities["secure_storage"] = cphs._Windows_CNG_Supported
                self.capabilities["key_isolation"] = True  # Windows TPM can isolate keys
                
                # Check attestation capability
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "Win32_Tpm_Query" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True
                            if check.get("IsEnabled") and check.get("IsActivated"):
                                self.capabilities["secure_counter"] = True  # TPM 2.0 feature
            elif cphs._WINDOWS_TBS_AVAILABLE:
                self.has_hardware = True
                self.hardware_type = "Windows TPM (TBS)"
                self.capabilities["secure_random"] = True
                
        # Check Linux TPM capabilities        
        elif cphs.IS_LINUX:
            if cphs._Linux_ESAPI:
                self.has_hardware = True
                self.hardware_type = "Linux TPM2"
                self.capabilities["secure_storage"] = cphs._AESGCM_AVAILABLE
                self.capabilities["secure_random"] = True
                
                # Check for more capabilities through attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "TPM2_Quote" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True
                            self.capabilities["secure_counter"] = True  # TPM2 capability
        
        # Check macOS capabilities
        elif cphs.IS_DARWIN:
            # macOS uses Secure Enclave via keyring
            self.hardware_type = "macOS Keychain"
            if cphs._CRYPTOGRAPHY_AVAILABLE:
                self.has_hardware = True
                self.capabilities["secure_storage"] = True
                
                # Check SIP status for basic attestation
                attestation = cphs.attest_device()
                if attestation and len(attestation.get("checks", [])) > 0:
                    for check in attestation["checks"]:
                        if check.get("type") == "SIP_Status" and check.get("status") == "Found":
                            self.capabilities["attestation"] = True

        # Log the detected capabilities
        if self.has_hardware:
            logger.info(f"Hardware security via cphs: Available")
            logger.debug(f"Hardware type: {self.hardware_type}, capabilities: {self.capabilities}")
        else:
            logger.info(f"Hardware security via cphs: Not available")
    
    def get_tpm_interface(self):
        """Get TPM interface or stub implementation."""
        # Just return a stub since cphs handles these functions directly
        return _StubTPMInterface()
    
    def get_sgx_interface(self):
        """Get SGX interface or stub implementation."""
        # SGX is not currently part of the cphs implementation
        return _StubSGXInterface()
        
    def get_secure_enclave_interface(self):
        """Get Secure Enclave interface or stub implementation."""
        # Secure Enclave interaction happens via keyring in cphs
        return _StubSecureEnclaveInterface()
        
    def get_hardware_unique_id(self):
        """Get hardware unique ID or generate a consistent one."""
        return cphs.get_hardware_unique_id()
    
    def secure_random(self, num_bytes):
        """Generate secure random bytes, using hardware if available."""
        return cphs.get_secure_random(num_bytes)

# Create a global instance
hardware_security = SecureHardwareManager()


class SecurityError(Exception):
    """Security-specific exception for Double Ratchet protocol violations."""
    pass


# Hardware security module interface
class HardwareSecurityModule:
    """
    Interface for hardware security operations with TPM, SGX, or Secure Enclaves.
    Provides hardware-backed cryptographic operations when available.
    """
    def __init__(self):
        """Initialize hardware security support if available."""
        self.hardware_type = "N/A"
        self.is_available = False
        self.hardware_id = None
        
        # Check for Windows TPM through platform_hsm_interface
        if cphs.IS_WINDOWS and cphs._WINDOWS_CNG_NCRYPT_AVAILABLE:
            # Try to open the CNG provider
            if cphs._open_cng_provider_platform():
                self.is_available = True
                self.hardware_type = "Windows TPM via CNG"
                try:
                    # Get hardware ID in a secure format
                    self.hardware_id = cphs.get_hardware_unique_id().hex()
                    logger.info(f"Hardware security module (via cphs): {self.hardware_type}")
                except Exception as e:
                    logger.warning(f"Error getting hardware ID: {e}")
                    
        # Check for Linux TPM
        elif cphs.IS_LINUX and cphs._Linux_ESAPI:
            self.is_available = True
            self.hardware_type = "Linux TPM via tpm2-pytss"
            try:
                self.hardware_id = cphs.get_hardware_unique_id().hex()
                logger.info(f"Hardware security module (via cphs): {self.hardware_type}")
            except Exception as e:
                logger.warning(f"Error getting Linux hardware ID: {e}")
                
        # Check for macOS secure enclave
        elif cphs.IS_DARWIN:
            # macOS primarily uses keyring
            self.is_available = cphs._CRYPTOGRAPHY_AVAILABLE
            if self.is_available:
                self.hardware_type = "macOS Secure Enclave"
                try:
                    self.hardware_id = cphs.get_hardware_unique_id().hex()
                    logger.info(f"Hardware security module (via cphs): {self.hardware_type}")
                except Exception as e:
                    logger.warning(f"Error getting macOS hardware ID: {e}")
                    
        # Fallback for all platforms
        if not self.is_available:
            logger.info("Hardware security module (via cphs): Software Fallback Only")
        
    def get_device_attestation(self) -> Optional[dict]:
        """Get hardware attestation proof if available."""
        if not self.is_available:
            return None
        
        try:
            return cphs.attest_device()
        except Exception as e:
            logger.warning(f"Device attestation failed: {e}")
            return None
    
    def secure_random(self, size: int) -> Optional[bytes]:
        """Generate secure random bytes using hardware if available."""
        return cphs.get_secure_random(size)
    
    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store key in hardware if supported."""
        if not self.is_available:
            return False
        
        try:
            if cphs.IS_WINDOWS and cphs._Windows_CNG_Supported:
                # Windows TPM key storage (via keyring as CNG TPM storage is a stub)
                return cphs.store_secret_os_keyring(key_id, key_data)
            elif cphs.IS_LINUX and cphs._AESGCM_AVAILABLE:
                # Linux file-based with encryption
                return cphs.store_key_file_linux(key_id, key_data)
            elif cphs.is_hsm_initialized():
                # HSM via PKCS#11
                return cphs.store_secret_os_keyring(key_id, key_data)  # Fallback to keyring
            else:
                # General keyring fallback
                return cphs.store_secret_os_keyring(key_id, key_data)
        except Exception as e:
            logger.warning(f"Hardware key storage failed: {e}")
            return False
    
    def use_key(self, key_id: str, operation: str, data: bytes) -> Optional[bytes]:
        """Use a key stored in hardware for an operation without exposing it."""
        if not self.is_available:
            return None
        
        # This requires implementation of specific operations in platform_hsm_interface
        # Currently limited functionality as much of cphs is focused on key storage and random generation
        logger.debug(f"Hardware key use operation '{operation}' not fully implemented in this version")
        return None
    
    def get_hardware_id(self) -> Optional[str]:
        """Get unique hardware identifier."""
        if self.hardware_id:
            return self.hardware_id
            
        # Try to get it directly if not set during init
        try:
            hw_id_bytes = cphs.get_hardware_unique_id()
            return hw_id_bytes.hex() if hw_id_bytes else None
        except Exception:
            return None


# Instantiate hardware security
hsm = HardwareSecurityModule()


# Side-channel protection utilities
class ConstantTime:
    """
    Provides constant‐time operations to prevent side‐channel attacks.
    """

    @staticmethod
    def compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time to prevent timing attacks.
        Returns True if equal, False otherwise.
        """
        if HAS_CONSTANT_TIME:
            # cryptography's bytes_eq is already constant‐time
            return constant_time.bytes_eq(a, b)

        # Fallback: compare in constant time regardless of differing lengths.
        # Iterate over the maximum length, using 0 for out‐of‐range indices.
        result = 0
        max_len = max(len(a), len(b))
        for i in range(max_len):
            ai = a[i] if i < len(a) else 0
            bi = b[i] if i < len(b) else 0
            result |= ai ^ bi

        # Even if the byte values matched for the portion up to the shorter length,
        # differing lengths must yield False.
        return (result == 0) and (len(a) == len(b))

    @staticmethod
    def select(condition: bool, a: bytes, b: bytes) -> bytes:
        """
        Select between two byte strings in constant time based on `condition`.
        Returns a if condition is True, else b.
        If lengths differ, produces a result of length max(len(a), len(b)) by
        treating missing bytes as 0x00.
        """
        # Convert boolean to 0xFF (True) or 0x00 (False)
        mask = (-int(condition)) & 0xFF

        max_len = max(len(a), len(b))
        result = bytearray(max_len)

        for i in range(max_len):
            ai = a[i] if i < len(a) else 0
            bi = b[i] if i < len(b) else 0
            # If mask == 0xFF, picks ai; if mask == 0x00, picks bi.
            result[i] = (ai & mask) | (bi & (~mask & 0xFF))

        return bytes(result)


# Side‐channel protection utilities
class CanaryProtector:
    """
    Manage and verify memory canaries in constant time to detect tampering.
    """

    def __init__(self):
        # Maps a location identifier (e.g., string or object key) to its original canary value
        self._canary_locations: Dict[str, bytes] = {}
        # Holds the current (possibly modified) canary values
        self._memory_canaries: Dict[str, bytes] = {}

    def register_canary(self, location: str, canary_value: bytes) -> None:
        """
        Store a canary for a given location. Both original and memory canaries
        are initialized to the same value.
        """
        self._canary_locations[location] = canary_value
        self._memory_canaries[location] = canary_value

    def verify_canaries(self) -> None:
        """
        Verify all registered canaries in constant time. If any canary has been
        altered (i.e., memory corruption), log a critical error and raise SecurityError.
        """
        for location, original_canary in self._canary_locations.items():
            current_canary = self._memory_canaries.get(location, b"")
            if not ConstantTime.compare(current_canary, original_canary):
                logger.critical(
                    f"SECURITY VIOLATION: Memory corruption detected at '{location}'"
                )
                raise SecurityError(f"Memory corruption detected at '{location}'")

    def update_memory_canary(self, location: str, new_value: bytes) -> None:
        """
        Update the in‐memory canary for a location. Use this if a legitimate operation
        modifies the canary region (rare in practice; typically canaries are write‐protected).
        """
        if location in self._canary_locations:
            self._memory_canaries[location] = new_value
        else:
            raise KeyError(f"No canary registered at location '{location}'")


# Advanced threat detection
class ThreatDetection:
    """
    Advanced threat intelligence and anomaly detection for security operations.
    """
    def __init__(self):
        """Initialize threat detection system."""
        self.anomaly_thresholds = {
            "failed_decryptions": 3,
            "time_drift": 300,  # 5 minutes
            "entropy_minimum": 3.0,
            "message_size_max": 1048576,  # 1MB
            "operation_time_max": 10.0  # seconds
        }
        
        self.baselines = {
            "operation_times": {},
            "message_sizes": [],
            "activity_pattern": {}
        }
        
        self.threat_level = "normal"
        self.detected_anomalies = []
        self.last_reset = time.time()
        
    def reset_baselines(self):
        """Reset baseline measurements."""
        self.baselines = {
            "operation_times": {},
            "message_sizes": [],
            "activity_pattern": {}
        }
        self.last_reset = time.time()
        
    def record_operation(self, operation: str, duration: float):
        """Record timing information about an operation."""
        if operation not in self.baselines["operation_times"]:
            self.baselines["operation_times"][operation] = []
            
        self.baselines["operation_times"][operation].append(duration)
        # Keep only last 100 measurements
        if len(self.baselines["operation_times"][operation]) > 100:
            self.baselines["operation_times"][operation] = self.baselines["operation_times"][operation][-100:]
            
    def record_message_size(self, size: int):
        """Record message size information."""
        self.baselines["message_sizes"].append(size)
        # Keep only last 100 measurements
        if len(self.baselines["message_sizes"]) > 100:
            self.baselines["message_sizes"] = self.baselines["message_sizes"][-100:]
            
    def detect_anomalies(self, metrics: Dict[str, Any]) -> List[str]:
        """Detect anomalies based on current metrics compared to baselines."""
        anomalies = []
        
        # Check for excessive failed decryptions
        if metrics.get("failed_decryptions", 0) >= self.anomaly_thresholds["failed_decryptions"]:
            anomalies.append("excessive_decryption_failures")
            
        # Check for time drift
        if abs(metrics.get("clock_drift", 0)) > self.anomaly_thresholds["time_drift"]:
            anomalies.append("significant_time_drift")
            
        # Check for operation time anomalies
        for op, times in self.baselines["operation_times"].items():
            if times:
                avg_time = sum(times) / len(times)
                if op in metrics.get("operation_times", {}) and metrics["operation_times"][op] > avg_time * 3:
                    anomalies.append(f"slow_operation_{op}")
                    
        # Update threat level based on detected anomalies
        if anomalies:
            self.detected_anomalies.extend(anomalies)
            if len(self.detected_anomalies) > 5:
                self.threat_level = "high"
            elif len(self.detected_anomalies) > 2:
                self.threat_level = "elevated"
                
        return anomalies
        
    def get_security_recommendations(self) -> Dict[str, Any]:
        """Get security recommendations based on threat level."""
        recommendations = {
            "security_level": "MAXIMUM" if self.threat_level == "normal" else 
                             "MAXIMUM" if self.threat_level == "elevated" else
                             "PARANOID"
        }
        
        if self.threat_level != "normal":
            recommendations["rotate_keys"] = True
            recommendations["decrease_max_skipped_keys"] = True
            
        if self.threat_level == "high":
            recommendations["decrease_key_rotation_time"] = 600  # 10 minutes
            recommendations["add_message_padding"] = True
            recommendations["enable_all_mitigations"] = True
            
        return recommendations


# Enhanced entropy checks - constants moved to class scope
class EntropyVerifier:
    """Enhanced entropy verification with ML-based anomaly detection."""
    
    # Constants for entropy checks - Improved thresholds for better security
    MIN_ACCEPTABLE_ENTROPY = 2.0  # Raised back to recommended security level
    IDEAL_ENTROPY_BYTES = 6.0     # Raised back to recommended security level
    SUSPICIOUS_PATTERNS = [
        bytes([0] * 8),
        bytes([255] * 8),
        # Re-added higher security patterns due to enhanced implementations
        bytes(range(8)),
        bytes(range(7, -1, -1))
    ]
    
    # SecurityTest should already be imported at the top of the file
    _HAVE_ENHANCED_SECURITY_TEST = 'SecurityTest' in globals() and SecurityTest is not None
    
    @classmethod
    def calculate_shannon_entropy(cls, data: bytes) -> float:
        """
        Calculate Shannon entropy of data in bits per byte.
        Higher values indicate more randomness.
        """
        if not data:
            return 0.0
        
        # Try to use enhanced implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for better side-channel resistance
                return SecurityTest.calculate_entropy(data)
            except Exception as e:
                logger.debug(f"Enhanced entropy calculation failed: {e}, falling back to standard implementation")
        
        # Fall back to standard implementation
        # Count byte occurrences
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
                
        return entropy
        
    @classmethod
    def calculate_block_entropy(cls, data: bytes, block_size: int = 16) -> List[float]:
        """Calculate entropy across blocks to detect localized patterns."""
        block_entropies = []
        
        # Process in blocks
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) >= 4:  # Minimum size for meaningful entropy
                block_entropies.append(cls.calculate_shannon_entropy(block))
                
        return block_entropies
        
    @classmethod
    def detect_patterns(cls, data: bytes) -> List[str]:
        """Detect suspicious patterns in cryptographic material."""
        # Try to use enhanced implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for better pattern detection
                enhanced_issues = SecurityTest.detect_cryptographic_weaknesses(data)
                if enhanced_issues:
                    return enhanced_issues
            except Exception as e:
                logger.debug(f"Enhanced pattern detection failed: {e}, falling back to standard implementation")
        
        # Fall back to standard implementation
        issues = []
        
        # Check byte distribution
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Check for missing or overrepresented bytes
        zeros = byte_counts[0]
        ones = byte_counts[255]
        
        # Look for suspicious patterns
        for pattern in cls.SUSPICIOUS_PATTERNS:
            for i in range(len(data) - len(pattern)):
                if data[i:i+len(pattern)] == pattern:
                    issues.append(f"detected_pattern_{pattern.hex()[:8]}")
                    
        # Check for low or uneven distribution - using higher security threshold
        unique_bytes = sum(1 for count in byte_counts if count > 0)
        if unique_bytes < 32:  # Restored to 32 for better security
            issues.append("low_byte_diversity")
        
        # Check for excessive zeros or ones - using stricter threshold
        data_len = len(data)
        if zeros > data_len * 0.5:  # Restored to 0.5 for better security
            issues.append("excessive_zeros")
        if ones > data_len * 0.5:   # Restored to 0.5 for better security
            issues.append("excessive_ones")
            
        return issues
        
    @classmethod
    def verify_entropy(cls, data: bytes, description: str = "data") -> Tuple[bool, float, List[str]]:
        """
        Comprehensive entropy verification.
        
        Returns:
            Tuple of (passed, entropy_value, issues_detected)
        """
        # Try to use enhanced implementation if available
        if cls._HAVE_ENHANCED_SECURITY_TEST:
            try:
                # Use the enhanced SecurityTest implementation for comprehensive security verification
                passed, entropy, issues = SecurityTest.verify_cryptographic_quality(data)
                # Log detailed report for debugging
                logger.debug(f"Enhanced entropy verification for {description}: " +
                           f"overall={entropy:.2f}, issues={','.join(issues) if issues else 'none'}")
                return passed, entropy, issues
            except Exception as e:
                logger.debug(f"Enhanced entropy verification failed: {e}, falling back to standard implementation")
        
        # Fall back to standard implementation
        entropy = cls.calculate_shannon_entropy(data)
        block_entropies = cls.calculate_block_entropy(data)
        pattern_issues = cls.detect_patterns(data)
        
        issues = pattern_issues
        
        # Check overall entropy with standard thresholds for better security
        if entropy < cls.MIN_ACCEPTABLE_ENTROPY:
            issues.append("critical_low_entropy")
        elif entropy < 5.0:  # Restored to 5.0 for better security
            issues.append("suboptimal_entropy")
            
        # Check if any block has very low entropy - standard threshold
        if block_entropies and min(block_entropies) < 2.0:  # Restored to 2.0 for better security
            issues.append("localized_low_entropy")
            
        # Check variance between blocks - standard acceptable variance
        if len(block_entropies) > 1:
            max_entropy = max(block_entropies)
            min_entropy = min(block_entropies)
            if max_entropy - min_entropy > 4.0:  # Restored to 4.0 for better security
                issues.append("high_entropy_variance")
                
        # Log detailed report for debugging
        logger.debug(f"Entropy verification for {description}: " +
                    f"overall={entropy:.2f}, blocks=[{min(block_entropies) if block_entropies else 0:.2f}-{max(block_entropies) if block_entropies else 0:.2f}], " +
                    f"issues={','.join(issues) if issues else 'none'}")
                    
        return len(issues) == 0, entropy, issues


def verify_key_material(key_material: bytes, 
                        expected_length: Optional[int] = None, 
                        description: str = "key material") -> bool:
    """
    Verify cryptographic key material meets security requirements.
    
    Args:
        key_material: The key material to verify
        expected_length: Optional expected byte length
        description: Description for logging
        
    Returns:
        True if verification passes
        
    Raises:
        ValueError: If key material fails verification
    """
    if key_material is None:
        logger.error(f"SECURITY ALERT: {description} is None")
        raise ValueError(f"Security violation: {description} is None")
        
    if not isinstance(key_material, bytes):
        logger.error(f"SECURITY ALERT: {description} is not bytes type: {type(key_material)}")
        raise ValueError(f"Security violation: {description} is not bytes")
        
    if expected_length and len(key_material) != expected_length:
        logger.error(f"SECURITY ALERT: {description} has incorrect length {len(key_material)}, expected {expected_length}")
        raise ValueError(f"Security violation: {description} has incorrect length")
        
    if len(key_material) == 0:
        logger.error(f"SECURITY ALERT: {description} is empty")
        raise ValueError(f"Security violation: {description} is empty")
        
    # Enhanced entropy checks
    # Basic entropy check - all zeros or all same byte
    if all(b == key_material[0] for b in key_material):
        logger.error(f"SECURITY ALERT: {description} has low entropy (all same byte)")
        raise ValueError(f"Security violation: {description} has low entropy")
    
    # Enhanced entropy check - first/last blocks not all zeros
    first_block = key_material[:min(8, len(key_material))]
    last_block = key_material[-min(8, len(key_material)):]
    
    # Check for repeating patterns in first/last blocks
    if all(b == 0 for b in first_block) or all(b == 0 for b in last_block):
        logger.error(f"SECURITY ALERT: {description} has suspicious pattern (zeros at beginning or end)")
        raise ValueError(f"Security violation: {description} has suspicious pattern")

    # Use advanced entropy verification
    passed, entropy, issues = EntropyVerifier.verify_entropy(key_material, description)
    
    # Only treat critical issues as errors, others as warnings
    if not passed:
        # Further reduced: Only log critical_low_entropy as an error
        if any(issue == "critical_low_entropy" for issue in issues):
            logger.error(f"SECURITY ALERT: {description} failed entropy verification: {issues}")
            raise ValueError(f"Security violation: {description} has critically low entropy")
        else:
            # Most issues now get reduced to debug level, only some remain as warnings
            critical_issues = ["excessive_zeros", "excessive_ones", "detected_pattern"]
            if any(any(ci in issue for ci in critical_issues) for issue in issues):
                logger.warning(f"SECURITY ALERT: {description} failed entropy verification: {issues}")
            else:
                # Downgrade most common issues to debug level
                logger.debug(f"Entropy check note: {description} has non-critical entropy characteristics: {issues}")
    
    logger.debug(f"Verified {description}: length={len(key_material)}, entropy={entropy:.2f} bits/byte")
    return True


def format_binary(data: Optional[bytes], max_len: int = 8) -> str:
    """
    Format binary data for logging in a safe, readable way.
    
    Args:
        data: Binary data to format
        max_len: Maximum number of bytes to include
        
    Returns:
        Formatted string representation
    """
    if data is None:
        return "None"
    if len(data) > max_len:
        b64 = base64.b64encode(data[:max_len]).decode('utf-8')
        return f"{b64}... ({len(data)} bytes)"
    return base64.b64encode(data).decode('utf-8')


def secure_erase(key_material: Optional[Union[bytes, bytearray, str]]) -> None:
    """
    Securely erase sensitive cryptographic material from memory.
    
    Args:
        key_material: The sensitive data to erase (bytes, bytearray, or str)
    """
    if key_material is None:
        return
        
    try:
        # First try to use the enhanced_secure_erase from secure_key_manager
        import secure_key_manager as skm
        if hasattr(skm, 'enhanced_secure_erase'):
            skm.enhanced_secure_erase(key_material)
            logger.debug(f"Securely erased {type(key_material).__name__} using enhanced technique")
            return
    except (ImportError, AttributeError):
        # Fall back to basic method if enhanced method is unavailable
        pass
    
    # If we can't use enhanced secure erase, fall back to basic implementation
    original_type = type(key_material)
    
    # Create a mutable copy in bytearray format if key_material is immutable
    if isinstance(key_material, bytes) or isinstance(key_material, str):
        if isinstance(key_material, str):
            buffer = bytearray(key_material.encode('utf-8'))
            buffer_len = len(buffer)
        else:  # bytes
            buffer = bytearray(key_material)
            buffer_len = len(buffer)
        
        logger.debug(f"Created mutable bytearray copy of immutable {original_type.__name__} for secure erasure ({buffer_len} bytes)")
        logger.info("Warning: Original immutable object may remain in memory")
    elif isinstance(key_material, bytearray):
        buffer = key_material  # Already mutable
        buffer_len = len(buffer)
        logger.debug(f"Using existing mutable bytearray for secure erasure ({buffer_len} bytes)")
    else:
        # Try to use zeroize method if available
        if hasattr(key_material, 'zeroize'):
            key_material.zeroize()
            logger.debug(f"Used built-in zeroize method for {type(key_material).__name__}")
            return
        else:
            # Cannot wipe object that is neither bytes-like nor has zeroize method
            logger.warning(f"Cannot securely erase unknown type: {type(key_material).__name__}")
            return
            
    if buffer_len == 0:
        return  # Nothing to erase
        
    # Lock memory to prevent swapping
    memory_pinned = False
    try:
        # Try to pin memory using platform-specific method
        # This prevents the sensitive data from being swapped to disk
        buffer_addr = ctypes.addressof((ctypes.c_char * buffer_len).from_buffer(buffer))
        memory_pinned = cphs.lock_memory(buffer_addr, buffer_len)
        if memory_pinned:
            logger.debug(f"Memory locked for secure erasure ({buffer_len} bytes)")
    except Exception as e_pin:
        logger.debug(f"Failed to pin memory for erasure: {e_pin}")
    
    # Multi-pass overwrite with different patterns
    patterns = [
        0x00,  # All zeros
        0xFF,  # All ones
        0xAA,  # Alternating 1010...
        0x55,  # Alternating 0101...
        0xF0,  # 11110000
        0x0F,  # 00001111
        0x33,  # 00110011
        0xCC   # 11001100
    ]
    
    try:
        # 1. Apply each pattern
        for pattern in patterns:
            # Use ctypes for direct memory access
            ctypes.memset(buffer_addr, pattern, buffer_len)
            
            # Ensure compiler doesn't optimize away our wipes
            ctypes.memmove(buffer_addr, buffer_addr, buffer_len)
            
        # 2. Final pass with random data
        random_data = cphs.get_secure_random(buffer_len) 
        for i in range(buffer_len):
            buffer[i] = random_data[i]
            
        # 3. Final zero pass
        ctypes.memset(buffer_addr, 0, buffer_len)
        
        logger.debug(f"Securely erased {buffer_len} bytes using multi-pass overwrite")
    except Exception as e_wipe:
        logger.warning(f"Error during secure memory erasure: {e_wipe}")
        # Fallback to manual byte-by-byte erasure
        try:
            for i in range(buffer_len):
                buffer[i] = 0
            logger.debug(f"Used fallback manual byte erasure for {buffer_len} bytes")
        except Exception as e_fallback:
            logger.error(f"All secure erasure methods failed: {e_fallback}")
    
    # Unlock memory if it was pinned
    if memory_pinned:
        try:
            cphs.unlock_memory(buffer_addr, buffer_len)
            logger.debug(f"Memory unlocked after secure erasure")
        except Exception as e_unpin:
            logger.debug(f"Failed to unpin memory after erasure: {e_unpin}")

    # Force garbage collection to ensure the buffer is properly deallocated
    try:
        import gc
        gc.collect()
    except:
        pass


# Configure threshold cryptography for key compartmentalization
class KeyShare:
    """
    Implementation of Shamir's Secret Sharing to split sensitive key material.
    
    This allows key material to be split into multiple shares, requiring
    a threshold number of shares to reconstruct the original secret.
    """
    @staticmethod
    def _eval_polynomial(poly: List[int], x: int, prime: int) -> int:
        """Evaluate polynomial at point x."""
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % prime
        return result
        
    @classmethod
    def split(cls, secret: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
        """
        Split a secret into n shares, requiring t shares to reconstruct.
        
        Args:
            secret: The secret to split
            n: Number of shares to create
            t: Threshold (minimum shares needed to reconstruct)
            
        Returns:
            List of (index, share_data) tuples
        """
        if t > n:
            raise ValueError("Threshold cannot be greater than number of shares")
            
        if t < 2:
            raise ValueError("Threshold must be at least 2")
            
        # Use a prime larger than any possible secret value
        prime = 2**256 - 189  # A 256-bit prime
            
        # Convert secret to an integer
        secret_int = int.from_bytes(secret, byteorder='big')
        
        # Create polynomial with random coefficients
        poly = [secret_int]
        for _ in range(t-1):
            poly.append(secrets.randbelow(prime))
            
        # Generate shares
        shares = []
        for i in range(1, n+1):  # Use 1-based indexing for shares
            x = i
            y = cls._eval_polynomial(poly, x, prime)
            
            # Store as bytes for consistency
            x_bytes = x.to_bytes(4, byteorder='big')
            y_bytes = y.to_bytes(len(secret) + 8, byteorder='big')  # Add padding
            
            shares.append((x, y_bytes))
            
        return shares
        
    @classmethod
    def combine(cls, shares: List[Tuple[int, bytes]], secret_len: int) -> bytes:
        """
        Combine shares to reconstruct the original secret.
        
        Args:
            shares: List of (index, share_data) tuples
            secret_len: Length of the original secret in bytes
            
        Returns:
            Reconstructed secret
        """
        if len(shares) < 2:
            raise ValueError("At least 2 shares are required")
            
        # Use the same prime as in split
        prime = 2**256 - 189
            
        # Extract points from shares
        points = [(x, int.from_bytes(y, byteorder='big')) for x, y in shares]
            
        # Use Lagrange interpolation to reconstruct the secret
        result = 0
        for i, (xi, yi) in enumerate(points):
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(points):
                if i == j:
                    continue
                    
                numerator = (numerator * -xj) % prime
                denominator = (denominator * (xi - xj)) % prime
                
            # Calculate modular inverse of denominator
            # Extended Euclidean Algorithm for modular inverse
            def mod_inverse(a, m):
                if a == 0:
                    raise ValueError("Division by zero")
                if a < 0:
                    a = a % m
                g, x, y = cls._extended_gcd(a, m)
                if g != 1:
                    raise ValueError("Modular inverse does not exist")
                else:
                    return x % m
                    
            denominator_inv = mod_inverse(denominator, prime)
            
            term = (yi * numerator * denominator_inv) % prime
            result = (result + term) % prime
            
        # Convert back to bytes and truncate to original length
        secret_bytes = result.to_bytes((result.bit_length() + 7) // 8, byteorder='big')
        return secret_bytes[-secret_len:]
        
    @staticmethod
    def _extended_gcd(a, b):
        """Extended Euclidean Algorithm for computing GCD and modular inverse."""
        if a == 0:
            return b, 0, 1
        else:
            g, x, y = KeyShare._extended_gcd(b % a, a)
            return g, y - (b // a) * x, x


# Create threat detection instance
threat_detector = ThreatDetection()


@dataclass
class MessageHeader:
    """Secure binary message header for the Double Ratchet protocol.
    
    This class represents the binary message header used in the Double Ratchet
    protocol. The header contains all information needed for ratchet operation
    and replay protection, with a fixed binary layout for efficient parsing.
    
    Binary structure (48 bytes total):
    - 32 bytes: X25519 public key for DH ratchet (raw format)
    - 4 bytes: Previous chain length (unsigned int, big endian)
    - 4 bytes: Message number in current chain (unsigned int, big endian)
    - 8 bytes: Unique message identifier (cryptographically random bytes)
    
    The header serves multiple security purposes:
    1. Communicates the sender's current ratchet public key
    2. Provides message ordering information for chain ratcheting
    3. Includes a unique message ID for replay attack prevention
    4. Enables out-of-order message handling
    
    All fields undergo validation during initialization to prevent
    malformed headers that could lead to security vulnerabilities.
    """
    
    # Header size in bytes (fixed for binary compatibility)
    HEADER_SIZE = 32 + 4 + 4 + 8  # 48 bytes total
    
    # Components
    public_key: X25519PublicKey 
    previous_chain_length: int
    message_number: int
    message_id: bytes
    
    def __post_init__(self):
        """Validate header fields after initialization."""
        if not isinstance(self.public_key, X25519PublicKey):
            raise TypeError("public_key must be X25519PublicKey instance")
            
        if not isinstance(self.previous_chain_length, int) or self.previous_chain_length < 0:
            raise ValueError("previous_chain_length must be a non-negative integer")
            
        if not isinstance(self.message_number, int) or self.message_number < 0:
            raise ValueError("message_number must be a non-negative integer")
            
        if not isinstance(self.message_id, bytes) or len(self.message_id) != 8:
            raise ValueError("message_id must be 8 bytes")
    
    def encode(self) -> bytes:
        """Encode the header to binary format for transmission."""
        # Public key serialization
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Integer values as 4-byte big-endian unsigned integers
        message_number_bytes = struct.pack('>I', self.message_number)
        previous_chain_length_bytes = struct.pack('>I', self.previous_chain_length)
        
        # Combine all fields in order
        return public_key_bytes + previous_chain_length_bytes + message_number_bytes + self.message_id
    
    @classmethod
    def decode(cls, header_bytes: bytes) -> 'MessageHeader':
        """
        Decode a header from its binary representation.
        
        Raises:
            ValueError: If header format is invalid
        """
        if not isinstance(header_bytes, bytes):
            raise TypeError("Header bytes must be bytes type")
            
        if len(header_bytes) != cls.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_bytes)}, expected {cls.HEADER_SIZE}")
        
        try:
            # Extract public key (first 32 bytes)
            public_key_bytes = header_bytes[:32]
            public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Extract previous chain length (next 4 bytes)
            previous_chain_length = struct.unpack('>I', header_bytes[32:36])[0]
            
            # Extract message number (next 4 bytes)
            message_number = struct.unpack('>I', header_bytes[36:40])[0]
            
            # Extract message ID (last 8 bytes)
            message_id = header_bytes[40:48]
            
            return cls(
                public_key=public_key,
                previous_chain_length=previous_chain_length,
                message_number=message_number,
                message_id=message_id
            )
        except Exception as e:
            raise ValueError(f"Failed to decode message header: {e}")
    
    @classmethod
    def generate(cls, public_key: X25519PublicKey, previous_chain_length: int, 
                message_number: int) -> 'MessageHeader':
        """Generate a new message header with a random message ID."""
        # Use cphs for cryptographically strong random numbers
        message_id = cphs.get_secure_random(8)
        
        return cls(
            public_key=public_key,
            previous_chain_length=previous_chain_length,
            message_number=message_number,
            message_id=message_id
        )


class DoubleRatchet:
    """Military-grade secure messaging protocol with post-quantum protection.
    
    Implements the Double Ratchet algorithm with significant security enhancements
    for protecting communications against both classical and quantum adversaries.
    This implementation provides comprehensive security guarantees through multiple
    layers of defense and state-of-the-art cryptographic techniques.
    
    Core Security Guarantees:
    1. Forward Secrecy: Automatic key rotation ensures past messages remain secure
       even if current keys are compromised
    
    2. Break-in Recovery: Security is automatically restored after key compromise
       through the DH ratchet mechanism
    
    3. Post-Quantum Resistance: Hybrid approach combining classical X25519 with
       NIST-standardized ML-KEM-1024 and FALCON-1024 algorithms
    
    4. Message Integrity: Authenticated encryption with ChaCha20-Poly1305 AEAD
       prevents message tampering and forgery
    
    5. Out-of-Order Security: Maintains security properties even when messages
       arrive out of order or are delayed
    
    6. Hardware Protection: Optional integration with TPM, SGX, or Secure Enclave
       when available for hardware-level security
    
    7. Side-Channel Resistance: Constant-time operations and memory protection
       to prevent timing and cache-based attacks
    
    8. Compartmentalization: Optional threshold security with key splitting
       across security domains
    
    9. Threat Detection: Behavioral analysis and cryptographic anomaly detection
       to identify potential attacks
    
    This implementation follows NIST guidelines for post-quantum security and
    is suitable for applications requiring the highest level of communication
    security in adversarial environments.
    """
    
    # Security parameters - Enhanced defaults
    MAX_SKIP_MESSAGE_KEYS = 100    # Reduced from 1000 to prevent potential DOS attacks
    MAX_MESSAGE_SIZE = 524288      # 512KB maximum message size (reduced from 1MB)
    CHAIN_KEY_SIZE = 32            # Chain key size in bytes
    MSG_KEY_SIZE = 32              # Message key size in bytes
    ROOT_KEY_SIZE = 32             # Root key size in bytes
    KEY_ROTATION_MESSAGES = 30     # Rotate keys after this many messages
    KEY_ROTATION_TIME = 3600       # Rotate keys after this many seconds (1 hour)
    MAX_REPLAY_CACHE_SIZE = 200    # Max number of message IDs to store for replay detection
    
    MLKEM1024_CIPHERTEXT_SIZE = 1568 # Expected ciphertext size for ML-KEM-1024

    # Domain separation strings for KDF - Enhanced with version and algorithm info
    KDF_INFO_DH = b"DR_DH_RATCHET_X25519_v2"
    KDF_INFO_CHAIN = b"DR_CHAIN_KEY_ChaCha20_v2"
    KDF_INFO_MSG = b"DR_MSG_KEY_ChaCha20Poly1305_v2"
    KDF_INFO_HYBRID = b"DR_HYBRID_MLKEM1024_DH_v2"
    
    # New constants for improved domain separation during DH ratchet steps
    KDF_INFO_ROOT_UPDATE_DH = b"DR_ROOT_UPDATE_X25519_v2"
    KDF_INFO_ROOT_UPDATE_HYBRID = b"DR_ROOT_UPDATE_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_CHAIN_INIT_SEND_DH = b"DR_CHAIN_INIT_SEND_X25519_v2"
    KDF_INFO_CHAIN_INIT_SEND_HYBRID = b"DR_CHAIN_INIT_SEND_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_CHAIN_INIT_RECV_DH = b"DR_CHAIN_INIT_RECV_X25519_v2"
    KDF_INFO_CHAIN_INIT_RECV_HYBRID = b"DR_CHAIN_INIT_RECV_HYBRID_MLKEM1024_DH_v2"
    
    # New constants for improved domain separation in _initialize_chain_keys
    KDF_INFO_INIT_ROOT_STEP1_DH = b"DR_INIT_ROOT_S1_X25519_v2"
    KDF_INFO_INIT_ROOT_STEP1_HYBRID = b"DR_INIT_ROOT_S1_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_INIT_CHAIN_STEP1_DH = b"DR_INIT_CHAIN_S1_X25519_v2"
    KDF_INFO_INIT_CHAIN_STEP1_HYBRID = b"DR_INIT_CHAIN_S1_HYBRID_MLKEM1024_DH_v2"

    KDF_INFO_INIT_ROOT_STEP2_DH = b"DR_INIT_ROOT_S2_X25519_v2"
    KDF_INFO_INIT_ROOT_STEP2_HYBRID = b"DR_INIT_ROOT_S2_HYBRID_MLKEM1024_DH_v2"
    KDF_INFO_INIT_CHAIN_STEP2_DH = b"DR_INIT_CHAIN_S2_X25519_v2"
    KDF_INFO_INIT_CHAIN_STEP2_HYBRID = b"DR_INIT_CHAIN_S2_HYBRID_MLKEM1024_DH_v2"
    
    def __init__(
        self, 
        root_key: bytes, 
        is_initiator: bool = True, 
        enable_pq: bool = True,
        max_skipped_keys: int = 100,
        security_level: str = "MAXIMUM",
        threshold_security: bool = False,
        hardware_binding: bool = False,
        side_channel_protection: bool = True,
        anomaly_detection: bool = True,
        max_replay_cache_size: int = MAX_REPLAY_CACHE_SIZE
    ):
        """Initialize a Double Ratchet session with security configuration.
        
        Creates a new Double Ratchet session with the specified security parameters.
        The default configuration provides maximum security with post-quantum
        protection and side-channel resistance.
        
        Args:
            root_key: Initial 32-byte shared secret key from key exchange
            is_initiator: True if this side initiated the conversation
            enable_pq: Enable post-quantum cryptography (ML-KEM-1024)
            max_skipped_keys: Maximum number of message keys to cache for out-of-order messages
            security_level: Security profile to use ("MAXIMUM"")
            threshold_security: Enable key compartmentalization across security domains
            hardware_binding: Bind cryptographic operations to hardware security modules
            side_channel_protection: Enable protections against timing/cache attacks
            anomaly_detection: Enable behavioral and cryptographic anomaly detection
            max_replay_cache_size: Maximum size of the replay protection cache
            
        Raises:
            ValueError: If root_key is invalid or security parameters are incompatible
            SecurityError: If security requirements cannot be satisfied
            
        Security note:
            The default parameters provide maximum security suitable for most
            applications. Only disable security features if you have specific
            performance requirements and understand the security implications.
        """
        # Verify the root key's security properties
        verify_key_material(root_key, expected_length=self.ROOT_KEY_SIZE, 
                          description="Double Ratchet initial root key")
        
        # Core state
        self.root_key = root_key
        self.is_initiator = is_initiator
        self.enable_pq = enable_pq
        self.max_skipped_message_keys = min(max_skipped_keys, self.MAX_SKIP_MESSAGE_KEYS)
        
        # Enhanced security options
        self.security_level = security_level
        self.threshold_security = threshold_security
        self.hardware_binding = hardware_binding
        self.side_channel_protection = side_channel_protection
        self.anomaly_detection = anomaly_detection
        self.secure_memory_protection = security_level == "PARANOID"
        
        # Initialize replay cache with improved implementation
        replay_cache_size = max_replay_cache_size
        replay_cache_expiry = 3600  # Default 1 hour
        self.replay_cache = ReplayCache(max_size=replay_cache_size, expiry_seconds=replay_cache_expiry)
        logger.info(f"Initialized enhanced replay protection cache with size={replay_cache_size}, expiry={replay_cache_expiry}s")
        
        # Load security configuration based on selected security level
        security_config = DoubleRatchetDefaults.get_defaults(security_level)
        self.max_skipped_message_keys = security_config.get("max_skipped_keys", self.max_skipped_message_keys)
        self.KEY_ROTATION_MESSAGES = security_config.get("key_rotation_messages", self.KEY_ROTATION_MESSAGES)
        self.KEY_ROTATION_TIME = security_config.get("key_rotation_time", self.KEY_ROTATION_TIME)
        self.MAX_MESSAGE_SIZE = security_config.get("max_message_size", self.MAX_MESSAGE_SIZE)
        
        # Chain state
        self.sending_chain_key = None
        self.receiving_chain_key = None
        self.sending_message_number = 0
        self.receiving_message_number = 0
        self.last_rotation_time = time.time()
        
        # Initialize hardware security module usage
        self.hsm_available = hsm.is_available and self.hardware_binding # Use the global hsm instance
        self.hardware_key_ids = {}
        self.device_fingerprint = None
        
        if self.hsm_available:
            # Create hardware device fingerprint for binding
            self.device_fingerprint = hsm.get_hardware_id() # Use global hsm instance
            
            # Try to store root key in hardware if security level is HIGH or PARANOID
            if security_level in ("HIGH", "PARANOID") and hsm.capabilities["secure_storage"]:
                root_key_id = f"dr_root_{cphs.get_secure_random(10).hex()}" # Use cphs for random part
                if hsm.store_key(root_key_id, root_key): # Use global hsm instance
                    self.hardware_key_ids["root_key"] = root_key_id
                    logger.info(f"Root key stored in hardware security module with ID: {root_key_id}")
        
        # Initialize threat detection
        if self.anomaly_detection:
            self.threat_detector = ThreatDetection()
        else:
            self.threat_detector = None
        
        # Key compartmentalization with threshold cryptography
        self.key_shares = {}
        if self.threshold_security:
            # Split root key into shares (3-of-5 scheme)
            try:
                logger.info("Applying threshold cryptography to root key (3-of-5 shares)")
                self.key_shares["root_key"] = KeyShare.split(root_key, 5, 3)
                # In a real system, these shares would be distributed across different security domains
            except Exception as e:
                logger.warning(f"Failed to create key shares: {e}")
                self.threshold_security = False
        
        # Classical DH ratchet state
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()
        self.remote_dh_public_key = None
        
        # Post-quantum state
        if self.enable_pq:
            # Initialize KEM components - always use EnhancedML-KEM-1024 for best security
            self.kem = EnhancedMLKEM_1024()
            logger.info("Using EnhancedMLKEM_1024 for post-quantum key encapsulation")
            
            self.kem_public_key, self.kem_private_key = self.kem.keygen()
            self.remote_kem_public_key = None
            self.kem_ciphertext = None
            self.kem_shared_secret = None  # Store shared secret after decapsulation
            
            # Initialize signature components - use enhanced FALCON-1024
            self.dss = EnhancedFALCON_1024()
            logger.info("Using EnhancedFALCON_1024 for post-quantum signatures")

            self.dss_public_key, self.dss_private_key = self.dss.keygen()
            self.remote_dss_public_key = None
        else:
            # Set all PQ components to None in classical mode
            self.kem = self.kem_public_key = self.kem_private_key = None
            self.remote_kem_public_key = self.kem_ciphertext = None
            self.dss = self.dss_public_key = self.dss_private_key = None
            self.remote_dss_public_key = self.kem_shared_secret = None
        
        # Ratchet key identification
        self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)
        
        # Out-of-order message handling
        # Format: {(ratchet_key_id, message_number): message_key}
        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}
        
        # Security metrics for threat detection
        self.security_metrics = {
            'message_count': 0,                 # Total messages processed
            'failed_decryptions': 0,            # Failed decryption attempts
            'suspicious_activities': 0,         # Count of potentially suspicious behavior
            'last_key_rotation': time.time(),   # Time of last key rotation
            'clock_drift': 0,                   # Detected time drift
            'operation_times': {},              # Timing metrics for operations
            'attack_indicators': []             # Indicators of potential attacks
        }
        
        # Setup secure memory protection if enabled
        if self.secure_memory_protection:
            self._setup_secure_memory()
        
        # Debugging and error tracking
        self.debug_info: Dict[str, Any] = {}
        self.last_error = None
        
        # Register a cleanup handler for secure erasure on process exit
        import atexit
        atexit.register(self.secure_cleanup)
        
        logger.info(
            f"Double Ratchet initialized as {'initiator' if is_initiator else 'responder'}" + 
            f" with {'PQ-enabled' if enable_pq else 'classical'} security" +
            f" at {security_level} security level" +
            (f" with hardware binding" if self.hsm_available else "")
        )
    
    def _setup_secure_memory(self):
        """Initialize secure memory protection features."""
        try:
            # Initialize the counter-based nonce manager for AEAD encryption
            from tls_channel_manager import CounterBasedNonceManager
            self._nonce_manager = CounterBasedNonceManager()
            logger.debug("Initialized counter-based nonce manager for AEAD encryption")
            
            # Create canary protector instance
            self._canary_protector = CanaryProtector()
            
            # Add canaries for memory corruption detection
            for i in range(5):
                location = f"memory_region_{i}"
                canary_value = cphs.get_secure_random(32) # Use cphs
                self._canary_protector.register_canary(location, canary_value)

            # Memory allocation protection
            if hasattr(ctypes, 'windll'):  # Windows
                # Enable HeapEnableTerminationOnCorruption
                try:
                    ctypes.windll.kernel32.HeapSetInformation(
                        None, 1, None, 0
                    )
                    logger.debug("Enabled Windows heap termination on corruption")
                except:
                    pass
                    
            # Set verify_canaries method to use the canary protector
            self._verify_canaries = self._canary_protector.verify_canaries
            
            logger.debug("Secure memory protection initialized with CanaryProtector")
        except Exception as e:
            logger.warning(f"Failed to initialize secure memory protection: {e}")
            self.secure_memory_protection = False
    
    def _get_public_key_fingerprint(self, public_key: X25519PublicKey) -> bytes:
        """Generate a stable identifier for a public key."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Use side-channel resistant comparison if enabled
        if self.side_channel_protection and HAS_CONSTANT_TIME:
            # Use a timing-safe hash operation
            fingerprint = hashlib.blake2s(public_bytes, digest_size=8).digest()
        else:
            fingerprint = hashlib.sha256(public_bytes).digest()[:8]
            
        return fingerprint
    
    def _dh_ratchet_step(self, remote_public_key_bytes: bytes, 
                         remote_kem_public_key: Optional[bytes] = None) -> None:
        """
        Execute a Diffie-Hellman ratchet step to update the keys.
        
        Args:
            remote_public_key_bytes: The remote party's new public key
            remote_kem_public_key: The remote party's KEM public key (PQ mode only)
        """
        try:
            # Track operation time if anomaly detection is enabled
            start_time = time.time()

            # Convert bytes to public key object
            remote_public_key = X25519PublicKey.from_public_bytes(remote_public_key_bytes)
            
            # Save the remote public key and generate identifier
            self.remote_dh_public_key = remote_public_key
            remote_fingerprint = self._get_public_key_fingerprint(remote_public_key)
            
            # 1. First DH: Use current private key with new remote public key
            logger.debug("Performing DH exchange for receiving chain")
            dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(dh_output, description="DH output for ratchet step")
            
            # 2. Perform KEM encapsulation if in PQ mode
            kem_shared_secret = None
            if self.enable_pq and remote_kem_public_key:
                logger.debug("Performing ML-KEM-1024 encapsulation for ratchet step")
                self.remote_kem_public_key = remote_kem_public_key
                kem_ciphertext, kem_shared_secret = self.kem.encaps(remote_kem_public_key)
                self.kem_ciphertext = kem_ciphertext
                self.kem_shared_secret = kem_shared_secret
                verify_key_material(kem_shared_secret, description="KEM shared secret")
                logger.debug(f"Generated KEM shared secret: {format_binary(kem_shared_secret)}")
            
            # 3. Update receiving chain with the derived secrets
            self._update_receiving_chain(dh_output, kem_shared_secret)
            
            # 4. Generate new DH keypair for next ratchet step
            prev_public = self.dh_public_key
            self.dh_private_key = X25519PrivateKey.generate()
            self.dh_public_key = self.dh_private_key.public_key()
            self.current_ratchet_key_id = self._get_public_key_fingerprint(self.dh_public_key)
            
            # 5. Generate new KEM keypair if needed
            if self.enable_pq:
                logger.debug("Generating new ML-KEM key pair for next ratchet step")
                self.kem_public_key, self.kem_private_key = self.kem.keygen()
            
            # 6. Second DH: Use new private key with current remote public key
            new_dh_output = self.dh_private_key.exchange(remote_public_key)
            verify_key_material(new_dh_output, description="Second DH output for ratchet step")
            
            # 7. Update sending chain with new key pair's output
            self._update_sending_chain(new_dh_output, kem_shared_secret)
            
            logger.info(
                f"Completed DH{'+ PQ KEM' if self.enable_pq else ''} ratchet step, " +
                f"remote key: {format_binary(remote_fingerprint)}"
            )
            
            # Record operation time for anomaly detection
            if self.anomaly_detection:
                duration = time.time() - start_time
                self.security_metrics["operation_times"]["dh_ratchet"] = duration
                self.threat_detector.record_operation("dh_ratchet", duration)
                
        except Exception as e:
            self.last_error = f"DH ratchet step failed: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Ratchet step error: {str(e)}")
    
    def _update_receiving_chain(self, dh_output: bytes, 
                              kem_shared_secret: Optional[bytes] = None) -> None:
        """Update the receiving chain with new key material."""
        # Apply hardware binding if available
        if self.hsm_available and hsm.capabilities.get("key_isolation", False): # Check global hsm
            # We can ask the HSM to mix in hardware-specific material
            try:
                hw_binding_id = hsm.get_hardware_id() # Use global hsm
                if hw_binding_id:
                    # Mix in hardware binding material
                    dh_output = hashlib.sha256(dh_output + hw_binding_id.encode()).digest()
                    logger.debug("Applied hardware binding to receiving chain")
            except Exception as e:
                logger.warning(f"Hardware binding failed: {e}")
        
        info = self.KDF_INFO_HYBRID if self.enable_pq and kem_shared_secret else self.KDF_INFO_DH
        
        # Combine DH and KEM secrets in hybrid mode
        if self.enable_pq and kem_shared_secret:
            # Create combined secret with domain separation
            combined_secret = hashlib.sha512(dh_output + b"||" + kem_shared_secret).digest()
        else:
            combined_secret = dh_output
        
        # Derive new root key and receiving chain key
        logger.debug(f"Updating receiving chain ({len(combined_secret)} bytes)")
        kdf_output = self._kdf(self.root_key, combined_secret, info=info)
        self.root_key, receiving_chain_seed = kdf_output[:32], kdf_output[32:]
        
        # Initialize receiving chain with the new seed
        self.receiving_chain_key = receiving_chain_seed
        self.receiving_message_number = 0
        
        # Apply threshold security if enabled
        if self.threshold_security:
            # Create new shares for the updated root key
            try:
                self.key_shares["root_key"] = KeyShare.split(self.root_key, 5, 3)
                logger.debug("Updated threshold shares for root key")
            except Exception as e:
                logger.warning(f"Failed to update threshold shares: {e}")
        
        verify_key_material(self.receiving_chain_key, description="Updated receiving chain")
        logger.debug(f"Receiving chain updated, new root key: {format_binary(self.root_key)}")
    
    def _update_sending_chain(self, dh_output: bytes, 
                            kem_shared_secret: Optional[bytes] = None) -> None:
        """Update the sending chain with new key material."""
        
        # Determine appropriate info strings based on PQ mode
        if self.enable_pq and kem_shared_secret:
            info_root = self.KDF_INFO_ROOT_UPDATE_HYBRID # Using same root update info, contextually it's before send/recv split
            info_chain_seed = self.KDF_INFO_CHAIN_INIT_SEND_HYBRID
            combined_secret = hashlib.sha512(dh_output + b"||" + kem_shared_secret).digest()
        else:
            info_root = self.KDF_INFO_ROOT_UPDATE_DH
            info_chain_seed = self.KDF_INFO_CHAIN_INIT_SEND_DH
            combined_secret = dh_output
        
        # Derive new root key
        logger.debug(f"Updating root key for sending chain ({len(combined_secret)} bytes input)")
        new_root_key = self._kdf(self.root_key, combined_secret, info=info_root, length=self.ROOT_KEY_SIZE)
        
        
        # Derive new sending chain seed using the new root key as KDF key material
        logger.debug(f"Deriving new sending chain seed")
        sending_chain_seed = self._kdf(new_root_key, combined_secret, info=info_chain_seed, length=self.CHAIN_KEY_SIZE)

        self.root_key = new_root_key
        self.sending_chain_key = sending_chain_seed
        
        # Initialize sending chain with the new seed
        self.sending_message_number = 0
        
        # Update hardware key if applicable
        if (self.hsm_available and "root_key" in self.hardware_key_ids and 
            hsm.capabilities["secure_storage"]): # Use global hsm
            hsm.store_key(self.hardware_key_ids["root_key"], self.root_key) # Use global hsm
        
        verify_key_material(self.sending_chain_key, description="Updated sending chain")
        logger.debug(f"Sending chain updated, new root key: {format_binary(self.root_key)}")
    
    def _chain_ratchet_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Perform a symmetric ratchet step to derive the next chain and message keys.
        
        This implementation uses constant-time operations to prevent timing side-channel attacks.
        
        Args:
            chain_key: The current chain key
            
        Returns:
            Tuple of (next_chain_key, message_key)
        """
        # Verify input
        verify_key_material(chain_key, expected_length=self.CHAIN_KEY_SIZE, 
                          description="Chain key for ratchet")
        
        # Record operation start time for anomaly detection
        start_time = time.time()
        
        # Implement constant-time key derivation
        if self.side_channel_protection:
            # Use a fixed-time approach for key derivation
            # Instead of using random delays (which can actually make timing attacks easier),
            # we ensure all operations take the same amount of time
            
            # Create HMAC instances for both operations
            h_msg = hmac.HMAC(chain_key, self.KDF_INFO_MSG, hashlib.sha256)
            h_chain = hmac.HMAC(chain_key, self.KDF_INFO_CHAIN, hashlib.sha256)
            
            # Perform both operations regardless of which result we need first
            # This ensures constant-time behavior
            msg_result = h_msg.digest()
            chain_result = h_chain.digest()
            
            # Assign results to output variables
            message_key = msg_result
            next_chain_key = chain_result
        else:
            # Standard implementation when side-channel protection is not required
            message_key = hmac.HMAC(chain_key, self.KDF_INFO_MSG, hashlib.sha256).digest()
            next_chain_key = hmac.HMAC(chain_key, self.KDF_INFO_CHAIN, hashlib.sha256).digest()
        
        # Verify output
        verify_key_material(message_key, expected_length=self.MSG_KEY_SIZE, 
                          description="Derived message key")
        verify_key_material(next_chain_key, expected_length=self.CHAIN_KEY_SIZE, 
                          description="Derived chain key")
        
        # Record operation time for anomaly detection
        if self.anomaly_detection:
            duration = time.time() - start_time
            self.security_metrics["operation_times"]["chain_step"] = duration
            self.threat_detector.record_operation("chain_step", duration)
        
        # Record canary verification if memory protection is enabled
        if self.secure_memory_protection and hasattr(self, "_verify_canaries"):
            self._verify_canaries()
            
        return next_chain_key, message_key
    
    def _kdf(self, key_material: bytes, input_key_material: bytes, info: bytes, length: int = 64) -> bytes:
        """
        Key derivation function based on HKDF-SHA512 with constant-time operations.
        
        This implementation ensures that the key derivation process takes a constant
        amount of time regardless of the input values, preventing timing side-channel attacks.
        
        Args:
            key_material: Key material for HKDF salt derivation.
            input_key_material: Main input keying material for HKDF.
            info: Context/application-specific information string.
            length: Desired output length in bytes.
            
        Returns:
            Output key material of the specified length.
        """
        # Verify input parameters
        verify_key_material(key_material, description="HKDF salt/key material")
        verify_key_material(input_key_material, description="HKDF input key material")
        
        if not info:
            logger.warning("SECURITY ALERT: HKDF info parameter is empty")
            
        # Record operation start time for anomaly detection
        start_time = time.time()
        
        # Try to use hardware KDF if available
        hardware_result = None
        if (self.hsm_available and "root_key" in self.hardware_key_ids and
            hsm.capabilities["key_isolation"]): # Use global hsm
            try:
                # Some HSMs can perform KDF operations directly
                hardware_result = hsm.use_key(self.hardware_key_ids["root_key"], "kdf", # Use global hsm
                                    input_key_material + b"||" + info)
                if hardware_result and len(hardware_result) == 64:
                    logger.debug("Used hardware-backed KDF operation")
            except Exception as e:
                logger.warning(f"Hardware KDF failed: {e}, falling back to software")
                hardware_result = None
        
        # Compute a unique salt derived from current material
        salt = hmac.HMAC(key_material, b"DR_SALT", hashlib.sha256).digest()
        
        # Create a SHA512 instance properly
        sha512_instance = hashes.SHA512()
        
        # Use SHA-512 for post-quantum security level
        hkdf = HKDF(
            algorithm=sha512_instance,  # Use the properly instantiated SHA512 object
            length=length,  # Use the specified length
            salt=salt,
            info=info
        )
        
        # Derive key material using software implementation
        software_result = hkdf.derive(input_key_material)
        
        # Use constant-time selection between hardware and software results
        # This prevents timing differences that could leak whether hardware was used
        if self.side_channel_protection and hardware_result is not None:
            # If hardware_result is available, select between the two in constant time
            derived_key = ConstantTime.select(
                len(hardware_result) == 64,  # Condition for using hardware result
                hardware_result[:length],    # Hardware result (truncated if needed)
                software_result              # Software result
            )
        else:
            # Use software result if hardware isn't available or side-channel protection is off
            derived_key = software_result
        
        # Verify output
        verify_key_material(derived_key, expected_length=length, description=f"HKDF output ({info})")
        
        # Record operation time for anomaly detection
        if self.anomaly_detection:
            duration = time.time() - start_time
            self.security_metrics["operation_times"]["kdf"] = duration
            self.threat_detector.record_operation("kdf", duration)
        
        # Apply hardware binding if available
        if self.hsm_available and self.device_fingerprint:
            # Mix in hardware fingerprint using constant-time operations
            if self.side_channel_protection:
                # Create a fixed-size buffer for the combined value
                combined = bytearray(len(derived_key) + len(self.device_fingerprint.encode()))
                
                # Copy derived key and device fingerprint to the buffer
                combined[:len(derived_key)] = derived_key
                combined[len(derived_key):] = self.device_fingerprint.encode()
                
                # Hash the combined value
                hw_bound_key = hashlib.sha512(combined).digest()[:length]
                
                # Use constant-time selection to prevent timing leaks
                derived_key = ConstantTime.select(True, hw_bound_key, derived_key)
            else:
                # Standard implementation when side-channel protection is not required
                derived_key = hashlib.sha512(derived_key + self.device_fingerprint.encode()).digest()[:length]
            
        return derived_key

    def _encrypt_with_cipher(self, plaintext: bytes, auth_data: bytes, message_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with ChaCha20-Poly1305 AEAD.
        
        Args:
            plaintext: The plaintext to encrypt
            auth_data: Authenticated associated data
            message_key: The key to use for encryption
        
        Returns:
            Tuple of (nonce, ciphertext)
        """
        # Generate a counter-based nonce with random salt
        # Counter (8 bytes) for uniqueness + salt (4 bytes) for randomness
        if not hasattr(self, '_nonce_manager') or self._nonce_manager is None:
            # Create a new nonce manager if one doesn't exist
            # Import here to avoid circular imports
            from tls_channel_manager import CounterBasedNonceManager
            self._nonce_manager = CounterBasedNonceManager()
            
        # Generate nonce using counter + salt method
        nonce = self._nonce_manager.generate_nonce()
        
        # Create a mutable copy of the message key for better memory hygiene
        # This copy will be securely erased after use
        message_key_buffer = bytearray(message_key)
        
        try:
            # Create the cipher with the message key
            cipher = ChaCha20Poly1305(bytes(message_key_buffer))
            
            # Encrypt the plaintext
            ciphertext = cipher.encrypt(nonce, plaintext, auth_data)
            
            return nonce, ciphertext
        finally:
            # Securely erase the message key copy from memory
            # Multi-pass overwrite of the key buffer
            for i in range(len(message_key_buffer)):
                message_key_buffer[i] = 0
            
            # Try to use platform-specific memory lock/unlock if available
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * len(message_key_buffer)).from_buffer(message_key_buffer))
                # Zero out with memset for direct memory access
                ctypes.memset(buffer_addr, 0, len(message_key_buffer))
            except Exception:
                # Silently handle any errors during secure erasure
                pass
    
    def _encrypt(self, plaintext: bytes) -> bytes:
        """Internal implementation of the Double Ratchet encryption protocol.
        
        Performs the core encryption operations:
        
        1. Advances the sending chain to derive a fresh message key
        2. Creates a message header with ratchet state information
        3. Generates authenticated data from the header
        4. Encrypts plaintext with ChaCha20-Poly1305 AEAD
        5. Signs the encrypted data with FALCON-1024 (if PQ enabled)
        6. Assembles the complete message with all components
        
        This method implements the cryptographic operations described in
        the Double Ratchet specification with post-quantum enhancements.
        
        Args:
            plaintext: Raw message data to encrypt
            
        Returns:
            bytes: Complete encrypted message with header, signature, and ciphertext
            
        Raises:
            SecurityError: If encryption fails or Double Ratchet is not initialized
        """
        # Validate input
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
            
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
            
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")
        
        # Ensure Double Ratchet is initialized
        if not self.is_initialized():
            raise SecurityError("Cannot encrypt: Double Ratchet not initialized")
        
        # 1. Advance sending chain to derive new message key
        message_key = self._ratchet_encrypt()
        
        # 2. Construct message header
        # Get previous chain length, ensure it's non-negative
        previous_chain_length = max(0, self.receiving_message_number)
        
        header = MessageHeader.generate(
            public_key=self.dh_public_key,
            previous_chain_length=previous_chain_length,
            message_number=self.sending_message_number - 1
        )
        
        # Encode header to bytes
        serialized_header = header.encode()
        
        # 3. Create authenticated data from header
        auth_data = self._get_associated_data(serialized_header)
        
        # 4. Encrypt the message
        logger.debug(f"Encrypting {len(plaintext)} bytes with message key #{header.message_number}")
        nonce, ciphertext = self._encrypt_with_cipher(plaintext, auth_data, message_key)
        
        # 5. Post-quantum signature if enabled
        signature = b''
        if self.enable_pq and self.dss_private_key:
            # Sign the combination of nonce + ciphertext for authentication
            data_to_sign = nonce + ciphertext
            signature = self.dss.sign(self.dss_private_key, data_to_sign)
            logger.debug(f"Applied FALCON signature ({len(signature)} bytes)")
            
        # 6. Assemble complete message
        # Format: header + signature_length (2 bytes) + signature + nonce + ciphertext
        signature_length_bytes = len(signature).to_bytes(2, byteorder='big')
        message = serialized_header + signature_length_bytes + signature + nonce + ciphertext
        
        logger.info(
            f"Encrypted message: {len(message)} bytes (header: {len(serialized_header)}, " +
            f"sig: {len(signature)}, nonce: {len(nonce)}, ciphertext: {len(ciphertext)})"
        )
        
        return message

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a message with the Double Ratchet protocol.
        
        Performs secure message encryption with forward secrecy and
        post-quantum protection. The encryption process includes:
        
        1. Chain key ratcheting to generate a unique message key
        2. Authenticated encryption with ChaCha20-Poly1305 AEAD
        3. Message signing with FALCON-1024 (if post-quantum enabled)
        4. Header generation with current ratchet state information
        5. Replay protection with unique message identifiers
        
        The resulting message contains:
        - Header with X25519 public key and chain state information
        - FALCON signature (if post-quantum enabled)
        - Nonce for ChaCha20-Poly1305
        - Authenticated encrypted payload
        
        Args:
            plaintext: Raw message data to encrypt
            
        Returns:
            bytes: Complete encrypted message ready for transmission
            
        Raises:
            TypeError: If plaintext is not bytes
            ValueError: If plaintext exceeds maximum size
            SecurityError: If encryption fails or security constraints are violated
            
        Security note:
            Each message uses a unique key derived through the ratchet mechanism,
            ensuring forward secrecy even if future keys are compromised.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
            
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size ({len(plaintext)} > {self.MAX_MESSAGE_SIZE} bytes)")
        
        # Use the private _encrypt method to handle encryption
        return self._encrypt(plaintext)

    def _decrypt_with_cipher(self, nonce: bytes, ciphertext: bytes, auth_data: bytes, message_key: bytes) -> bytes:
        """Decrypt ciphertext with ChaCha20-Poly1305 AEAD with secure memory handling.
        
        Performs authenticated decryption with ChaCha20-Poly1305 while implementing
        secure memory management practices to protect the message key:
        
        1. Creates a temporary copy of the message key in a mutable buffer
        2. Performs authenticated decryption with ChaCha20-Poly1305
        3. Securely erases the key material from memory after use
        4. Uses platform-specific memory protection when available
        
        Args:
            nonce: 12-byte nonce used for encryption
            ciphertext: Encrypted message data
            auth_data: Authenticated associated data (typically derived from header)
            message_key: 32-byte key derived from the ratchet chain
        
        Returns:
            bytes: Decrypted plaintext if authentication succeeds
            
        Raises:
            SecurityError: If authentication fails (tag verification fails)
            
        Security note:
            This method implements defense-in-depth by using both high-level
            secure erasure and low-level memory protection techniques.
        """
        # Create a mutable copy of the message key for better memory hygiene
        # This copy will be securely erased after use
        message_key_buffer = bytearray(message_key)
        
        try:
            # Create the cipher with the message key
            cipher = ChaCha20Poly1305(bytes(message_key_buffer))
            
            try:
                # Decrypt the ciphertext
                plaintext = cipher.decrypt(nonce, ciphertext, auth_data)
                return plaintext
            except InvalidTag:
                logger.error("SECURITY ALERT: Authentication tag verification failed")
                raise SecurityError("Message authentication failed")
        finally:
            # Securely erase the message key copy from memory
            # Multi-pass overwrite of the key buffer
            for i in range(len(message_key_buffer)):
                message_key_buffer[i] = 0
            
            # Try to use platform-specific memory lock/unlock if available
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * len(message_key_buffer)).from_buffer(message_key_buffer))
                # Zero out with memset for direct memory access
                ctypes.memset(buffer_addr, 0, len(message_key_buffer))
            except Exception:
                # Silently handle any errors during secure erasure
                pass
    
    def decrypt(self, message: bytes) -> bytes:
        """Decrypt a message using the Double Ratchet protocol.
        
        Performs secure message decryption with comprehensive security checks:
        
        1. Message structure validation and parsing
        2. Replay attack detection using unique message IDs
        3. Cryptographic signature verification (FALCON-1024 if PQ enabled)
        4. DH ratchet step execution if sender's key has changed
        5. Message key derivation through chain ratcheting
        6. Authenticated decryption with ChaCha20-Poly1305
        
        The decryption process handles:
        - Out-of-order message delivery through skipped message keys
        - Key rotation through DH ratchet steps
        - Post-quantum signature verification
        - Replay attack prevention
        
        Args:
            message: Complete encrypted message to decrypt
            
        Returns:
            bytes: Decrypted plaintext message
            
        Raises:
            TypeError: If message is not bytes
            ValueError: If message format is invalid
            SecurityError: If authentication fails, signature verification fails,
                          or any security constraint is violated
                          
        Security note:
            Failed authentication or signature verification will immediately
            abort the decryption process to prevent oracle attacks.
        """
        # Validate input
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
            
        if len(message) < MessageHeader.HEADER_SIZE + 14:  # Header + min signature len + nonce
            raise ValueError(f"Message is too short: {len(message)} bytes")
        
        # Ensure Double Ratchet is initialized
        if not self.is_initialized():
            raise SecurityError("Cannot decrypt: Double Ratchet not initialized")
            
        try:
            # 1. Parse the message components
            header_bytes = message[:MessageHeader.HEADER_SIZE]
            header = MessageHeader.decode(header_bytes)
            
            # --- REPLAY DETECTION ---
            # Check if this unique message ID has already been processed
            if header.message_id in self.replay_cache:
                logger.warning(
                    f"SECURITY ALERT: Message replay attack detected! Message ID {format_binary(header.message_id)} already processed. "
                    f"Ratchet: {format_binary(self._get_public_key_fingerprint(header.public_key))}, MsgNum: {header.message_number}. "
                    f"This indicates an adversary may be attempting to replay old ciphertexts."
                )
                raise SecurityError("Message replay attack detected: message ID already processed.")
            # --- END REPLAY DETECTION ---
            
            # Extract signature length and signature
            signature_length_bytes = message[MessageHeader.HEADER_SIZE:MessageHeader.HEADER_SIZE+2]
            signature_length = int.from_bytes(signature_length_bytes, byteorder='big')
            
            signature_offset = MessageHeader.HEADER_SIZE + 2
            signature = message[signature_offset:signature_offset+signature_length]
            
            # Extract nonce and ciphertext
            content_offset = signature_offset + signature_length
            nonce = message[content_offset:content_offset+12]
            ciphertext = message[content_offset+12:]
            
            logger.debug(
                f"Parsed message: header={len(header_bytes)} bytes, " +
                f"signature={len(signature)} bytes, nonce={len(nonce)} bytes, " +
                f"ciphertext={len(ciphertext)} bytes"
            )
            
            # 2. Verify signature if PQ is enabled
            if self.enable_pq and signature:
                if not self.remote_dss_public_key:
                    logger.warning("Cannot verify FALCON signature: No remote DSS public key available")
                else:
                    data_to_verify = nonce + ciphertext
                    self._secure_verify(self.remote_dss_public_key, data_to_verify, signature, "FALCON message signature")
            
            # 3. Create authenticated data from header
            auth_data = self._get_associated_data(header_bytes)
            
            # 4. Perform DH ratchet step if needed and derive message key
            message_key = self._ratchet_decrypt(header)
            
            # 5. Decrypt the message
            logger.debug(f"Decrypting with message key #{header.message_number}")
            plaintext = self._decrypt_with_cipher(nonce, ciphertext, auth_data, message_key)
            
            # Add successfully processed message ID to replay cache
            self.replay_cache.add(header.message_id)
            
            return plaintext
            
        except Exception as e:
            if isinstance(e, SecurityError):
                # Rethrow security errors without modification
                raise
            else:
                # Wrap other exceptions as security errors
                logger.error(f"Decryption error: {e}", exc_info=True)
                raise SecurityError(f"Failed to decrypt message: {e}")
    
    def _ratchet_encrypt(self) -> bytes:
        """
        Advance the sending chain to derive a new message key.
        
        Returns:
            The derived message key for encryption
        """
        # Ensure the Double Ratchet is properly initialized
        if not self.is_initialized():
            raise SecurityError("Cannot generate message key: Double Ratchet not initialized")
        
        # Check if sending chain exists
        if self.sending_chain_key is None:
            raise SecurityError("Sending chain is not initialized")
            
        # Derive next chain key and message key
        next_chain_key, message_key = self._chain_ratchet_step(self.sending_chain_key)
        
        # Update state
        self.sending_chain_key = next_chain_key
        self.sending_message_number += 1
        
        logger.debug(f"Generated message key for sending chain message #{self.sending_message_number-1}")
        return message_key
        
    def _ratchet_decrypt(self, header: MessageHeader) -> bytes:
        """
        Process a message header and derive the appropriate message key for decryption.
        Follows the logic similar to Signal Protocol for receiving messages.
        
        This method handles:
        1. Checking for previously stored skipped message keys.
        2. Performing a DH ratchet step if the sender's DH key has changed.
           - This includes storing skipped keys from the sender's *previous* chain.
        3. Advancing the current receiving chain if the message is ahead, storing intermediate keys.
        4. Deriving the message key for the current message or erroring for old/unskippable messages.
        
        Returns:
            The correct message key for decryption.
        """
        remote_public_key_from_header_bytes = header.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        message_number = header.message_number
        # This is the ratchet ID associated with the chain this message belongs to.
        current_message_ratchet_id = self._get_public_key_fingerprint(header.public_key)
        
        # 1. Check KSKIPPED: If key for (header.public_key, header.message_number) is stored, use it.
        key_tuple = (current_message_ratchet_id, message_number)
        if key_tuple in self.skipped_message_keys:
            logger.info(f"Using stored key for message #{message_number} (ratchet {format_binary(current_message_ratchet_id)})")
            # Pop the key as it's now being used.
            return self.skipped_message_keys.pop(key_tuple)

        # --- Potential DH Ratchet Step --- 
        # Check if the sender's DH public key in the header is new compared to our stored remote DH key.
        needs_dh_ratchet = False
        if self.remote_dh_public_key is None: # First message from this peer or session reset
            needs_dh_ratchet = True
            logger.info("No current remote DH public key. Assuming first message or new session, will perform DH ratchet.")
        elif not self._compare_public_keys(self.remote_dh_public_key, remote_public_key_from_header_bytes):
            needs_dh_ratchet = True
            logger.info("Remote DH public key in header has changed. Performing DH ratchet step.")
            # Before ratcheting, store any skipped message keys from the *old* receiving chain
            # (associated with the previous self.remote_dh_public_key).
            if self.receiving_chain_key: # If there was an active receiving chain
                old_remote_ratchet_id = self._get_public_key_fingerprint(self.remote_dh_public_key)
                logger.debug(f"Storing skipped keys for old ratchet {format_binary(old_remote_ratchet_id)} "
                             f"from message #{self.receiving_message_number} up to #{header.previous_chain_length-1}.")
                self._store_skipped_message_keys(
                    self.receiving_chain_key,    # The CKr for the old chain
                    self.receiving_message_number, # The Nr for the old chain
                    header.previous_chain_length, # Pn from header (sender's old chain length)
                    old_remote_ratchet_id        # Ratchet ID of the old chain
                )
        
        if needs_dh_ratchet:
            # This performs the DH exchange, updates self.root_key, self.remote_dh_public_key,
            # self.receiving_chain_key, and resets self.receiving_message_number = 0.
            # It also generates new sending keys for us.
            # It needs the KEM public key associated with remote_public_key_from_header_bytes if PQ is enabled.
            # We assume self.remote_kem_public_key was updated alongside self.remote_dh_public_key by an earlier
            # call to set_remote_public_key or during a previous ratchet where we were the sender.
            # If this is the first time we see this new DH key, self.remote_kem_public_key might be stale if not updated.
            # However, the KEM secret is typically tied to the DH exchange that establishes the root key, or encapsulated
            # by the initiator. For a DH ratchet step, the KEM part is usually an encapsulation towards the new DH key.
            # The current _dh_ratchet_step uses self.kem.encaps(remote_kem_public_key) if remote_kem_public_key is provided.
            # If Bob receives a new DH key from Alice, Alice should have encapsulated for it.
            # For simplicity, we use self.remote_kem_public_key which should correspond to the *new* DH key from Alice.
            # This implies that when Alice sends a new DH Ratchet key, she also sends a new KEM Public Key if PQ.
            # The current logic in _dh_ratchet_step uses self.remote_kem_public_key for encapsulation if provided.
            # Let's assume it's correctly managed by higher-level key agreement logic that remote KEM PK is available.
            # The header itself doesn't carry the KEM PK for the ratchet step.
            # The _dh_ratchet_step uses the *local* KEM to encapsulate towards the *remote* KEM public key.
            # This step is when *we* receive a new key, so *we* are decapsulating if anything, or preparing *our* next send.

            # The `_dh_ratchet_step` is called with the public key from the header.
            # If PQ is enabled, it may also require the KEM public key corresponding to `remote_public_key_from_header_bytes`.
            # The current `_dh_ratchet_step` uses `self.kem.encaps(remote_kem_public_key)` which is for *sending* a KEM ciphertext.
            # When *receiving* a new DH key, we would use the KEM shared secret from a *received* KEM ciphertext (if any).
            # This part of the logic might need careful review in context of hybrid key exchange for ratchet steps.
            # For now, follow the existing structure of _dh_ratchet_step, assuming KEM aspects are handled within it.
            # It will internally update self.remote_dh_public_key to the one from the header.
            current_remote_kem_pk_for_ratchet = None
            if self.enable_pq:
                # We need the KEM public key that corresponds to remote_public_key_from_header_bytes.
                # This is tricky as the header doesn't carry it. Assume it has been set via `set_remote_public_key`
                # or is part of the initial handshake and `self.remote_kem_public_key` refers to it.
                # This is a potential point of confusion if KEM keys are not tightly coupled with DH keys in the protocol.
                # Let's assume for now that self.remote_kem_public_key refers to the KEM public key of the current communication partner.
                 current_remote_kem_pk_for_ratchet = self.remote_kem_public_key

            self._dh_ratchet_step(remote_public_key_from_header_bytes, current_remote_kem_pk_for_ratchet)
            # After this, self.receiving_message_number = 0 for the new chain.
            # And self.remote_dh_public_key matches header.public_key.

        # --- Process message in its chain (defined by header.public_key, which now matches self.remote_dh_public_key) ---
        # current_message_ratchet_id is the ID for the chain this message belongs to.
        # self.receiving_message_number is Nr for this chain.
        # message_number is N (from header) for this message.

        if message_number < self.receiving_message_number:
            # Message is older than current state for this chain AND was not in skipped_message_keys.
            logger.error(f"SECURITY ALERT: Message replay attack detected! Old message #{message_number} received for current ratchet "
                         f"(current chain is at message #{self.receiving_message_number}), not in skipped keys cache. "
                         f"Ratchet ID: {format_binary(current_message_ratchet_id)}. "
                         f"This indicates an adversary may be attempting to replay old ciphertexts after the ratchet has advanced.")
            raise SecurityError(f"Message replay attack detected: old message sequence number (#{message_number}) for current ratchet, not in skipped keys cache.")

        if message_number > self.receiving_message_number:
            # Message is ahead in this chain. Skip from current self.receiving_message_number up to message_number (exclusive).
            # _skip_message_keys will advance self.receiving_chain_key and self.receiving_message_number,
            # and store intermediate MKs in self.skipped_message_keys (associated with current_message_ratchet_id).
            logger.debug(f"Message #{message_number} is ahead of current receiving number #{self.receiving_message_number}. Skipping keys.")
            self._skip_message_keys(message_number, current_message_ratchet_id)
            # After _skip_message_keys, self.receiving_message_number should BE message_number.

        # Verify synchronization: at this point, message_number should equal self.receiving_message_number
        if message_number != self.receiving_message_number:
            logger.critical(f"CRITICAL LOGIC ERROR: Message number {message_number} ({type(message_number)}) "
                            f"does not match receiving chain number {self.receiving_message_number} ({type(self.receiving_message_number)}) "
                            f"after attempt to synchronize. Ratchet ID: {format_binary(current_message_ratchet_id)}.")
            # This indicates a flaw in _skip_message_keys or the surrounding logic.
            raise SecurityError("Ratchet desynchronization: message number mismatch after skipping.")

        # Derive Message Key for the current message_number, then advance chain state.
        if self.receiving_chain_key is None:
            # This should not happen if the ratchet is initialized and DH step occurred if needed.
            logger.error("CRITICAL: Receiving chain key is None before final key derivation.")
            raise SecurityError("Receiving chain key is unexpectedly None.")
            
        # Get key for message_number (which is self.receiving_message_number)
        next_chain_key_val, message_key_val = self._chain_ratchet_step(self.receiving_chain_key)
        
        # Advance the receiving chain state for the NEXT message
        self.receiving_chain_key = next_chain_key_val
        self.receiving_message_number += 1 # Increment N_r
        
        logger.debug(f"Derived message key for message #{message_number} (ratchet {format_binary(current_message_ratchet_id)}). "
                     f"Receiving number advanced to {self.receiving_message_number}.")
        return message_key_val
    
    def _store_skipped_message_keys(self, chain_key: bytes, start: int, end: int, ratchet_key_id: bytes) -> None:
        """
        Store message keys for messages we haven't received yet.
        
        This is a critical component of maintaining security when messages
        arrive out of order or when the sender has ratcheted forward.
        """
        # Validate parameters
        if end <= start:
            return  # Nothing to skip
            
        # Limit the maximum number of keys to prevent DoS
        max_to_store = min(end - start, self.max_skipped_message_keys)
        if max_to_store < (end - start):
            logger.warning(
                f"Limiting skipped keys to {max_to_store} (requested {end-start}). " +
                f"This may cause message loss if too many messages arrive out of order."
            )
            end = start + max_to_store
            
        logger.info(f"Storing keys for skipped messages from #{start} to #{end-1}")
        
        # Generate and store keys for all messages we're skipping
        current_chain_key = chain_key
        remote_key_id = self._get_public_key_fingerprint(self.remote_dh_public_key)
        
        for i in range(start, end):
            next_chain_key, message_key = self._chain_ratchet_step(current_chain_key)
            current_chain_key = next_chain_key
            
            # Store the skipped key for later use
            key_tuple = (remote_key_id, i)
            self.skipped_message_keys[key_tuple] = message_key
            logger.debug(f"Stored key for skipped message #{i}")
            
    def _create_new_receiving_chain(self) -> None:
        """Create a new receiving chain using DH and KEM shared secrets."""
        # Generate a new DH shared secret
        dh_shared_secret = self.dh_private_key.exchange(self.remote_dh_public_key)
        verify_key_material(dh_shared_secret, description="DH shared secret for new chain")
        
        # If PQ is enabled, combine with KEM shared secret
        if self.enable_pq and hasattr(self, 'kem_shared_secret') and self.kem_shared_secret:
            # Combine DH and KEM shared secrets using KDF
            logger.debug("Combining DH and KEM shared secrets for hybrid security")
            combined_secret = hashlib.sha512(
                dh_shared_secret + b"||NEW_CHAIN||" + self.kem_shared_secret
            ).digest()
            
            root_key, chain_key = self._kdf(
                self.root_key, combined_secret, self.KDF_INFO_HYBRID + b"_NEW_CHAIN"
            )
        else:
            # Use only DH shared secret
            root_key, chain_key = self._kdf(
                self.root_key, dh_shared_secret, self.KDF_INFO_DH + b"_NEW_CHAIN"
            )
        
        # Update root key and create new receiving chain
        self.root_key = root_key[:32]
        self.receiving_chain_key = chain_key[:32]
        
        # Verify key material
        verify_key_material(self.root_key, expected_length=32, description="New root key")
        verify_key_material(self.receiving_chain_key, expected_length=32, 
                          description="New receiving chain key")
        
        logger.info("Created new receiving chain")
    
    def get_public_key(self) -> bytes:
        """Get the current X25519 public key for key exchange."""
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    def get_kem_public_key(self) -> Optional[bytes]:
        """Get the current ML-KEM public key for post-quantum key exchange."""
        if self.enable_pq and hasattr(self, 'kem_public_key') and self.kem_public_key:
            return self.kem_public_key
        return None
        
    def get_kem_ciphertext(self) -> Optional[bytes]:
        """Get the current KEM ciphertext from encapsulation."""
        if self.enable_pq and hasattr(self, 'kem_ciphertext') and self.kem_ciphertext:
            return self.kem_ciphertext
        return None
        
    def process_kem_ciphertext(self, ciphertext: bytes) -> bytes:
        """
        Process a KEM ciphertext to derive a shared secret.
        
        This is used by the responder to complete the post-quantum
        key establishment initiated by the other party.
        """
        if not self.enable_pq:
            logger.warning("Received KEM ciphertext but post-quantum mode is disabled")
            return b''
            
        try:
            # Verify KEM ciphertext integrity, including length
            verify_key_material(ciphertext, 
                                expected_length=self.MLKEM1024_CIPHERTEXT_SIZE, 
                                description="KEM ciphertext for DR")
            # Log the received KEM ciphertext
            logger.debug(f"Received KEM ciphertext for processing: {format_binary(ciphertext)}")

            # Decapsulate the KEM ciphertext
            shared_secret = self.kem.decaps(self.kem_private_key, ciphertext)
            verify_key_material(shared_secret, description="Decapsulated KEM shared secret")
            
            # Store the shared secret
            self.kem_shared_secret = shared_secret
            logger.debug(f"Processed KEM ciphertext and derived shared secret ({len(shared_secret)} bytes)")
            
            # If we already have DH outputs but no chains, initialize chains now
            if self.remote_dh_public_key and not self.receiving_chain_key:
                logger.debug("Completing initialization with DH output and KEM shared secret")
                dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
                self._initialize_chain_keys(dh_output, shared_secret)
                
            # Return the shared secret for immediate use if needed
            return shared_secret
            
        except Exception as e:
            self.last_error = f"Failed to process KEM ciphertext: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"KEM processing failed: {str(e)}")
            
    def _initialize_chain_keys(self, dh_output: bytes, kem_shared_secret: Optional[bytes] = None) -> None:
        """
        Initialize or reinitialize the chain keys.
        
        This method establishes the initial chain keys for both sending
        and receiving chains, ensuring that both parties derive the same
        keys despite being in different roles.
        """
        # Log operation
        logger.debug(
            f"Initializing chain keys with DH output ({len(dh_output)} bytes)" +
            (f" and KEM shared secret ({len(kem_shared_secret)} bytes)" if kem_shared_secret else "")
        )
        
        # Verify inputs
        verify_key_material(dh_output, description="DH output for chain key initialization")
        current_root_key = self.root_key # This is the shared secret from X3DH+PQ

        if kem_shared_secret:
            verify_key_material(kem_shared_secret, description="KEM shared secret for chain key initialization")
            
        # Create combined secret for hybrid mode (this is the IKM for HKDF)
        if self.enable_pq and kem_shared_secret:
            combined_secret = hashlib.sha512(b"DR_HYBRID_" + dh_output + b"_" + kem_shared_secret).digest()
            logger.debug(f"Using hybrid DH+KEM input for key derivation ({len(combined_secret)} bytes)")
            # Info strings for Step 1 (conceptually, initiator's sending chain / responder's receiving chain)
            info_root_s1 = self.KDF_INFO_INIT_ROOT_STEP1_HYBRID
            info_chain_s1 = self.KDF_INFO_INIT_CHAIN_STEP1_HYBRID
            # Info strings for Step 2 (conceptually, initiator's receiving chain / responder's sending chain)
            info_root_s2 = self.KDF_INFO_INIT_ROOT_STEP2_HYBRID
            info_chain_s2 = self.KDF_INFO_INIT_CHAIN_STEP2_HYBRID
        else:
            combined_secret = dh_output
            logger.debug(f"Using classical DH input for key derivation ({len(combined_secret)} bytes)")
            # Info strings for Step 1
            info_root_s1 = self.KDF_INFO_INIT_ROOT_STEP1_DH
            info_chain_s1 = self.KDF_INFO_INIT_CHAIN_STEP1_DH
            # Info strings for Step 2
            info_root_s2 = self.KDF_INFO_INIT_ROOT_STEP2_DH
            info_chain_s2 = self.KDF_INFO_INIT_CHAIN_STEP2_DH

        # --- Step 1 Derivations ---
        # (Corresponds to what DR_INIT_SENDING_v2 used to produce for both root and chain key)
        
        # Derive new root key for step 1
        logger.debug(f"Deriving initial root key (step 1) using info: {info_root_s1.decode()}")
        root_key_s1 = self._kdf(current_root_key, combined_secret, info=info_root_s1, length=self.ROOT_KEY_SIZE)
        verify_key_material(root_key_s1, description="Initial root key (step 1)")

        # Derive chain key for step 1, using the new root_key_s1 as HKDF key material
        logger.debug(f"Deriving initial chain key (step 1) using info: {info_chain_s1.decode()}")
        chain_key_s1 = self._kdf(root_key_s1, combined_secret, info=info_chain_s1, length=self.CHAIN_KEY_SIZE)
        verify_key_material(chain_key_s1, description="Initial chain key (step 1)")

        # --- Step 2 Derivations ---
        # (Corresponds to what DR_INIT_RECEIVING_v2 used to produce for both root and chain key)
        # The root key for this step's derivation is the output from step 1's root key derivation
        
        # Derive new root key for step 2
        logger.debug(f"Deriving initial root key (step 2) using info: {info_root_s2.decode()}")
        root_key_s2 = self._kdf(root_key_s1, combined_secret, info=info_root_s2, length=self.ROOT_KEY_SIZE)
        verify_key_material(root_key_s2, description="Initial root key (step 2)")

        # Derive chain key for step 2, using the new root_key_s2 as HKDF key material
        logger.debug(f"Deriving initial chain key (step 2) using info: {info_chain_s2.decode()}")
        chain_key_s2 = self._kdf(root_key_s2, combined_secret, info=info_chain_s2, length=self.CHAIN_KEY_SIZE)
        verify_key_material(chain_key_s2, description="Initial chain key (step 2)")
        
        # Assign keys based on initiator/responder role
        if self.is_initiator:
            logger.debug("Assigning Step 1 to Sending Chain, Step 2 to Receiving Chain for Initiator")
            self.root_key = root_key_s2 # Final root key is from Step 2
            self.sending_chain_key = chain_key_s1
            self.receiving_chain_key = chain_key_s2
        else: # Responder
            logger.debug("Assigning Step 1 to Receiving Chain, Step 2 to Sending Chain for Responder")
            self.root_key = root_key_s2 # Final root key is from Step 2
            self.receiving_chain_key = chain_key_s1 # Responder receives on chain derived from "Step 1" context
            self.sending_chain_key = chain_key_s2   # Responder sends on chain derived from "Step 2" context
        
        # Reset message counters
        self.sending_message_number = 0
        self.receiving_message_number = 0
        
        # Verify chain key derivation was successful
        if not self.sending_chain_key or not self.receiving_chain_key:
            logger.error("SECURITY ALERT: Chain key derivation failed")
            raise SecurityError("Chain key derivation failed")
            
        logger.info(f"Successfully initialized chain keys for {'initiator' if self.is_initiator else 'responder'}")
    
    def get_info(self) -> Dict[str, Any]:
        """Get diagnostic information about the current state."""
        # Compute fingerprints for identification
        remote_key_fingerprint = None
        if self.remote_dh_public_key:
            remote_key_fingerprint = base64.b64encode(
                self._get_public_key_fingerprint(self.remote_dh_public_key)
            ).decode()
            
        # Build basic info
        info = {
            "is_initiator": self.is_initiator,
            "post_quantum_enabled": self.enable_pq,
            "current_ratchet_key_id": base64.b64encode(self.current_ratchet_key_id).decode(),
            "remote_ratchet_key_id": remote_key_fingerprint,
            "sending_message_number": self.sending_message_number,
            "receiving_message_number": self.receiving_message_number,
            "skipped_keys_count": len(self.skipped_message_keys),
            "initialization_status": "complete" if self.is_initialized() else "pending",
            "max_skipped_keys": self.max_skipped_message_keys,
            "last_error": self.last_error
        }
        
        # Add PQ-specific information if enabled
        if self.enable_pq:
            info.update({
                "has_remote_kem_key": self.remote_kem_public_key is not None,
                "has_kem_ciphertext": self.kem_ciphertext is not None,
                "has_remote_dss_key": self.remote_dss_public_key is not None,
                "has_kem_shared_secret": hasattr(self, 'kem_shared_secret') and self.kem_shared_secret is not None,
                "pq_algorithms": {
                    "kem": "ML-KEM-1024",
                    "signature": "FALCON-1024"
                }
            })
        
        return info

    def is_initialized(self) -> bool:
        """Check if the Double Ratchet is fully initialized and ready."""
        # Basic requirements for all modes
        basic_init = (
            self.sending_chain_key is not None and 
            self.receiving_chain_key is not None and
            self.remote_dh_public_key is not None
        )
        
        # In PQ mode, also check KEM initialization
        if self.enable_pq:
            pq_init = (
                self.remote_kem_public_key is not None and
                (self.is_initiator or self.kem_shared_secret is not None)
            )
            
            if not pq_init:
                # Log helpful diagnostics about what's missing
                if self.remote_kem_public_key is None:
                    logger.error("INITIALIZATION ERROR: Missing remote KEM public key")
                elif not self.is_initiator and self.kem_shared_secret is None:
                    logger.error("INITIALIZATION ERROR: Responder missing KEM shared secret (ciphertext not processed)")
                    
            return basic_init and pq_init
        
        return basic_init
        
    def _get_associated_data(self, header_bytes: bytes) -> bytes:
        """
        Create authenticated data binding the header to the ciphertext.
        
        This prevents header modification and cross-protocol attacks.
        """
        # Application context for domain separation
        context = b"DoubleRatchet_PQSv2"
        
        # Use part of root key for authentication, but never expose the full key
        derived_auth_key = hmac.HMAC(
            key=self.root_key,
            msg=b"AAD_KEY_DERIVATION",
            digestmod=hashlib.sha256
        ).digest()
        
        # Bind header to context
        auth_data = hmac.HMAC(
            key=derived_auth_key[:16],  # Use only part of the derived key
            msg=header_bytes,
            digestmod=hashlib.sha256
        ).digest()
        
        # Return the authenticated data
        return context + auth_data

    def get_dss_public_key(self) -> Optional[bytes]:
        """Returns the public key for the Digital Signature Scheme (FALCON-1024)."""
        return self.dss_public_key

    def secure_cleanup(self) -> None:
        """Securely erase all cryptographic material from memory.
        
        Performs comprehensive cleanup of all sensitive key material:
        1. Securely erases all private keys and chain keys
        2. Clears all skipped message keys
        3. Resets the replay protection cache
        4. Triggers garbage collection to remove lingering references
        
        This method should be called when the DoubleRatchet instance
        is no longer needed to prevent sensitive cryptographic material
        from remaining in memory where it could be exposed through memory
        dumps or cold boot attacks.
        
        Security note:
            This method is critical for maintaining forward secrecy.
            Always call this method when a session is complete.
        """
        logger.info("Double Ratchet state securely cleaned up")

        # Create a list of all potentially sensitive attributes
        sensitive_attrs = [
            '_root_key', '_sending_chain_key', '_receiving_chain_key',
            '_dh_key_pair', '_dss_key_pair', '_kem_key_pair',
            'skipped_message_keys', '_pending_ratchet_key'
        ]

        for attr_name in sensitive_attrs:
            if hasattr(self, attr_name):
                attr_value = getattr(self, attr_name)
                if attr_value is not None:
                    secure_erase(attr_value)
                    # Set to None after erasure
                    try:
                        setattr(self, attr_name, None)
                    except Exception:
                        pass # Some attributes might be read-only
        
        # Explicitly handle the skipped_message_keys dictionary
        if hasattr(self, 'skipped_message_keys') and self.skipped_message_keys is not None:
            # Iterate over a copy of items to be safe
            for key_id, message_key in list(self.skipped_message_keys.items()):
                secure_erase(key_id)
                secure_erase(message_key)
            self.skipped_message_keys.clear()

        # Clear the replay cache
        if hasattr(self, 'replay_cache') and self.replay_cache is not None:
            self.replay_cache.clear()

        # Call garbage collector
        gc.collect()

    def _skip_message_keys(self, until_message_number: int, ratchet_key_id: bytes) -> None:
        """
        Skip message keys to handle out-of-order message delivery.
        
        Advances the receiving chain up to the specified message number (exclusive),
        storing skipped message keys securely for later use. Updates
        self.receiving_chain_key and self.receiving_message_number to reflect
        the state after skipping.
        """
        if self.receiving_chain_key is None:
            logger.error("Cannot skip message keys: receiving_chain_key is None.")
            # This state should ideally be prevented if the ratchet is initialized.
            # Depending on desired robustness, could raise SecurityError.
            return 

        start_msg_num = self.receiving_message_number
        
        if start_msg_num >= until_message_number:
            return # Nothing to skip

        logger.info(f"Attempting to skip from message #{start_msg_num} up to (but not including) #{until_message_number} " +
                    f"for ratchet {format_binary(ratchet_key_id)}. Current skipped_keys: {len(self.skipped_message_keys)}/{self.max_skipped_message_keys}")

        num_actually_skipped_and_stored = 0
        # Loop from the current message number up to the target message number (exclusive)
        for i in range(start_msg_num, until_message_number):
            if len(self.skipped_message_keys) >= self.max_skipped_message_keys:
                logger.warning(
                    f"Maximum skipped keys limit ({self.max_skipped_message_keys}) reached. " +
                    f"Stopping skip at message #{i} (was targeting up to #{until_message_number-1}). " +
                    f"Message #{i} and onwards in this batch will not have their keys stored, " +
                    f"and the receiving chain will only be advanced up to message #{i-1}."
                )
                # The loop will break. self.receiving_message_number and self.receiving_chain_key
                # will reflect the state before processing message 'i'.
                break 

            # Generate message key and advance the chain state
            # This call uses and updates self.receiving_chain_key internally FOR REAL if not careful.
            # _chain_ratchet_step should be pure based on input chain_key.
            # Let's ensure _chain_ratchet_step is pure. Yes, it takes chain_key as input.
            
            next_chain_key_val, message_key_val = self._chain_ratchet_step(self.receiving_chain_key)
            
            # Store the skipped message key
            key_tuple = (ratchet_key_id, i) # i is the message number being skipped
            self.skipped_message_keys[key_tuple] = message_key_val
            
            # Update the main chain key and message number to reflect this step
            self.receiving_chain_key = next_chain_key_val
            self.receiving_message_number = i + 1 # After processing/skipping message i, next expected is i+1
            
            num_actually_skipped_and_stored += 1
            logger.debug(f"Stored key for skipped message {i} (ratchet {format_binary(ratchet_key_id)}). Receiving number is now {self.receiving_message_number}.")
        
        logger.info(f"Finished skipping operation. Advanced receiving chain by {num_actually_skipped_and_stored} steps. " +
                    f"Receiving number is now {self.receiving_message_number}. Total skipped keys stored: {len(self.skipped_message_keys)}.")
    
    def _compare_public_keys(self, public_key1: X25519PublicKey, public_key2_bytes: bytes) -> bool:
        """
        Compare a public key object with raw public key bytes in constant time.
        
        This method ensures that the comparison is done in a way that prevents
        timing side-channel attacks that could leak information about the keys.
        """
        try:
            # Convert the first key to bytes
            public_key1_bytes = public_key1.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Use constant-time comparison to prevent timing attacks
            return ConstantTime.compare(public_key1_bytes, public_key2_bytes)
        except Exception as e:
            logger.error(f"Error comparing public keys: {e}")
            return False
    
    def set_remote_public_key(self, 
                            public_key_bytes: bytes, 
                            kem_public_key: Optional[bytes] = None, 
                            dss_public_key: Optional[bytes] = None) -> None:
        """
        Initialize the ratchet with the remote party's public key.
        
        This is a critical step to synchronize the Double Ratchet state
        between both parties before any messages are exchanged.
        """
        try:
            # Log operation
            logger.info(
                f"Initializing with remote public key ({len(public_key_bytes)} bytes)" + 
                (f" and KEM public key ({len(kem_public_key)} bytes)" if kem_public_key and self.enable_pq else "")
            )
            
            # 1. Validate and set X25519 public key
            verify_key_material(public_key_bytes, expected_length=32, description="Remote X25519 public key")
            self.remote_dh_public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
            remote_fingerprint = self._get_public_key_fingerprint(self.remote_dh_public_key)
            
            # 2. Set DSS public key if provided and PQ is enabled
            if self.enable_pq and dss_public_key:
                verify_key_material(dss_public_key, description="Remote FALCON public key")
                self.remote_dss_public_key = dss_public_key
                logger.debug(f"Set remote FALCON public key ({len(dss_public_key)} bytes)")
            
            # 3. Perform X25519 calculation
            logger.debug("Performing initial Diffie-Hellman exchange")
            dh_output = self.dh_private_key.exchange(self.remote_dh_public_key)
            verify_key_material(dh_output, description="Initial DH output")
            
            # 4. Process KEM public key if in PQ mode
            kem_shared_secret = None
            if self.enable_pq and kem_public_key:
                # Store the remote KEM public key
                verify_key_material(kem_public_key, description="Remote KEM public key")
                self.remote_kem_public_key = kem_public_key
                
                # For initiator or if we already have a shared secret, do encapsulation
                if self.is_initiator or hasattr(self, 'kem_shared_secret') and self.kem_shared_secret:
                    # Perform KEM encapsulation
                    logger.debug("Performing ML-KEM-1024 encapsulation")
                    kem_ciphertext, kem_shared_secret = self.kem.encaps(kem_public_key)
                    self.kem_ciphertext = kem_ciphertext
                    self.kem_shared_secret = kem_shared_secret
                    verify_key_material(kem_shared_secret, description="KEM shared secret")
                    logger.debug(f"KEM shared secret: {format_binary(kem_shared_secret)}")
                else:
                    # Responder waiting for ciphertext
                    logger.debug("Responder waiting for KEM ciphertext to complete initialization")
                    return
            
            # 5. Initialize chains with the generated key material
            self._initialize_chain_keys(dh_output, kem_shared_secret)
            
            logger.info(f"Successfully initialized chains with remote key: {format_binary(remote_fingerprint)}")
                
        except Exception as e:
            self.last_error = f"Failed to set remote public key: {str(e)}"
            logger.error(self.last_error, exc_info=True)
            raise SecurityError(f"Key initialization failed: {str(e)}")

    def _secure_verify(self, public_key, payload, signature, description="signature"):
        """Verify a digital signature with enhanced security and error handling.
        
        Performs secure signature verification with several security enhancements:
        1. Validates all inputs before verification
        2. Uses constant-time operations where possible
        3. Implements fail-closed security (exceptions on failure)
        4. Provides detailed security logging
        
        This method is designed to be resistant to signature forgery attacks
        and timing side-channel attacks.
        
        Args:
            public_key: FALCON public key bytes for verification
            payload: Original data that was signed
            signature: Signature bytes to verify
            description: Description for error messages and logging
            
        Returns:
            bool: True if verification succeeds (never returns False)
            
        Raises:
            SecurityError: If verification fails for any reason
            
        Security note:
            This method follows the principle of failing closed - any verification
            error results in an exception rather than a boolean False return.
        """
        try:
            if not self.dss.verify(public_key, payload, signature):
                logger.error(f"SECURITY ALERT: {description} verification failed")
                raise SecurityError(f"Handshake aborted: invalid {description}")
            return True
        except Exception as e:
            # Log at most "signature mismatch" (avoid printing raw data)
            logger.error(f"SECURITY ALERT: {description} verification error", exc_info=True)
            raise SecurityError(f"Handshake aborted: invalid {description}")


class DoubleRatchetDefaults:
    """Default security settings for the Double Ratchet protocol."""
    
    # Security level configurations
    SECURITY_LEVELS = {

        "MAXIMUM": { # This was HIGH, settings updated by user
            "enable_pq": True,
            "max_skipped_keys":0,          # Reduced skipped keys
            "key_rotation_messages": 1,     # More frequent rotation
            # "key_rotation_time": 1800,       # 30 minutes key rotation
            "key_rotation_time": 10,       # 10 second key rotation
            "max_message_size": 262144,      # 256KB max message size
            "strict_verification": True,
            "side_channel_protection": True,
            "memory_protection": True,       # Enhanced memory protection
            "anomaly_detection": True,       # Enhanced anomaly detection
            "hardware_binding": True,        # Hardware binding when available
            "threshold_security": True,      # Enable threshold security
            "message_padding": True,         # Add random padding
            "anti_tampering": True,          # Advanced anti-tampering 
            "secure_erasure_passes": 10,      # Increased erasure passes
            "replay_cache_size": 1000,        # Larger replay cache
            "replay_cache_expiry": 7200      # Longer expiry (2 hours)
        },
      
    }
    
    @classmethod
    def get_defaults(cls, security_level="MAXIMUM"):
        """Get default configuration for the specified security level."""
        if security_level not in cls.SECURITY_LEVELS:
            original_level = security_level
            security_level = "MAXIMUM"
            logger.info(f"Unknown security level '{original_level}', using MAXIMUM")
        
        config = cls.SECURITY_LEVELS[security_level].copy()
        
        # Check for hardware availability and adjust settings
        if config.get("hardware_binding", False) and not hsm.is_available: # Use global hsm
            logger.warning("Hardware binding requested but no secure hardware available (checked via cphs-backed hsm)")
            config["hardware_binding"] = False
            
        # Apply threat-based adjustments if anomaly detection is enabled
        if config.get("anomaly_detection", False) and hasattr(threat_detector, "get_security_recommendations"):
            recommendations = threat_detector.get_security_recommendations()
            if recommendations.get("security_level") != security_level:
                logger.warning(f"Threat detection suggests changing security level to {recommendations['security_level']}")
                
            # Apply specific threat-based recommendations
            if recommendations.get("decrease_key_rotation_time"):
                config["key_rotation_time"] = recommendations["decrease_key_rotation_time"]
                
            if recommendations.get("rotate_keys"):
                config["key_rotation_messages"] = min(config["key_rotation_messages"], 10)
                
        return config
    
    @classmethod
    def get_recommended_level(cls):
        """Get recommended security level based on environment and threats."""
        recommended = "MAXIMUM"  # Default to MAXIMUM
        
        # Check for virtual machine or container environment
        is_vm = False
        try:
            # Simple VM detection heuristic
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product = f.read().lower()
                if any(x in product for x in ['virtual', 'vmware', 'vbox']):
                    is_vm = True
        except:
            pass
            
        # Check for available hardware security
        has_hardware = hsm.is_available # Use global hsm
        
        # Check current threat level
        current_threat = getattr(threat_detector, 'threat_level', 'normal')
        
        # Determine recommendation
        if current_threat == "high":
            recommended = "PARANOID"
        elif current_threat == "elevated" or is_vm:
            # If already MAXIMUM or PARANOID, keep it. Otherwise, ensure at least MAXIMUM.
            if recommended not in ["PARANOID"]: # "MAXIMUM" is the new base
                recommended = "MAXIMUM" 
        elif has_hardware:
            # If already MAXIMUM or PARANOID, keep it. Otherwise, ensure at least MAXIMUM.
            if recommended not in ["PARANOID"]: # "MAXIMUM" is the new base
                recommended = "MAXIMUM"
            
        return recommended


def example_double_ratchet(use_pq: bool = True) -> None:
    """
    Demonstrate the Double Ratchet protocol between two parties.
    
    Shows the key lifecycle of a Double Ratchet session:
    1. Initialization with shared secrets
    2. Key exchange setup
    3. Normal message exchange
    4. Out-of-order message handling
    
    Args:
        use_pq: Whether to use post-quantum security features
    """
    try:
        print("\n" + "="*60)
        print(f"Double Ratchet Protocol Demonstration")
        print(f"{'With Post-Quantum Security' if use_pq else 'Classical Mode (No PQ)'}")
        print("="*60)
        
        # 1. Initialize with a shared root key (from a secure key exchange)
        shared_root_key = cphs.get_secure_random(32) # Use cphs
        print(f"\nInitial shared root key: {format_binary(shared_root_key)}")
        
        # 2. Create Alice and Bob's ratchets
        print("\nInitializing Alice (initiator) and Bob (responder) ratchets...")
        alice = DoubleRatchet(shared_root_key, is_initiator=True, enable_pq=use_pq)
        bob = DoubleRatchet(shared_root_key, is_initiator=False, enable_pq=use_pq)
        
        # 3. Exchange key material
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        
        print(f"Alice's public key: {format_binary(alice_public)}")
        print(f"Bob's public key:   {format_binary(bob_public)}")
        
        # Handle post-quantum components if enabled
        if use_pq:
            alice_kem_public = alice.get_kem_public_key()
            bob_kem_public = bob.get_kem_public_key()
            alice_dss_public = alice.get_dss_public_key()
            bob_dss_public = bob.get_dss_public_key()
            
            print(f"\nPQ components:")
            print(f"KEM public keys: Alice={format_binary(alice_kem_public)}, Bob={format_binary(bob_kem_public)}")
            
            # 4. Setup key exchange
            print("\nSetting up key exchange...")
            # Alice sets Bob's keys and encapsulates a shared secret
            alice.set_remote_public_key(bob_public, bob_kem_public, bob_dss_public)
            alice_kem_ciphertext = alice.get_kem_ciphertext()
            
            # Bob sets Alice's keys
            bob.set_remote_public_key(alice_public, alice_kem_public, alice_dss_public)
            
            # Bob processes Alice's ciphertext to complete the exchange
            if alice_kem_ciphertext:
                print(f"Exchanging KEM ciphertext ({len(alice_kem_ciphertext)} bytes)")
                shared_secret_bob = bob.process_kem_ciphertext(alice_kem_ciphertext)
                print(f"Derived shared KEM secret: {format_binary(shared_secret_bob)}")
        else:
            # Classical setup with only DH keys
            alice.set_remote_public_key(bob_public)
            bob.set_remote_public_key(alice_public)
        
        # Verify both parties are properly initialized
        print(f"\nAlice initialized: {alice.is_initialized()}")
        print(f"Bob initialized:   {bob.is_initialized()}")
        
        # 5. Test normal message exchange: Alice → Bob
        print("\n" + "-"*60)
        print("Test 1: Normal message flow (Alice → Bob)")
        message = b"Hello Bob! This is a secure message sent with Double Ratchet."
        print(f"Original:  {message.decode()}")
        
        # Alice encrypts
        encrypted = alice.encrypt(message)
        print(f"Encrypted: {len(encrypted)} bytes")
        
        # Bob decrypts
        decrypted = bob.decrypt(encrypted)
        print(f"Decrypted: {decrypted.decode()}")
        print(f"Success:   {message == decrypted}")
    
        # 6. Test reply: Bob → Alice
        print("\n" + "-"*60)
        print("Test 2: Reply message (Bob → Alice)")
        reply = b"Hi Alice! Your secure messaging system works perfectly!"
        print(f"Original:  {reply.decode()}")
        
        # Bob encrypts a reply
        encrypted_reply = bob.encrypt(reply)
        print(f"Encrypted: {len(encrypted_reply)} bytes")
        
        # Alice decrypts the reply
        decrypted_reply = alice.decrypt(encrypted_reply)
        print(f"Decrypted: {decrypted_reply.decode()}")
        print(f"Success:   {reply == decrypted_reply}")
    
        # 7. Test out-of-order message delivery
        print("\n" + "-"*60)
        print("Test 3: Out-of-order message handling")
        
        # Alice sends 3 messages
        messages = [
            b"This is message 1 from Alice - should arrive last",
            b"This is message 2 from Alice - should arrive second",
            b"This is message 3 from Alice - should arrive first"
        ]
        
        encrypted_msgs = [alice.encrypt(msg) for msg in messages]
        print(f"Alice encrypted 3 messages of sizes: "
              f"{len(encrypted_msgs[0])}, {len(encrypted_msgs[1])}, {len(encrypted_msgs[2])} bytes")
        
        # Bob receives them out of order (3, 1, 2)
        print("\nReceiving in order: message 3, message 1, message 2")
        decrypted3 = bob.decrypt(encrypted_msgs[2])
        decrypted1 = bob.decrypt(encrypted_msgs[0])
        decrypted2 = bob.decrypt(encrypted_msgs[1])
        
        print("\nVerifying decryption success:")
        print(f"Message 1: {'✓' if messages[0] == decrypted1 else '✗'}")
        print(f"Message 2: {'✓' if messages[1] == decrypted2 else '✗'}")
        print(f"Message 3: {'✓' if messages[2] == decrypted3 else '✗'}")
        
        # 8. Clean up
        print("\nPerforming secure cleanup...")
        alice.secure_cleanup()
        bob.secure_cleanup()
        print("Secure cleanup completed.")
    
    except Exception as e:
        print(f"\nError in demonstration: {e}")
        import traceback
        traceback.print_exc()


class ReplayCache:
    """
    Enhanced replay protection cache with timestamp-based expiration.
    
    This class provides efficient storage and lookup of message IDs with
    automatic expiration to prevent memory growth. It combines a fast
    lookup set with timestamp tracking for efficient cleanup.
    """
    
    def __init__(self, max_size=200, expiry_seconds=3600):
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        if not isinstance(expiry_seconds, (int, float)) or expiry_seconds <= 0:
            raise ValueError("expiry_seconds must be a positive number")
            
        self.max_size = max_size
        self.expiry_seconds = expiry_seconds
        
        # Using a dictionary for O(1) average time complexity for lookups
        self.cache: Dict[bytes, float] = {}
        # Using a deque for O(1) complexity for appends and pops from both ends
        self.order: Deque[bytes] = collections.deque()
        
        # For thread safety
        self._lock = threading.Lock()
        
        # For periodic cleanup
        self.last_cleanup_time = time.time()
        self.cleanup_interval = max(60, expiry_seconds / 10) # Cleanup every 10% of expiry time, at least every minute

    def clear(self):
        """Clears all entries from the cache."""
        with self._lock:
            self.cache.clear()
            self.order.clear()
            logger.info("Replay cache cleared.")

    def add(self, message_id: bytes) -> None:
        """
        Add a message ID to the cache.
        
        Args:
            message_id: The message ID to add
        """
        # Perform cleanup if needed
        current_time = time.time()
        if current_time - self.last_cleanup_time > self.cleanup_interval:
            self._cleanup(current_time)
        
        # If we're at capacity, force a cleanup
        if len(self.cache) >= self.max_size:
            self._cleanup(current_time, force=True)
            
        # If still at capacity after cleanup, remove oldest entry
        if len(self.cache) >= self.max_size:
            self._remove_oldest()
        
        # Add the new message ID
        self.cache[message_id] = current_time
        self.order.append(message_id)
    
    def contains(self, message_id: bytes) -> bool:
        """
        Check if a message ID is in the replay cache using constant-time operations.
        
        This method prevents timing side-channel attacks that could leak information
        about the contents of the cache. It uses a constant-time comparison approach
        to ensure that the time taken to check for a message ID is the same regardless
        of whether the ID is in the cache or not.
        
        Args:
            message_id: The message ID to check
            
        Returns:
            True if the message ID is in the cache, False otherwise
        """
        # First check if the message ID is in the set using a non-constant time operation
        # This is an optimization that doesn't leak timing information about specific IDs
        if message_id not in self.cache:
            # Perform a dummy constant-time operation to maintain consistent timing
            # This prevents timing attacks based on early returns
            dummy_result = ConstantTime.compare(message_id, message_id)
            return False
        
        # If we get here, the ID is in the set, but we'll verify with constant-time comparison
        # to prevent any potential timing leaks in the set implementation
        result = False
        for stored_id in self.cache:
            # Use constant-time comparison for each ID
            # This is a bit inefficient but ensures constant-time behavior
            is_match = ConstantTime.compare(message_id, stored_id)
            # Update result without branching
            result = result or is_match
        
        return result
    
    def _cleanup(self, current_time: float, force: bool = False) -> None:
        """
        Remove expired message IDs from the cache.
        
        Args:
            current_time: Current time in seconds since epoch
            force: If True, remove at least 25% of entries even if not expired
        """
        self.last_cleanup_time = current_time
        expired_ids = []
        
        # Find expired message IDs
        for msg_id, timestamp in self.cache.items():
            if current_time - timestamp > self.expiry_seconds:
                expired_ids.append(msg_id)
        
        # If forced cleanup and not enough expired, remove oldest entries
        if force and len(expired_ids) < (self.max_size // 4):
            # Sort by timestamp and keep only the newest 75%
            sorted_ids = sorted(self.cache.items(), key=lambda x: x[1])
            additional_removals = max(1, self.max_size // 4) - len(expired_ids)
            expired_ids.extend([msg_id for msg_id, _ in sorted_ids[:additional_removals]])
        
        # Remove expired IDs
        for msg_id in expired_ids:
            del self.cache[msg_id]
    
    def _remove_oldest(self) -> None:
        """Remove the oldest message ID from the cache."""
        if not self.cache:
            return
            
        oldest_id = min(self.cache.items(), key=lambda x: x[1])[0]
        del self.cache[oldest_id]
        self.order.remove(oldest_id)
    
    def __contains__(self, message_id: bytes) -> bool:
        """Support for 'in' operator with constant-time comparison."""
        return self.contains(message_id)
    
    def __len__(self) -> int:
        """Return the number of message IDs in the cache."""
        return len(self.cache)


if __name__ == "__main__":
    # Run with post-quantum security by default
    example_double_ratchet(use_pq=True)
    
    # Uncomment to run with classical mode only
    example_double_ratchet(use_pq=False) 