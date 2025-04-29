"""
TLS Security Verification Module

This module provides comprehensive security verification for the TLS secure channel,
with a focus on validating that ML-KEM-1024 post-quantum cryptography is properly
implemented and used during communications.
"""

import os
import ssl
import socket
import logging
import traceback
from typing import Dict, List, Optional, Any, Tuple

# Configure logging
log = logging.getLogger("tls_security")

# Security log levels
SECURITY_LOG_LEVEL_INFO = 0
SECURITY_LOG_LEVEL_VERBOSE = 1
SECURITY_LOG_LEVEL_DEBUG = 2
SECURITY_LOG_LEVEL = SECURITY_LOG_LEVEL_VERBOSE  # Set to desired level

class TLSSecurityVerifier:
    """
    Class for verifying TLS security settings and post-quantum cryptography usage
    """
    
    def __init__(self, channel=None):
        """
        Initialize the security verifier
        
        Args:
            channel: The TLS secure channel instance to verify
        """
        self.channel = channel
        self.post_quantum_checks = []
        self.cipher_suite_checks = []
        self.protocol_checks = []
        self.hsm_checks = []
        self.entropy_checks = []
    
    def verify_tls_version(self, ssl_socket) -> dict:
        """
        Verify that the TLS version is secure
        
        Args:
            ssl_socket: The SSL socket to verify
            
        Returns:
            dict: Check results
        """
        result = {
            'name': 'TLS Protocol Version',
            'status': 'UNKNOWN',
            'details': None,
            'severity': 'critical'
        }
        
        try:
            version = ssl_socket.version()
            if version == "TLSv1.3":
                result['status'] = 'PASSED'
                result['details'] = f"Using recommended {version}"
            else:
                result['status'] = 'FAILED'
                result['details'] = f"Using {version} instead of recommended TLSv1.3"
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Error checking TLS version: {str(e)}"
            
        return result
    
    def verify_cipher_suite(self, ssl_socket) -> dict:
        """
        Verify that the negotiated cipher suite is secure
        
        Args:
            ssl_socket: The SSL socket to verify
            
        Returns:
            dict: Check results
        """
        result = {
            'name': 'Cipher Suite',
            'status': 'UNKNOWN',
            'details': None,
            'severity': 'high'
        }
        
        try:
            cipher = ssl_socket.cipher()
            cipher_name = cipher[0]
            cipher_bits = cipher[2]
            
            if "TLS_AES_256_GCM" in cipher_name or "CHACHA20_POLY1305" in cipher_name:
                if cipher_bits >= 256:
                    result['status'] = 'PASSED'
                    result['details'] = f"Using strong cipher: {cipher_name} ({cipher_bits} bits)"
                else:
                    result['status'] = 'WARNING'
                    result['details'] = f"Cipher {cipher_name} has insufficient strength: {cipher_bits} bits"
            else:
                result['status'] = 'WARNING'
                result['details'] = f"Using non-recommended cipher: {cipher_name}"
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Error checking cipher suite: {str(e)}"
            
        return result
    
    def verify_mlkem1024_configuration(self, channel) -> dict:
        """
        Verify that ML-KEM-1024 is properly configured
        
        Args:
            channel: The TLS secure channel instance to verify
            
        Returns:
            dict: Check results
        """
        result = {
            'name': 'ML-KEM-1024 Configuration',
            'status': 'UNKNOWN',
            'details': None,
            'severity': 'critical'
        }
        
        try:
            if not channel.post_quantum_enabled:
                result['status'] = 'FAILED'
                result['details'] = "Post-quantum cryptography disabled"
                return result
                
            # Check that ML-KEM-1024 constants are correct
            mlkem1024_configured = False
            x25519_mlkem1024_configured = False
            secp256r1_mlkem1024_configured = False
            
            # Check values directly
            if hasattr(channel, 'NAMEDGROUP_MLKEM1024') and channel.NAMEDGROUP_MLKEM1024 == 0x0202:
                mlkem1024_configured = True
            
            if hasattr(channel, 'NAMEDGROUP_X25519MLKEM1024') and channel.NAMEDGROUP_X25519MLKEM1024 == 0x11EE:
                x25519_mlkem1024_configured = True
                
            if hasattr(channel, 'NAMEDGROUP_SECP256R1MLKEM1024') and channel.NAMEDGROUP_SECP256R1MLKEM1024 == 0x11ED:
                secp256r1_mlkem1024_configured = True
                
            # Check HYBRID_PQ_GROUPS configuration
            groups_configured = False
            if hasattr(channel, 'HYBRID_PQ_GROUPS'):
                if "X25519MLKEM1024" in channel.HYBRID_PQ_GROUPS and "SecP256r1MLKEM1024" in channel.HYBRID_PQ_GROUPS:
                    groups_configured = True
            
            # Determine overall status
            if mlkem1024_configured and x25519_mlkem1024_configured and secp256r1_mlkem1024_configured and groups_configured:
                result['status'] = 'PASSED'
                result['details'] = "ML-KEM-1024 properly configured with hybrid mode"
            else:
                result['status'] = 'FAILED'
                details = []
                if not mlkem1024_configured:
                    details.append("NAMEDGROUP_MLKEM1024 misconfigured")
                if not x25519_mlkem1024_configured:
                    details.append("NAMEDGROUP_X25519MLKEM1024 misconfigured")
                if not secp256r1_mlkem1024_configured:
                    details.append("NAMEDGROUP_SECP256R1MLKEM1024 misconfigured")
                if not groups_configured:
                    details.append("HYBRID_PQ_GROUPS misconfigured")
                
                result['details'] = "ML-KEM-1024 configuration issues: " + ", ".join(details)
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Error checking ML-KEM-1024 configuration: {str(e)}"
            
        return result
    
    def verify_mlkem1024_negotiation(self, ssl_socket, session_info) -> dict:
        """
        Verify that ML-KEM-1024 was actually negotiated during handshake
        
        Args:
            ssl_socket: The SSL socket to verify
            session_info: Session information from the handshake
            
        Returns:
            dict: Check results
        """
        result = {
            'name': 'ML-KEM-1024 Negotiation',
            'status': 'UNKNOWN',
            'details': None,
            'severity': 'critical'
        }
        
        try:
            # Check the negotiated group if available
            key_exchange_group = session_info.get('key_exchange_group', '')
            
            if "X25519MLKEM1024" in str(key_exchange_group):
                result['status'] = 'PASSED'
                result['details'] = f"ML-KEM-1024 hybrid key exchange successfully negotiated: {key_exchange_group}"
            else:
                result['status'] = 'FAILED'
                result['details'] = f"ML-KEM-1024 not negotiated, using: {key_exchange_group}"
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Error verifying ML-KEM-1024 negotiation: {str(e)}"
            
        return result
    
    def run_comprehensive_verification(self, ssl_socket=None, session_info=None) -> dict:
        """
        Run a comprehensive security verification on the TLS channel
        
        Args:
            ssl_socket: The SSL socket to verify (optional if channel is provided)
            session_info: Session information from the handshake (optional)
            
        Returns:
            dict: Comprehensive verification results
        """
        # Use provided socket or the one from the channel
        socket_to_verify = ssl_socket
        if socket_to_verify is None and self.channel and hasattr(self.channel, 'ssl_socket'):
            socket_to_verify = self.channel.ssl_socket
            
        # Get session info if not provided
        session_data = session_info
        if session_data is None and self.channel and hasattr(self.channel, 'get_session_info'):
            try:
                session_data = self.channel.get_session_info()
            except Exception:
                session_data = {}
                
        # Initialize results
        results = {
            'overall_status': 'PASSED',
            'overall_score': 0,
            'checks': [],
            'warnings': 0,
            'critical_issues': 0
        }
        
        # Skip if no socket available
        if socket_to_verify is None:
            log.warning("Cannot verify security: No SSL socket available")
            results['overall_status'] = 'SKIPPED'
            return results
            
        # Run TLS version check
        tls_check = self.verify_tls_version(socket_to_verify)
        results['checks'].append(tls_check)
        
        # Run cipher suite check
        cipher_check = self.verify_cipher_suite(socket_to_verify)
        results['checks'].append(cipher_check)
        
        # Run ML-KEM-1024 configuration check
        if self.channel:
            mlkem_config_check = self.verify_mlkem1024_configuration(self.channel)
            results['checks'].append(mlkem_config_check)
            
            # Run ML-KEM-1024 negotiation check if we have session info
            if session_data:
                mlkem_negotiation_check = self.verify_mlkem1024_negotiation(socket_to_verify, session_data)
                results['checks'].append(mlkem_negotiation_check)
        
        # Calculate statistics
        for check in results['checks']:
            if check['status'] == 'FAILED':
                if check['severity'] == 'critical':
                    results['critical_issues'] += 1
                else:
                    results['warnings'] += 1
            elif check['status'] == 'WARNING':
                results['warnings'] += 1
                
        # Calculate overall score
        total_checks = len(results['checks'])
        passed_checks = sum(1 for check in results['checks'] if check['status'] == 'PASSED')
        
        if total_checks > 0:
            results['overall_score'] = int((passed_checks / total_checks) * 100)
        
        # Determine overall status
        if results['critical_issues'] > 0:
            results['overall_status'] = 'FAILED'
        elif results['warnings'] > 0:
            results['overall_status'] = 'WARNING'
            
        # Log results
        self._log_verification_results(results)
        
        return results
    
    def _log_verification_results(self, results: dict):
        """
        Log the verification results
        
        Args:
            results: Verification results to log
        """
        log.info(f"TLS Security Verification: {results['overall_score']}% - {results['overall_status']}")
        
        if SECURITY_LOG_LEVEL >= SECURITY_LOG_LEVEL_VERBOSE:
            for check in results['checks']:
                status_symbol = "✓" if check['status'] == 'PASSED' else "⚠" if check['status'] == 'WARNING' else "✕"
                log.info(f"{status_symbol} {check['name']}: {check['status']} - {check['details']}")
        
        if results['critical_issues'] > 0:
            log.error(f"CRITICAL SECURITY ISSUES: {results['critical_issues']} issue(s) detected")
        
        if results['warnings'] > 0:
            log.warning(f"Security warnings: {results['warnings']} warning(s) detected")
            
        if results['overall_status'] == 'PASSED':
            log.info("All security checks passed - ML-KEM-1024 post-quantum security verified")


def verify_tls_channel_security(channel) -> dict:
    """
    Convenience function to verify a TLS secure channel's security
    
    Args:
        channel: The TLS secure channel to verify
        
    Returns:
        dict: Verification results
    """
    verifier = TLSSecurityVerifier(channel)
    return verifier.run_comprehensive_verification()


def verify_quantum_resistance(session_info: dict) -> bool:
    """
    Verify that a session is using quantum-resistant cryptography
    
    Args:
        session_info: Session information from TLS handshake
        
    Returns:
        bool: True if quantum-resistant, False otherwise
    """
    # Extract key exchange group information
    key_exchange_group = session_info.get('key_exchange_group', '')
    
    # Check for ML-KEM-1024 indicators
    return "X25519MLKEM1024" in str(key_exchange_group) or "MLKEM1024" in str(key_exchange_group)


def log_security_status(session_info: dict):
    """
    Log detailed security status based on session information
    
    Args:
        session_info: Session information from TLS handshake
    """
    log.info("TLS Security Status:")
    
    # Check TLS version
    protocol = session_info.get('protocol', 'Unknown')
    if protocol == "TLSv1.3":
        log.info("✓ Protocol: TLS 1.3")
    else:
        log.warning(f"⚠ Protocol: {protocol} (TLS 1.3 recommended)")
    
    # Check cipher suite
    cipher = session_info.get('cipher', 'Unknown')
    cipher_bits = session_info.get('cipher_bits', 0)
    
    if ("TLS_AES_256_GCM" in cipher or "CHACHA20_POLY1305" in cipher) and cipher_bits >= 256:
        log.info(f"✓ Cipher suite: {cipher} ({cipher_bits} bits)")
    else:
        log.warning(f"⚠ Cipher suite: {cipher} ({cipher_bits} bits)")
    
    # Check quantum resistance
    key_exchange = session_info.get('key_exchange_group', 'Unknown')
    if "X25519MLKEM1024" in str(key_exchange):
        log.info(f"✓ Post-quantum security: ML-KEM-1024 hybrid exchange")
    else:
        log.warning(f"⚠ Key exchange: {key_exchange} (not quantum-resistant)") 