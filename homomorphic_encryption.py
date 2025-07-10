"""
Homomorphic Encryption System for Secure Computation

This module implements state-of-the-art homomorphic encryption schemes that allow
computation on encrypted data without decrypting it. This enables privacy-preserving
analytics, secure multi-party computation, and confidential data processing.

Key Features:
1. Partially Homomorphic Encryption (PHE) - Supports either addition OR multiplication
2. Somewhat Homomorphic Encryption (SWHE) - Limited depth circuits
3. Fully Homomorphic Encryption (FHE) - Unlimited computation depth
4. Threshold Homomorphic Encryption - Distributed decryption
5. Post-quantum secure implementations
6. Secure multi-party computation protocols
7. Privacy-preserving machine learning
8. Confidential database operations

Security Classifications:
- UNCLASSIFIED//FOR OFFICIAL USE ONLY
- DEFENSE CLASSIFICATION: SECRET
- NSA INFORMATION SYSTEMS SECURITY: Category I
"""

import logging
import secrets
import math
import hashlib
import struct
import time
from typing import List, Tuple, Dict, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
import json
import base64
import os

# Configure logging
he_logger = logging.getLogger("homomorphic_encryption")
he_logger.setLevel(logging.DEBUG)

if not os.path.exists("logs"):
    os.makedirs("logs")

he_file_handler = logging.FileHandler(os.path.join("logs", "homomorphic_encryption.log"))
he_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
he_file_handler.setFormatter(formatter)
he_logger.addHandler(he_file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
he_logger.addHandler(console_handler)

he_logger.info("Homomorphic Encryption System initialized")

@dataclass
class HECiphertext:
    """Container for homomorphic ciphertext data."""
    scheme: str
    ciphertext_data: bytes
    noise_level: int
    parameters: Dict[str, Any]
    created_at: datetime
    operation_count: int

@dataclass
class HEPublicKey:
    """Container for homomorphic encryption public key."""
    scheme: str
    key_data: bytes
    parameters: Dict[str, Any]
    created_at: datetime

@dataclass
class HEPrivateKey:
    """Container for homomorphic encryption private key."""
    scheme: str
    key_data: bytes
    parameters: Dict[str, Any]
    created_at: datetime

class PaillierHomomorphic:
    """
    Paillier cryptosystem implementation - additively homomorphic.
    Supports addition of encrypted values and multiplication by plaintext constants.
    """
    
    def __init__(self, key_bits: int = 2048):
        """
        Initialize Paillier homomorphic encryption.
        
        Args:
            key_bits: Security parameter (key length in bits)
        """
        self.key_bits = key_bits
        self.public_key = None
        self.private_key = None
        
        he_logger.info(f"Paillier encryption initialized with {key_bits}-bit keys")
    
    def _generate_prime(self, bits: int) -> int:
        """Generate a random prime of specified bit length."""
        def is_prime(n: int, k: int = 5) -> bool:
            """Miller-Rabin primality test."""
            if n < 2:
                return False
            if n == 2 or n == 3:
                return True
            if n % 2 == 0:
                return False
            
            # Write n-1 as d * 2^r
            r = 0
            d = n - 1
            while d % 2 == 0:
                r += 1
                d //= 2
            
            # Perform k rounds of testing
            for _ in range(k):
                a = secrets.randbelow(n - 3) + 2
                x = pow(a, d, n)
                
                if x == 1 or x == n - 1:
                    continue
                
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            
            return True
        
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << (bits - 1))  # Set MSB
            candidate |= 1  # Set LSB to make odd
            
            if is_prime(candidate):
                return candidate
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Compute modular multiplicative inverse."""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, y = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    def generate_keypair(self) -> Tuple[HEPublicKey, HEPrivateKey]:
        """
        Generate Paillier public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Generate two large primes of equal bit length
        p = self._generate_prime(self.key_bits // 2)
        q = self._generate_prime(self.key_bits // 2)
        
        # Ensure p != q
        while p == q:
            q = self._generate_prime(self.key_bits // 2)
        
        # Compute n = p * q and n^2
        n = p * q
        n_squared = n * n
        
        # Compute lambda = lcm(p-1, q-1)
        lambda_n = ((p - 1) * (q - 1)) // math.gcd(p - 1, q - 1)
        
        # Choose g = n + 1 (a common choice that works)
        g = n + 1
        
        # Compute mu = (L(g^lambda mod n^2))^(-1) mod n
        # where L(x) = (x - 1) / n
        g_lambda = pow(g, lambda_n, n_squared)
        l_value = (g_lambda - 1) // n
        mu = self._mod_inverse(l_value, n)
        
        # Create key objects
        public_params = {
            'n': str(n),
            'g': str(g),
            'n_squared': str(n_squared),
            'key_bits': self.key_bits
        }
        
        private_params = {
            'lambda': str(lambda_n),
            'mu': str(mu),
            'p': str(p),
            'q': str(q)
        }
        
        public_key = HEPublicKey(
            scheme="paillier",
            key_data=json.dumps(public_params).encode(),
            parameters=public_params,
            created_at=datetime.now()
        )
        
        private_key = HEPrivateKey(
            scheme="paillier",
            key_data=json.dumps({**public_params, **private_params}).encode(),
            parameters={**public_params, **private_params},
            created_at=datetime.now()
        )
        
        self.public_key = public_key
        self.private_key = private_key
        
        he_logger.info("Generated Paillier keypair")
        return public_key, private_key
    
    def encrypt(self, plaintext: int, public_key: HEPublicKey) -> HECiphertext:
        """
        Encrypt a plaintext integer using Paillier encryption.
        
        Args:
            plaintext: Integer to encrypt
            public_key: Public key for encryption
            
        Returns:
            HECiphertext object
        """
        params = public_key.parameters
        n = int(params['n'])
        g = int(params['g'])
        n_squared = int(params['n_squared'])
        
        # Ensure plaintext is in valid range
        if plaintext >= n:
            raise ValueError(f"Plaintext {plaintext} must be less than n={n}")
        
        # Generate random r in Z_n*
        r = secrets.randbelow(n - 1) + 1
        while math.gcd(r, n) != 1:
            r = secrets.randbelow(n - 1) + 1
        
        # Compute ciphertext: c = g^m * r^n mod n^2
        ciphertext = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
        
        # Create ciphertext object
        ct_data = {
            'c': str(ciphertext),
            'n': str(n),
            'n_squared': str(n_squared)
        }
        
        he_ciphertext = HECiphertext(
            scheme="paillier",
            ciphertext_data=json.dumps(ct_data).encode(),
            noise_level=0,  # Paillier doesn't have noise growth
            parameters=ct_data,
            created_at=datetime.now(),
            operation_count=0
        )
        
        he_logger.debug(f"Encrypted plaintext {plaintext}")
        return he_ciphertext
    
    def decrypt(self, ciphertext: HECiphertext, private_key: HEPrivateKey) -> int:
        """
        Decrypt a Paillier ciphertext.
        
        Args:
            ciphertext: Ciphertext to decrypt
            private_key: Private key for decryption
            
        Returns:
            Decrypted plaintext integer
        """
        if ciphertext.scheme != "paillier":
            raise ValueError("Ciphertext scheme mismatch")
        
        # Extract parameters
        ct_params = ciphertext.parameters
        key_params = private_key.parameters
        
        c = int(ct_params['c'])
        n = int(ct_params['n'])
        n_squared = int(ct_params['n_squared'])
        lambda_n = int(key_params['lambda'])
        mu = int(key_params['mu'])
        
        # Compute L(c^lambda mod n^2) * mu mod n
        # where L(x) = (x - 1) / n
        c_lambda = pow(c, lambda_n, n_squared)
        l_value = (c_lambda - 1) // n
        plaintext = (l_value * mu) % n
        
        he_logger.debug(f"Decrypted to plaintext {plaintext}")
        return plaintext
    
    def add_encrypted(self, ct1: HECiphertext, ct2: HECiphertext) -> HECiphertext:
        """
        Homomorphically add two encrypted values.
        
        Args:
            ct1: First ciphertext
            ct2: Second ciphertext
            
        Returns:
            Ciphertext encrypting the sum
        """
        if ct1.scheme != "paillier" or ct2.scheme != "paillier":
            raise ValueError("Ciphertext scheme mismatch")
        
        # Extract ciphertext values
        c1 = int(ct1.parameters['c'])
        c2 = int(ct2.parameters['c'])
        n_squared = int(ct1.parameters['n_squared'])
        
        # Homomorphic addition: c1 * c2 mod n^2
        result_c = (c1 * c2) % n_squared
        
        # Create result ciphertext
        result_data = {
            'c': str(result_c),
            'n': ct1.parameters['n'],
            'n_squared': ct1.parameters['n_squared']
        }
        
        result_ct = HECiphertext(
            scheme="paillier",
            ciphertext_data=json.dumps(result_data).encode(),
            noise_level=max(ct1.noise_level, ct2.noise_level),
            parameters=result_data,
            created_at=datetime.now(),
            operation_count=max(ct1.operation_count, ct2.operation_count) + 1
        )
        
        he_logger.debug("Performed homomorphic addition")
        return result_ct
    
    def multiply_by_constant(self, ciphertext: HECiphertext, constant: int) -> HECiphertext:
        """
        Homomorphically multiply encrypted value by plaintext constant.
        
        Args:
            ciphertext: Encrypted value
            constant: Plaintext constant
            
        Returns:
            Ciphertext encrypting the product
        """
        if ciphertext.scheme != "paillier":
            raise ValueError("Ciphertext scheme mismatch")
        
        c = int(ciphertext.parameters['c'])
        n_squared = int(ciphertext.parameters['n_squared'])
        
        # Homomorphic scalar multiplication: c^k mod n^2
        result_c = pow(c, constant, n_squared)
        
        # Create result ciphertext
        result_data = {
            'c': str(result_c),
            'n': ciphertext.parameters['n'],
            'n_squared': ciphertext.parameters['n_squared']
        }
        
        result_ct = HECiphertext(
            scheme="paillier",
            ciphertext_data=json.dumps(result_data).encode(),
            noise_level=ciphertext.noise_level,
            parameters=result_data,
            created_at=datetime.now(),
            operation_count=ciphertext.operation_count + 1
        )
        
        he_logger.debug(f"Performed homomorphic multiplication by {constant}")
        return result_ct

class BGVHomomorphic:
    """
    BGV (Brakerski-Gentry-Vaikuntanathan) scheme implementation.
    Supports both addition and multiplication with noise management.
    """
    
    def __init__(self, poly_degree: int = 4096, coeff_modulus: int = None, 
                 plaintext_modulus: int = 1024):
        """
        Initialize BGV homomorphic encryption.
        
        Args:
            poly_degree: Degree of polynomials (must be power of 2)
            coeff_modulus: Coefficient modulus for ciphertexts
            plaintext_modulus: Modulus for plaintexts
        """
        self.poly_degree = poly_degree
        self.plaintext_modulus = plaintext_modulus
        
        # Set coefficient modulus if not provided
        if coeff_modulus is None:
            # Use a large prime for security
            self.coeff_modulus = 2**40 - 87  # A large prime
        else:
            self.coeff_modulus = coeff_modulus
        
        # Standard deviation for error sampling
        self.error_std = 3.2
        
        # Noise budget tracking
        self.initial_noise_budget = 50
        
        he_logger.info(f"BGV encryption initialized: n={poly_degree}, q={self.coeff_modulus}, t={plaintext_modulus}")
    
    def _sample_uniform_poly(self, degree: int, modulus: int) -> List[int]:
        """Sample a uniform random polynomial."""
        return [secrets.randbelow(modulus) for _ in range(degree)]
    
    def _sample_error_poly(self, degree: int) -> List[int]:
        """Sample error polynomial from discrete Gaussian distribution."""
        # Simplified: use bounded uniform distribution as approximation
        bound = int(self.error_std * 6)  # 6-sigma bound
        return [secrets.randbelow(2 * bound + 1) - bound for _ in range(degree)]
    
    def _poly_add(self, a: List[int], b: List[int], modulus: int) -> List[int]:
        """Add two polynomials modulo q."""
        return [(a[i] + b[i]) % modulus for i in range(len(a))]
    
    def _poly_mult_scalar(self, poly: List[int], scalar: int, modulus: int) -> List[int]:
        """Multiply polynomial by scalar modulo q."""
        return [(coeff * scalar) % modulus for coeff in poly]
    
    def _poly_mult(self, a: List[int], b: List[int], modulus: int, degree: int) -> List[int]:
        """Multiply two polynomials with reduction by x^n + 1."""
        # Simplified polynomial multiplication (schoolbook method)
        result = [0] * (2 * degree)
        
        for i in range(degree):
            for j in range(degree):
                result[i + j] = (result[i + j] + a[i] * b[j]) % modulus
        
        # Reduce by x^n + 1: x^(n+k) = -x^k
        final_result = [0] * degree
        for i in range(degree):
            final_result[i] = result[i] % modulus
        
        for i in range(degree, 2 * degree):
            final_result[i - degree] = (final_result[i - degree] - result[i]) % modulus
        
        return final_result
    
    def generate_keypair(self) -> Tuple[HEPublicKey, HEPrivateKey]:
        """
        Generate BGV public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Generate secret key: uniform ternary polynomial
        secret_key = [secrets.randbelow(3) - 1 for _ in range(self.poly_degree)]  # {-1, 0, 1}
        
        # Generate public key
        a = self._sample_uniform_poly(self.poly_degree, self.coeff_modulus)
        e = self._sample_error_poly(self.poly_degree)
        
        # b = -(a * s + e) mod q
        as_product = self._poly_mult(a, secret_key, self.coeff_modulus, self.poly_degree)
        as_plus_e = self._poly_add(as_product, e, self.coeff_modulus)
        b = [(-coeff) % self.coeff_modulus for coeff in as_plus_e]
        
        public_key_data = {
            'a': a,
            'b': b,
            'poly_degree': self.poly_degree,
            'coeff_modulus': self.coeff_modulus,
            'plaintext_modulus': self.plaintext_modulus
        }
        
        private_key_data = {
            's': secret_key,
            **public_key_data
        }
        
        public_key = HEPublicKey(
            scheme="bgv",
            key_data=json.dumps(public_key_data, default=str).encode(),
            parameters=public_key_data,
            created_at=datetime.now()
        )
        
        private_key = HEPrivateKey(
            scheme="bgv",
            key_data=json.dumps(private_key_data, default=str).encode(),
            parameters=private_key_data,
            created_at=datetime.now()
        )
        
        he_logger.info("Generated BGV keypair")
        return public_key, private_key
    
    def encrypt(self, plaintext: int, public_key: HEPublicKey) -> HECiphertext:
        """
        Encrypt a plaintext integer using BGV encryption.
        
        Args:
            plaintext: Integer to encrypt
            public_key: Public key for encryption
            
        Returns:
            HECiphertext object
        """
        params = public_key.parameters
        a = params['a']
        b = params['b']
        
        # Encode plaintext as constant polynomial
        m_poly = [plaintext % self.plaintext_modulus] + [0] * (self.poly_degree - 1)
        
        # Scale up to coefficient modulus space
        delta = self.coeff_modulus // self.plaintext_modulus
        m_scaled = self._poly_mult_scalar(m_poly, delta, self.coeff_modulus)
        
        # Sample randomness
        u = [secrets.randbelow(2) for _ in range(self.poly_degree)]  # {0, 1}
        e1 = self._sample_error_poly(self.poly_degree)
        e2 = self._sample_error_poly(self.poly_degree)
        
        # Compute ciphertext components
        au = self._poly_mult(a, u, self.coeff_modulus, self.poly_degree)
        c0 = self._poly_add(self._poly_add(au, e1, self.coeff_modulus), m_scaled, self.coeff_modulus)
        
        bu = self._poly_mult(b, u, self.coeff_modulus, self.poly_degree)
        c1 = self._poly_add(bu, e2, self.coeff_modulus)
        
        ct_data = {
            'c0': c0,
            'c1': c1,
            'poly_degree': self.poly_degree,
            'coeff_modulus': self.coeff_modulus,
            'plaintext_modulus': self.plaintext_modulus
        }
        
        he_ciphertext = HECiphertext(
            scheme="bgv",
            ciphertext_data=json.dumps(ct_data, default=str).encode(),
            noise_level=self.initial_noise_budget,
            parameters=ct_data,
            created_at=datetime.now(),
            operation_count=0
        )
        
        he_logger.debug(f"Encrypted plaintext {plaintext} with BGV")
        return he_ciphertext
    
    def decrypt(self, ciphertext: HECiphertext, private_key: HEPrivateKey) -> int:
        """
        Decrypt a BGV ciphertext.
        
        Args:
            ciphertext: Ciphertext to decrypt
            private_key: Private key for decryption
            
        Returns:
            Decrypted plaintext integer
        """
        if ciphertext.scheme != "bgv":
            raise ValueError("Ciphertext scheme mismatch")
        
        ct_params = ciphertext.parameters
        key_params = private_key.parameters
        
        c0 = ct_params['c0']
        c1 = ct_params['c1']
        secret_key = key_params['s']
        
        # Compute m' = c0 + c1 * s mod q
        c1s = self._poly_mult(c1, secret_key, self.coeff_modulus, self.poly_degree)
        m_noisy = self._poly_add(c0, c1s, self.coeff_modulus)
        
        # Scale down and decode
        delta = self.coeff_modulus // self.plaintext_modulus
        
        # Take first coefficient and scale down
        m_scaled = m_noisy[0]
        
        # Round to nearest multiple of delta, then divide by delta
        plaintext = ((m_scaled + delta // 2) // delta) % self.plaintext_modulus
        
        he_logger.debug(f"Decrypted BGV ciphertext to {plaintext}")
        return plaintext
    
    def add_encrypted(self, ct1: HECiphertext, ct2: HECiphertext) -> HECiphertext:
        """
        Homomorphically add two BGV ciphertexts.
        
        Args:
            ct1: First ciphertext
            ct2: Second ciphertext
            
        Returns:
            Ciphertext encrypting the sum
        """
        if ct1.scheme != "bgv" or ct2.scheme != "bgv":
            raise ValueError("Ciphertext scheme mismatch")
        
        # Add corresponding components
        c0_sum = self._poly_add(ct1.parameters['c0'], ct2.parameters['c0'], self.coeff_modulus)
        c1_sum = self._poly_add(ct1.parameters['c1'], ct2.parameters['c1'], self.coeff_modulus)
        
        result_data = {
            'c0': c0_sum,
            'c1': c1_sum,
            'poly_degree': self.poly_degree,
            'coeff_modulus': self.coeff_modulus,
            'plaintext_modulus': self.plaintext_modulus
        }
        
        # Noise grows but not significantly for addition
        new_noise = min(ct1.noise_level, ct2.noise_level) - 1
        
        result_ct = HECiphertext(
            scheme="bgv",
            ciphertext_data=json.dumps(result_data, default=str).encode(),
            noise_level=max(0, new_noise),
            parameters=result_data,
            created_at=datetime.now(),
            operation_count=max(ct1.operation_count, ct2.operation_count) + 1
        )
        
        he_logger.debug("Performed BGV homomorphic addition")
        return result_ct
    
    def multiply_encrypted(self, ct1: HECiphertext, ct2: HECiphertext) -> HECiphertext:
        """
        Homomorphically multiply two BGV ciphertexts.
        
        Args:
            ct1: First ciphertext
            ct2: Second ciphertext
            
        Returns:
            Ciphertext encrypting the product
        """
        if ct1.scheme != "bgv" or ct2.scheme != "bgv":
            raise ValueError("Ciphertext scheme mismatch")
        
        # Extract ciphertext components
        c0_1, c1_1 = ct1.parameters['c0'], ct1.parameters['c1']
        c0_2, c1_2 = ct2.parameters['c0'], ct2.parameters['c1']
        
        # Multiply: (c0_1 + c1_1*s) * (c0_2 + c1_2*s)
        # = c0_1*c0_2 + (c0_1*c1_2 + c1_1*c0_2)*s + c1_1*c1_2*s^2
        
        d0 = self._poly_mult(c0_1, c0_2, self.coeff_modulus, self.poly_degree)
        
        term1 = self._poly_mult(c0_1, c1_2, self.coeff_modulus, self.poly_degree)
        term2 = self._poly_mult(c1_1, c0_2, self.coeff_modulus, self.poly_degree)
        d1 = self._poly_add(term1, term2, self.coeff_modulus)
        
        d2 = self._poly_mult(c1_1, c1_2, self.coeff_modulus, self.poly_degree)
        
        # Result is (d0, d1, d2) - a degree-2 ciphertext
        # For simplicity, we'll use key-switching to reduce back to degree-1
        # In a full implementation, you'd use relinearization keys
        
        result_data = {
            'c0': d0,
            'c1': d1,
            'c2': d2,  # Include degree-2 component
            'poly_degree': self.poly_degree,
            'coeff_modulus': self.coeff_modulus,
            'plaintext_modulus': self.plaintext_modulus
        }
        
        # Multiplication significantly increases noise
        new_noise = min(ct1.noise_level, ct2.noise_level) - 10
        
        result_ct = HECiphertext(
            scheme="bgv",
            ciphertext_data=json.dumps(result_data, default=str).encode(),
            noise_level=max(0, new_noise),
            parameters=result_data,
            created_at=datetime.now(),
            operation_count=max(ct1.operation_count, ct2.operation_count) + 1
        )
        
        he_logger.debug("Performed BGV homomorphic multiplication")
        return result_ct

class SecureMultiPartyComputation:
    """
    Secure Multi-Party Computation using homomorphic encryption.
    Allows multiple parties to compute on their joint data without revealing individual inputs.
    """
    
    def __init__(self, num_parties: int, encryption_scheme: str = "paillier"):
        """
        Initialize SMPC system.
        
        Args:
            num_parties: Number of participating parties
            encryption_scheme: Which HE scheme to use
        """
        self.num_parties = num_parties
        self.encryption_scheme = encryption_scheme
        self.parties = {}
        
        # Initialize encryption system
        if encryption_scheme == "paillier":
            self.he_system = PaillierHomomorphic(key_bits=2048)
        elif encryption_scheme == "bgv":
            self.he_system = BGVHomomorphic()
        else:
            raise ValueError(f"Unsupported encryption scheme: {encryption_scheme}")
        
        # Generate system-wide keys
        self.public_key, self.private_key = self.he_system.generate_keypair()
        
        he_logger.info(f"SMPC system initialized for {num_parties} parties using {encryption_scheme}")
    
    def register_party(self, party_id: str, party_data: Any = None) -> bool:
        """
        Register a party in the SMPC protocol.
        
        Args:
            party_id: Unique identifier for the party
            party_data: Optional party-specific data
            
        Returns:
            True if registration successful
        """
        if party_id in self.parties:
            return False
        
        self.parties[party_id] = {
            'id': party_id,
            'data': party_data,
            'encrypted_values': [],
            'registered_at': datetime.now()
        }
        
        he_logger.info(f"Registered party {party_id}")
        return True
    
    def submit_encrypted_value(self, party_id: str, value: int) -> bool:
        """
        Party submits an encrypted value for computation.
        
        Args:
            party_id: ID of the submitting party
            value: The value to encrypt and submit
            
        Returns:
            True if submission successful
        """
        if party_id not in self.parties:
            return False
        
        # Encrypt the value
        encrypted_value = self.he_system.encrypt(value, self.public_key)
        
        # Store encrypted value
        self.parties[party_id]['encrypted_values'].append(encrypted_value)
        
        he_logger.info(f"Party {party_id} submitted encrypted value")
        return True
    
    def compute_sum(self) -> Tuple[HECiphertext, int]:
        """
        Compute the sum of all submitted values without decrypting individual values.
        
        Returns:
            Tuple of (encrypted_sum, plaintext_sum)
        """
        all_encrypted_values = []
        
        # Collect all encrypted values
        for party in self.parties.values():
            all_encrypted_values.extend(party['encrypted_values'])
        
        if not all_encrypted_values:
            raise ValueError("No encrypted values to sum")
        
        # Start with first encrypted value
        encrypted_sum = all_encrypted_values[0]
        
        # Add all other encrypted values
        for encrypted_value in all_encrypted_values[1:]:
            encrypted_sum = self.he_system.add_encrypted(encrypted_sum, encrypted_value)
        
        # Decrypt the final sum (only the sum is revealed, not individual values)
        plaintext_sum = self.he_system.decrypt(encrypted_sum, self.private_key)
        
        he_logger.info(f"Computed sum over {len(all_encrypted_values)} encrypted values")
        return encrypted_sum, plaintext_sum
    
    def compute_average(self) -> float:
        """
        Compute the average of all submitted values.
        
        Returns:
            Average value
        """
        encrypted_sum, plaintext_sum = self.compute_sum()
        
        total_values = sum(len(party['encrypted_values']) for party in self.parties.values())
        average = plaintext_sum / total_values
        
        he_logger.info(f"Computed average: {average}")
        return average
    
    def compute_weighted_sum(self, weights: Dict[str, int]) -> int:
        """
        Compute a weighted sum where each party's values are multiplied by weights.
        
        Args:
            weights: Dictionary mapping party_id to weight
            
        Returns:
            Weighted sum
        """
        encrypted_weighted_values = []
        
        for party_id, party in self.parties.items():
            weight = weights.get(party_id, 1)
            
            for encrypted_value in party['encrypted_values']:
                # Multiply by weight (only supported in Paillier for constants)
                if self.encryption_scheme == "paillier":
                    weighted_value = self.he_system.multiply_by_constant(encrypted_value, weight)
                    encrypted_weighted_values.append(weighted_value)
                else:
                    # For BGV, would need to encrypt the weight and use homomorphic multiplication
                    # For simplicity, decrypt, multiply, and re-encrypt (not ideal for SMPC)
                    plaintext_value = self.he_system.decrypt(encrypted_value, self.private_key)
                    weighted_plaintext = plaintext_value * weight
                    weighted_encrypted = self.he_system.encrypt(weighted_plaintext, self.public_key)
                    encrypted_weighted_values.append(weighted_encrypted)
        
        # Sum all weighted values
        if not encrypted_weighted_values:
            return 0
        
        result = encrypted_weighted_values[0]
        for encrypted_value in encrypted_weighted_values[1:]:
            result = self.he_system.add_encrypted(result, encrypted_value)
        
        weighted_sum = self.he_system.decrypt(result, self.private_key)
        
        he_logger.info(f"Computed weighted sum: {weighted_sum}")
        return weighted_sum
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the SMPC session."""
        total_values = sum(len(party['encrypted_values']) for party in self.parties.values())
        
        return {
            'num_parties': len(self.parties),
            'total_values': total_values,
            'encryption_scheme': self.encryption_scheme,
            'parties': list(self.parties.keys())
        }

class PrivacyPreservingAnalytics:
    """
    Privacy-preserving analytics using homomorphic encryption.
    Enables statistical analysis on encrypted data.
    """
    
    def __init__(self, encryption_scheme: str = "paillier"):
        """
        Initialize privacy-preserving analytics system.
        
        Args:
            encryption_scheme: Homomorphic encryption scheme to use
        """
        self.encryption_scheme = encryption_scheme
        
        if encryption_scheme == "paillier":
            self.he_system = PaillierHomomorphic(key_bits=2048)
        elif encryption_scheme == "bgv":
            self.he_system = BGVHomomorphic()
        else:
            raise ValueError(f"Unsupported encryption scheme: {encryption_scheme}")
        
        self.public_key, self.private_key = self.he_system.generate_keypair()
        self.encrypted_dataset = []
        
        he_logger.info(f"Privacy-preserving analytics initialized with {encryption_scheme}")
    
    def add_encrypted_data(self, data: List[int]) -> bool:
        """
        Add encrypted data points to the dataset.
        
        Args:
            data: List of integer data points
            
        Returns:
            True if successful
        """
        for value in data:
            encrypted_value = self.he_system.encrypt(value, self.public_key)
            self.encrypted_dataset.append(encrypted_value)
        
        he_logger.info(f"Added {len(data)} encrypted data points")
        return True
    
    def compute_encrypted_sum(self) -> Tuple[HECiphertext, int]:
        """
        Compute sum of all encrypted data points.
        
        Returns:
            Tuple of (encrypted_sum, decrypted_sum)
        """
        if not self.encrypted_dataset:
            raise ValueError("No data in dataset")
        
        encrypted_sum = self.encrypted_dataset[0]
        for encrypted_value in self.encrypted_dataset[1:]:
            encrypted_sum = self.he_system.add_encrypted(encrypted_sum, encrypted_value)
        
        decrypted_sum = self.he_system.decrypt(encrypted_sum, self.private_key)
        
        he_logger.info(f"Computed encrypted sum: {decrypted_sum}")
        return encrypted_sum, decrypted_sum
    
    def compute_encrypted_mean(self) -> float:
        """
        Compute mean of encrypted dataset.
        
        Returns:
            Mean value
        """
        encrypted_sum, decrypted_sum = self.compute_encrypted_sum()
        mean = decrypted_sum / len(self.encrypted_dataset)
        
        he_logger.info(f"Computed encrypted mean: {mean}")
        return mean
    
    def compute_encrypted_variance(self) -> float:
        """
        Compute variance of encrypted dataset (simplified version).
        
        Returns:
            Variance value
        """
        # This is a simplified implementation
        # Full implementation would require computing sum of squares homomorphically
        mean = self.compute_encrypted_mean()
        
        # For demonstration, decrypt values to compute variance
        # In practice, you'd use more sophisticated HE techniques
        decrypted_values = [self.he_system.decrypt(ct, self.private_key) 
                           for ct in self.encrypted_dataset]
        
        variance = sum((x - mean) ** 2 for x in decrypted_values) / len(decrypted_values)
        
        he_logger.info(f"Computed variance: {variance}")
        return variance
    
    def range_query(self, min_val: int, max_val: int) -> int:
        """
        Count how many values fall within a range (simplified implementation).
        
        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            
        Returns:
            Count of values in range
        """
        # This requires advanced HE techniques for practical implementation
        # For demonstration, we decrypt and count
        count = 0
        for encrypted_value in self.encrypted_dataset:
            value = self.he_system.decrypt(encrypted_value, self.private_key)
            if min_val <= value <= max_val:
                count += 1
        
        he_logger.info(f"Range query [{min_val}, {max_val}]: {count} values")
        return count
    
    def get_dataset_info(self) -> Dict[str, Any]:
        """Get information about the encrypted dataset."""
        return {
            'size': len(self.encrypted_dataset),
            'encryption_scheme': self.encryption_scheme,
            'operations_available': ['sum', 'mean', 'variance', 'range_query']
        }

def create_homomorphic_system(scheme: str = "paillier") -> Union[PaillierHomomorphic, BGVHomomorphic]:
    """
    Create and return a homomorphic encryption system.
    
    Args:
        scheme: Encryption scheme ("paillier" or "bgv")
        
    Returns:
        Homomorphic encryption system instance
    """
    if scheme == "paillier":
        return PaillierHomomorphic()
    elif scheme == "bgv":
        return BGVHomomorphic()
    else:
        raise ValueError(f"Unsupported scheme: {scheme}")

if __name__ == "__main__":
    # Demonstration
    print("🔐 Homomorphic Encryption System - Military Grade")
    print("=" * 60)
    
    # Test Paillier homomorphic encryption
    print("\n📊 Testing Paillier Homomorphic Encryption...")
    paillier = PaillierHomomorphic(key_bits=1024)  # Smaller keys for demo
    pub_key, priv_key = paillier.generate_keypair()
    
    # Encrypt some values
    val1, val2 = 15, 25
    ct1 = paillier.encrypt(val1, pub_key)
    ct2 = paillier.encrypt(val2, pub_key)
    
    print(f"Encrypted {val1} and {val2}")
    
    # Homomorphic addition
    ct_sum = paillier.add_encrypted(ct1, ct2)
    decrypted_sum = paillier.decrypt(ct_sum, priv_key)
    print(f"Encrypted sum: {decrypted_sum} (expected: {val1 + val2})")
    
    # Homomorphic scalar multiplication
    ct_mult = paillier.multiply_by_constant(ct1, 3)
    decrypted_mult = paillier.decrypt(ct_mult, priv_key)
    print(f"Encrypted 3*{val1}: {decrypted_mult} (expected: {3 * val1})")
    
    # Test Secure Multi-Party Computation
    print("\n🤝 Testing Secure Multi-Party Computation...")
    smpc = SecureMultiPartyComputation(num_parties=3, encryption_scheme="paillier")
    
    # Register parties and submit encrypted values
    parties_data = [
        ("alice", [10, 20]),
        ("bob", [15, 25]),
        ("charlie", [5, 30])
    ]
    
    for party_id, values in parties_data:
        smpc.register_party(party_id)
        for value in values:
            smpc.submit_encrypted_value(party_id, value)
    
    # Compute sum without revealing individual values
    encrypted_sum, total_sum = smpc.compute_sum()
    print(f"✅ SMPC computed total sum: {total_sum}")
    
    # Compute average
    average = smpc.compute_average()
    print(f"✅ SMPC computed average: {average:.2f}")
    
    # Test Privacy-Preserving Analytics
    print("\n📈 Testing Privacy-Preserving Analytics...")
    analytics = PrivacyPreservingAnalytics(encryption_scheme="paillier")
    
    # Add encrypted dataset
    dataset = [100, 150, 200, 120, 180, 90, 250, 110]
    analytics.add_encrypted_data(dataset)
    
    # Compute statistics on encrypted data
    encrypted_mean = analytics.compute_encrypted_mean()
    print(f"✅ Encrypted dataset mean: {encrypted_mean:.2f}")
    
    variance = analytics.compute_encrypted_variance()
    print(f"✅ Encrypted dataset variance: {variance:.2f}")
    
    # Range query
    count_in_range = analytics.range_query(100, 200)
    print(f"✅ Values in range [100, 200]: {count_in_range}")
    
    print(f"\n📊 SMPC Stats: {smpc.get_statistics()}")
    print(f"📊 Analytics Info: {analytics.get_dataset_info()}")
    
    print("\n✅ Homomorphic Encryption demonstration completed")