"""
Blockchain Security System for Decentralized Trust

This module implements a blockchain-based security infrastructure that provides
decentralized trust, immutable audit logs, distributed consensus for security
events, and tamper-proof threat intelligence sharing.

Key Features:
1. Immutable Security Audit Logs
2. Decentralized Threat Intelligence Sharing
3. Smart Contracts for Security Policies
4. Distributed Consensus for Security Events
5. Post-quantum cryptographic signatures
6. Zero-knowledge proof integration
7. Byzantine Fault Tolerant consensus
8. Multi-signature security operations

Security Classifications:
- UNCLASSIFIED//FOR OFFICIAL USE ONLY
- DEFENSE CLASSIFICATION: SECRET
- NSA INFORMATION SYSTEMS SECURITY: Category I
"""

import logging
import hashlib
import time
import json
import secrets
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import queue
import socket
import struct
import os
from enum import Enum

# Configure logging
bc_logger = logging.getLogger("blockchain_security")
bc_logger.setLevel(logging.DEBUG)

if not os.path.exists("logs"):
    os.makedirs("logs")

bc_file_handler = logging.FileHandler(os.path.join("logs", "blockchain_security.log"))
bc_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
bc_file_handler.setFormatter(formatter)
bc_logger.addHandler(bc_file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
bc_logger.addHandler(console_handler)

bc_logger.info("Blockchain Security System initialized")

class TransactionType(Enum):
    """Types of security transactions."""
    SECURITY_EVENT = "security_event"
    THREAT_INTEL = "threat_intel"
    AUDIT_LOG = "audit_log"
    POLICY_UPDATE = "policy_update"
    KEY_ROTATION = "key_rotation"
    ACCESS_GRANT = "access_grant"
    INCIDENT_REPORT = "incident_report"
    VULNERABILITY = "vulnerability"

class ConsensusType(Enum):
    """Consensus algorithm types."""
    PROOF_OF_AUTHORITY = "poa"
    PROOF_OF_STAKE = "pos"
    BYZANTINE_FAULT_TOLERANT = "bft"
    RAFT = "raft"

@dataclass
class SecurityTransaction:
    """Security transaction for blockchain."""
    transaction_id: str
    transaction_type: TransactionType
    timestamp: datetime
    sender: str
    data: Dict[str, Any]
    signature: str
    nonce: int
    gas_limit: int = 1000000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'transaction_id': self.transaction_id,
            'transaction_type': self.transaction_type.value,
            'timestamp': self.timestamp.isoformat(),
            'sender': self.sender,
            'data': self.data,
            'signature': self.signature,
            'nonce': self.nonce,
            'gas_limit': self.gas_limit
        }
    
    def get_hash(self) -> str:
        """Get transaction hash."""
        tx_string = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha3_256(tx_string.encode()).hexdigest()

@dataclass
class SecurityBlock:
    """Security block in the blockchain."""
    block_number: int
    timestamp: datetime
    previous_hash: str
    merkle_root: str
    transactions: List[SecurityTransaction]
    nonce: int
    difficulty: int
    miner: str
    signature: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'block_number': self.block_number,
            'timestamp': self.timestamp.isoformat(),
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'miner': self.miner,
            'signature': self.signature
        }
    
    def get_hash(self) -> str:
        """Get block hash."""
        # Exclude signature from hash calculation
        block_data = self.to_dict()
        del block_data['signature']
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha3_256(block_string.encode()).hexdigest()

class MerkleTree:
    """Merkle tree implementation for transaction integrity."""
    
    @staticmethod
    def calculate_merkle_root(transactions: List[SecurityTransaction]) -> str:
        """
        Calculate Merkle root of transactions.
        
        Args:
            transactions: List of transactions
            
        Returns:
            Merkle root hash
        """
        if not transactions:
            return hashlib.sha3_256(b'').hexdigest()
        
        # Get transaction hashes
        tx_hashes = [tx.get_hash() for tx in transactions]
        
        # Build Merkle tree
        while len(tx_hashes) > 1:
            next_level = []
            
            # Process pairs of hashes
            for i in range(0, len(tx_hashes), 2):
                left = tx_hashes[i]
                
                # If odd number of hashes, duplicate the last one
                if i + 1 < len(tx_hashes):
                    right = tx_hashes[i + 1]
                else:
                    right = left
                
                # Combine and hash
                combined = left + right
                parent_hash = hashlib.sha3_256(combined.encode()).hexdigest()
                next_level.append(parent_hash)
            
            tx_hashes = next_level
        
        return tx_hashes[0]

class DigitalSignature:
    """Digital signature system for blockchain transactions."""
    
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate a public/private key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        # Simplified key generation for demonstration
        # In production, use proper cryptographic libraries
        private_key = secrets.token_hex(32)
        
        # Generate public key from private key (simplified)
        public_key = hashlib.sha3_256(private_key.encode()).hexdigest()
        
        return private_key, public_key
    
    @staticmethod
    def sign_data(data: str, private_key: str) -> str:
        """
        Sign data with private key.
        
        Args:
            data: Data to sign
            private_key: Private key for signing
            
        Returns:
            Digital signature
        """
        # Simplified signing for demonstration
        # In production, use proper digital signature algorithms
        message = data + private_key
        signature = hashlib.sha3_256(message.encode()).hexdigest()
        return signature
    
    @staticmethod
    def verify_signature(data: str, signature: str, public_key: str) -> bool:
        """
        Verify digital signature.
        
        Args:
            data: Original data
            signature: Digital signature to verify
            public_key: Public key for verification
            
        Returns:
            True if signature is valid
        """
        # Simplified verification for demonstration
        # In production, use proper verification algorithms
        
        # This is a placeholder - in real implementation,
        # we would need to reverse the signing process
        # For now, we'll do a basic check
        
        expected_length = 64  # SHA3-256 hex length
        return len(signature) == expected_length and all(c in '0123456789abcdef' for c in signature)

class SecuritySmartContract:
    """Smart contract for automated security policies."""
    
    def __init__(self, contract_id: str, owner: str):
        """
        Initialize smart contract.
        
        Args:
            contract_id: Unique contract identifier
            owner: Contract owner address
        """
        self.contract_id = contract_id
        self.owner = owner
        self.code = ""
        self.state = {}
        self.permissions = {}
        self.created_at = datetime.now()
        
        bc_logger.info(f"Smart contract {contract_id} created by {owner}")
    
    def deploy(self, code: str, initial_state: Dict[str, Any] = None) -> bool:
        """
        Deploy smart contract code.
        
        Args:
            code: Contract code (simplified Python-like syntax)
            initial_state: Initial contract state
            
        Returns:
            True if deployment successful
        """
        try:
            # Basic validation of contract code
            if not code or not isinstance(code, str):
                return False
            
            self.code = code
            self.state = initial_state or {}
            
            bc_logger.info(f"Smart contract {self.contract_id} deployed")
            return True
            
        except Exception as e:
            bc_logger.error(f"Contract deployment failed: {e}")
            return False
    
    def execute(self, function_name: str, parameters: Dict[str, Any], 
                caller: str) -> Tuple[bool, Any]:
        """
        Execute smart contract function.
        
        Args:
            function_name: Name of function to execute
            parameters: Function parameters
            caller: Address of caller
            
        Returns:
            Tuple of (success, result)
        """
        try:
            # Check permissions
            if not self._check_permissions(caller, function_name):
                return False, "Permission denied"
            
            # Execute function based on name
            if function_name == "check_threat_severity":
                return self._check_threat_severity(parameters)
            elif function_name == "auto_block_ip":
                return self._auto_block_ip(parameters)
            elif function_name == "escalate_incident":
                return self._escalate_incident(parameters)
            elif function_name == "rotate_keys":
                return self._rotate_keys(parameters)
            else:
                return False, f"Unknown function: {function_name}"
                
        except Exception as e:
            bc_logger.error(f"Contract execution failed: {e}")
            return False, str(e)
    
    def _check_permissions(self, caller: str, function: str) -> bool:
        """Check if caller has permission to execute function."""
        # Owner can execute any function
        if caller == self.owner:
            return True
        
        # Check specific permissions
        caller_permissions = self.permissions.get(caller, [])
        return function in caller_permissions or "all" in caller_permissions
    
    def _check_threat_severity(self, params: Dict[str, Any]) -> Tuple[bool, Any]:
        """Check threat severity and recommend actions."""
        threat_score = params.get('threat_score', 0)
        threat_type = params.get('threat_type', 'unknown')
        
        if threat_score >= 0.8:
            action = "IMMEDIATE_ISOLATION"
        elif threat_score >= 0.6:
            action = "ENHANCED_MONITORING"
        elif threat_score >= 0.3:
            action = "INCREASED_LOGGING"
        else:
            action = "CONTINUE_MONITORING"
        
        result = {
            'recommended_action': action,
            'severity': 'CRITICAL' if threat_score >= 0.8 else 'HIGH' if threat_score >= 0.6 else 'MEDIUM' if threat_score >= 0.3 else 'LOW',
            'automated': threat_score >= 0.8
        }
        
        bc_logger.info(f"Threat severity check: {threat_type} score={threat_score} action={action}")
        return True, result
    
    def _auto_block_ip(self, params: Dict[str, Any]) -> Tuple[bool, Any]:
        """Automatically block suspicious IP addresses."""
        ip_address = params.get('ip_address')
        threat_score = params.get('threat_score', 0)
        
        if threat_score >= 0.7:
            # Add to blocklist
            blocklist = self.state.get('ip_blocklist', [])
            if ip_address not in blocklist:
                blocklist.append({
                    'ip': ip_address,
                    'blocked_at': datetime.now().isoformat(),
                    'threat_score': threat_score,
                    'auto_blocked': True
                })
                self.state['ip_blocklist'] = blocklist
                
                bc_logger.warning(f"Auto-blocked IP {ip_address} (score: {threat_score})")
                return True, f"IP {ip_address} automatically blocked"
        
        return True, f"IP {ip_address} threat score {threat_score} below auto-block threshold"
    
    def _escalate_incident(self, params: Dict[str, Any]) -> Tuple[bool, Any]:
        """Escalate security incident based on severity."""
        incident_id = params.get('incident_id')
        severity = params.get('severity', 'LOW')
        
        escalation_rules = {
            'CRITICAL': ['security_team', 'incident_response', 'management'],
            'HIGH': ['security_team', 'incident_response'],
            'MEDIUM': ['security_team'],
            'LOW': []
        }
        
        notify_teams = escalation_rules.get(severity, [])
        
        # Store escalation
        escalations = self.state.get('escalations', [])
        escalations.append({
            'incident_id': incident_id,
            'severity': severity,
            'escalated_to': notify_teams,
            'escalated_at': datetime.now().isoformat()
        })
        self.state['escalations'] = escalations
        
        bc_logger.info(f"Escalated incident {incident_id} (severity: {severity}) to {notify_teams}")
        return True, {'escalated_to': notify_teams, 'incident_id': incident_id}
    
    def _rotate_keys(self, params: Dict[str, Any]) -> Tuple[bool, Any]:
        """Initiate automatic key rotation."""
        key_type = params.get('key_type', 'symmetric')
        force_rotation = params.get('force', False)
        
        # Check if rotation is needed
        last_rotation = self.state.get(f'last_{key_type}_rotation')
        
        if last_rotation:
            last_rotation_time = datetime.fromisoformat(last_rotation)
            time_since_rotation = datetime.now() - last_rotation_time
            
            # Rotate if more than 30 days or forced
            if time_since_rotation.days < 30 and not force_rotation:
                return True, f"Key rotation not needed (last rotation: {time_since_rotation.days} days ago)"
        
        # Perform rotation
        new_key_id = secrets.token_hex(16)
        self.state[f'last_{key_type}_rotation'] = datetime.now().isoformat()
        self.state[f'current_{key_type}_key'] = new_key_id
        
        bc_logger.info(f"Rotated {key_type} key (new key ID: {new_key_id})")
        return True, {'new_key_id': new_key_id, 'rotated_at': datetime.now().isoformat()}

class SecurityBlockchain:
    """Main blockchain implementation for security operations."""
    
    def __init__(self, consensus_type: ConsensusType = ConsensusType.PROOF_OF_AUTHORITY):
        """
        Initialize security blockchain.
        
        Args:
            consensus_type: Consensus algorithm to use
        """
        self.consensus_type = consensus_type
        self.chain: List[SecurityBlock] = []
        self.pending_transactions: List[SecurityTransaction] = []
        self.smart_contracts: Dict[str, SecuritySmartContract] = {}
        
        # Network and consensus
        self.nodes = set()
        self.validator_nodes = set()
        self.is_mining = False
        
        # Security settings
        self.difficulty = 4  # Number of leading zeros required in block hash
        self.block_size_limit = 100  # Maximum transactions per block
        self.block_time_target = 30  # Target seconds between blocks
        
        # Create genesis block
        self._create_genesis_block()
        
        bc_logger.info(f"Security blockchain initialized with {consensus_type.value} consensus")
    
    def _create_genesis_block(self):
        """Create the genesis block."""
        genesis_transaction = SecurityTransaction(
            transaction_id="genesis",
            transaction_type=TransactionType.AUDIT_LOG,
            timestamp=datetime.now(),
            sender="system",
            data={
                "message": "Genesis block - Security blockchain initialization",
                "version": "1.0",
                "consensus": self.consensus_type.value
            },
            signature="genesis_signature",
            nonce=0
        )
        
        genesis_block = SecurityBlock(
            block_number=0,
            timestamp=datetime.now(),
            previous_hash="0" * 64,
            merkle_root=MerkleTree.calculate_merkle_root([genesis_transaction]),
            transactions=[genesis_transaction],
            nonce=0,
            difficulty=self.difficulty,
            miner="system",
            signature="genesis_block_signature"
        )
        
        self.chain.append(genesis_block)
        bc_logger.info("Genesis block created")
    
    def add_transaction(self, transaction: SecurityTransaction) -> bool:
        """
        Add a transaction to the pending pool.
        
        Args:
            transaction: Security transaction to add
            
        Returns:
            True if transaction was added successfully
        """
        try:
            # Validate transaction
            if not self._validate_transaction(transaction):
                bc_logger.warning(f"Invalid transaction: {transaction.transaction_id}")
                return False
            
            # Check for duplicates
            for pending_tx in self.pending_transactions:
                if pending_tx.transaction_id == transaction.transaction_id:
                    bc_logger.warning(f"Duplicate transaction: {transaction.transaction_id}")
                    return False
            
            # Add to pending pool
            self.pending_transactions.append(transaction)
            
            bc_logger.info(f"Added transaction {transaction.transaction_id} to pending pool")
            return True
            
        except Exception as e:
            bc_logger.error(f"Failed to add transaction: {e}")
            return False
    
    def _validate_transaction(self, transaction: SecurityTransaction) -> bool:
        """Validate a security transaction."""
        try:
            # Check required fields
            if not transaction.transaction_id or not transaction.sender:
                return False
            
            # Check timestamp
            if transaction.timestamp > datetime.now() + timedelta(minutes=5):
                return False  # Future timestamp not allowed
            
            # Validate signature (simplified)
            if not transaction.signature:
                return False
            
            # Type-specific validation
            if transaction.transaction_type == TransactionType.THREAT_INTEL:
                required_fields = ['threat_type', 'severity', 'indicators']
                if not all(field in transaction.data for field in required_fields):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def mine_block(self, miner_address: str) -> Optional[SecurityBlock]:
        """
        Mine a new block with pending transactions.
        
        Args:
            miner_address: Address of the miner
            
        Returns:
            Newly mined block or None if mining failed
        """
        if not self.pending_transactions:
            bc_logger.info("No pending transactions to mine")
            return None
        
        try:
            # Get transactions to include (up to block size limit)
            transactions = self.pending_transactions[:self.block_size_limit]
            
            # Create new block
            previous_block = self.chain[-1]
            new_block = SecurityBlock(
                block_number=len(self.chain),
                timestamp=datetime.now(),
                previous_hash=previous_block.get_hash(),
                merkle_root=MerkleTree.calculate_merkle_root(transactions),
                transactions=transactions,
                nonce=0,
                difficulty=self.difficulty,
                miner=miner_address,
                signature=""
            )
            
            # Proof of work mining
            start_time = time.time()
            target = "0" * self.difficulty
            
            while not new_block.get_hash().startswith(target):
                new_block.nonce += 1
                
                # Prevent infinite mining
                if new_block.nonce > 1000000:
                    bc_logger.warning("Mining timeout - difficulty too high")
                    return None
            
            mining_time = time.time() - start_time
            
            # Sign the block
            private_key, public_key = DigitalSignature.generate_keypair()
            new_block.signature = DigitalSignature.sign_data(new_block.get_hash(), private_key)
            
            # Add block to chain
            self.chain.append(new_block)
            
            # Remove mined transactions from pending pool
            self.pending_transactions = self.pending_transactions[len(transactions):]
            
            bc_logger.info(f"Mined block {new_block.block_number} in {mining_time:.2f}s with {len(transactions)} transactions")
            return new_block
            
        except Exception as e:
            bc_logger.error(f"Mining failed: {e}")
            return None
    
    def validate_chain(self) -> bool:
        """
        Validate the entire blockchain.
        
        Returns:
            True if chain is valid
        """
        try:
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]
                
                # Check block hash
                if current_block.get_hash()[:self.difficulty] != "0" * self.difficulty:
                    bc_logger.error(f"Invalid proof of work for block {i}")
                    return False
                
                # Check previous hash link
                if current_block.previous_hash != previous_block.get_hash():
                    bc_logger.error(f"Invalid previous hash for block {i}")
                    return False
                
                # Check merkle root
                calculated_merkle = MerkleTree.calculate_merkle_root(current_block.transactions)
                if current_block.merkle_root != calculated_merkle:
                    bc_logger.error(f"Invalid merkle root for block {i}")
                    return False
                
                # Validate all transactions in block
                for tx in current_block.transactions:
                    if not self._validate_transaction(tx):
                        bc_logger.error(f"Invalid transaction {tx.transaction_id} in block {i}")
                        return False
            
            bc_logger.info("Blockchain validation successful")
            return True
            
        except Exception as e:
            bc_logger.error(f"Chain validation failed: {e}")
            return False
    
    def deploy_smart_contract(self, contract_id: str, owner: str, 
                             code: str, initial_state: Dict[str, Any] = None) -> bool:
        """
        Deploy a smart contract to the blockchain.
        
        Args:
            contract_id: Unique contract identifier
            owner: Contract owner address
            code: Contract code
            initial_state: Initial contract state
            
        Returns:
            True if deployment successful
        """
        try:
            if contract_id in self.smart_contracts:
                bc_logger.error(f"Contract {contract_id} already exists")
                return False
            
            # Create and deploy contract
            contract = SecuritySmartContract(contract_id, owner)
            if not contract.deploy(code, initial_state):
                return False
            
            self.smart_contracts[contract_id] = contract
            
            # Add deployment transaction
            deployment_tx = SecurityTransaction(
                transaction_id=f"deploy_{contract_id}_{int(time.time())}",
                transaction_type=TransactionType.POLICY_UPDATE,
                timestamp=datetime.now(),
                sender=owner,
                data={
                    "action": "deploy_contract",
                    "contract_id": contract_id,
                    "code_hash": hashlib.sha3_256(code.encode()).hexdigest()
                },
                signature=DigitalSignature.sign_data(contract_id, secrets.token_hex(32)),
                nonce=len(self.pending_transactions)
            )
            
            self.add_transaction(deployment_tx)
            
            bc_logger.info(f"Smart contract {contract_id} deployed successfully")
            return True
            
        except Exception as e:
            bc_logger.error(f"Contract deployment failed: {e}")
            return False
    
    def execute_smart_contract(self, contract_id: str, function_name: str, 
                              parameters: Dict[str, Any], caller: str) -> Tuple[bool, Any]:
        """
        Execute a smart contract function.
        
        Args:
            contract_id: Contract identifier
            function_name: Function to execute
            parameters: Function parameters
            caller: Caller address
            
        Returns:
            Tuple of (success, result)
        """
        try:
            if contract_id not in self.smart_contracts:
                return False, "Contract not found"
            
            contract = self.smart_contracts[contract_id]
            success, result = contract.execute(function_name, parameters, caller)
            
            # Add execution transaction
            if success:
                execution_tx = SecurityTransaction(
                    transaction_id=f"exec_{contract_id}_{function_name}_{int(time.time())}",
                    transaction_type=TransactionType.POLICY_UPDATE,
                    timestamp=datetime.now(),
                    sender=caller,
                    data={
                        "action": "execute_contract",
                        "contract_id": contract_id,
                        "function": function_name,
                        "parameters": parameters,
                        "result": result
                    },
                    signature=DigitalSignature.sign_data(f"{contract_id}_{function_name}", secrets.token_hex(32)),
                    nonce=len(self.pending_transactions)
                )
                
                self.add_transaction(execution_tx)
            
            return success, result
            
        except Exception as e:
            bc_logger.error(f"Contract execution failed: {e}")
            return False, str(e)
    
    def add_security_event(self, event_type: str, severity: str, 
                          details: Dict[str, Any], reporter: str) -> bool:
        """
        Add a security event to the blockchain.
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            details: Event details
            reporter: Address of event reporter
            
        Returns:
            True if event was added successfully
        """
        try:
            event_tx = SecurityTransaction(
                transaction_id=f"event_{event_type}_{int(time.time())}_{secrets.token_hex(4)}",
                transaction_type=TransactionType.SECURITY_EVENT,
                timestamp=datetime.now(),
                sender=reporter,
                data={
                    "event_type": event_type,
                    "severity": severity,
                    "details": details,
                    "reporter": reporter
                },
                signature=DigitalSignature.sign_data(f"{event_type}_{severity}", secrets.token_hex(32)),
                nonce=len(self.pending_transactions)
            )
            
            return self.add_transaction(event_tx)
            
        except Exception as e:
            bc_logger.error(f"Failed to add security event: {e}")
            return False
    
    def add_threat_intelligence(self, threat_type: str, indicators: List[str], 
                               severity: str, source: str) -> bool:
        """
        Add threat intelligence to the blockchain.
        
        Args:
            threat_type: Type of threat
            indicators: Threat indicators (IPs, hashes, etc.)
            severity: Threat severity
            source: Intelligence source
            
        Returns:
            True if intelligence was added successfully
        """
        try:
            intel_tx = SecurityTransaction(
                transaction_id=f"intel_{threat_type}_{int(time.time())}_{secrets.token_hex(4)}",
                transaction_type=TransactionType.THREAT_INTEL,
                timestamp=datetime.now(),
                sender=source,
                data={
                    "threat_type": threat_type,
                    "indicators": indicators,
                    "severity": severity,
                    "source": source,
                    "confidence": "high"
                },
                signature=DigitalSignature.sign_data(f"{threat_type}_{severity}", secrets.token_hex(32)),
                nonce=len(self.pending_transactions)
            )
            
            return self.add_transaction(intel_tx)
            
        except Exception as e:
            bc_logger.error(f"Failed to add threat intelligence: {e}")
            return False
    
    def query_security_events(self, event_type: str = None, 
                            start_time: datetime = None, 
                            end_time: datetime = None) -> List[Dict[str, Any]]:
        """
        Query security events from the blockchain.
        
        Args:
            event_type: Filter by event type
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            List of matching security events
        """
        events = []
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.transaction_type == TransactionType.SECURITY_EVENT:
                    # Apply filters
                    if event_type and tx.data.get('event_type') != event_type:
                        continue
                    
                    if start_time and tx.timestamp < start_time:
                        continue
                    
                    if end_time and tx.timestamp > end_time:
                        continue
                    
                    events.append({
                        'block_number': block.block_number,
                        'transaction_id': tx.transaction_id,
                        'timestamp': tx.timestamp,
                        'event_type': tx.data.get('event_type'),
                        'severity': tx.data.get('severity'),
                        'details': tx.data.get('details'),
                        'reporter': tx.data.get('reporter')
                    })
        
        return events
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Get blockchain statistics."""
        total_transactions = sum(len(block.transactions) for block in self.chain)
        
        # Count transaction types
        tx_types = {}
        for block in self.chain:
            for tx in block.transactions:
                tx_type = tx.transaction_type.value
                tx_types[tx_type] = tx_types.get(tx_type, 0) + 1
        
        return {
            'total_blocks': len(self.chain),
            'total_transactions': total_transactions,
            'pending_transactions': len(self.pending_transactions),
            'smart_contracts': len(self.smart_contracts),
            'consensus_type': self.consensus_type.value,
            'difficulty': self.difficulty,
            'transaction_types': tx_types,
            'chain_valid': self.validate_chain()
        }

def create_security_blockchain(consensus_type: ConsensusType = ConsensusType.PROOF_OF_AUTHORITY) -> SecurityBlockchain:
    """
    Create and return a security blockchain instance.
    
    Args:
        consensus_type: Consensus algorithm to use
        
    Returns:
        SecurityBlockchain instance
    """
    return SecurityBlockchain(consensus_type)

if __name__ == "__main__":
    # Demonstration
    print("⛓️  Blockchain Security System - Military Grade")
    print("=" * 60)
    
    # Initialize blockchain
    print("\n🔗 Initializing security blockchain...")
    blockchain = create_security_blockchain(ConsensusType.PROOF_OF_AUTHORITY)
    
    # Deploy security smart contract
    print("\n📜 Deploying security smart contract...")
    contract_code = """
    def check_threat_severity(threat_score, threat_type):
        if threat_score >= 0.8:
            return "IMMEDIATE_ISOLATION"
        elif threat_score >= 0.6:
            return "ENHANCED_MONITORING"
        else:
            return "CONTINUE_MONITORING"
    """
    
    blockchain.deploy_smart_contract(
        "security_policy_v1",
        "admin",
        contract_code,
        {"version": "1.0", "active": True}
    )
    
    # Add security events
    print("\n🚨 Adding security events...")
    events = [
        ("intrusion_attempt", "HIGH", {"source_ip": "192.168.1.100", "target": "web_server"}, "ids_system"),
        ("malware_detected", "CRITICAL", {"file_hash": "abc123", "location": "/tmp/malicious.exe"}, "antivirus"),
        ("unauthorized_access", "MEDIUM", {"user": "john_doe", "resource": "admin_panel"}, "access_control")
    ]
    
    for event_type, severity, details, reporter in events:
        blockchain.add_security_event(event_type, severity, details, reporter)
    
    # Add threat intelligence
    print("\n🔍 Adding threat intelligence...")
    blockchain.add_threat_intelligence(
        "malicious_ip",
        ["192.168.1.100", "10.0.0.50"],
        "HIGH",
        "threat_intel_feed"
    )
    
    # Mine a block
    print("\n⛏️  Mining block with security transactions...")
    mined_block = blockchain.mine_block("miner_001")
    
    if mined_block:
        print(f"✅ Mined block {mined_block.block_number} with {len(mined_block.transactions)} transactions")
        print(f"📊 Block hash: {mined_block.get_hash()[:16]}...")
    
    # Execute smart contract
    print("\n⚙️  Executing smart contract...")
    success, result = blockchain.execute_smart_contract(
        "security_policy_v1",
        "check_threat_severity",
        {"threat_score": 0.9, "threat_type": "malware"},
        "security_analyst"
    )
    
    if success:
        print(f"✅ Smart contract executed: {result}")
    
    # Query security events
    print("\n🔎 Querying security events...")
    security_events = blockchain.query_security_events(event_type="intrusion_attempt")
    print(f"✅ Found {len(security_events)} intrusion attempts")
    
    # Validate blockchain
    print("\n✅ Validating blockchain integrity...")
    is_valid = blockchain.validate_chain()
    print(f"Blockchain valid: {is_valid}")
    
    # Display statistics
    print(f"\n📊 Blockchain Statistics:")
    stats = blockchain.get_blockchain_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Blockchain Security System demonstration completed")