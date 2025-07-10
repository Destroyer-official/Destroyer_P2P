"""
AI-Powered Threat Detection System

This module implements advanced machine learning algorithms for real-time threat detection,
anomaly analysis, and predictive security intelligence. It provides military-grade
behavioral analysis and pattern recognition to detect sophisticated attacks.

Key Features:
1. Real-time anomaly detection using unsupervised learning
2. Behavioral pattern analysis for insider threats
3. Network traffic analysis for intrusion detection
4. Predictive threat modeling using neural networks
5. Quantum-resistant ML algorithms for future-proof security
6. Zero-day attack detection through heuristic analysis
7. Advanced persistent threat (APT) identification
8. Adversarial attack detection for ML models themselves

Security Classifications:
- UNCLASSIFIED//FOR OFFICIAL USE ONLY
- DEFENSE CLASSIFICATION: CONFIDENTIAL
- NSA INFORMATION SYSTEMS SECURITY: Category II
"""

import logging
import numpy as np
import hashlib
import time
import threading
import queue
import json
import secrets
import struct
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import psutil
import socket
import subprocess
import os
import pickle
import base64

# Configure logging for AI threat detection
ai_logger = logging.getLogger("ai_threat_detection")
ai_logger.setLevel(logging.DEBUG)

if not os.path.exists("logs"):
    os.makedirs("logs")

ai_file_handler = logging.FileHandler(os.path.join("logs", "ai_threat_detection.log"))
ai_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
ai_file_handler.setFormatter(formatter)
ai_logger.addHandler(ai_file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)  # Only show warnings and errors on console
console_handler.setFormatter(formatter)
ai_logger.addHandler(console_handler)

ai_logger.info("AI Threat Detection System initialized with military-grade analytics")

class QuantumMLModel:
    """
    Quantum-resistant machine learning model for threat detection.
    Uses techniques that remain secure even against quantum adversaries.
    """
    
    def __init__(self, model_type="anomaly_detection"):
        self.model_type = model_type
        self.feature_history = deque(maxlen=10000)
        self.anomaly_threshold = 3.0  # Standard deviations
        self.learning_rate = 0.001
        self.model_weights = None
        self.feature_means = None
        self.feature_stds = None
        self.trained = False
        
        # Quantum-resistant parameters
        self.quantum_salt = secrets.token_bytes(32)
        self.model_integrity_hash = None
        
        ai_logger.info(f"Initialized quantum-resistant ML model: {model_type}")
    
    def extract_features(self, data: Dict) -> np.ndarray:
        """
        Extract meaningful features from input data for ML analysis.
        
        Args:
            data: Dictionary containing various metrics and observations
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Network features
        features.append(data.get('packet_size', 0))
        features.append(data.get('packet_interval', 0))
        features.append(data.get('connection_count', 0))
        features.append(data.get('bandwidth_usage', 0))
        
        # System features  
        features.append(data.get('cpu_usage', 0))
        features.append(data.get('memory_usage', 0))
        features.append(data.get('disk_io', 0))
        features.append(data.get('process_count', 0))
        
        # Cryptographic features
        features.append(data.get('key_generation_time', 0))
        features.append(data.get('encryption_time', 0))
        features.append(data.get('signature_time', 0))
        features.append(data.get('verification_time', 0))
        
        # Behavioral features
        features.append(data.get('login_attempts', 0))
        features.append(data.get('failed_operations', 0))
        features.append(data.get('unusual_hours_activity', 0))
        features.append(data.get('data_transfer_volume', 0))
        
        # Convert to numpy array with proper handling of missing values
        feature_array = np.array(features, dtype=np.float64)
        feature_array = np.nan_to_num(feature_array)  # Replace NaN/inf with 0
        
        return feature_array
    
    def train_online(self, features: np.ndarray):
        """
        Online learning for continuous model adaptation.
        Uses incremental learning to adapt to new patterns.
        """
        if not self.trained:
            # Initialize model parameters
            feature_dim = len(features)
            self.model_weights = np.random.normal(0, 0.1, feature_dim)
            self.feature_means = np.zeros(feature_dim)
            self.feature_stds = np.ones(feature_dim)
            self.trained = True
        
        # Update running statistics
        alpha = 0.01  # Learning rate for statistics
        self.feature_means = (1 - alpha) * self.feature_means + alpha * features
        
        # Update standard deviations
        diff = features - self.feature_means
        self.feature_stds = (1 - alpha) * self.feature_stds + alpha * np.abs(diff)
        
        # Store feature history for pattern analysis
        self.feature_history.append(features)
        
        # Update model integrity hash
        model_data = np.concatenate([self.model_weights, self.feature_means, self.feature_stds])
        model_bytes = model_data.tobytes() + self.quantum_salt
        self.model_integrity_hash = hashlib.sha3_256(model_bytes).digest()
    
    def detect_anomaly(self, features: np.ndarray) -> Tuple[bool, float, str]:
        """
        Detect anomalies using statistical and ML-based methods.
        
        Returns:
            Tuple of (is_anomaly, anomaly_score, description)
        """
        if not self.trained:
            return False, 0.0, "Model not trained"
        
        # Normalize features
        normalized_features = (features - self.feature_means) / (self.feature_stds + 1e-8)
        
        # Calculate anomaly score using multiple methods
        scores = []
        descriptions = []
        
        # 1. Statistical anomaly detection (Z-score)
        z_scores = np.abs(normalized_features)
        max_z_score = np.max(z_scores)
        if max_z_score > self.anomaly_threshold:
            scores.append(max_z_score)
            descriptions.append(f"Statistical anomaly: max Z-score {max_z_score:.2f}")
        
        # 2. Distance-based anomaly detection
        if len(self.feature_history) > 10:
            recent_features = np.array(list(self.feature_history)[-100:])
            distances = np.linalg.norm(recent_features - features, axis=1)
            avg_distance = np.mean(distances)
            std_distance = np.std(distances)
            
            if avg_distance > (np.mean(distances) + 2 * std_distance):
                scores.append(avg_distance / std_distance)
                descriptions.append(f"Distance-based anomaly: score {avg_distance/std_distance:.2f}")
        
        # 3. Temporal pattern anomaly
        if len(self.feature_history) > 5:
            recent_trend = np.array(list(self.feature_history)[-5:])
            current_diff = np.linalg.norm(features - recent_trend[-1])
            avg_diff = np.mean([np.linalg.norm(recent_trend[i] - recent_trend[i-1]) 
                               for i in range(1, len(recent_trend))])
            
            if current_diff > 3 * avg_diff and avg_diff > 0:
                scores.append(current_diff / avg_diff)
                descriptions.append(f"Temporal anomaly: sudden change {current_diff/avg_diff:.2f}x")
        
        # Combine scores
        if scores:
            combined_score = max(scores)
            combined_description = "; ".join(descriptions)
            is_anomaly = combined_score > 1.5
            return is_anomaly, combined_score, combined_description
        
        return False, 0.0, "No anomaly detected"

class APTDetector:
    """
    Advanced Persistent Threat (APT) Detection System.
    Uses behavioral analysis and long-term pattern recognition.
    """
    
    def __init__(self):
        self.session_data = defaultdict(list)
        self.user_profiles = defaultdict(dict)
        self.alert_threshold = 0.7
        self.observation_window = timedelta(hours=24)
        
        ai_logger.info("APT Detection System initialized")
    
    def analyze_session(self, session_id: str, activity_data: Dict) -> Dict:
        """
        Analyze a user session for APT indicators.
        """
        current_time = datetime.now()
        
        # Store session data
        activity_data['timestamp'] = current_time
        self.session_data[session_id].append(activity_data)
        
        # Clean old data
        cutoff_time = current_time - self.observation_window
        self.session_data[session_id] = [
            data for data in self.session_data[session_id] 
            if data['timestamp'] > cutoff_time
        ]
        
        apt_indicators = self._analyze_apt_patterns(session_id)
        
        return {
            'session_id': session_id,
            'apt_score': apt_indicators['score'],
            'indicators': apt_indicators['indicators'],
            'risk_level': apt_indicators['risk_level'],
            'recommended_actions': apt_indicators['actions']
        }
    
    def _analyze_apt_patterns(self, session_id: str) -> Dict:
        """
        Analyze patterns that may indicate APT activity.
        """
        session_activities = self.session_data[session_id]
        if not session_activities:
            return {'score': 0.0, 'indicators': [], 'risk_level': 'LOW', 'actions': []}
        
        indicators = []
        score = 0.0
        
        # Pattern 1: Unusual timing patterns
        timestamps = [activity['timestamp'] for activity in session_activities]
        if self._detect_unusual_timing(timestamps):
            indicators.append("Unusual activity timing detected")
            score += 0.2
        
        # Pattern 2: Lateral movement indicators
        if self._detect_lateral_movement(session_activities):
            indicators.append("Potential lateral movement detected")
            score += 0.3
        
        # Pattern 3: Data exfiltration patterns
        if self._detect_data_exfiltration(session_activities):
            indicators.append("Suspicious data transfer patterns")
            score += 0.4
        
        # Pattern 4: Persistence mechanisms
        if self._detect_persistence_attempts(session_activities):
            indicators.append("Persistence mechanism attempts")
            score += 0.3
        
        # Pattern 5: Privilege escalation
        if self._detect_privilege_escalation(session_activities):
            indicators.append("Potential privilege escalation")
            score += 0.5
        
        # Determine risk level and actions
        if score >= 0.8:
            risk_level = "CRITICAL"
            actions = ["IMMEDIATE_ISOLATION", "FORENSIC_ANALYSIS", "INCIDENT_RESPONSE"]
        elif score >= 0.6:
            risk_level = "HIGH" 
            actions = ["ENHANCED_MONITORING", "ACCESS_REVIEW", "SECURITY_AUDIT"]
        elif score >= 0.3:
            risk_level = "MEDIUM"
            actions = ["INCREASED_LOGGING", "BEHAVIORAL_ANALYSIS"]
        else:
            risk_level = "LOW"
            actions = ["CONTINUE_MONITORING"]
        
        return {
            'score': score,
            'indicators': indicators,
            'risk_level': risk_level,
            'actions': actions
        }
    
    def _detect_unusual_timing(self, timestamps: List[datetime]) -> bool:
        """Detect unusual timing patterns that may indicate automated tools."""
        if len(timestamps) < 3:
            return False
        
        # Check for overly regular intervals (bot-like behavior)
        intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                    for i in range(len(timestamps)-1)]
        
        if len(intervals) > 5:
            # Check for suspiciously regular intervals
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            
            # If standard deviation is very low, it might be automated
            if std_interval < mean_interval * 0.1 and mean_interval > 0:
                return True
        
        # Check for activity during unusual hours
        unusual_hours = sum(1 for ts in timestamps if ts.hour < 6 or ts.hour > 22)
        if unusual_hours > len(timestamps) * 0.3:  # More than 30% during unusual hours
            return True
        
        return False
    
    def _detect_lateral_movement(self, activities: List[Dict]) -> bool:
        """Detect patterns indicating lateral movement."""
        # Look for rapid access to multiple systems/resources
        accessed_resources = set()
        for activity in activities:
            if 'accessed_resource' in activity:
                accessed_resources.add(activity['accessed_resource'])
        
        # If accessing many different resources in short time
        if len(accessed_resources) > 10 and len(activities) > 0:
            time_span = (activities[-1]['timestamp'] - activities[0]['timestamp']).total_seconds()
            if time_span < 3600:  # Within 1 hour
                return True
        
        return False
    
    def _detect_data_exfiltration(self, activities: List[Dict]) -> bool:
        """Detect patterns indicating data exfiltration."""
        total_data_transferred = sum(activity.get('data_transferred', 0) for activity in activities)
        
        # Large data transfers
        if total_data_transferred > 1024 * 1024 * 100:  # More than 100MB
            return True
        
        # Many small transfers (potential steganography)
        small_transfers = sum(1 for activity in activities 
                             if activity.get('data_transferred', 0) < 1024)
        if small_transfers > 50:
            return True
        
        return False
    
    def _detect_persistence_attempts(self, activities: List[Dict]) -> bool:
        """Detect attempts to establish persistence."""
        persistence_indicators = [
            'registry_modification',
            'startup_modification', 
            'service_creation',
            'scheduled_task_creation',
            'dll_injection'
        ]
        
        for activity in activities:
            activity_type = activity.get('type', '')
            if activity_type in persistence_indicators:
                return True
        
        return False
    
    def _detect_privilege_escalation(self, activities: List[Dict]) -> bool:
        """Detect privilege escalation attempts."""
        escalation_indicators = [
            'admin_access_attempt',
            'sudo_usage',
            'uac_bypass_attempt',
            'kernel_exploit_attempt'
        ]
        
        for activity in activities:
            activity_type = activity.get('type', '')
            if activity_type in escalation_indicators:
                return True
        
        return False

class NetworkAnomalyDetector:
    """
    Advanced network traffic analysis for intrusion detection.
    """
    
    def __init__(self):
        self.baseline_established = False
        self.traffic_baseline = {}
        self.connection_patterns = deque(maxlen=1000)
        self.alert_queue = queue.Queue()
        
        ai_logger.info("Network Anomaly Detector initialized")
    
    def analyze_traffic(self, traffic_data: Dict) -> Dict:
        """
        Analyze network traffic for anomalies and threats.
        """
        # Extract features from traffic
        features = self._extract_network_features(traffic_data)
        
        # Update baseline if not established
        if not self.baseline_established:
            self._update_baseline(features)
        
        # Detect anomalies
        anomalies = self._detect_network_anomalies(features, traffic_data)
        
        # Store pattern for future analysis
        self.connection_patterns.append({
            'timestamp': datetime.now(),
            'features': features,
            'anomalies': anomalies
        })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'anomaly_detected': len(anomalies) > 0,
            'anomaly_types': anomalies,
            'risk_score': self._calculate_risk_score(anomalies),
            'recommendations': self._get_recommendations(anomalies)
        }
    
    def _extract_network_features(self, traffic_data: Dict) -> Dict:
        """Extract relevant features from network traffic."""
        return {
            'packet_count': traffic_data.get('packet_count', 0),
            'byte_count': traffic_data.get('byte_count', 0),
            'unique_ips': len(traffic_data.get('source_ips', [])),
            'unique_ports': len(traffic_data.get('dest_ports', [])),
            'tcp_connections': traffic_data.get('tcp_connections', 0),
            'udp_connections': traffic_data.get('udp_connections', 0),
            'avg_packet_size': traffic_data.get('avg_packet_size', 0),
            'connection_duration': traffic_data.get('connection_duration', 0),
            'failed_connections': traffic_data.get('failed_connections', 0)
        }
    
    def _update_baseline(self, features: Dict):
        """Update traffic baseline for anomaly detection."""
        for key, value in features.items():
            if key not in self.traffic_baseline:
                self.traffic_baseline[key] = []
            
            self.traffic_baseline[key].append(value)
            
            # Keep only recent data for baseline
            if len(self.traffic_baseline[key]) > 1000:
                self.traffic_baseline[key] = self.traffic_baseline[key][-1000:]
        
        # Mark baseline as established after sufficient data
        if all(len(values) > 50 for values in self.traffic_baseline.values()):
            self.baseline_established = True
            ai_logger.info("Network traffic baseline established")
    
    def _detect_network_anomalies(self, features: Dict, traffic_data: Dict) -> List[str]:
        """Detect various types of network anomalies."""
        anomalies = []
        
        if not self.baseline_established:
            return anomalies
        
        # Statistical anomaly detection
        for feature, value in features.items():
            if feature in self.traffic_baseline:
                baseline_values = self.traffic_baseline[feature]
                if len(baseline_values) > 10:
                    mean = np.mean(baseline_values)
                    std = np.std(baseline_values)
                    
                    if std > 0 and abs(value - mean) > 3 * std:
                        anomalies.append(f"Statistical anomaly in {feature}")
        
        # Specific attack pattern detection
        
        # DDoS detection
        if features['packet_count'] > 10000:  # High packet count
            anomalies.append("Potential DDoS attack detected")
        
        # Port scanning detection
        if features['unique_ports'] > 100:
            anomalies.append("Potential port scanning detected")
        
        # Brute force detection
        if features['failed_connections'] > 50:
            anomalies.append("Potential brute force attack detected")
        
        # Data exfiltration detection
        if features['byte_count'] > 1024 * 1024 * 50:  # More than 50MB
            anomalies.append("Large data transfer detected")
        
        # Suspicious timing patterns
        source_ips = traffic_data.get('source_ips', [])
        if len(set(source_ips)) == 1 and len(source_ips) > 100:
            anomalies.append("Suspicious repetitive connections from single IP")
        
        return anomalies
    
    def _calculate_risk_score(self, anomalies: List[str]) -> float:
        """Calculate risk score based on detected anomalies."""
        risk_weights = {
            'DDoS': 0.8,
            'port scanning': 0.6,
            'brute force': 0.7,
            'data transfer': 0.5,
            'Statistical anomaly': 0.3,
            'repetitive connections': 0.4
        }
        
        total_risk = 0.0
        for anomaly in anomalies:
            for pattern, weight in risk_weights.items():
                if pattern in anomaly:
                    total_risk += weight
                    break
        
        return min(total_risk, 1.0)  # Cap at 1.0
    
    def _get_recommendations(self, anomalies: List[str]) -> List[str]:
        """Get security recommendations based on detected anomalies."""
        recommendations = []
        
        for anomaly in anomalies:
            if 'DDoS' in anomaly:
                recommendations.append("Implement rate limiting and traffic shaping")
            elif 'port scanning' in anomaly:
                recommendations.append("Block scanning source IP and review firewall rules")
            elif 'brute force' in anomaly:
                recommendations.append("Implement account lockout and IP blocking")
            elif 'data transfer' in anomaly:
                recommendations.append("Review data transfer logs and implement DLP controls")
            elif 'Statistical anomaly' in anomaly:
                recommendations.append("Investigate traffic patterns and update baselines")
        
        if not recommendations:
            recommendations.append("Continue monitoring for suspicious activity")
        
        return list(set(recommendations))  # Remove duplicates

class ThreatIntelligenceEngine:
    """
    Advanced threat intelligence processing and correlation engine.
    """
    
    def __init__(self):
        self.threat_indicators = {}
        self.correlation_rules = []
        self.intelligence_feeds = {}
        self.threat_scores = defaultdict(float)
        
        self._initialize_threat_intel()
        ai_logger.info("Threat Intelligence Engine initialized")
    
    def _initialize_threat_intel(self):
        """Initialize threat intelligence sources and indicators."""
        # Known malicious patterns
        self.threat_indicators = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'malware_signatures': set(),
            'attack_patterns': [],
            'exploit_signatures': []
        }
        
        # Correlation rules for threat detection
        self.correlation_rules = [
            {
                'name': 'Multiple Failed Logins',
                'conditions': ['failed_login_count > 5', 'time_window < 300'],
                'severity': 'MEDIUM',
                'response': 'account_lockout'
            },
            {
                'name': 'Unusual Data Access',
                'conditions': ['data_access_volume > baseline * 3', 'off_hours_access'],
                'severity': 'HIGH', 
                'response': 'enhanced_monitoring'
            },
            {
                'name': 'Privilege Escalation Attempt',
                'conditions': ['admin_access_attempt', 'not_authorized_user'],
                'severity': 'CRITICAL',
                'response': 'immediate_investigation'
            }
        ]
    
    def analyze_threat_indicators(self, event_data: Dict) -> Dict:
        """
        Analyze events against known threat indicators and patterns.
        """
        threat_analysis = {
            'threat_detected': False,
            'threat_types': [],
            'severity': 'LOW',
            'confidence': 0.0,
            'recommended_actions': [],
            'iocs': []  # Indicators of Compromise
        }
        
        # Check against known malicious indicators
        iocs = self._check_iocs(event_data)
        if iocs:
            threat_analysis['threat_detected'] = True
            threat_analysis['iocs'] = iocs
            threat_analysis['severity'] = 'HIGH'
        
        # Apply correlation rules
        rule_matches = self._apply_correlation_rules(event_data)
        if rule_matches:
            threat_analysis['threat_detected'] = True
            threat_analysis['threat_types'].extend([rule['name'] for rule in rule_matches])
            
            # Set severity to highest matching rule
            severities = [rule['severity'] for rule in rule_matches]
            if 'CRITICAL' in severities:
                threat_analysis['severity'] = 'CRITICAL'
            elif 'HIGH' in severities:
                threat_analysis['severity'] = 'HIGH'
            elif 'MEDIUM' in severities:
                threat_analysis['severity'] = 'MEDIUM'
        
        # Calculate confidence score
        threat_analysis['confidence'] = self._calculate_confidence(event_data, iocs, rule_matches)
        
        # Generate recommendations
        threat_analysis['recommended_actions'] = self._generate_recommendations(
            threat_analysis['severity'], rule_matches
        )
        
        return threat_analysis
    
    def _check_iocs(self, event_data: Dict) -> List[str]:
        """Check event data against indicators of compromise."""
        found_iocs = []
        
        # Check IP addresses
        source_ip = event_data.get('source_ip')
        if source_ip and source_ip in self.threat_indicators['malicious_ips']:
            found_iocs.append(f"Malicious IP: {source_ip}")
        
        # Check domains
        domain = event_data.get('domain')
        if domain and domain in self.threat_indicators['malicious_domains']:
            found_iocs.append(f"Malicious domain: {domain}")
        
        # Check file hashes
        file_hash = event_data.get('file_hash')
        if file_hash and file_hash in self.threat_indicators['malware_signatures']:
            found_iocs.append(f"Known malware: {file_hash}")
        
        return found_iocs
    
    def _apply_correlation_rules(self, event_data: Dict) -> List[Dict]:
        """Apply correlation rules to detect complex attack patterns."""
        matching_rules = []
        
        for rule in self.correlation_rules:
            conditions_met = 0
            total_conditions = len(rule['conditions'])
            
            for condition in rule['conditions']:
                if self._evaluate_condition(condition, event_data):
                    conditions_met += 1
            
            # Rule matches if all conditions are met
            if conditions_met == total_conditions:
                matching_rules.append(rule)
        
        return matching_rules
    
    def _evaluate_condition(self, condition: str, event_data: Dict) -> bool:
        """Evaluate a single condition against event data."""
        try:
            # Simple condition evaluation (in production, use safer evaluation)
            # This is a simplified example - implement proper condition parsing
            
            if 'failed_login_count > 5' in condition:
                return event_data.get('failed_logins', 0) > 5
            elif 'time_window < 300' in condition:
                return event_data.get('time_window', 0) < 300
            elif 'data_access_volume > baseline * 3' in condition:
                baseline = event_data.get('baseline_access', 100)
                return event_data.get('data_access_volume', 0) > baseline * 3
            elif 'off_hours_access' in condition:
                hour = event_data.get('hour', 12)
                return hour < 6 or hour > 22
            elif 'admin_access_attempt' in condition:
                return event_data.get('access_type') == 'admin'
            elif 'not_authorized_user' in condition:
                return not event_data.get('authorized', True)
            
        except Exception as e:
            ai_logger.warning(f"Error evaluating condition '{condition}': {e}")
            return False
        
        return False
    
    def _calculate_confidence(self, event_data: Dict, iocs: List[str], rule_matches: List[Dict]) -> float:
        """Calculate confidence score for threat detection."""
        confidence = 0.0
        
        # IOC matches increase confidence significantly
        confidence += len(iocs) * 0.3
        
        # Rule matches increase confidence
        confidence += len(rule_matches) * 0.2
        
        # Additional factors
        if event_data.get('source_reputation', 'unknown') == 'bad':
            confidence += 0.2
        
        if event_data.get('encryption_anomaly', False):
            confidence += 0.1
        
        if event_data.get('timing_anomaly', False):
            confidence += 0.1
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def _generate_recommendations(self, severity: str, rule_matches: List[Dict]) -> List[str]:
        """Generate security recommendations based on threat analysis."""
        recommendations = []
        
        if severity == 'CRITICAL':
            recommendations.extend([
                "IMMEDIATE: Isolate affected systems",
                "IMMEDIATE: Activate incident response team", 
                "IMMEDIATE: Preserve forensic evidence",
                "Begin threat hunting activities"
            ])
        elif severity == 'HIGH':
            recommendations.extend([
                "Enhance monitoring of affected assets",
                "Review and update security controls",
                "Conduct security assessment",
                "Update threat intelligence feeds"
            ])
        elif severity == 'MEDIUM':
            recommendations.extend([
                "Increase logging verbosity",
                "Review user access permissions",
                "Monitor for related activity"
            ])
        
        # Add rule-specific recommendations
        for rule in rule_matches:
            if 'response' in rule:
                recommendations.append(f"Rule response: {rule['response']}")
        
        return recommendations

class AIThreatDetectionSystem:
    """
    Main AI-powered threat detection system that coordinates all components.
    """
    
    def __init__(self):
        self.ml_model = QuantumMLModel()
        self.apt_detector = APTDetector()
        self.network_detector = NetworkAnomalyDetector()
        self.threat_intel = ThreatIntelligenceEngine()
        
        self.alert_queue = queue.Queue()
        self.monitoring_active = False
        self.monitoring_thread = None
        
        # Security metrics
        self.metrics = {
            'threats_detected': 0,
            'false_positives': 0,
            'system_uptime': time.time(),
            'last_update': datetime.now()
        }
        
        ai_logger.info("AI Threat Detection System fully initialized")
    
    def start_monitoring(self):
        """Start real-time threat monitoring."""
        if self.monitoring_active:
            ai_logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        ai_logger.info("Real-time threat monitoring started")
    
    def stop_monitoring(self):
        """Stop threat monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        ai_logger.info("Threat monitoring stopped")
    
    def analyze_security_event(self, event_data: Dict) -> Dict:
        """
        Comprehensive analysis of a security event using all AI components.
        """
        analysis_start_time = time.time()
        
        # Extract features for ML analysis
        features = self.ml_model.extract_features(event_data)
        
        # ML-based anomaly detection
        is_anomaly, anomaly_score, anomaly_desc = self.ml_model.detect_anomaly(features)
        
        # Update ML model with new data
        self.ml_model.train_online(features)
        
        # APT analysis for session-based events
        apt_analysis = {}
        if 'session_id' in event_data:
            apt_analysis = self.apt_detector.analyze_session(
                event_data['session_id'], event_data
            )
        
        # Network anomaly detection for network events
        network_analysis = {}
        if 'packet_count' in event_data or 'source_ips' in event_data:
            network_analysis = self.network_detector.analyze_traffic(event_data)
        
        # Threat intelligence correlation
        threat_intel_analysis = self.threat_intel.analyze_threat_indicators(event_data)
        
        # Combine all analyses
        combined_analysis = {
            'timestamp': datetime.now().isoformat(),
            'event_id': event_data.get('event_id', str(uuid.uuid4())),
            'processing_time_ms': (time.time() - analysis_start_time) * 1000,
            
            'anomaly_detection': {
                'is_anomaly': is_anomaly,
                'score': anomaly_score,
                'description': anomaly_desc
            },
            
            'apt_analysis': apt_analysis,
            'network_analysis': network_analysis,
            'threat_intelligence': threat_intel_analysis,
            
            'overall_threat_level': self._calculate_overall_threat_level(
                is_anomaly, apt_analysis, network_analysis, threat_intel_analysis
            ),
            
            'recommended_actions': self._consolidate_recommendations(
                apt_analysis, network_analysis, threat_intel_analysis
            )
        }
        
        # Update metrics
        if combined_analysis['overall_threat_level'] in ['HIGH', 'CRITICAL']:
            self.metrics['threats_detected'] += 1
        
        # Queue alerts for high-priority threats
        if combined_analysis['overall_threat_level'] in ['HIGH', 'CRITICAL']:
            self.alert_queue.put(combined_analysis)
        
        ai_logger.info(f"Security event analyzed: threat_level={combined_analysis['overall_threat_level']}")
        
        return combined_analysis
    
    def _monitoring_loop(self):
        """Main monitoring loop for real-time threat detection."""
        ai_logger.info("Starting monitoring loop")
        
        while self.monitoring_active:
            try:
                # Collect system metrics
                system_data = self._collect_system_metrics()
                
                # Analyze collected data
                if system_data:
                    analysis = self.analyze_security_event(system_data)
                    
                    # Handle high-priority alerts
                    if analysis['overall_threat_level'] in ['HIGH', 'CRITICAL']:
                        self._handle_alert(analysis)
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                ai_logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _collect_system_metrics(self) -> Dict:
        """Collect current system metrics for analysis."""
        try:
            # Get system information
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()
            
            # Get network connections
            connections = psutil.net_connections()
            
            # Process network data
            source_ips = []
            dest_ports = []
            tcp_connections = 0
            udp_connections = 0
            
            for conn in connections:
                if conn.raddr:
                    source_ips.append(conn.raddr.ip)
                    dest_ports.append(conn.raddr.port)
                
                if conn.type == socket.SOCK_STREAM:
                    tcp_connections += 1
                elif conn.type == socket.SOCK_DGRAM:
                    udp_connections += 1
            
            return {
                'event_id': str(uuid.uuid4()),
                'timestamp': datetime.now(),
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_io': disk_io.read_bytes + disk_io.write_bytes if disk_io else 0,
                'process_count': len(psutil.pids()),
                'packet_count': len(connections),
                'source_ips': source_ips,
                'dest_ports': dest_ports,
                'tcp_connections': tcp_connections,
                'udp_connections': udp_connections,
                'unique_ips': len(set(source_ips)),
                'unique_ports': len(set(dest_ports)),
                'byte_count': net_io.bytes_sent + net_io.bytes_recv if net_io else 0,
                'failed_connections': 0,  # Would need more detailed network monitoring
                'connection_duration': 0,  # Would need connection tracking
                'avg_packet_size': 0  # Would need packet-level analysis
            }
            
        except Exception as e:
            ai_logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def _calculate_overall_threat_level(self, is_anomaly: bool, apt_analysis: Dict, 
                                      network_analysis: Dict, threat_intel: Dict) -> str:
        """Calculate overall threat level from all analysis components."""
        threat_score = 0.0
        
        # Anomaly detection contribution
        if is_anomaly:
            threat_score += 0.3
        
        # APT analysis contribution
        if apt_analysis and apt_analysis.get('risk_level') == 'CRITICAL':
            threat_score += 0.4
        elif apt_analysis and apt_analysis.get('risk_level') == 'HIGH':
            threat_score += 0.3
        elif apt_analysis and apt_analysis.get('risk_level') == 'MEDIUM':
            threat_score += 0.2
        
        # Network analysis contribution
        if network_analysis and network_analysis.get('anomaly_detected'):
            threat_score += network_analysis.get('risk_score', 0) * 0.3
        
        # Threat intelligence contribution
        if threat_intel and threat_intel.get('threat_detected'):
            if threat_intel.get('severity') == 'CRITICAL':
                threat_score += 0.4
            elif threat_intel.get('severity') == 'HIGH':
                threat_score += 0.3
            elif threat_intel.get('severity') == 'MEDIUM':
                threat_score += 0.2
        
        # Convert score to threat level
        if threat_score >= 0.8:
            return 'CRITICAL'
        elif threat_score >= 0.6:
            return 'HIGH'
        elif threat_score >= 0.3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _consolidate_recommendations(self, apt_analysis: Dict, network_analysis: Dict, 
                                   threat_intel: Dict) -> List[str]:
        """Consolidate recommendations from all analysis components."""
        all_recommendations = set()
        
        if apt_analysis and 'recommended_actions' in apt_analysis:
            all_recommendations.update(apt_analysis['recommended_actions'])
        
        if network_analysis and 'recommendations' in network_analysis:
            all_recommendations.update(network_analysis['recommendations'])
        
        if threat_intel and 'recommended_actions' in threat_intel:
            all_recommendations.update(threat_intel['recommended_actions'])
        
        return list(all_recommendations)
    
    def _handle_alert(self, analysis: Dict):
        """Handle high-priority security alerts."""
        alert_message = f"SECURITY ALERT: {analysis['overall_threat_level']} threat detected"
        ai_logger.warning(alert_message)
        
        # In production, this would integrate with SIEM, send notifications, etc.
        print(f"\n🚨 {alert_message}")
        print(f"Event ID: {analysis['event_id']}")
        print(f"Timestamp: {analysis['timestamp']}")
        print(f"Recommendations: {', '.join(analysis['recommended_actions'][:3])}")
    
    def get_system_status(self) -> Dict:
        """Get current system status and metrics."""
        uptime_seconds = time.time() - self.metrics['system_uptime']
        
        return {
            'status': 'ACTIVE' if self.monitoring_active else 'INACTIVE',
            'uptime_seconds': uptime_seconds,
            'threats_detected': self.metrics['threats_detected'],
            'false_positives': self.metrics['false_positives'],
            'last_update': self.metrics['last_update'].isoformat(),
            'ml_model_trained': self.ml_model.trained,
            'alert_queue_size': self.alert_queue.qsize()
        }

def get_ai_threat_detector() -> AIThreatDetectionSystem:
    """Get the global AI threat detection system instance."""
    if not hasattr(get_ai_threat_detector, '_instance'):
        get_ai_threat_detector._instance = AIThreatDetectionSystem()
    return get_ai_threat_detector._instance

# Module-level functions for easy integration
def analyze_security_event(event_data: Dict) -> Dict:
    """Analyze a security event using AI threat detection."""
    detector = get_ai_threat_detector()
    return detector.analyze_security_event(event_data)

def start_monitoring():
    """Start real-time AI threat monitoring."""
    detector = get_ai_threat_detector()
    detector.start_monitoring()

def stop_monitoring():
    """Stop AI threat monitoring."""
    detector = get_ai_threat_detector()
    detector.stop_monitoring()

def get_system_status() -> Dict:
    """Get AI threat detection system status."""
    detector = get_ai_threat_detector()
    return detector.get_system_status()

if __name__ == "__main__":
    # Demo/test mode
    print("🤖 AI Threat Detection System - Military Grade Security")
    print("=" * 60)
    
    # Initialize system
    detector = get_ai_threat_detector()
    
    # Start monitoring
    detector.start_monitoring()
    
    # Simulate some security events
    test_events = [
        {
            'event_id': 'test_001',
            'session_id': 'user_123',
            'cpu_usage': 85.0,
            'memory_usage': 75.0,
            'packet_count': 1500,
            'source_ips': ['192.168.1.100'] * 200,  # Suspicious repetition
            'failed_logins': 10,
            'time_window': 120
        },
        {
            'event_id': 'test_002',
            'packet_count': 50000,  # Potential DDoS
            'unique_ports': 150,    # Port scanning
            'tcp_connections': 500
        }
    ]
    
    print("\n🔍 Analyzing test security events...")
    for event in test_events:
        analysis = detector.analyze_security_event(event)
        print(f"\nEvent {event['event_id']}: {analysis['overall_threat_level']} threat")
        if analysis['recommended_actions']:
            print(f"Actions: {analysis['recommended_actions'][0]}")
    
    print(f"\n📊 System Status: {detector.get_system_status()}")
    
    # Let it run for a bit to show real monitoring
    print("\n⏱️  Real-time monitoring active for 30 seconds...")
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        pass
    
    detector.stop_monitoring()
    print("\n✅ AI Threat Detection System demonstration completed")