import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
import time
import folium
from streamlit_folium import folium_static
import gc
import resource
from contextlib import contextmanager
import asyncio
import warnings
import requests
from bs4 import BeautifulSoup
import json
import io
import base64
from PIL import Image
import threading

warnings.filterwarnings('ignore')

# Advanced system optimization
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(16384, hard), hard))
except (ImportError, ValueError):
    pass

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="NEXUS-7 | Quantum Neural Defense Matrix",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENHANCED CYBER CSS WITH MORE ANIMATIONS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&family=Exo+2:wght@300;400;500;600;700&display=swap');
    
    .neuro-header {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 30%, #24243e 70%, #000000 100%);
        color: white;
        padding: 2.5rem;
        border-radius: 20px;
        border: 1px solid #00ffff;
        box-shadow: 
            0 0 50px #00ffff33,
            inset 0 0 100px #00ffff11,
            0 0 0 1px #00ffff22;
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
        text-align: center;
        backdrop-filter: blur(20px);
    }
    
    .neuro-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, #00ffff22, transparent);
        animation: neuro-shimmer 6s infinite;
    }
    
    @keyframes neuro-shimmer {
        0% { left: -100%; }
        50% { left: 100%; }
        100% { left: 100%; }
    }
    
    .quantum-card {
        background: linear-gradient(145deg, #0a0a1a, #151528);
        border: 1px solid #00ffff;
        border-radius: 16px;
        padding: 1.8rem;
        margin: 0.8rem 0;
        backdrop-filter: blur(15px);
        box-shadow: 
            0 8px 32px rgba(0, 255, 255, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        position: relative;
        overflow: hidden;
        transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    }
    
    .quantum-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, #00ffff, #ff00ff, transparent);
        animation: border-glow 3s infinite;
    }
    
    @keyframes border-glow {
        0%, 100% { opacity: 0.3; }
        50% { opacity: 1; }
    }
    
    .quantum-card:hover {
        transform: translateY(-8px) scale(1.02);
        box-shadow: 
            0 20px 40px rgba(0, 255, 255, 0.2),
            0 0 80px rgba(255, 0, 255, 0.1);
        border-color: #ff00ff;
    }
    
    .neuro-text {
        color: #00ffff;
        text-shadow: 
            0 0 10px #00ffff,
            0 0 20px #00ffff,
            0 0 40px #00ffff;
        font-family: 'Orbitron', monospace;
        font-weight: 900;
        background: linear-gradient(45deg, #00ffff, #ff00ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: text-pulse 4s infinite;
    }
    
    @keyframes text-pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    
    .hologram-text {
        font-family: 'Exo 2', sans-serif;
        color: transparent;
        background: linear-gradient(45deg, #00ffff, #ff00ff, #ffff00, #00ff00);
        -webkit-background-clip: text;
        background-size: 400% 400%;
        animation: hologram-shift 6s ease infinite;
    }
    
    @keyframes hologram-shift {
        0%, 100% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
    }
    
    .quantum-metric {
        background: linear-gradient(135deg, rgba(26, 26, 46, 0.9), rgba(22, 33, 62, 0.9));
        border: 1px solid;
        border-image: linear-gradient(45deg, #00ffff, #ff00ff) 1;
        border-radius: 12px;
        padding: 1.2rem;
        margin: 0.4rem;
        box-shadow: 
            0 8px 32px rgba(0, 255, 255, 0.15),
            inset 0 0 20px rgba(0, 255, 255, 0.05);
        position: relative;
        overflow: hidden;
    }
    
    .quantum-metric::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: conic-gradient(transparent, rgba(0, 255, 255, 0.1), transparent 30%);
        animation: metric-rotate 8s linear infinite;
    }
    
    @keyframes metric-rotate {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    .neural-activity {
        background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
        border: 1px solid #00ff00;
        border-radius: 12px;
        padding: 1rem;
        margin: 0.5rem 0;
        position: relative;
        overflow: hidden;
    }
    
    .neural-activity::after {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.2), transparent);
        animation: neural-scan 3s infinite;
    }
    
    @keyframes neural-scan {
        0% { left: -100%; }
        100% { left: 100%; }
    }

    .live-data-badge {
        background: linear-gradient(45deg, #ff0000, #ff6b00);
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }

    .log-container {
        background-color: #050510;
        color: #00ff00;
        font-family: 'Share Tech Mono', monospace;
        padding: 1rem;
        border-radius: 8px;
        height: 400px;
        overflow-y: scroll;
        border: 1px solid #00ff00;
    }
    
    .attack-path {
        background: linear-gradient(135deg, #1a1a2e, #2d1a2e);
        border: 1px solid #ff0000;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        position: relative;
    }
    
    .attack-path::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 4px;
        height: 100%;
        background: linear-gradient(180deg, #ff0000, #ff6b00);
    }
    
    .threat-indicator {
        display: inline-block;
        padding: 0.2rem 0.8rem;
        border-radius: 15px;
        font-size: 0.8rem;
        font-weight: bold;
        margin: 0.1rem;
    }
    
    .critical { background: linear-gradient(45deg, #ff0000, #ff6b00); color: white; }
    .high { background: linear-gradient(45deg, #ff6b00, #ffd000); color: black; }
    .medium { background: linear-gradient(45deg, #ffd000, #ffff00); color: black; }
    .low { background: linear-gradient(45deg, #00ff00, #00cc00); color: white; }
    
    .incident-timeline {
        border-left: 3px solid #00ffff;
        padding-left: 1rem;
        margin: 1rem 0;
    }
    
    .timeline-event {
        background: rgba(0, 255, 255, 0.1);
        padding: 0.8rem;
        margin: 0.5rem 0;
        border-radius: 8px;
        border-left: 3px solid #00ffff;
    }
    
    .security-control {
        background: linear-gradient(135deg, #1a2e1a, #1a2e2a);
        border: 1px solid #00ff00;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    .compliance-badge {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        background: linear-gradient(45deg, #00cc00, #00ff00);
        color: white;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        margin: 0.2rem;
    }
</style>
""", unsafe_allow_html=True)

@contextmanager
def quantum_resource_manager():
    """Advanced resource management"""
    try:
        yield
    finally:
        gc.collect()

# --- ENHANCED BACKEND CLASSES ---

class AdvancedThreatIntelligence:
    """Enhanced threat intelligence with MITRE ATT&CK mapping"""
    
    def __init__(self):
        self.mitre_techniques = self.load_mitre_matrix()
        self.threat_actors = self.load_threat_actors()
        
    def load_mitre_matrix(self):
        """Load MITRE ATT&CK techniques"""
        return {
            'TA0001': {'name': 'Initial Access', 'techniques': ['T1566', 'T1190', 'T1133']},
            'TA0002': {'name': 'Execution', 'techniques': ['T1059', 'T1204', 'T1047']},
            'TA0003': {'name': 'Persistence', 'techniques': ['T1136', 'T1547', 'T1037']},
            'TA0004': {'name': 'Privilege Escalation', 'techniques': ['T1068', 'T1134', 'T1078']},
            'TA0005': {'name': 'Defense Evasion', 'techniques': ['T1027', 'T1112', 'T1222']},
            'TA0006': {'name': 'Credential Access', 'techniques': ['T1110', 'T1555', 'T1003']},
            'TA0007': {'name': 'Discovery', 'techniques': ['T1083', 'T1018', 'T1069']},
            'TA0008': {'name': 'Lateral Movement', 'techniques': ['T1021', 'T1570', 'T1091']},
            'TA0009': {'name': 'Collection', 'techniques': ['T1113', 'T1115', 'T1213']},
            'TA0011': {'name': 'Command and Control', 'techniques': ['T1071', 'T1090', 'T1573']},
            'TA0010': {'name': 'Exfiltration', 'techniques': ['T1041', 'T1020', 'T1030']},
            'TA0040': {'name': 'Impact', 'techniques': ['T1485', 'T1486', 'T1490']}
        }
    
    def load_threat_actors(self):
        """Load advanced threat actor profiles"""
        return {
            'APT29': {'name': 'Cozy Bear', 'origin': 'Russia', 'targets': ['Government', 'Energy', 'Finance']},
            'APT28': {'name': 'Fancy Bear', 'origin': 'Russia', 'targets': ['Government', 'Military', 'Political']},
            'Lazarus': {'name': 'Lazarus Group', 'origin': 'North Korea', 'targets': ['Finance', 'Cryptocurrency']},
            'Equation': {'name': 'Equation Group', 'origin': 'USA', 'targets': ['Telecom', 'Government']}
        }
    
    def get_attack_path_analysis(self, indicators):
        """Analyze potential attack paths based on indicators"""
        paths = []
        for indicator in indicators[:3]:  # Analyze top 3 indicators
            path = {
                'indicator': indicator,
                'mitre_tactics': random.sample(list(self.mitre_techniques.keys()), 3),
                'confidence': random.uniform(0.7, 0.95),
                'estimated_time': f"{random.randint(1, 24)} hours",
                'threat_actors': random.sample(list(self.threat_actors.keys()), 2)
            }
            paths.append(path)
        return paths

class XDRIntegration:
    """Extended Detection and Response integration"""
    
    def __init__(self):
        self.endpoints = self.generate_endpoints()
        self.incidents = self.generate_incidents()
        
    def generate_endpoints(self):
        """Generate simulated endpoint data"""
        endpoints = []
        for i in range(50):
            endpoint = {
                'id': f"EP-{1000 + i}",
                'hostname': f"WORKSTATION-{i:03d}",
                'ip': f"192.168.1.{random.randint(10, 250)}",
                'os': random.choice(['Windows 11', 'Windows 10', 'Linux', 'macOS']),
                'status': random.choice(['Healthy', 'At Risk', 'Compromised']),
                'last_seen': (datetime.now() - timedelta(hours=random.randint(0, 72))).strftime('%Y-%m-%d %H:%M:%S'),
                'threat_score': random.randint(0, 100)
            }
            endpoints.append(endpoint)
        return endpoints
    
    def generate_incidents(self):
        """Generate simulated security incidents"""
        incidents = []
        severities = ['Low', 'Medium', 'High', 'Critical']
        for i in range(20):
            incident = {
                'id': f"INC-{5000 + i}",
                'title': f"Security Incident #{i+1}",
                'severity': random.choice(severities),
                'status': random.choice(['Open', 'In Progress', 'Closed']),
                'created': (datetime.now() - timedelta(hours=random.randint(1, 168))).strftime('%Y-%m-%d %H:%M:%S'),
                'assigned_to': random.choice(['SOC Team', 'Tier 2', 'CIRT', 'Unassigned']),
                'description': f"Detected suspicious activity involving {random.choice(['malware', 'unauthorized access', 'data exfiltration', 'phishing'])}"
            }
            incidents.append(incident)
        return incidents
    
    def get_endpoint_risk_analysis(self):
        """Analyze endpoint risks"""
        risk_data = {
            'total_endpoints': len(self.endpoints),
            'healthy': len([e for e in self.endpoints if e['status'] == 'Healthy']),
            'at_risk': len([e for e in self.endpoints if e['status'] == 'At Risk']),
            'compromised': len([e for e in self.endpoints if e['status'] == 'Compromised']),
            'avg_threat_score': np.mean([e['threat_score'] for e in self.endpoints])
        }
        return risk_data

class CloudSecurityModule:
    """Cloud security posture management"""
    
    def __init__(self):
        self.cloud_resources = self.generate_cloud_resources()
        self.security_findings = self.generate_security_findings()
        
    def generate_cloud_resources(self):
        """Generate simulated cloud resources"""
        resources = []
        resource_types = ['EC2', 'S3', 'RDS', 'Lambda', 'VPC', 'IAM', 'CloudTrail']
        
        for i in range(30):
            resource = {
                'id': f"RES-{2000 + i}",
                'type': random.choice(resource_types),
                'name': f"{random.choice(['prod', 'dev', 'test'])}-{random.choice(['web', 'db', 'api'])}-{i:03d}",
                'cloud': random.choice(['AWS', 'Azure', 'GCP']),
                'region': random.choice(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']),
                'compliance': random.choice(['Compliant', 'Non-Compliant', 'At Risk']),
                'last_scan': (datetime.now() - timedelta(hours=random.randint(1, 48))).strftime('%Y-%m-%d %H:%M:%S')
            }
            resources.append(resource)
        return resources
    
    def generate_security_findings(self):
        """Generate cloud security findings"""
        findings = []
        severities = ['Low', 'Medium', 'High', 'Critical']
        
        for i in range(25):
            finding = {
                'id': f"FND-{3000 + i}",
                'resource_id': random.choice(self.cloud_resources)['id'],
                'severity': random.choice(severities),
                'category': random.choice(['Encryption', 'Access Control', 'Network Security', 'Logging']),
                'description': f"Security finding for {random.choice(['S3 bucket', 'EC2 instance', 'IAM role', 'Security group'])}",
                'status': random.choice(['Open', 'In Progress', 'Resolved']),
                'remediation': random.choice(['Enable encryption', 'Restrict permissions', 'Enable logging', 'Update policy'])
            }
            findings.append(finding)
        return findings
    
    def get_cloud_posture_score(self):
        """Calculate cloud security posture score"""
        total_resources = len(self.cloud_resources)
        compliant = len([r for r in self.cloud_resources if r['compliance'] == 'Compliant'])
        return (compliant / total_resources) * 100 if total_resources > 0 else 0

class ComplianceManager:
    """Compliance and governance management"""
    
    def __init__(self):
        self.frameworks = {
            'NIST': {'name': 'NIST CSF', 'compliance': 87, 'controls': 108},
            'ISO27001': {'name': 'ISO 27001', 'compliance': 92, 'controls': 114},
            'SOC2': {'name': 'SOC 2', 'compliance': 95, 'controls': 64},
            'GDPR': {'name': 'GDPR', 'compliance': 88, 'controls': 99},
            'HIPAA': {'name': 'HIPAA', 'compliance': 91, 'controls': 75}
        }
        
    def get_compliance_dashboard(self):
        """Get compliance dashboard data"""
        return self.frameworks

class LiveDataIntegration:
    """Enhanced live data integration"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.threat_intel = AdvancedThreatIntelligence()
        self.xdr = XDRIntegration()
        self.cloud_security = CloudSecurityModule()
        self.compliance = ComplianceManager()
    
    def fetch_cisa_alerts(self):
        """Fetch live CISA alerts - enhanced"""
        try:
            return self._get_simulated_cisa_alerts()
        except Exception as e:
            st.error(f"Error fetching CISA data: {str(e)}")
            return self._get_simulated_cisa_alerts()
    
    def _get_simulated_cisa_alerts(self):
        return [
            {"title": "Critical Vulnerability in Network Infrastructure Devices", "link": "https://www.cisa.gov", "date": "2025-10-17", "severity": "CRITICAL", "source": "CISA", "type": "Advisory"},
            {"title": "Phishing Campaign Targeting Financial Sector", "link": "https://www.cisa.gov", "date": "2025-10-15", "severity": "HIGH", "source": "CISA", "type": "Alert"},
            {"title": "Ransomware Attacks on Healthcare Organizations", "link": "https://www.cisa.gov", "date": "2025-10-14", "severity": "HIGH", "source": "CISA", "type": "Alert"}
        ]
    
    def fetch_mitre_techniques(self):
        """Fetch MITRE ATT&CK techniques - enhanced"""
        try:
            techniques = []
            for tactic_id, tactic_info in self.threat_intel.mitre_techniques.items():
                for technique in tactic_info['techniques'][:2]:  # Limit to 2 techniques per tactic
                    techniques.append({
                        "id": technique,
                        "name": f"MITRE Technique {technique}",
                        "description": f"Description of MITRE ATT&CK technique {technique}",
                        "tactic": tactic_info['name'],
                        "platforms": ["Windows", "Linux", "macOS"],
                        "data_sources": ["Process Monitoring", "Network Traffic", "File Monitoring"]
                    })
            return techniques[:15]  # Return first 15 techniques
        except Exception as e:
            st.error(f"Error fetching MITRE data: {str(e)}")
            return self._get_simulated_mitre_techniques()
    
    def _get_simulated_mitre_techniques(self):
        return [
            {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "description": "...", "tactic": "Initial Access", "platforms": ["Windows", "Linux"], "data_sources": ["Email Gateway"]},
            {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "description": "...", "tactic": "Execution", "platforms": ["Windows"], "data_sources": ["Process Monitoring"]}
        ]
    
    def fetch_vulnerability_data(self):
        """Fetch recent vulnerability data - enhanced"""
        try:
            return self._get_simulated_vulnerabilities()
        except Exception as e:
            st.error(f"Error fetching vulnerability data: {str(e)}")
            return self._get_simulated_vulnerabilities()

    def _get_simulated_vulnerabilities(self):
        return [
            {"cve_id": "CVE-2025-12345", "description": "Remote code execution vulnerability in web server", "cvss_score": 9.8, "published_date": "2025-10-15", "severity": "CRITICAL"},
            {"cve_id": "CVE-2025-12346", "description": "Privilege escalation in OS kernel", "cvss_score": 7.8, "published_date": "2025-10-14", "severity": "HIGH"},
            {"cve_id": "CVE-2025-12347", "description": "Information disclosure in database system", "cvss_score": 6.5, "published_date": "2025-10-13", "severity": "MEDIUM"}
        ]

class QuantumThreatSimulator:
    """Enhanced threat simulator"""
    
    def __init__(self):
        self.simulation_history = []
        self.active_scenarios = []
    
    def create_threat_scenario(self, scenario_type, intensity, target_sector, duration):
        scenario_id = f"SIM-{random.randint(10000, 99999)}"
        scenario_templates = {
            'ransomware': {
                'name': 'Quantum Ransomware Attack', 
                'description': 'Advanced ransomware using quantum encryption', 
                'indicators': ['File encryption patterns', 'Unusual network traffic', 'Ransom notes'], 
                'mitre_techniques': ['T1486', 'T1566.001', 'T1059.003']
            },
            'supply_chain': {
                'name': 'Supply Chain Compromise', 
                'description': 'Attack through third-party software dependencies', 
                'indicators': ['Modified DLLs', 'Unverified signatures', 'Suspicious network calls'], 
                'mitre_techniques': ['T1195.002', 'T1554', 'T1071']
            },
            'ai_poisoning': {
                'name': 'AI Model Poisoning', 
                'description': 'Adversarial attacks on machine learning models', 
                'indicators': ['Model drift', 'Anomalous predictions', 'Training data tampering'], 
                'mitre_techniques': ['T1565.001', 'T1591', 'T1588']
            },
            'zero_day': {
                'name': 'Zero-Day Exploitation', 
                'description': 'Exploitation of unknown vulnerabilities', 
                'indicators': ['Memory corruption', 'Shellcode execution', 'Privilege escalation'], 
                'mitre_techniques': ['T1190', 'T1068', 'T1210']
            }
        }
        template = scenario_templates.get(scenario_type, scenario_templates['ransomware'])
        scenario = {
            'id': scenario_id, 'type': scenario_type, 'name': template['name'],
            'description': template['description'], 'intensity': intensity,
            'target_sector': target_sector, 'duration': duration, 'start_time': datetime.now(),
            'status': 'ACTIVE', 'risk_score': self.calculate_risk_score(intensity, duration),
            'indicators': template['indicators'], 'mitre_techniques': template['mitre_techniques'],
            'quantum_entanglement': random.uniform(0.6, 0.95),
            'defense_recommendations': self.generate_defense_recommendations(scenario_type, intensity)
        }
        self.active_scenarios.append(scenario)
        self.simulation_history.append(scenario)
        return scenario
    
    def calculate_risk_score(self, intensity, duration):
        base_risk = intensity * 0.7 + (duration / 60) * 0.3
        return max(0.1, min(0.99, base_risk + random.uniform(-0.1, 0.1)))
    
    def generate_defense_recommendations(self, scenario_type, intensity):
        recommendations = {
            'ransomware': ["Deploy quantum-resistant backups", "Implement behavioral analysis", "Activate temporal rollback"],
            'supply_chain': ["Enable quantum code signing", "Implement SBOM", "Deploy runtime application self-protection"],
            'ai_poisoning': ["Activate adversarial training", "Implement model integrity monitoring", "Deploy quantum-resistant validation"],
            'zero_day': ["Enable quantum memory protection", "Implement zero-trust microsegmentation", "Deploy behavioral anomaly detection"]
        }
        base_recommendations = recommendations.get(scenario_type, [])
        if intensity > 0.8:
            base_recommendations.append("🚨 ACTIVATE QUANTUM EMERGENCY PROTOCOLS")
        return base_recommendations
    
    def run_simulation(self, scenario_id):
        # Simulation logic remains the same
        return True

    def get_simulation_analytics(self):
        if not self.simulation_history:
            return {'total_simulations': 0, 'average_risk': 0, 'most_common_scenario': 'None', 'quantum_entanglement_avg': 0}
        
        scenario_types = [s.get('type', 'unknown') for s in self.simulation_history]
        return {
            'total_simulations': len(self.simulation_history),
            'average_risk': np.mean([s['risk_score'] for s in self.simulation_history]),
            'most_common_scenario': max(set(scenario_types), key=scenario_types.count) if scenario_types else 'None',
            'quantum_entanglement_avg': np.mean([s.get('quantum_entanglement', 0) for s in self.simulation_history])
        }

class QuantumNeuralNetwork:
    """Enhanced neural network"""
    
    def predict_quantum_threat(self, input_data):
        return max(0.1, min(0.99, random.uniform(0.4, 0.9)))

class HolographicThreatIntelligence:
    """Enhanced main application state class"""
    
    def __init__(self):
        self.live_data = LiveDataIntegration()
        self.threat_simulator = QuantumThreatSimulator()
        self.quantum_neural_net = QuantumNeuralNetwork()
        self.cisa_integration = self.live_data
        self.mitre_integration = self.live_data
        self.threat_intel = AdvancedThreatIntelligence()
        self.xdr = XDRIntegration()
        self.cloud_security = CloudSecurityModule()
        self.compliance = ComplianceManager()

# --- NEW FEATURE HELPER FUNCTIONS ---

def get_simulated_log():
    """Generates a single simulated log entry."""
    log_templates = [
        ("INFO", "Successful login for user '{user}' from IP {ip}"),
        ("INFO", "File '{file}' accessed by user '{user}'"),
        ("WARN", "Failed login attempt for user '{user}' from IP {ip}"),
        ("ERROR", "Access denied for user '{user}' on resource '{resource}'"),
        ("CRITICAL", "Multiple failed login attempts for user '{user}' from IP {ip} - Potential Brute-force"),
        ("INFO", "System health check PASSED on server '{server}'"),
        ("WARN", "High CPU usage detected on server '{server}'"),
        ("CRITICAL", "Unusual outbound traffic detected from {ip} to {malicious_ip}"),
        ("ALERT", "Suspicious process '{process}' spawned by user '{user}'"),
        ("INFO", "Database backup completed successfully"),
        ("WARN", "Unusual network scan detected from IP {ip}"),
        ("CRITICAL", "Potential data exfiltration attempt detected from {ip}"),
    ]
    users = ["admin", "j.doe", "s.smith", "guest", "root", "system"]
    ips = [f"192.168.1.{random.randint(10, 200)}", "10.0.0.5", "203.0.113.88", "172.16.0.12"]
    files = ["/etc/passwd", "/var/www/config.php", "C:\\Users\\s.smith\\Documents\\project_alpha.docx", "/app/secrets.env"]
    resources = ["/api/v1/admin", "/db/customer_records", "/financial/reports"]
    servers = ["WEB_PROD_01", "DB_MASTER_A", "AUTH_SRV_3", "FILE_SRV_2"]
    processes = ["powershell.exe", "cmd.exe", "bash", "mimikatz.exe", "netcat"]
    
    level, template = random.choice(log_templates)
    log = template.format(
        user=random.choice(users), 
        ip=random.choice(ips),
        file=random.choice(files),
        resource=random.choice(resources),
        server=random.choice(servers),
        malicious_ip=f"123.45.67.{random.randint(1,254)}",
        process=random.choice(processes)
    )
    return f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} [{level}]: {log}"

def analyze_log(log):
    """Generates an AI analysis for a given log entry."""
    log_lower = log.lower()
    if "critical" in log_lower or "brute-force" in log_lower:
        return "🚨 CRITICAL THREAT: Brute-force attack detected. Recommending immediate IP block and user account lockdown. Escalating to Tier 2 SOC."
    if "failed login" in log_lower:
        return "⚠️ WARNING: Failed authentication. Correlating with other attempts from this IP. Monitoring for suspicious patterns."
    if "unusual outbound traffic" in log_lower or "exfiltration" in log_lower:
        return "🔥 HIGH SEVERITY: Potential C2 communication or data exfiltration. Initiating automated network isolation playbook for the source IP."
    if "access denied" in log_lower:
        return "🧐 ANOMALY: Unauthorized access attempt. Checking user's typical behavior and permissions. Flagged for review."
    if "suspicious process" in log_lower:
        return "🔍 SUSPICIOUS ACTIVITY: Unusual process execution detected. Analyzing process tree and network connections."
    if "network scan" in log_lower:
        return "🛡️ RECONNAISSANCE: Network scanning activity detected. Blocking source IP and monitoring for follow-up attacks."
    if "successful login" in log_lower:
        if "admin" in log_lower or "root" in log_lower:
            return "ℹ️ INFO: Privileged account login detected. Verifying against location and time heuristics. No anomalies found."
        return "ℹ️ INFO: Standard user login. Activity appears normal."
    return "✅ INFO: Routine system event. No action required."

def generate_attack_path():
    """Generate a simulated attack path"""
    techniques = ['T1566.001', 'T1059.003', 'T1068', 'T1027', 'T1110', 'T1003', 'T1082', 'T1018']
    return {
        'start_point': f"192.168.1.{random.randint(10, 50)}",
        'target': f"SRV-{random.randint(100, 999)}",
        'techniques': random.sample(techniques, random.randint(3, 6)),
        'confidence': random.uniform(0.7, 0.95),
        'timeline': f"{random.randint(1, 24)} hours",
        'risk_level': random.choice(['High', 'Critical'])
    }

# --- ENHANCED UI RENDERING FUNCTIONS ---

def render_neural_matrix():
    st.markdown("### 🧠 QUANTUM NEURAL THREAT MATRIX")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🚨 REAL-TIME THREAT MATRIX")
        threats_data = []
        for i in range(8):
            threat = {
                'ID': f"QT-{random.randint(10000, 99999)}",
                'Type': random.choice(['AI Model Poisoning', 'Supply Chain', 'Zero-Day', 'Ransomware', 'Insider Threat']),
                'Quantum Risk': f"{st.session_state.holographic_intel.quantum_neural_net.predict_quantum_threat([]):.1%}",
                'Impact': random.choice(['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM']),
                'Status': random.choice(['🔄 Active', '📈 Growing', '📉 Declining']),
            }
            threats_data.append(threat)
        st.dataframe(pd.DataFrame(threats_data), use_container_width=True, height=300)

    with col2:
        st.markdown("#### 🌊 NEURAL ACTIVITY MONITOR")
        activities = [('Quantum Processing', 0.95), ('Neural Inference', 0.98), ('Pattern Recognition', 0.90)]
        for activity, level in activities:
            st.markdown(f'<div class="neural-activity">', unsafe_allow_html=True)
            st.write(f"**{activity}**")
            st.progress(random.uniform(level-0.1, level))
            st.markdown('</div>', unsafe_allow_html=True)

def render_multiverse_analytics():
    st.markdown("### 🌌 MULTIVERSE THREAT INTELLIGENCE")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 HOLOGRAPHIC RISK ANALYSIS")
        st.markdown('<div class="quantum-card">', unsafe_allow_html=True)
        st.metric("🧿 Holographic Risk", f"{random.uniform(0.6, 0.95):.1%}")
        st.metric("⚡ Quantum Prediction", f"{random.uniform(0.5, 0.9):.1%}")
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col2:
        st.markdown("#### 📈 MULTIVERSE TIMELINE ANALYSIS")
        timelines = ['Prime Timeline', 'Quantum Branch 1', 'Quantum Branch 2']
        fig = go.Figure(data=[
            go.Bar(name='Probability', x=timelines, y=[0.65, 0.15, 0.10], marker_color='#00ffff'),
            go.Bar(name='Threat Level', x=timelines, y=[0.7, 0.9, 0.4], marker_color='#ff00ff'),
        ])
        fig.update_layout(title="Multiverse Threat Timeline Analysis", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'), height=400)
        st.plotly_chart(fig, use_container_width=True)

def render_quantum_simulator():
    st.markdown("### 🎮 QUANTUM THREAT SIMULATOR")
    simulator = st.session_state.holographic_intel.threat_simulator
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚙️ SIMULATION CONTROLS")
        scenario_type = st.selectbox("Threat Scenario Type:", ["ransomware", "supply_chain", "ai_poisoning", "zero_day"], format_func=lambda x: x.replace("_", " ").title())
        intensity = st.slider("Attack Intensity", 0.1, 1.0, 0.7, 0.1)
        target_sector = st.selectbox("Target Sector:", ["Financial", "Healthcare", "Government", "Energy", "Technology"])
        
        if st.button("🚀 LAUNCH SIMULATION", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
            scenario = simulator.create_threat_scenario(scenario_type, intensity, target_sector, 30)
            st.session_state.active_simulations.append(scenario)
            st.success(f"🎯 Simulation {scenario['id']} Launched!")
    
    with col2:
        st.markdown("#### 📊 SIMULATION ANALYTICS")
        analytics = simulator.get_simulation_analytics()
        st.metric("Total Simulations", analytics['total_simulations'])
        st.metric("Average Risk Score", f"{analytics['average_risk']:.1%}")
        st.metric("Most Common Scenario", analytics['most_common_scenario'].replace("_", " ").title())
        
        if st.session_state.active_simulations:
            st.markdown("#### 🔥 ACTIVE SIMULATIONS")
            for sim in st.session_state.active_simulations[-3:]:  # Show last 3
                with st.expander(f"{sim['name']} - Risk: {sim['risk_score']:.1%}"):
                    st.write(f"**Description:** {sim['description']}")
                    st.write(f"**Target:** {sim['target_sector']}")
                    st.write(f"**Indicators:** {', '.join(sim['indicators'])}")

def render_live_cisa_data():
    st.markdown("### 🔗 LIVE CISA THREAT INTELLIGENCE")
    if not st.session_state.cisa_connected:
        st.warning("⚠️ Connect to CISA data to view live intelligence.")
        return
    
    cisa_alerts = st.session_state.holographic_intel.cisa_integration.fetch_cisa_alerts()
    for alert in cisa_alerts:
        with st.expander(f"{alert['severity']} - {alert['title']}"):
            st.write(f"**Date:** {alert['date']}")
            st.write(f"**Source:** {alert['source']}")
            st.write(f"**Type:** {alert['type']}")
            st.markdown(f"[View Alert]({alert['link']})")

def render_live_mitre_data():
    st.markdown("### 🎯 LIVE MITRE ATT&CK FRAMEWORK")
    if not st.session_state.mitre_connected:
        st.warning("⚠️ Connect to MITRE data to view attack framework.")
        return
    
    mitre_techniques = st.session_state.holographic_intel.mitre_integration.fetch_mitre_techniques()
    
    # Group by tactic
    tactics = {}
    for technique in mitre_techniques:
        tactic = technique['tactic']
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(technique)
    
    for tactic, techniques in tactics.items():
        with st.expander(f"🧩 {tactic}"):
            for tech in techniques[:3]:  # Show first 3 techniques per tactic
                st.write(f"**{tech['id']}** - {tech['name']}")
                st.write(f"*Platforms:* {', '.join(tech['platforms'])}")

def render_global_threat_map():
    st.markdown("### 🌍 GLOBAL THREAT INTELLIGENCE MAP")
    
    # Enhanced threat data with more countries and threat types
    countries = [
        {'country': 'United States', 'lat': 38.9, 'lon': -77.0, 'threat': 0.95, 'type': 'Cyber Espionage'},
        {'country': 'China', 'lat': 39.9, 'lon': 116.4, 'threat': 0.9, 'type': 'State-Sponsored'},
        {'country': 'Russia', 'lat': 55.7, 'lon': 37.6, 'threat': 0.85, 'type': 'Ransomware'},
        {'country': 'North Korea', 'lat': 39.0, 'lon': 125.7, 'threat': 0.8, 'type': 'Financial Attacks'},
        {'country': 'Iran', 'lat': 35.7, 'lon': 51.4, 'threat': 0.75, 'type': 'Critical Infrastructure'},
        {'country': 'Brazil', 'lat': -15.8, 'lon': -47.9, 'threat': 0.6, 'type': 'Financial Fraud'},
        {'country': 'Nigeria', 'lat': 9.1, 'lon': 7.4, 'threat': 0.5, 'type': 'Business Email Compromise'},
        {'country': 'India', 'lat': 28.6, 'lon': 77.2, 'threat': 0.4, 'type': 'Phishing'},
    ]
    
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    for c in countries:
        # Color based on threat level
        color = 'red' if c['threat'] > 0.8 else 'orange' if c['threat'] > 0.6 else 'yellow'
        
        folium.Marker(
            [c['lat'], c['lon']], 
            tooltip=f"{c['country']} - Threat: {c['threat']:.1%} - {c['type']}",
            popup=f"<b>{c['country']}</b><br>Threat Level: {c['threat']:.1%}<br>Type: {c['type']}",
            icon=folium.Icon(color=color, icon='warning-sign')
        ).add_to(m)
    
    folium_static(m, width=1000, height=500)

def render_vulnerability_intel():
    st.markdown("### 📊 VULNERABILITY INTELLIGENCE DASHBOARD")
    vulnerabilities = st.session_state.holographic_intel.live_data.fetch_vulnerability_data()
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    critical = len([v for v in vulnerabilities if v['severity'] == 'CRITICAL'])
    high = len([v for v in vulnerabilities if v['severity'] == 'HIGH'])
    medium = len([v for v in vulnerabilities if v['severity'] == 'MEDIUM'])
    
    col1.metric("Critical", critical)
    col2.metric("High", high)
    col3.metric("Medium", medium)
    col4.metric("Total", len(vulnerabilities))
    
    # Vulnerability details
    for vuln in vulnerabilities:
        with st.expander(f"{vuln['cve_id']} - CVSS: {vuln['cvss_score']} - {vuln['severity']}"):
            st.write(f"**Description:** {vuln['description']}")
            st.write(f"**Published:** {vuln['published_date']}")

def render_defense_operations():
    st.markdown("### 🛡️ QUANTUM DEFENSE OPERATIONS CENTER")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 ACTIVE DEFENSE SYSTEMS")
        defenses = [("Quantum Firewall", 0.99), ("Neural IDS", 0.97), ("Holographic Grid", 0.92)]
        for defense, efficiency in defenses:
            st.markdown(f'<div class="quantum-card">**{defense}**<br><progress value="{int(efficiency*100)}" max="100"></progress>{efficiency:.1%}</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### 🚀 DEFENSE METRICS")
        st.metric("Threats Blocked Today", f"{random.randint(1000, 5000):,}")
        st.metric("System Uptime", f"99.99%")
        st.metric("Average Response Time", f"{random.uniform(50, 200):.1f}ms")

# --- NEW INNOVATIVE FEATURES ---

def render_live_nexus():
    """Renders the live data feed and AI analysis bot tab."""
    st.markdown("### 🧬 LIVE DATA NEXUS & AI ANALYST")
    st.markdown("Simulating real-time event streams from across the infrastructure. The **NEXUS-7 AI Analyst** interprets data to identify threats.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📡 LIVE DATA INPUT STREAM")
        st.markdown('<span class="live-data-badge">LIVE</span>', unsafe_allow_html=True)
        log_placeholder = st.empty()
        
    with col2:
        st.markdown("#### 🤖 NEXUS-7 AI ANALYST")
        st.markdown('<span class="live-data-badge">ANALYZING</span>', unsafe_allow_html=True)
        analysis_placeholder = st.empty()

    # Initialize session state for logs if not exists
    if 'log_history' not in st.session_state:
        st.session_state.log_history = "Initializing log stream...\n"
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = "AI Analyst is online. Awaiting data...\n"
    
    # Display current state
    log_placeholder.markdown(f'<div class="log-container">{st.session_state.log_history}</div>', unsafe_allow_html=True)
    analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{st.session_state.analysis_history}</div>', unsafe_allow_html=True)
    
    # Add new log entry
    if st.button("➕ Add New Event", key="add_event"):
        new_log = get_simulated_log()
        st.session_state.log_history += f"{new_log}\n"
        
        new_analysis = analyze_log(new_log)
        st.session_state.analysis_history += f"[{datetime.now().strftime('%H:%M:%S')}] {new_analysis}\n"
        
        # Auto-scroll effect by slicing the history
        log_display = "<br>".join(st.session_state.log_history.split("\n")[-20:])
        analysis_display = "<br>".join(st.session_state.analysis_history.split("\n")[-20:])
        
        log_placeholder.markdown(f'<div class="log-container">{log_display}</div>', unsafe_allow_html=True)
        analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{analysis_display}</div>', unsafe_allow_html=True)
        
    # Clear logs button
    if st.button("🗑️ Clear Logs", key="clear_logs"):
        st.session_state.log_history = "Logs cleared.\n"
        st.session_state.analysis_history = "AI Analyst ready.\n"
        st.rerun()

def render_identity_matrix():
    """Renders the Identity & Access Management dashboard."""
    st.markdown("### 👤 IDENTITY & ACCESS MATRIX")
    st.caption("Monitoring identity-based threats and access anomalies.")

    col1, col2, col3 = st.columns(3)
    col1.metric("👥 Privileged Accounts", "1,284")
    col2.metric("🚨 Risky Sign-ins (24h)", "47", delta="5")
    col3.metric("⏳ Stale Credentials", "312")

    st.markdown("---")

    col_a, col_b = st.columns([1, 2])
    with col_a:
        st.markdown("#### TOP RISKY USERS")
        risky_users = pd.DataFrame({
            'User': ['a.jones', 'b.davis', 'c.miller', 'ext_vendor_1', 't.brown'],
            'Risk Score': [92, 85, 78, 71, 65]
        })
        fig = px.bar(risky_users, x='Risk Score', y='User', orientation='h', title="Top 5 Risky Users", color='Risk Score', color_continuous_scale='reds')
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'), yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col_b:
        st.markdown("#### RECENT HIGH-RISK SIGN-IN EVENTS")
        sign_in_data = [
            {'User': 'a.jones', 'IP': '185.220.101.35', 'Location': 'Russia', 'Risk': '🔴 High', 'Action': 'Block'},
            {'User': 'c.miller', 'IP': '103.76.12.102', 'Location': 'Vietnam', 'Risk': '🔴 High', 'Action': 'Block'},
            {'User': 'guest', 'IP': '203.0.113.88', 'Location': 'Unknown', 'Risk': '🟠 Medium', 'Action': 'Force MFA'},
            {'User': 'b.davis', 'IP': '192.168.1.54', 'Location': 'Internal', 'Risk': '🟠 Medium', 'Action': 'Alert'},
        ]
        df = pd.DataFrame(sign_in_data)
        st.dataframe(df, use_container_width=True)
        if st.session_state.get('mode') == 'Admin':
            st.button("Force MFA for all Risky Users", type="primary")

def render_soar_playbooks():
    """Renders the Automated SOAR dashboard."""
    st.markdown("### ⚙️ AUTOMATED RESPONSE (SOAR)")
    st.caption("Orchestrating and automating security responses to active threats.")

    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("#### PLAYBOOK CATALOG")
        playbook = st.selectbox("Select a Playbook:", 
                                ("Ransomware Containment", "Phishing Response", "Insider Threat Investigation"))
        
        st.markdown("---")
        st.markdown("##### Playbook Steps:")
        steps = {
            "Ransomware Containment": ["1. Isolate Host Network", "2. Snapshot Memory/Disk", "3. Block C2 IP in Firewall", "4. Revoke User Credentials", "5. Notify SOC Lead"],
            "Phishing Response": ["1. Analyze Email Headers", "2. Detonate URL in Sandbox", "3. Search & Purge Similar Emails", "4. Block Sender & Domain", "5. Reset Credentials if Clicked"],
            "Insider Threat Investigation": ["1. Enable Silent Endpoint Logging", "2. Capture Network Traffic", "3. Analyze File Access Patterns", "4. Correlate with Login Times", "5. Alert HR & Legal"]
        }
        for step in steps.get(playbook, []):
            st.info(step)

    with col_b:
        st.markdown("#### PLAYBOOK EXECUTION LOG")
        if st.button(f"🚀 Trigger '{playbook}' Playbook", disabled=(st.session_state.get('mode') != 'Admin')):
            log_placeholder = st.empty()
            log_text = ""
            for i, step in enumerate(steps.get(playbook, [])):
                log_text += f"[{datetime.now().strftime('%H:%M:%S')}] EXECUTING: {step}...\n"
                log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
                time.sleep(1)
                log_text += f"[{datetime.now().strftime('%H:%M:%S')}] COMPLETED: Step {i+1}\n"
                log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
            log_text += f"[{datetime.now().strftime('%H:%M:%S')}] ✅ PLAYBOOK COMPLETED SUCCESSFULLY.\n"
            log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="log-container">Awaiting playbook execution...</div>', unsafe_allow_html=True)

def render_data_governance():
    """Renders the Data Governance & DLP dashboard."""
    st.markdown("### 📂 DATA GOVERNANCE (DLP)")
    st.caption("Classifying sensitive data and preventing data loss.")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("📑 Classified Documents", "1.2M")
    col2.metric("📤 Data Exfiltration Alerts (7d)", "14", delta="-2")
    col3.metric("📜 Policy Violations", "89")

    st.markdown("---")
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("#### DATA SENSITIVITY DISTRIBUTION")
        labels = ['Confidential', 'Internal', 'Restricted', 'Public']
        sizes = [45, 30, 15, 10]
        fig = go.Figure(data=[go.Pie(labels=labels, values=sizes, hole=.4)])
        fig.update_layout(title_text='Data Classification', paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'))
        st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.markdown("#### RECENT DLP ALERTS")
        dlp_alerts = [
            {'Policy': 'Credit Card Numbers', 'Source': 'SharePoint', 'User': 'r.green', 'Action': 'Blocked Upload'},
            {'Policy': 'Project Chimera Docs', 'Source': 'Email', 'User': 'k.white', 'Action': 'Blocked Send'},
            {'Policy': 'Source Code', 'Source': 'USB Drive', 'User': 'p.black', 'Action': 'Blocked Transfer'},
            {'Policy': 'PII Detection', 'Source': 'OneDrive', 'User': 'r.green', 'Action': 'Alert'},
        ]
        df = pd.DataFrame(dlp_alerts)
        st.dataframe(df, use_container_width=True)
        if st.session_state.get('mode') == 'Admin':
            st.button("Review All Pending Alerts", type="primary")

def render_attack_path_analysis():
    """Renders attack path analysis similar to CrowdStrike"""
    st.markdown("### 🎯 ATTACK PATH ANALYSIS")
    st.caption("Visualizing potential attack paths and MITRE ATT&CK techniques")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🔍 POTENTIAL ATTACK PATHS")
        
        # Generate simulated attack paths
        for i in range(3):
            path = generate_attack_path()
            with st.expander(f"Attack Path {i+1} - Risk: {path['risk_level']}"):
                st.markdown(f"**Start:** {path['start_point']}")
                st.markdown(f"**Target:** {path['target']}")
                st.markdown(f"**Confidence:** {path['confidence']:.1%}")
                st.markdown(f"**Estimated Timeline:** {path['timeline']}")
                
                st.markdown("**MITRE ATT&CK Techniques:**")
                for technique in path['techniques']:
                    st.markdown(f"- {technique}")
                
                st.markdown("**Recommended Actions:**")
                actions = ["Isolate endpoint", "Block network traffic", "Reset credentials", "Deploy additional monitoring"]
                for action in actions:
                    st.markdown(f"- {action}")

    with col2:
        st.markdown("#### 🎯 MITRE ATT&CK COVERAGE")
        
        # Simulated MITRE coverage
        tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion']
        coverage = [85, 92, 78, 88, 75]
        
        fig = go.Figure(data=[go.Bar(x=tactics, y=coverage, marker_color='#00ffff')])
        fig.update_layout(
            title="Defense Coverage by Tactic",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)

def render_xdr_dashboard():
    """Renders XDR dashboard similar to CrowdStrike/Palo Alto"""
    st.markdown("### 🖥️ EXTENDED DETECTION & RESPONSE (XDR)")
    st.caption("Unified security monitoring across endpoints, network, and cloud")
    
    # Endpoint risk analysis
    risk_data = st.session_state.holographic_intel.xdr.get_endpoint_risk_analysis()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Endpoints", risk_data['total_endpoints'])
    col2.metric("Healthy", risk_data['healthy'])
    col3.metric("At Risk", risk_data['at_risk'])
    col4.metric("Compromised", risk_data['compromised'])
    
    st.markdown("---")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("#### 📊 ENDPOINT RISK DISTRIBUTION")
        labels = ['Healthy', 'At Risk', 'Compromised']
        values = [risk_data['healthy'], risk_data['at_risk'], risk_data['compromised']]
        colors = ['#00ff00', '#ffff00', '#ff0000']
        
        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3, marker_colors=colors)])
        fig.update_layout(
            title="Endpoint Health Status",
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col_b:
        st.markdown("#### 🚨 SECURITY INCIDENTS")
        incidents = st.session_state.holographic_intel.xdr.incidents[:5]  # Show last 5 incidents
        
        for incident in incidents:
            severity_color = {
                'Critical': 'red',
                'High': 'orange', 
                'Medium': 'yellow',
                'Low': 'green'
            }.get(incident['severity'], 'gray')
            
            st.markdown(f"""
            <div class="incident-timeline">
                <div class="timeline-event">
                    <strong>{incident['title']}</strong><br>
                    <span style="color: {severity_color}">● {incident['severity']}</span> | 
                    Status: {incident['status']}<br>
                    {incident['created']} | {incident['assigned_to']}
                </div>
            </div>
            """, unsafe_allow_html=True)

def render_cloud_security():
    """Renders cloud security posture dashboard"""
    st.markdown("### ☁️ CLOUD SECURITY POSTURE")
    st.caption("Multi-cloud security assessment and compliance monitoring")
    
    posture_score = st.session_state.holographic_intel.cloud_security.get_cloud_posture_score()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Cloud Posture Score", f"{posture_score:.1f}%")
    col2.metric("Resources Monitored", len(st.session_state.holographic_intel.cloud_security.cloud_resources))
    col3.metric("Active Findings", len(st.session_state.holographic_intel.cloud_security.security_findings))
    
    st.markdown("---")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("#### 📋 CLOUD RESOURCES BY TYPE")
        resource_types = {}
        for resource in st.session_state.holographic_intel.cloud_security.cloud_resources:
            rtype = resource['type']
            resource_types[rtype] = resource_types.get(rtype, 0) + 1
        
        fig = go.Figure(data=[go.Bar(x=list(resource_types.keys()), y=list(resource_types.values()), marker_color='#00ffff')])
        fig.update_layout(
            title="Resource Distribution",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col_b:
        st.markdown("#### ⚠️ SECURITY FINDINGS BY SEVERITY")
        severity_counts = {}
        for finding in st.session_state.holographic_intel.cloud_security.security_findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        colors = {'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'}
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker_colors=[colors.get(s, 'gray') for s in severity_counts.keys()]
        )])
        fig.update_layout(
            title="Finding Severity Distribution",
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)

def render_compliance_dashboard():
    """Renders compliance and governance dashboard"""
    st.markdown("### 📜 COMPLIANCE & GOVERNANCE")
    st.caption("Multi-framework compliance tracking and audit readiness")
    
    frameworks = st.session_state.holographic_intel.compliance.get_compliance_dashboard()
    
    # Framework metrics
    cols = st.columns(len(frameworks))
    for i, (framework_id, framework) in enumerate(frameworks.items()):
        with cols[i]:
            st.metric(framework['name'], f"{framework['compliance']}%")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 COMPLIANCE SCORE TREND")
        # Simulated trend data
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        scores = [75, 78, 82, 85, 87, 89]
        
        fig = go.Figure(data=go.Scatter(x=months, y=scores, mode='lines+markers', line=dict(color='#00ffff', width=3)))
        fig.update_layout(
            title="Overall Compliance Trend",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### 🛡️ SECURITY CONTROLS")
        st.markdown("**Active Security Controls:**")
        
        controls = [
            "🔐 Encryption at Rest - **Enabled**",
            "🔑 Multi-Factor Authentication - **Enabled**",
            "📝 Audit Logging - **Enabled**",
            "🛡️ Network Segmentation - **Enabled**",
            "🔍 Vulnerability Scanning - **Enabled**",
            "🚨 Intrusion Detection - **Enabled**"
        ]
        
        for control in controls:
            st.markdown(f"- {control}")
        
        st.markdown('<div class="compliance-badge">NIST CSF: 87%</div>', unsafe_allow_html=True)
        st.markdown('<div class="compliance-badge">ISO 27001: 92%</div>', unsafe_allow_html=True)
        st.markdown('<div class="compliance-badge">SOC 2: 95%</div>', unsafe_allow_html=True)

def render_threat_intelligence():
    """Renders advanced threat intelligence dashboard"""
    st.markdown("### 🕵️ ADVANCED THREAT INTELLIGENCE")
    st.caption("Global threat actor tracking and campaign analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🌐 ACTIVE THREAT ACTORS")
        threat_actors = st.session_state.holographic_intel.threat_intel.threat_actors
        
        for actor_id, actor in threat_actors.items():
            with st.expander(f"🔴 {actor['name']} ({actor_id})"):
                st.write(f"**Origin:** {actor['origin']}")
                st.write(f"**Primary Targets:** {', '.join(actor['targets'])}")
                st.write(f"**Recent Activity:** {random.choice(['High', 'Medium', 'Low'])}")
                st.write(f"**Associated Campaigns:** {random.randint(1, 5)} active campaigns")
    
    with col2:
        st.markdown("#### 📈 THREAT INDICATORS")
        indicators = [
            {"type": "IP Address", "count": "1,284", "trend": "↗️"},
            {"type": "Domain", "count": "892", "trend": "↗️"},
            {"type": "File Hash", "count": "2,457", "trend": "↗️"},
            {"type": "URL", "count": "1,567", "trend": "↗️"},
        ]
        
        for indicator in indicators:
            st.metric(f"{indicator['type']}s", indicator['count'], indicator['trend'])

# --- MAIN APPLICATION LOGIC ---

def main():
    with quantum_resource_manager():
        # Initialize session state
        if 'holographic_intel' not in st.session_state:
            st.session_state.holographic_intel = HolographicThreatIntelligence()
        if 'cisa_connected' not in st.session_state:
            st.session_state.cisa_connected = False
        if 'mitre_connected' not in st.session_state:
            st.session_state.mitre_connected = False
        if 'active_simulations' not in st.session_state:
            st.session_state.active_simulations = []
        if 'log_history' not in st.session_state:
            st.session_state.log_history = "Initializing log stream...\n"
        if 'analysis_history' not in st.session_state:
            st.session_state.analysis_history = "AI Analyst is online. Awaiting data...\n"

        # --- MODE SELECTION (LOGIN) ---
        if 'mode' not in st.session_state:
            st.session_state.mode = "Locked"

        with st.sidebar:
            st.markdown("<h1 class='neuro-text'>NEXUS-7</h1>", unsafe_allow_html=True)
            st.markdown("---")
            
            # Mode selection
            if st.session_state.mode == "Locked":
                st.info("Enter PIN to unlock Admin Mode or proceed in Demo Mode.")
                pin = st.text_input("Admin PIN:", type="password", key="pin_input")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Unlock Admin", use_container_width=True):
                        if pin == "100370":
                            st.session_state.mode = "Admin"
                            st.success("Admin Mode Unlocked!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Incorrect PIN.")
                with col2:
                    if st.button("Demo Mode", use_container_width=True):
                        st.session_state.mode = "Demo"
                        st.rerun()
            else:
                st.success(f"Mode: **{st.session_state.mode}**")
                if st.button("🔒 Lock System", use_container_width=True):
                    st.session_state.mode = "Locked"
                    st.rerun()
            
            st.markdown("---")
            
            # Quick stats in sidebar
            st.markdown("### 📊 Quick Stats")
            st.metric("Active Threats", f"{random.randint(5, 25)}")
            st.metric("Systems Monitored", f"{random.randint(500, 2000)}")
            st.metric("Incidents Today", f"{random.randint(0, 15)}")

        if st.session_state.mode == "Locked":
            st.title("Welcome to the NEXUS-7 Quantum Neural Defense Matrix")
            st.warning("Please select a mode from the sidebar to continue.")
            st.stop()
            
        # --- HEADER ---
        st.markdown("""
        <div class="neuro-header">
            <h1 class="neuro-text" style="font-size: 4rem; margin: 0;">🧠 NEXUS-7 QUANTUM NEURAL MATRIX</h1>
            <h3 class="hologram-text" style="font-size: 1.8rem; margin: 1rem 0;">
                Live Threat Intelligence • Quantum Simulation • Global Defense
            </h3>
            <p style="color: #00ffff; font-family: 'Exo 2'; font-size: 1.2rem;">
                Mode: <strong>{}</strong> | Last Updated: {}
            </p>
        </div>
        """.format(st.session_state.mode, datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)
        
        # --- QUICK ACTIONS ---
        st.markdown("### 🚀 QUICK ACTIONS")
        cols = st.columns(6)
        with cols[0]:
            if st.button("🔗 Connect CISA", use_container_width=True):
                st.session_state.cisa_connected = True
                st.success("CISA System Connected!")
        with cols[1]:
            if st.button("🎯 Connect MITRE", use_container_width=True):
                st.session_state.mitre_connected = True
                st.success("MITRE Framework Loaded!")
        with cols[2]:
            if st.button("🧠 Run Analysis", use_container_width=True):
                with st.spinner("🌀 Running quantum neural analysis..."):
                    time.sleep(2)
                    st.success("Analysis Complete!")
        with cols[3]:
            if st.button("📊 Generate Report", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
                st.info("Report generation initiated.")
        with cols[4]:
            if st.button("🔄 Refresh Data", use_container_width=True):
                st.rerun()
        with cols[5]:
            if st.button("🚨 Emergency Protocol", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
                st.error("🚨 QUANTUM EMERGENCY PROTOCOL ACTIVATED!")

        # --- QUANTUM METRICS ---
        st.markdown("### 📊 REAL-TIME QUANTUM METRICS")
        m_cols = st.columns(6)
        metrics = ["🌌 Quantum Coherence", "🧠 Neural Activity", "⚡ Threat Velocity", "🔗 Entanglement", "🌊 Temporal Stability", "🛡️ Holographic Shield"]
        for i, col in enumerate(m_cols):
            with col:
                st.markdown('<div class="quantum-metric">', unsafe_allow_html=True)
                st.metric(metrics[i], f"{random.uniform(0.75, 0.99):.1%}", f"{random.uniform(1, 5):+.1f}%")
                st.markdown('</div>', unsafe_allow_html=True)
        
        # --- MAIN TABS ---
        tabs = st.tabs([
            "🧠 NEURAL MATRIX",
            "🧬 LIVE NEXUS & AI",
            "🎮 QUANTUM SIMULATOR", 
            "🕵️ THREAT INTEL",
            "🎯 ATTACK PATHS",
            "🖥️ XDR DASHBOARD",
            "☁️ CLOUD SECURITY",
            "👤 IDENTITY & ACCESS",
            "⚙️ AUTOMATED SOAR",
            "📂 DATA GOVERNANCE",
            "📜 COMPLIANCE",
            "🔗 LIVE CISA DATA",
            "🎯 LIVE MITRE DATA",
            "🌍 GLOBAL THREAT MAP",
            "📊 VULNERABILITY INTEL",
            "🛡️ DEFENSE OPS"
        ])
        
        with tabs[0]: render_neural_matrix()
        with tabs[1]: render_live_nexus()
        with tabs[2]: render_quantum_simulator()
        with tabs[3]: render_threat_intelligence()
        with tabs[4]: render_attack_path_analysis()
        with tabs[5]: render_xdr_dashboard()
        with tabs[6]: render_cloud_security()
        with tabs[7]: render_identity_matrix()
        with tabs[8]: render_soar_playbooks()
        with tabs[9]: render_data_governance()
        with tabs[10]: render_compliance_dashboard()
        with tabs[11]: render_live_cisa_data()
        with tabs[12]: render_live_mitre_data()
        with tabs[13]: render_global_threat_map()
        with tabs[14]: render_vulnerability_intel()
        with tabs[15]: render_defense_operations()

if __name__ == "__main__":
    main()
