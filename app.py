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
import networkx as nx
from pytz import timezone
import pytz

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
    
    .mitre-technique {
        background: rgba(0, 255, 255, 0.1);
        border: 1px solid #00ffff;
        border-radius: 6px;
        padding: 0.5rem;
        margin: 0.2rem;
        font-size: 0.8rem;
        display: inline-block;
    }
    
    .test-card {
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        border: 1px solid #ffd700;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        transition: all 0.3s ease;
    }
    
    .test-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(255, 215, 0, 0.3);
    }
    
    .sentinel-incident {
        background: linear-gradient(135deg, #1a1a2e, #2d1a2e);
        border: 1px solid #0078d4;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid #0078d4;
    }
    
    .threat-graph-node {
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        border: 2px solid #00ffff;
        border-radius: 50%;
        padding: 1rem;
        text-align: center;
        min-width: 100px;
    }
    
    .data-classification-tag {
        display: inline-block;
        padding: 0.2rem 0.8rem;
        border-radius: 15px;
        font-size: 0.8rem;
        font-weight: bold;
        margin: 0.1rem;
    }
    
    .confidential { background: linear-gradient(45deg, #ff0000, #cc0000); color: white; }
    .internal { background: linear-gradient(45deg, #ff6b00, #cc5500); color: white; }
    .restricted { background: linear-gradient(45deg, #ffd000, #ccaa00); color: black; }
    .public { background: linear-gradient(45deg, #00cc00, #008800); color: white; }
</style>
""", unsafe_allow_html=True)

@contextmanager
def quantum_resource_manager():
    """Advanced resource management"""
    try:
        yield
    finally:
        gc.collect()

# --- ENHANCED BACKEND CLASSES WITH LIVE DATA FETCHING ---

def get_ist_time():
    """Get current IST time"""
    ist = timezone('Asia/Kolkata')
    return datetime.now(ist)

class LiveDataFetcher:
    """Enhanced live data fetcher with real API calls"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def fetch_cisa_alerts(self):
        """Fetch real CISA alerts from their API"""
        try:
            # CISA's public API endpoint for alerts
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            with st.spinner("🔄 Fetching live CISA alerts..."):
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                alerts = []
                for vuln in data.get('vulnerabilities', [])[:5]:  # Get first 5
                    alert = {
                        'title': vuln.get('vulnerabilityName', 'Unknown'),
                        'date': vuln.get('dateAdded', ''),
                        'severity': 'HIGH',
                        'source': 'CISA',
                        'type': 'Known Exploited Vulnerability',
                        'description': vuln.get('shortDescription', ''),
                        'link': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
                    }
                    alerts.append(alert)
                
                return alerts
                
        except Exception as e:
            st.error(f"Failed to fetch CISA alerts: {str(e)}")
            # Return simulated data as fallback
            return self._get_simulated_cisa_alerts()
    
    def _get_simulated_cisa_alerts(self):
        """Fallback simulated CISA alerts"""
        return [
            {"title": "Critical Vulnerability in Network Infrastructure Devices", "date": get_ist_time().strftime('%Y-%m-%d'), "severity": "CRITICAL", "source": "CISA", "type": "Advisory", "description": "Multiple vulnerabilities requiring immediate patching"},
            {"title": "Phishing Campaign Targeting Financial Sector", "date": (get_ist_time() - timedelta(days=1)).strftime('%Y-%m-%d'), "severity": "HIGH", "source": "CISA", "type": "Alert", "description": "Sophisticated phishing campaign detected"},
            {"title": "Ransomware Attacks on Healthcare Organizations", "date": (get_ist_time() - timedelta(days=2)).strftime('%Y-%m-%d'), "severity": "HIGH", "source": "CISA", "type": "Alert", "description": "Increased ransomware activity in healthcare sector"}
        ]
    
    def fetch_mitre_techniques(self):
        """Fetch MITRE ATT&CK techniques from MITRE CTI"""
        try:
            # MITRE ATT&CK Enterprise API
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            with st.spinner("🔄 Fetching MITRE ATT&CK techniques..."):
                response = self.session.get(url, timeout=15)
                response.raise_for_status()
                data = response.json()
                
                techniques = []
                for obj in data.get('objects', []):
                    if obj.get('type') == 'attack-pattern' and 'external_references' in obj:
                        # Find the MITRE ID
                        mitre_id = None
                        for ref in obj['external_references']:
                            if ref.get('source_name') == 'mitre-attack':
                                mitre_id = ref.get('external_id')
                                break
                        
                        if mitre_id and mitre_id.startswith('T'):
                            technique = {
                                "id": mitre_id,
                                "name": obj.get('name', ''),
                                "description": obj.get('description', '')[:200] + "..." if obj.get('description') else "",
                                "tactic": obj.get('kill_chain_phases', [{}])[0].get('phase_name', 'Unknown') if obj.get('kill_chain_phases') else 'Unknown',
                                "platforms": obj.get('x_mitre_platforms', ['Windows']),
                                "data_sources": obj.get('x_mitre_data_sources', [])
                            }
                            techniques.append(technique)
                            
                            if len(techniques) >= 10:  # Limit to 10 techniques
                                break
                
                return techniques
                
        except Exception as e:
            st.error(f"Failed to fetch MITRE techniques: {str(e)}")
            # Return simulated data as fallback
            return self._get_simulated_mitre_techniques()
    
    def _get_simulated_mitre_techniques(self):
        """Fallback simulated MITRE techniques"""
        return [
            {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "description": "Adversaries may send spearphishing emails with a malicious attachment...", "tactic": "Initial Access", "platforms": ["Windows", "Linux"], "data_sources": ["Email Gateway"]},
            {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "description": "Adversaries may abuse the Windows command shell for execution...", "tactic": "Execution", "platforms": ["Windows"], "data_sources": ["Process Monitoring"]},
            {"id": "T1027", "name": "Obfuscated Files or Information", "description": "Adversaries may attempt to make an executable or file difficult to discover...", "tactic": "Defense Evasion", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring"]}
        ]

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
            'APT29': {'name': 'Cozy Bear', 'origin': 'Russia', 'targets': ['Government', 'Energy', 'Finance'], 'tools': ['WellMess', 'WellMail']},
            'APT28': {'name': 'Fancy Bear', 'origin': 'Russia', 'targets': ['Government', 'Military', 'Political'], 'tools': ['X-Agent', 'X-Tunnel']},
            'Lazarus': {'name': 'Lazarus Group', 'origin': 'North Korea', 'targets': ['Finance', 'Cryptocurrency'], 'tools': ['AppleJeus', 'Brambul']},
            'Equation': {'name': 'Equation Group', 'origin': 'USA', 'targets': ['Telecom', 'Government'], 'tools': ['DoubleFantasy', 'Fanny']}
        }

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
                'last_seen': (get_ist_time() - timedelta(hours=random.randint(0, 72))).strftime('%Y-%m-%d %H:%M:%S'),
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
                'created': (get_ist_time() - timedelta(hours=random.randint(1, 168))).strftime('%Y-%m-%d %H:%M:%S'),
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
            'target_sector': target_sector, 'duration': duration, 'start_time': get_ist_time(),
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
        self.live_fetcher = LiveDataFetcher()  # Fixed: Added live_fetcher
        self.threat_simulator = QuantumThreatSimulator()
        self.quantum_neural_net = QuantumNeuralNetwork()
        self.threat_intel = AdvancedThreatIntelligence()
        self.xdr = XDRIntegration()

# --- UI COMPONENTS ---

def render_neural_matrix():
    """Render the neural matrix dashboard"""
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

def render_live_nexus():
    """Renders the live data feed and AI analysis bot tab."""
    st.markdown("### 🧬 LIVE DATA NEXUS & AI ANALYST")
    st.markdown("Real-time event streams from across the infrastructure. The **NEXUS-7 AI Analyst** interprets data to identify threats.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📡 LIVE DATA INPUT STREAM")
        st.markdown('<span class="live-data-badge">LIVE</span>', unsafe_allow_html=True)
        
        # Real-time metrics
        metric_cols = st.columns(4)
        metric_cols[0].metric("Events/sec", f"{random.randint(100, 500)}")
        metric_cols[1].metric("Alerts", f"{random.randint(5, 20)}")
        metric_cols[2].metric("Threats", f"{random.randint(1, 8)}")
        metric_cols[3].metric("Response Time", f"{random.randint(50, 200)}ms")
        
        log_placeholder = st.empty()
        
    with col2:
        st.markdown("#### 🤖 ADVANCED AI ANALYST")
        st.markdown('<span class="live-data-badge">CORRELATING</span>', unsafe_allow_html=True)
        
        # AI Analysis metrics
        ai_cols = st.columns(3)
        ai_cols[0].metric("Confidence", f"{random.randint(85, 98)}%")
        ai_cols[1].metric("Patterns", f"{random.randint(50, 200)}")
        ai_cols[2].metric("Correlations", f"{random.randint(10, 50)}")
        
        analysis_placeholder = st.empty()

    # Initialize session state for enhanced logs
    if 'enhanced_log_history' not in st.session_state:
        st.session_state.enhanced_log_history = "🚀 Enhanced NEXUS-7 AI Analyst Initialized\n"
        st.session_state.enhanced_log_history += "🔧 Loading advanced correlation engines...\n"
        st.session_state.enhanced_log_history += "✅ Behavioral analysis module active\n"
        st.session_state.enhanced_log_history += "✅ Threat intelligence feeds connected\n\n"
    
    if 'enhanced_analysis_history' not in st.session_state:
        st.session_state.enhanced_analysis_history = "🧠 AI Analyst Online - Enhanced Mode\n"
        st.session_state.enhanced_analysis_history += "🔍 Monitoring multi-source data streams\n"
        st.session_state.enhanced_analysis_history += "🎯 Advanced pattern recognition active\n\n"

    # Display current state
    log_placeholder.markdown(f'<div class="log-container">{st.session_state.enhanced_log_history}</div>', unsafe_allow_html=True)
    analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{st.session_state.enhanced_analysis_history}</div>', unsafe_allow_html=True)
    
    # Enhanced control panel
    st.markdown("#### 🎛️ ENHANCED CONTROL PANEL")
    control_cols = st.columns(4)
    
    with control_cols[0]:
        if st.button("➕ Add Multi-Source Event", key="enhanced_event"):
            new_log = get_enhanced_simulated_log()
            st.session_state.enhanced_log_history += f"{new_log}\n"
            
            new_analysis = enhanced_ai_analysis(new_log)
            st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] {new_analysis}\n"
            
            # Auto-scroll with enhanced display
            log_display = "<br>".join(st.session_state.enhanced_log_history.split("\n")[-25:])
            analysis_display = "<br>".join(st.session_state.enhanced_analysis_history.split("\n")[-25:])
            
            log_placeholder.markdown(f'<div class="log-container">{log_display}</div>', unsafe_allow_html=True)
            analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{analysis_display}</div>', unsafe_allow_html=True)
            
    with control_cols[1]:
        if st.button("🎯 Run Correlation Analysis", key="correlation"):
            correlation_result = run_correlation_analysis()
            st.session_state.enhanced_analysis_history += f"🔗 CORRELATION RESULT: {correlation_result}\n"
            analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{st.session_state.enhanced_analysis_history}</div>', unsafe_allow_html=True)
            
    with control_cols[2]:
        if st.button("📊 Generate Threat Report", key="threat_report"):
            threat_report = generate_threat_report()
            st.session_state.enhanced_analysis_history += f"📋 THREAT REPORT: {threat_report}\n"
            analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{st.session_state.enhanced_analysis_history}</div>', unsafe_allow_html=True)
    
    with control_cols[3]:
        if st.button("🗑️ Clear All Logs", key="clear_enhanced"):
            st.session_state.enhanced_log_history = "Logs cleared. Enhanced monitoring active.\n"
            st.session_state.enhanced_analysis_history = "AI Analyst ready for enhanced analysis.\n"
            st.rerun()

def get_enhanced_simulated_log():
    """Generate enhanced simulated log entries with more context"""
    log_templates = [
        ("SECURITY", "Advanced threat detected: {threat_type} from IP {ip} targeting {asset}"),
        ("NETWORK", "Unusual traffic pattern: {protocol} from {src_ip} to {dst_ip} volume {volume}MB"),
        ("ENDPOINT", "Suspicious process {process} spawned by {user} with commandline {cmd}"),
        ("IDENTITY", "Risky sign-in: {user} from {location} on device {device} with risk score {risk_score}"),
        ("CLOUD", "Security group modification: {resource} in {region} by {identity}"),
        ("APPLICATION", "Potential SQL injection attempt detected in {app} from {ip}"),
        ("COMPLIANCE", "Data policy violation: {user} accessed {sensitive_data} from {location}"),
    ]
    
    threats = ["credential harvesting", "lateral movement", "data exfiltration", "C2 communication", "ransomware activity"]
    protocols = ["HTTP", "HTTPS", "SSH", "RDP", "DNS", "SMB"]
    processes = ["powershell.exe", "cmd.exe", "mimikatz.exe", "nc.exe", "wmic.exe"]
    users = ["admin", "svc_backup", "john.doe", "sarah.connor"]
    locations = ["New York, US", "London, UK", "Tokyo, JP", "Unknown/Proxy"]
    assets = ["Domain Controller", "File Server", "Database Server", "Web Application"]
    
    level, template = random.choice(log_templates)
    
    log = template.format(
        threat_type=random.choice(threats),
        ip=f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        src_ip=f"192.168.1.{random.randint(10, 250)}",
        dst_ip=f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        asset=random.choice(assets),
        protocol=random.choice(protocols),
        volume=random.randint(10, 500),
        process=random.choice(processes),
        user=random.choice(users),
        cmd=random.choice(["Get-Process", "net user", "reg query", "whoami"]),
        location=random.choice(locations),
        device=random.choice(["Windows Device", "iPhone", "Android", "Unknown"]),
        risk_score=random.randint(30, 95),
        resource=random.choice(["EC2-SecurityGroup", "NSG-Production", "Firewall-Rule"]),
        region=random.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
        identity=random.choice(users),
        app=random.choice(["Customer Portal", "HR System", "Financial App"]),
        sensitive_data=random.choice(["PII Records", "Financial Data", "Source Code"])
    )
    
    return f"{get_ist_time().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} [{level}] {log}"

def enhanced_ai_analysis(log):
    """Enhanced AI analysis with correlation and recommendations"""
    log_lower = log.lower()
    
    analysis_templates = {
        "credential harvesting": "🚨 CRITICAL: Credential harvesting detected. Correlated with 3 similar events. Recommending immediate credential rotation and MFA enforcement.",
        "lateral movement": "🔥 HIGH: Lateral movement attempt. Multiple endpoint correlations found. Isolate affected systems and review network segmentation.",
        "data exfiltration": "💀 CRITICAL: Potential data exfiltration. Large outbound transfer detected. Block destination IPs and initiate incident response.",
        "c2 communication": "🔴 HIGH: Command and control communication. Correlated with known malicious IPs. Isolate endpoint and begin forensic analysis.",
        "ransomware activity": "💀 CRITICAL: Ransomware behavior patterns. File encryption signatures detected. Activate emergency response protocol.",
        "sql injection": "🟠 MEDIUM: SQL injection attempt. Web application firewall triggered. Review application logs and block source IP.",
        "unusual traffic": "🟡 LOW: Unusual network patterns. Monitoring for further anomalies. No immediate action required.",
    }
    
    for pattern, response in analysis_templates.items():
        if pattern in log_lower:
            return response
    
    # Default analysis for unknown patterns
    return "🔍 ANALYZING: New pattern detected. Adding to machine learning model. Monitoring for similar events across environment."

def run_correlation_analysis():
    """Run advanced correlation analysis"""
    correlations = [
        "Multiple failed logins correlated with suspicious process execution",
        "Network scan followed by exploitation attempts",
        "Data access patterns matching exfiltration behavior",
        "Timeline analysis reveals coordinated attack campaign",
        "User behavior anomalies correlated with threat intelligence"
    ]
    return random.choice(correlations)

def generate_threat_report():
    """Generate threat intelligence report"""
    reports = [
        "Emerging ransomware campaign targeting financial sector",
        "New APT group tactics observed in wild",
        "Supply chain compromise indicators detected",
        "Zero-day vulnerability exploitation patterns identified"
    ]
    return random.choice(reports)

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

def handle_cisa_connection():
    """Handle CISA connection with live data fetching"""
    if st.session_state.get('cisa_connected'):
        return
    
    st.session_state.cisa_connected = True
    
    # Update AI Nexus with connection process
    if 'enhanced_analysis_history' in st.session_state:
        st.session_state.enhanced_analysis_history += f"\n[{get_ist_time().strftime('%H:%M:%S')}] 🔗 Connecting to CISA API...\n"
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] 📡 Fetching Known Exploited Vulnerabilities catalog...\n"
    
    # Fetch live CISA data
    cisa_data = st.session_state.holographic_intel.live_fetcher.fetch_cisa_alerts()
    
    # Update AI Nexus with results
    if 'enhanced_analysis_history' in st.session_state:
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] ✅ Retrieved {len(cisa_data)} CISA alerts\n"
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] 🎯 Analyzing vulnerability patterns...\n"
    
    st.session_state.cisa_data = cisa_data
    st.success("CISA System Connected with Live Data!")

def handle_mitre_connection():
    """Handle MITRE connection with live data fetching"""
    if st.session_state.get('mitre_connected'):
        return
    
    st.session_state.mitre_connected = True
    
    # Update AI Nexus with connection process
    if 'enhanced_analysis_history' in st.session_state:
        st.session_state.enhanced_analysis_history += f"\n[{get_ist_time().strftime('%H:%M:%S')}] 🔗 Connecting to MITRE ATT&CK API...\n"
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] 📡 Downloading enterprise attack patterns...\n"
    
    # Fetch live MITRE data
    mitre_data = st.session_state.holographic_intel.live_fetcher.fetch_mitre_techniques()
    
    # Update AI Nexus with results
    if 'enhanced_analysis_history' in st.session_state:
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] ✅ Retrieved {len(mitre_data)} MITRE techniques\n"
        st.session_state.enhanced_analysis_history += f"[{get_ist_time().strftime('%H:%M:%S')}] 🎯 Mapping techniques to defense controls...\n"
    
    st.session_state.mitre_data = mitre_data
    st.success("MITRE Framework Loaded with Live Data!")

def render_unified_intelligence():
    """Renders unified threat intelligence dashboard"""
    st.markdown("### 🌐 UNIFIED THREAT INTELLIGENCE")
    
    tab1, tab2, tab3 = st.tabs(["🕵️ Threat Intel", "🎯 Attack Analysis", "🔗 External Feeds"])
    
    with tab1:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### 🌍 GLOBAL THREAT MAP")
            countries = [
                {'country': 'United States', 'lat': 38.9, 'lon': -77.0, 'threat': 0.95, 'type': 'Cyber Espionage'},
                {'country': 'China', 'lat': 39.9, 'lon': 116.4, 'threat': 0.9, 'type': 'State-Sponsored'},
                {'country': 'Russia', 'lat': 55.7, 'lon': 37.6, 'threat': 0.85, 'type': 'Ransomware'},
            ]
            
            m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
            for c in countries:
                color = 'red' if c['threat'] > 0.8 else 'orange' if c['threat'] > 0.6 else 'yellow'
                folium.Marker(
                    [c['lat'], c['lon']], 
                    tooltip=f"{c['country']} - Threat: {c['threat']:.1%} - {c['type']}",
                    icon=folium.Icon(color=color, icon='warning-sign')
                ).add_to(m)
            folium_static(m, width=700, height=400)
        
        with col2:
            st.markdown("#### 🎯 ACTIVE THREAT ACTORS")
            threat_actors = st.session_state.holographic_intel.threat_intel.threat_actors
            
            for actor_id, actor in threat_actors.items():
                with st.expander(f"🔴 {actor['name']}"):
                    st.write(f"**Origin:** {actor['origin']}")
                    st.write(f"**Targets:** {', '.join(actor['targets'])}")
                    st.write(f"**Activity:** {random.choice(['High', 'Medium', 'Low'])}")
    
    with tab2:
        st.markdown("#### 🎯 MITRE ATT&CK NAVIGATOR")
        st.caption("Interactive MITRE ATT&CK framework visualization")
        
        # Show MITRE data if connected
        if st.session_state.get('mitre_connected') and 'mitre_data' in st.session_state:
            mitre_data = st.session_state.mitre_data
            st.success(f"✅ Loaded {len(mitre_data)} MITRE techniques")
            
            for technique in mitre_data[:5]:
                with st.expander(f"{technique['id']} - {technique['name']}"):
                    st.write(f"**Tactic:** {technique['tactic']}")
                    st.write(f"**Platforms:** {', '.join(technique['platforms'])}")
                    st.write(f"**Description:** {technique['description']}")
        else:
            st.info("Click 'Connect MITRE' to load live MITRE ATT&CK data")
        
    with tab3:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔗 CISA ALERTS")
            # Show CISA data if connected
            if st.session_state.get('cisa_connected') and 'cisa_data' in st.session_state:
                cisa_data = st.session_state.cisa_data
                st.success(f"✅ Loaded {len(cisa_data)} CISA alerts")
                
                for alert in cisa_data[:3]:
                    with st.expander(f"{alert['severity']} - {alert['title']}"):
                        st.write(f"**Date:** {alert['date']}")
                        st.write(f"**Type:** {alert['type']}")
                        st.write(f"**Description:** {alert['description']}")
            else:
                st.info("Click 'Connect CISA' to load live CISA alerts")
        
        with col2:
            st.markdown("#### 📊 VULNERABILITY INTELLIGENCE")
            vulnerabilities = [
                {"cve_id": "CVE-2025-12345", "description": "Remote code execution vulnerability in web server", "cvss_score": 9.8, "published_date": "2025-10-15", "severity": "CRITICAL"},
                {"cve_id": "CVE-2025-12346", "description": "Privilege escalation in OS kernel", "cvss_score": 7.8, "published_date": "2025-10-14", "severity": "HIGH"},
                {"cve_id": "CVE-2025-12347", "description": "Information disclosure in database system", "cvss_score": 6.5, "published_date": "2025-10-13", "severity": "MEDIUM"}
            ]
            for vuln in vulnerabilities:
                with st.expander(f"{vuln['cve_id']} - {vuln['severity']}"):
                    st.write(f"**CVSS:** {vuln['cvss_score']}")
                    st.write(f"**Description:** {vuln['description']}")

def render_unified_defense():
    """Renders unified defense operations"""
    st.markdown("### 🛡️ UNIFIED DEFENSE OPERATIONS")
    
    tab1, tab2 = st.tabs(["🖥️ XDR Dashboard", "📜 Compliance"])
    
    with tab1:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### 📊 ENDPOINT RISK ANALYSIS")
            risk_data = st.session_state.holographic_intel.xdr.get_endpoint_risk_analysis()
            
            metrics_cols = st.columns(4)
            metrics_cols[0].metric("Total Endpoints", risk_data['total_endpoints'])
            metrics_cols[1].metric("Healthy", risk_data['healthy'])
            metrics_cols[2].metric("At Risk", risk_data['at_risk'])
            metrics_cols[3].metric("Compromised", risk_data['compromised'])
            
            # Endpoint health chart
            labels = ['Healthy', 'At Risk', 'Compromised']
            values = [risk_data['healthy'], risk_data['at_risk'], risk_data['compromised']]
            fig = px.pie(values=values, names=labels, title="Endpoint Health Distribution")
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'))
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### 🚨 RECENT INCIDENTS")
            incidents = st.session_state.holographic_intel.xdr.incidents[:5]
            for incident in incidents:
                st.markdown(f"""
                **{incident['title']}**
                - Severity: {incident['severity']}
                - Status: {incident['status']}
                - Created: {incident['created']}
                """)
    
    with tab2:
        st.markdown("#### 📜 COMPLIANCE DASHBOARD")
        frameworks = {
            'NIST': {'name': 'NIST CSF', 'compliance': 87, 'controls': 108},
            'ISO27001': {'name': 'ISO 27001', 'compliance': 92, 'controls': 114},
            'SOC2': {'name': 'SOC 2', 'compliance': 95, 'controls': 64},
            'GDPR': {'name': 'GDPR', 'compliance': 88, 'controls': 99},
            'HIPAA': {'name': 'HIPAA', 'compliance': 91, 'controls': 75}
        }
        
        cols = st.columns(len(frameworks))
        for i, (framework_id, framework) in enumerate(frameworks.items()):
            with cols[i]:
                st.metric(framework['name'], f"{framework['compliance']}%")
        
        st.markdown("#### 🛡️ SECURITY CONTROLS")
        controls = [
            "🔐 Encryption at Rest - **Enabled**",
            "🔑 Multi-Factor Authentication - **Enabled**",
            "📝 Audit Logging - **Enabled**",
            "🛡️ Network Segmentation - **Enabled**",
        ]
        for control in controls:
            st.markdown(f"- {control}")

def render_automated_response():
    """Renders automated response and testing"""
    st.markdown("### ⚙️ AUTOMATED RESPONSE & TESTING")
    
    tab1, tab2 = st.tabs(["⚡ SOAR Playbooks", "🧪 Security Tests"])
    
    with tab1:
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("#### PLAYBOOK CATALOG")
            playbook = st.selectbox("Select Playbook:", 
                                    ("Ransomware Containment", "Phishing Response", "Insider Threat Investigation"))
            
            st.markdown("##### Playbook Steps:")
            steps = {
                "Ransomware Containment": ["1. Isolate Host Network", "2. Snapshot Memory/Disk", "3. Block C2 IP", "4. Revoke Credentials"],
                "Phishing Response": ["1. Analyze Email Headers", "2. Detonate URL", "3. Search & Purge Emails", "4. Block Sender"],
                "Insider Threat Investigation": ["1. Enable Logging", "2. Capture Traffic", "3. Analyze Patterns", "4. Alert HR"]
            }
            for step in steps.get(playbook, []):
                st.info(step)
        
        with col2:
            st.markdown("#### PLAYBOOK EXECUTION")
            if st.button(f"🚀 Trigger '{playbook}' Playbook", disabled=(st.session_state.get('mode') != 'Admin')):
                log_placeholder = st.empty()
                log_text = ""
                for i, step in enumerate(steps.get(playbook, [])):
                    log_text += f"[{get_ist_time().strftime('%H:%M:%S')}] EXECUTING: {step}...\n"
                    log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
                    time.sleep(1)
                    log_text += f"[{get_ist_time().strftime('%H:%M:%S')}] COMPLETED: Step {i+1}\n"
                    log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
                log_text += f"[{get_ist_time().strftime('%H:%M:%S')}] ✅ PLAYBOOK COMPLETED.\n"
                log_placeholder.markdown(f'<div class="log-container">{log_text}</div>', unsafe_allow_html=True)
    
    with tab2:
        st.markdown("#### 🧪 SECURITY TESTING SUITE")
        
        if st.button("Run Vulnerability Scan", disabled=(st.session_state.get('mode') != 'Admin')):
            with st.spinner("Scanning for vulnerabilities..."):
                time.sleep(3)
                st.success("Scan completed!")
                
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Critical", "3")
                col2.metric("High", "12")
                col3.metric("Medium", "28")
                col4.metric("Low", "45")

# --- AUTO-LOGIN WITH ENTER KEY ---

def check_login():
    """Check if login should be processed"""
    if 'login_processed' not in st.session_state:
        st.session_state.login_processed = False
    
    # Check if PIN is entered and Enter was pressed
    if (st.session_state.get('pin_input') and 
        len(st.session_state.pin_input) > 0 and
        not st.session_state.login_processed):
        
        # Check if it's the correct PIN
        if st.session_state.pin_input == "100370":
            st.session_state.mode = "Admin"
            st.session_state.login_processed = True
            st.success("Admin Mode Unlocked!")
            st.rerun()
        else:
            st.error("Incorrect PIN.")
            st.session_state.login_processed = True

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
        if 'enhanced_log_history' not in st.session_state:
            st.session_state.enhanced_log_history = "🚀 Enhanced NEXUS-7 AI Analyst Initialized\n"
        if 'enhanced_analysis_history' not in st.session_state:
            st.session_state.enhanced_analysis_history = "🧠 AI Analyst Online - Enhanced Mode\n"
        if 'login_processed' not in st.session_state:
            st.session_state.login_processed = False

        # --- MODE SELECTION (LOGIN) WITH AUTO-LOGIN ---
        if 'mode' not in st.session_state:
            st.session_state.mode = "Locked"

        with st.sidebar:
            st.markdown("<h1 class='neuro-text'>NEXUS-7</h1>", unsafe_allow_html=True)
            st.markdown("---")
            
            # Mode selection with auto-login on Enter key
            if st.session_state.mode == "Locked":
                st.info("Enter PIN to unlock Admin Mode or proceed in Demo Mode.")
                
                # Use form for Enter key support
                with st.form(key='login_form'):
                    pin = st.text_input("Admin PIN:", type="password", key="pin_input", 
                                      help="Enter '100370' for Admin access. Press Enter to submit.")
                    submit_cols = st.columns(2)
                    with submit_cols[0]:
                        submit_button = st.form_submit_button("Unlock Admin", use_container_width=True)
                    with submit_cols[1]:
                        demo_button = st.form_submit_button("Demo Mode", use_container_width=True, 
                                                          type="secondary")
                
                # Check for form submission
                if submit_button or (st.session_state.get('pin_input') and len(st.session_state.pin_input) > 0):
                    if st.session_state.pin_input == "100370":
                        st.session_state.mode = "Admin"
                        st.session_state.login_processed = True
                        st.success("Admin Mode Unlocked!")
                        st.rerun()
                    elif st.session_state.pin_input:
                        st.error("Incorrect PIN.")
                
                if demo_button:
                    st.session_state.mode = "Demo"
                    st.rerun()
                    
            else:
                st.success(f"Mode: **{st.session_state.mode}**")
                if st.button("🔒 Lock System", use_container_width=True):
                    st.session_state.mode = "Locked"
                    st.session_state.login_processed = False
                    st.session_state.pin_input = ""
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
            
        # --- HEADER WITH IST TIME ---
        current_ist = get_ist_time()
        st.markdown(f"""
        <div class="neuro-header">
            <h1 class="neuro-text" style="font-size: 4rem; margin: 0;">🧠 NEXUS-7 QUANTUM NEURAL MATRIX</h1>
            <h3 class="hologram-text" style="font-size: 1.8rem; margin: 1rem 0;">
                Live Threat Intelligence • Quantum Simulation • Global Defense
            </h3>
            <p style="color: #00ffff; font-family: 'Exo 2'; font-size: 1.2rem;">
                Mode: <strong>{st.session_state.mode}</strong> | IST: <strong>{current_ist.strftime("%Y-%m-%d %H:%M:%S")}</strong>
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # --- QUICK ACTIONS WITH LIVE DATA FETCHING ---
        st.markdown("### 🚀 QUICK ACTIONS")
        cols = st.columns(6)
        with cols[0]:
            if st.button("🔗 Connect CISA", use_container_width=True):
                handle_cisa_connection()
        with cols[1]:
            if st.button("🎯 Connect MITRE", use_container_width=True):
                handle_mitre_connection()
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

        # Show connection status
        status_cols = st.columns(2)
        with status_cols[0]:
            if st.session_state.get('cisa_connected'):
                st.success("✅ CISA: Connected with Live Data")
            else:
                st.warning("🔴 CISA: Not Connected")
        
        with status_cols[1]:
            if st.session_state.get('mitre_connected'):
                st.success("✅ MITRE: Connected with Live Data")
            else:
                st.warning("🔴 MITRE: Not Connected")

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
            "🌐 THREAT INTELLIGENCE",
            "🛡️ DEFENSE OPERATIONS",  
            "⚡ RESPONSE & TESTING"
        ])
        
        with tabs[0]: render_neural_matrix()
        with tabs[1]: render_live_nexus()
        with tabs[2]: render_quantum_simulator()
        with tabs[3]: render_unified_intelligence()
        with tabs[4]: render_unified_defense()
        with tabs[5]: render_automated_response()

if __name__ == "__main__":
    main()
