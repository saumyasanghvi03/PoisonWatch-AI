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
            'APT29': {'name': 'Cozy Bear', 'origin': 'Russia', 'targets': ['Government', 'Energy', 'Finance'], 'tools': ['WellMess', 'WellMail']},
            'APT28': {'name': 'Fancy Bear', 'origin': 'Russia', 'targets': ['Government', 'Military', 'Political'], 'tools': ['X-Agent', 'X-Tunnel']},
            'Lazarus': {'name': 'Lazarus Group', 'origin': 'North Korea', 'targets': ['Finance', 'Cryptocurrency'], 'tools': ['AppleJeus', 'Brambul']},
            'Equation': {'name': 'Equation Group', 'origin': 'USA', 'targets': ['Telecom', 'Government'], 'tools': ['DoubleFantasy', 'Fanny']}
        }

class MicrosoftSentinelIntegration:
    """Microsoft Sentinel-inspired incident management"""
    
    def __init__(self):
        self.incidents = self.generate_sentinel_incidents()
        self.analytics_rules = self.generate_analytics_rules()
        
    def generate_sentinel_incidents(self):
        """Generate Microsoft Sentinel-style incidents"""
        incidents = []
        severities = ['Low', 'Medium', 'High', 'Critical']
        statuses = ['New', 'Active', 'Closed']
        
        for i in range(15):
            incident = {
                'id': f"INC-{5000 + i}",
                'title': f"Suspicious PowerShell Execution - {random.choice(['Mass', 'Obfuscated', 'Encoded'])}",
                'severity': random.choice(severities),
                'status': random.choice(statuses),
                'created_time': (datetime.now() - timedelta(hours=random.randint(1, 72))).strftime('%Y-%m-%d %H:%M:%S'),
                'last_modified': (datetime.now() - timedelta(hours=random.randint(0, 24))).strftime('%Y-%m-%d %H:%M:%S'),
                'assigned_to': random.choice(['SOC Analyst', 'Tier 2', 'CIRT', 'Unassigned']),
                'description': f"Multiple suspicious PowerShell commands detected from endpoint {random.choice(['WORKSTATION-', 'SERVER-'])}{random.randint(100, 999)}",
                'tactics': random.sample(['Initial Access', 'Execution', 'Persistence', 'Lateral Movement'], 2),
                'entities_count': random.randint(2, 8),
                'alerts_count': random.randint(1, 5)
            }
            incidents.append(incident)
        return incidents
    
    def generate_analytics_rules(self):
        """Generate analytics rules"""
        return [
            {'name': 'Multiple Failed Logons', 'status': 'Enabled', 'alerts': random.randint(50, 200)},
            {'name': 'Suspicious Process Creation', 'status': 'Enabled', 'alerts': random.randint(30, 150)},
            {'name': 'Impossible Travel', 'status': 'Enabled', 'alerts': random.randint(10, 80)},
            {'name': 'Data Exfiltration Pattern', 'status': 'Enabled', 'alerts': random.randint(5, 40)},
            {'name': 'Ransomware Behavior', 'status': 'Enabled', 'alerts': random.randint(2, 25)}
        ]

class CrowdStrikeThreatGraph:
    """CrowdStrike-inspired threat graph visualization"""
    
    def __init__(self):
        self.graph_data = self.generate_threat_graph()
        
    def generate_threat_graph(self):
        """Generate threat relationship graph"""
        G = nx.DiGraph()
        
        # Add nodes
        entities = [
            ('user1', 'User', 'compromised'),
            ('workstation1', 'Endpoint', 'suspicious'),
            ('server1', 'Server', 'normal'),
            ('attacker_ip', 'IP', 'malicious'),
            ('c2_domain', 'Domain', 'malicious'),
            ('malware_hash', 'File', 'malicious')
        ]
        
        for entity_id, entity_type, status in entities:
            G.add_node(entity_id, type=entity_type, status=status)
        
        # Add edges
        relationships = [
            ('attacker_ip', 'workstation1', 'communicated_with'),
            ('workstation1', 'server1', 'accessed'),
            ('user1', 'workstation1', 'logged_into'),
            ('c2_domain', 'workstation1', 'connected_to'),
            ('malware_hash', 'workstation1', 'executed_on')
        ]
        
        for source, target, relationship in relationships:
            G.add_edge(source, target, relationship=relationship)
            
        return G

class MicrosoftEntraIntegration:
    """Microsoft Entra-inspired identity security"""
    
    def __init__(self):
        self.identity_risks = self.generate_identity_risks()
        self.conditional_access = self.generate_conditional_access()
        
    def generate_identity_risks(self):
        """Generate identity risk events"""
        risks = []
        risk_levels = ['low', 'medium', 'high']
        
        for i in range(10):
            risk = {
                'user': f"user{i}@company.com",
                'risk_level': random.choice(risk_levels),
                'risk_type': random.choice(['Impossible Travel', 'Unfamiliar Location', 'Malware Linked', 'Suspicious Inbox Rules']),
                'detected_time': (datetime.now() - timedelta(hours=random.randint(1, 48))).strftime('%Y-%m-%d %H:%M:%S'),
                'status': random.choice(['Active', 'Dismissed', 'Remediated']),
                'signin_location': random.choice(['New York, US', 'London, UK', 'Tokyo, JP', 'Unknown']),
                'device': random.choice(['Windows Device', 'iPhone', 'Android', 'Unknown'])
            }
            risks.append(risk)
        return risks

class MicrosoftPurviewIntegration:
    """Microsoft Purview-inspired data governance"""
    
    def __init__(self):
        self.data_classification = self.generate_data_classification()
        self.sensitivity_labels = self.generate_sensitivity_labels()
        
    def generate_data_classification(self):
        """Generate data classification results"""
        classifications = []
        sensitivity_levels = ['Public', 'General', 'Confidential', 'Highly Confidential']
        
        for i in range(8):
            classification = {
                'file_path': f"/shared_drive/{random.choice(['Finance', 'HR', 'R&D'])}/document_{i}.pdf",
                'sensitivity': random.choice(sensitivity_levels),
                'file_type': random.choice(['PDF', 'DOCX', 'XLSX', 'PPTX']),
                'size_mb': random.randint(1, 50),
                'last_modified': (datetime.now() - timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d'),
                'owner': f"user{random.randint(1, 20)}@company.com"
            }
            classifications.append(classification)
        return classifications

class PaloAltoIntegration:
    """Palo Alto Networks-inspired network security"""
    
    def __init__(self):
        self.firewall_logs = self.generate_firewall_logs()
        self.threat_prevention = self.generate_threat_prevention()
        
    def generate_firewall_logs(self):
        """Generate firewall traffic logs"""
        logs = []
        actions = ['Allow', 'Deny', 'Drop']
        
        for i in range(12):
            log = {
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime('%H:%M:%S'),
                'source_ip': f"192.168.1.{random.randint(10, 250)}",
                'dest_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'dest_port': random.choice([80, 443, 22, 3389, 53]),
                'action': random.choice(actions),
                'application': random.choice(['HTTP', 'HTTPS', 'SSH', 'DNS', 'RDP']),
                'threat_name': random.choice(['', '', '', 'Malware', 'C&C Communication'])
            }
            logs.append(log)
        return logs

# --- ENHANCED FRONTEND COMPONENTS ---

def render_sentinel_incidents():
    """Microsoft Sentinel-inspired incident management"""
    st.markdown("### 🔍 MICROSOFT SENTINEL INCIDENT QUEUE")
    
    sentinel = MicrosoftSentinelIntegration()
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("#### 📋 ACTIVE INCIDENTS")
        for incident in sentinel.incidents[:5]:
            severity_color = {
                'Critical': '🔴',
                'High': '🟠', 
                'Medium': '🟡',
                'Low': '🟢'
            }
            
            with st.container():
                st.markdown(f"""
                <div class="sentinel-incident">
                    <div style="display: flex; justify-content: between; align-items: center;">
                        <h4>{severity_color[incident['severity']]} {incident['title']}</h4>
                        <span class="threat-indicator {incident['severity'].lower()}">{incident['severity']}</span>
                    </div>
                    <p><strong>ID:</strong> {incident['id']} | <strong>Status:</strong> {incident['status']}</p>
                    <p><strong>Tactics:</strong> {', '.join(incident['tactics'])}</p>
                    <p><strong>Assigned to:</strong> {incident['assigned_to']}</p>
                </div>
                """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### 📊 INCIDENT ANALYTICS")
        st.metric("Total Incidents", len(sentinel.incidents))
        st.metric("Critical Incidents", len([i for i in sentinel.incidents if i['severity'] == 'Critical']))
        st.metric("Active Cases", len([i for i in sentinel.incidents if i['status'] in ['New', 'Active']]))
        
        st.markdown("#### ⚡ ANALYTICS RULES")
        for rule in sentinel.analytics_rules:
            st.write(f"**{rule['name']}**")
            st.progress(rule['alerts'] / 200)
            st.caption(f"Alerts: {rule['alerts']}")

def render_crowdstrike_threat_graph():
    """CrowdStrike-inspired threat graph visualization"""
    st.markdown("### 🕸️ CROWDSTRIKE THREAT GRAPH")
    
    threat_graph = CrowdStrikeThreatGraph()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🔗 THREAT RELATIONSHIP MAP")
        
        # Create a simple network visualization using plotly
        G = threat_graph.graph_data
        pos = nx.spring_layout(G)
        
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=2, color='#00ffff'),
            hoverinfo='none',
            mode='lines')
            
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            # Color nodes based on status
            status = G.nodes[node]['status']
            if status == 'malicious':
                node_color.append('#ff0000')
            elif status == 'suspicious':
                node_color.append('#ff6b00')
            else:
                node_color.append('#00ff00')
                
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="middle center",
            marker=dict(
                color=node_color,
                size=40,
                line=dict(width=2, color='white')
            )
        )
        
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=0,l=0,r=0,t=0),
                           paper_bgcolor='rgba(0,0,0,0)',
                           plot_bgcolor='rgba(0,0,0,0)',
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           height=400
                       ))
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### 🎯 THREAT INTELLIGENCE")
        st.markdown("**Detected Attack Chain:**")
        st.write("1. Initial Compromise (C2 Communication)")
        st.write("2. Lateral Movement")
        st.write("3. Data Collection")
        st.write("4. Exfiltration Attempt")
        
        st.markdown("**Recommended Actions:**")
        st.write("✅ Isolate compromised endpoints")
        st.write("✅ Block malicious IPs/Domains")
        st.write("✅ Reset compromised credentials")
        st.write("✅ Investigate lateral movement")

def render_mandiant_intelligence():
    """Mandiant-style threat intelligence"""
    st.markdown("### 🔥 MANDIANT THREAT INTELLIGENCE")
    
    threat_intel = AdvancedThreatIntelligence()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🎭 ADVERSARY PROFILES")
        
        for actor_id, actor in threat_intel.threat_actors.items():
            with st.expander(f"🔴 {actor['name']} ({actor_id})"):
                st.write(f"**Origin:** {actor['origin']}")
                st.write(f"**Primary Targets:** {', '.join(actor['targets'])}")
                st.write(f"**Known Tools:** {', '.join(actor['tools'])}")
                
                # Recent activity
                st.write("**Recent Campaigns:**")
                campaigns = [
                    f"Operation {random.choice(['Ghost', 'Shadow', 'Phantom'])}",
                    f"{random.choice(['Spear', 'Whale', 'Business'])} Phishing Campaign",
                    f"Supply Chain Compromise - {random.choice(['Software', 'Hardware', 'Firmware'])}"
                ]
                for campaign in random.sample(campaigns, 2):
                    st.write(f"- {campaign}")
    
    with col2:
        st.markdown("#### 📈 THREAT INDICATORS")
        
        indicators = [
            {'type': 'IP', 'value': '185.220.101.35', 'confidence': 'High'},
            {'type': 'Domain', 'value': 'malicious-c2.com', 'confidence': 'High'},
            {'type': 'Hash', 'value': 'a1b2c3d4...', 'confidence': 'Medium'},
            {'type': 'URL', 'value': 'http://evil.com/payload', 'confidence': 'High'}
        ]
        
        for indicator in indicators:
            st.markdown(f"""
            <div style="background: rgba(255,0,0,0.1); padding: 0.5rem; border-radius: 5px; margin: 0.2rem 0;">
                <strong>{indicator['type']}:</strong> {indicator['value']}<br>
                <small>Confidence: {indicator['confidence']}</small>
            </div>
            """, unsafe_allow_html=True)

def render_palo_alto_network():
    """Palo Alto Networks-style network security"""
    st.markdown("### 🌐 PALO ALTO NETWORK SECURITY")
    
    palo_alto = PaloAltoIntegration()
    
    tab1, tab2 = st.tabs(["🛡️ Firewall Logs", "📊 Threat Prevention"])
    
    with tab1:
        st.markdown("#### 🔥 REAL-TIME FIREWALL TRAFFIC")
        
        # Display firewall logs
        for log in palo_alto.firewall_logs[:8]:
            action_color = {
                'Allow': '#00ff00',
                'Deny': '#ffff00', 
                'Drop': '#ff0000'
            }
            
            st.markdown(f"""
            <div style="background: rgba(0,255,255,0.05); padding: 0.5rem; border-radius: 5px; margin: 0.2rem 0; border-left: 3px solid {action_color[log['action']]}">
                <strong>{log['timestamp']}</strong> | {log['source_ip']} → {log['dest_ip']}:{log['dest_port']}<br>
                <small>Action: <span style="color: {action_color[log['action']]}">{log['action']}</span> | App: {log['application']}</small>
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🚨 THREAT PREVENTION")
            threats_blocked = random.randint(500, 2000)
            st.metric("Threats Blocked (24h)", threats_blocked)
            st.metric("WildFire Submissions", random.randint(50, 200))
            st.metric("DNS Security Blocks", random.randint(100, 500))
        
        with col2:
            st.markdown("#### 📈 SECURITY EFFECTIVENESS")
            st.write("**Threat Prevention Score:** 98.7%")
            st.progress(0.987)
            st.write("**WildFire Detection Rate:** 99.2%")
            st.progress(0.992)

def render_entra_identity():
    """Microsoft Entra identity security"""
    st.markdown("### 👤 MICROSOFT ENTRA IDENTITY PROTECTION")
    
    entra = MicrosoftEntraIntegration()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🚨 IDENTITY RISK EVENTS")
        
        for risk in entra.identity_risks[:5]:
            risk_color = {
                'high': '🔴',
                'medium': '🟠',
                'low': '🟡'
            }
            
            st.markdown(f"""
            <div style="background: rgba(255,100,100,0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                <div style="display: flex; justify-content: between; align-items: center;">
                    <h4>{risk_color[risk['risk_level']]} {risk['user']}</h4>
                    <span class="threat-indicator {risk['risk_level']}">{risk['risk_level'].upper()}</span>
                </div>
                <p><strong>Risk Type:</strong> {risk['risk_type']}</p>
                <p><strong>Location:</strong> {risk['signin_location']} | <strong>Device:</strong> {risk['device']}</p>
                <p><strong>Detected:</strong> {risk['detected_time']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### 📊 IDENTITY SECURITY POSTURE")
        st.metric("Risky Users", len(entra.identity_risks))
        st.metric("MFA Adoption", "94%")
        st.metric("Privileged Accounts", "284")
        
        st.markdown("#### ⚙️ CONDITIONAL ACCESS")
        st.write("✅ MFA required for admins")
        st.write("✅ Block legacy authentication")
        st.write("✅ Require compliant devices")
        st.write("✅ Risk-based policies enabled")

def render_purview_governance():
    """Microsoft Purview data governance"""
    st.markdown("### 📊 MICROSOFT PURVIEW DATA GOVERNANCE")
    
    purview = MicrosoftPurviewIntegration()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 📁 DATA CLASSIFICATION")
        
        for item in purview.data_classification:
            sensitivity_class = item['sensitivity'].lower().replace(' ', '_')
            st.markdown(f"""
            <div style="background: rgba(0,255,255,0.05); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                <div style="display: flex; justify-content: between; align-items: center;">
                    <h4>{item['file_path']}</h4>
                    <span class="data-classification-tag {sensitivity_class}">{item['sensitivity']}</span>
                </div>
                <p><strong>Type:</strong> {item['file_type']} | <strong>Size:</strong> {item['size_mb']} MB</p>
                <p><strong>Owner:</strong> {item['owner']} | <strong>Modified:</strong> {item['last_modified']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### 📈 DATA INSIGHTS")
        
        # Data distribution pie chart
        labels = ['Public', 'General', 'Confidential', 'Highly Confidential']
        sizes = [15, 45, 30, 10]
        
        fig = px.pie(values=sizes, names=labels, title="Data Sensitivity Distribution")
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font=dict(color='white'))
        st.plotly_chart(fig, use_container_width=True)
        
        st.metric("Total Classified Files", "1.2M")
        st.metric("Sensitive Data Found", "245K")
        st.metric("Policy Violations", "47")

def render_enhanced_live_nexus():
    """Enhanced live data feed and AI analysis bot tab."""
    st.markdown("### 🧬 ENHANCED LIVE DATA NEXUS & AI ANALYST")
    st.markdown("Real-time event streams with advanced AI correlation and threat detection.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📡 ENHANCED LIVE DATA STREAM")
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
            st.session_state.enhanced_analysis_history += f"[{datetime.now().strftime('%H:%M:%S')}] {new_analysis}\n"
            
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
    
    return f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} [{level}] {log}"

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

# --- INTEGRATE NEW FEATURES INTO MAIN APPLICATION ---

def render_enhanced_threat_intelligence():
    """Enhanced threat intelligence dashboard combining all sources"""
    st.markdown("### 🌐 ENHANCED THREAT INTELLIGENCE")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🕵️ Mandiant Intel", 
        "🔍 Sentinel Incidents", 
        "🕸️ CrowdStrike Graph",
        "🌐 Palo Alto Network", 
        "👤 Entra Identity"
    ])
    
    with tab1:
        render_mandiant_intelligence()
    with tab2:
        render_sentinel_incidents()
    with tab3:
        render_crowdstrike_threat_graph()
    with tab4:
        render_palo_alto_network()
    with tab5:
        render_entra_identity()

def render_enhanced_data_governance():
    """Enhanced data governance and compliance"""
    st.markdown("### 📊 ENHANCED DATA GOVERNANCE & COMPLIANCE")
    
    tab1, tab2, tab3 = st.tabs(["📁 Purview Governance", "📜 Compliance", "🛡️ Security Controls"])
    
    with tab1:
        render_purview_governance()
    with tab2:
        # Enhanced compliance dashboard
        st.markdown("#### 📜 COMPLIANCE DASHBOARD")
        frameworks = {
            'NIST': {'name': 'NIST CSF', 'compliance': 92, 'controls': 108},
            'ISO27001': {'name': 'ISO 27001', 'compliance': 95, 'controls': 114},
            'SOC2': {'name': 'SOC 2', 'compliance': 98, 'controls': 64},
            'GDPR': {'name': 'GDPR', 'compliance': 91, 'controls': 99},
            'HIPAA': {'name': 'HIPAA', 'compliance': 94, 'controls': 75},
            'PCI-DSS': {'name': 'PCI DSS', 'compliance': 96, 'controls': 300}
        }
        
        cols = st.columns(len(frameworks))
        for i, (framework_id, framework) in enumerate(frameworks.items()):
            with cols[i]:
                st.metric(framework['name'], f"{framework['compliance']}%")
                st.caption(f"{framework['controls']} controls")
    with tab3:
        st.markdown("#### 🛡️ SECURITY CONTROLS STATUS")
        controls = [
            {"name": "Endpoint Protection", "status": "Enabled", "health": "Healthy"},
            {"name": "Network Segmentation", "status": "Enabled", "health": "Healthy"},
            {"name": "Data Loss Prevention", "status": "Enabled", "health": "Warning"},
            {"name": "Identity Protection", "status": "Enabled", "health": "Healthy"},
            {"name": "Cloud Security", "status": "Enabled", "health": "Healthy"},
            {"name": "Email Security", "status": "Enabled", "health": "Critical"}
        ]
        
        for control in controls:
            status_color = {
                "Healthy": "🟢",
                "Warning": "🟡", 
                "Critical": "🔴"
            }
            st.write(f"{status_color[control['health']]} **{control['name']}** - {control['status']}")

# Update the main application class to include new integrations
class HolographicThreatIntelligence:
    """Enhanced main application state class with all integrations"""
    
    def __init__(self):
        self.live_data = LiveDataIntegration()
        self.threat_simulator = QuantumThreatSimulator()
        self.quantum_neural_net = QuantumNeuralNetwork()
        self.cisa_integration = self.live_data
        self.mitre_integration = self.live_data
        
        # Initialize the enhanced components
        self.threat_intel = AdvancedThreatIntelligence()
        self.xdr = XDRIntegration()
        self.cloud_security = CloudSecurityModule()
        self.compliance = ComplianceManager()
        
        # New enhanced integrations
        self.sentinel = MicrosoftSentinelIntegration()
        self.crowdstrike = CrowdStrikeThreatGraph()
        self.entra = MicrosoftEntraIntegration()
        self.purview = MicrosoftPurviewIntegration()
        self.palo_alto = PaloAltoIntegration()

# Update the main tabs to include enhanced features
def main():
    with quantum_resource_manager():
        # Initialize session state with enhanced features
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
            
            # Enhanced quick stats in sidebar
            st.markdown("### 📊 Enhanced Stats")
            st.metric("Active Threats", f"{random.randint(8, 32)}")
            st.metric("Systems Monitored", f"{random.randint(1000, 5000)}")
            st.metric("Incidents Today", f"{random.randint(5, 25)}")
            st.metric("AI Confidence", f"{random.randint(92, 99)}%")

        if st.session_state.mode == "Locked":
            st.title("Welcome to the Enhanced NEXUS-7 Quantum Neural Defense Matrix")
            st.warning("Please select a mode from the sidebar to continue.")
            st.stop()
            
        # --- ENHANCED HEADER ---
        st.markdown("""
        <div class="neuro-header">
            <h1 class="neuro-text" style="font-size: 4rem; margin: 0;">🧠 NEXUS-7 QUANTUM NEURAL MATRIX</h1>
            <h3 class="hologram-text" style="font-size: 1.8rem; margin: 1rem 0;">
                Enhanced Threat Intelligence • Multi-Source Correlation • Advanced AI Defense
            </h3>
            <p style="color: #00ffff; font-family: 'Exo 2'; font-size: 1.2rem;">
                Mode: <strong>{}</strong> | AI Confidence: {}% | Last Updated: {}
            </p>
        </div>
        """.format(st.session_state.mode, random.randint(92, 99), datetime.now().strftime("%Y-%m-%d %H:%M:%S")), unsafe_allow_html=True)
        
        # --- ENHANCED QUICK ACTIONS ---
        st.markdown("### 🚀 ENHANCED QUICK ACTIONS")
        cols = st.columns(6)
        with cols[0]:
            if st.button("🔗 Connect All Feeds", use_container_width=True):
                st.session_state.cisa_connected = True
                st.session_state.mitre_connected = True
                st.success("All Intelligence Feeds Connected!")
        with cols[1]:
            if st.button("🎯 Run Correlation", use_container_width=True):
                with st.spinner("🌀 Running advanced correlation analysis..."):
                    time.sleep(2)
                    st.success("Correlation Complete!")
        with cols[2]:
            if st.button("🧠 AI Deep Analysis", use_container_width=True):
                with st.spinner("🧠 Executing neural threat analysis..."):
                    time.sleep(3)
                    st.success("Deep Analysis Complete!")
        with cols[3]:
            if st.button("📊 Enhanced Report", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
                st.info("Enhanced report generation initiated.")
        with cols[4]:
            if st.button("🔄 Refresh All", use_container_width=True):
                st.rerun()
        with cols[5]:
            if st.button("🚨 Quantum Protocol", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
                st.error("🚨 QUANTUM EMERGENCY PROTOCOL ACTIVATED!")

        # --- ENHANCED QUANTUM METRICS ---
        st.markdown("### 📊 ENHANCED REAL-TIME METRICS")
        m_cols = st.columns(8)
        metrics = ["🌌 Quantum Coherence", "🧠 Neural Activity", "⚡ Threat Velocity", "🔗 Entanglement", "🌊 Temporal Stability", "🛡️ Holographic Shield", "🔍 AI Accuracy", "🎯 Correlation Power"]
        for i, col in enumerate(m_cols):
            with col:
                st.markdown('<div class="quantum-metric">', unsafe_allow_html=True)
                st.metric(metrics[i], f"{random.uniform(0.85, 0.99):.1%}", f"{random.uniform(1, 5):+.1f}%")
                st.markdown('</div>', unsafe_allow_html=True)
        
        # --- ENHANCED MAIN TABS ---
        tabs = st.tabs([
            "🧠 NEURAL MATRIX",
            "🧬 ENHANCED LIVE NEXUS", 
            "🎮 QUANTUM SIMULATOR",
            "🌐 ENHANCED THREAT INTEL",  # Combined: Mandiant, Sentinel, CrowdStrike, Palo Alto, Entra
            "🛡️ DEFENSE OPERATIONS",  
            "📊 ENHANCED GOVERNANCE",   # Combined: Purview, Compliance, Controls
            "⚡ RESPONSE & TESTING"
        ])
        
        with tabs[0]: 
            render_neural_matrix()
        with tabs[1]: 
            render_enhanced_live_nexus()  # Enhanced version
        with tabs[2]: 
            render_quantum_simulator()
        with tabs[3]: 
            render_enhanced_threat_intelligence()  # Combined threat intel
        with tabs[4]: 
            render_unified_defense()
        with tabs[5]: 
            render_enhanced_data_governance()  # Enhanced governance
        with tabs[6]: 
            render_automated_response()

if __name__ == "__main__":
    main()
