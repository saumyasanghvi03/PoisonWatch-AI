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

# --- ADVANCED CYBER CSS ---
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
</style>
""", unsafe_allow_html=True)

@contextmanager
def quantum_resource_manager():
    """Advanced resource management"""
    try:
        yield
    finally:
        gc.collect()

# --- BACKEND CLASSES (No changes from original) ---

class LiveDataIntegration:
    """Live data integration from multiple threat intelligence sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def fetch_cisa_alerts(self):
        """Fetch live CISA alerts"""
        try:
            url = "https://www.cisa.gov/news-events/cybersecurity-advisories"
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            alerts = []
            advisory_items = soup.find_all('div', class_='c-view__row')[:5]
            
            for item in advisory_items:
                try:
                    title_elem = item.find('h3', class_='c-teaser__title').find('a')
                    date_elem = item.find('time')
                    
                    if title_elem and date_elem:
                        alert = {
                            "title": title_elem.text.strip(),
                            "link": "https://www.cisa.gov" + title_elem.get('href', ''),
                            "date": date_elem.text.strip(),
                            "severity": self._classify_cisa_severity(title_elem.text),
                            "source": "CISA",
                            "type": "Advisory"
                        }
                        alerts.append(alert)
                except:
                    continue
            
            if not alerts:
                alerts = self._get_simulated_cisa_alerts()
                
            return alerts
            
        except Exception as e:
            st.error(f"Error fetching CISA data: {str(e)}")
            return self._get_simulated_cisa_alerts()
    
    def _classify_cisa_severity(self, title):
        title_lower = title.lower()
        if any(word in title_lower for word in ['critical', 'emergency', 'immediate']):
            return "CRITICAL"
        elif any(word in title_lower for word in ['high', 'urgent']):
            return "HIGH"
        elif any(word in title_lower for word in ['medium', 'moderate']):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_simulated_cisa_alerts(self):
        return [
            {"title": "Critical Vulnerability in Network Infrastructure Devices", "link": "https://www.cisa.gov", "date": "2025-10-17", "severity": "CRITICAL", "source": "CISA", "type": "Advisory"},
            {"title": "Phishing Campaign Targeting Financial Sector", "link": "https://www.cisa.gov", "date": "2025-10-15", "severity": "HIGH", "source": "CISA", "type": "Alert"}
        ]
    
    def fetch_mitre_techniques(self):
        """Fetch MITRE ATT&CK techniques"""
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                techniques = []
                
                for obj in data['objects']:
                    if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
                        ext_refs = obj.get('external_references', [])
                        mitre_id = next((ref['external_id'] for ref in ext_refs if ref.get('source_name') == 'mitre-attack'), None)
                        
                        if mitre_id and mitre_id.startswith('T'):
                            technique = {
                                "id": mitre_id,
                                "name": obj.get('name', ''),
                                "description": obj.get('description', ''),
                                "tactic": obj.get('kill_chain_phases', [{}])[0].get('phase_name', '') if obj.get('kill_chain_phases') else '',
                                "platforms": obj.get('x_mitre_platforms', []),
                                "data_sources": obj.get('x_mitre_data_sources', [])
                            }
                            techniques.append(technique)
                
                return techniques[:10]
            else:
                return self._get_simulated_mitre_techniques()
                
        except Exception as e:
            st.error(f"Error fetching MITRE data: {str(e)}")
            return self._get_simulated_mitre_techniques()
    
    def _get_simulated_mitre_techniques(self):
        return [
            {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "description": "...", "tactic": "Initial Access", "platforms": ["Windows", "Linux"], "data_sources": ["Email Gateway"]},
            {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "description": "...", "tactic": "Execution", "platforms": ["Windows"], "data_sources": ["Process Monitoring"]}
        ]
    
    def fetch_vulnerability_data(self):
        """Fetch recent vulnerability data from NVD"""
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'N/A')
                    description = next((desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'), 'No description available.')
                    
                    cvss_score = "N/A"
                    severity = "UNKNOWN"
                    if 'cvssMetricV31' in cve.get('metrics', {}):
                        metric = cve['metrics']['cvssMetricV31'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        severity = metric['cvssData']['baseSeverity']

                    vulnerability = {
                        "cve_id": cve_id,
                        "description": description[:200] + "...",
                        "cvss_score": cvss_score,
                        "published_date": cve.get('published', ''),
                        "severity": severity
                    }
                    vulnerabilities.append(vulnerability)
                
                return vulnerabilities
            else:
                return self._get_simulated_vulnerabilities()
                
        except Exception as e:
            st.error(f"Error fetching vulnerability data: {str(e)}")
            return self._get_simulated_vulnerabilities()

    def _get_simulated_vulnerabilities(self):
        return [
            {"cve_id": "CVE-2025-12345", "description": "Remote code execution vulnerability...", "cvss_score": 9.8, "published_date": "2025-10-15", "severity": "CRITICAL"},
            {"cve_id": "CVE-2025-12346", "description": "Privilege escalation in OS kernel...", "cvss_score": 7.8, "published_date": "2025-10-14", "severity": "HIGH"}
        ]

class QuantumThreatSimulator:
    def __init__(self):
        self.simulation_history = []
        self.active_scenarios = []
    
    def create_threat_scenario(self, scenario_type, intensity, target_sector, duration):
        scenario_id = f"SIM-{random.randint(10000, 99999)}"
        scenario_templates = {
            'ransomware': {'name': 'Quantum Ransomware Attack', 'description': '...', 'indicators': ['...'], 'mitre_techniques': ['T1486', 'T1566.001', 'T1059.003']},
            'supply_chain': {'name': 'Supply Chain Compromise', 'description': '...', 'indicators': ['...'], 'mitre_techniques': ['T1195.002', 'T1554', 'T1071']},
            'ai_poisoning': {'name': 'AI Model Poisoning', 'description': '...', 'indicators': ['...'], 'mitre_techniques': ['T1565.001', 'T1591', 'T1588']},
            'zero_day': {'name': 'Zero-Day Exploitation', 'description': '...', 'indicators': ['...'], 'mitre_techniques': ['T1190', 'T1068', 'T1210']}
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
    # Class remains the same
    def predict_quantum_threat(self, input_data):
        return max(0.1, min(0.99, random.uniform(0.4, 0.9)))

class HolographicThreatIntelligence:
    """Main application state class"""
    def __init__(self):
        self.live_data = LiveDataIntegration()
        self.threat_simulator = QuantumThreatSimulator()
        self.quantum_neural_net = QuantumNeuralNetwork()
        self.cisa_integration = self.live_data
        self.mitre_integration = self.live_data

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
    ]
    users = ["admin", "j.doe", "s.smith", "guest", "root"]
    ips = [f"192.168.1.{random.randint(10, 200)}", "10.0.0.5", "203.0.113.88"]
    files = ["/etc/passwd", "/var/www/config.php", "C:\\Users\\s.smith\\Documents\\project_alpha.docx"]
    resources = ["/api/v1/admin", "/db/customer_records"]
    servers = ["WEB_PROD_01", "DB_MASTER_A", "AUTH_SRV_3"]
    
    level, template = random.choice(log_templates)
    log = template.format(
        user=random.choice(users), 
        ip=random.choice(ips),
        file=random.choice(files),
        resource=random.choice(resources),
        server=random.choice(servers),
        malicious_ip=f"123.45.67.{random.randint(1,254)}"
    )
    return f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level}]: {log}"

def analyze_log(log):
    """Generates an AI analysis for a given log entry."""
    log_lower = log.lower()
    if "critical" in log_lower or "brute-force" in log_lower:
        return "🚨 CRITICAL THREAT: Brute-force attack detected. Recommending immediate IP block and user account lockdown. Escalating to Tier 2 SOC."
    if "failed login" in log_lower:
        return "⚠️ WARNING: Failed authentication. Correlating with other attempts from this IP. Monitoring for suspicious patterns."
    if "unusual outbound traffic" in log_lower:
        return "🔥 HIGH SEVERITY: Potential C2 communication or data exfiltration. Initiating automated network isolation playbook for the source IP."
    if "access denied" in log_lower:
        return "🧐 ANOMALY: Unauthorized access attempt. Checking user's typical behavior and permissions. Flagged for review."
    if "successful login" in log_lower:
        if "admin" in log_lower or "root" in log_lower:
            return "ℹ️ INFO: Privileged account login detected. Verifying against location and time heuristics. No anomalies found."
        return "ℹ️ INFO: Standard user login. Activity appears normal."
    return "✅ INFO: Routine system event. No action required."


# --- UI RENDERING FUNCTIONS ---

def render_neural_matrix():
    st.markdown("### 🧠 QUANTUM NEURAL THREAT MATRIX")
    # This function remains largely the same, using random data for demonstration.
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("#### 🚨 REAL-TIME THREAT MATRIX")
        threats_data = []
        for i in range(8):
            threat = {
                'ID': f"QT-{random.randint(10000, 99999)}",
                'Type': random.choice(['AI Model Poisoning', 'Supply Chain', 'Zero-Day', 'Ransomware']),
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
    # This function remains the same.
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
    # This function remains the same.
    simulator = st.session_state.holographic_intel.threat_simulator
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("#### ⚙️ SIMULATION CONTROLS")
        scenario_type = st.selectbox("Threat Scenario Type:", ["ransomware", "supply_chain", "ai_poisoning", "zero_day"], format_func=lambda x: x.replace("_", " ").title())
        intensity = st.slider("Attack Intensity", 0.1, 1.0, 0.7, 0.1)
        if st.button("🚀 LAUNCH SIMULATION", use_container_width=True, disabled=(st.session_state.get('mode') != 'Admin')):
            scenario = simulator.create_threat_scenario(scenario_type, intensity, "Financial", 30)
            st.session_state.active_simulations.append(scenario)
            st.success(f"🎯 Simulation {scenario['id']} Launched!")
    
    with col2:
        st.markdown("#### 📊 SIMULATION ANALYTICS")
        analytics = simulator.get_simulation_analytics()
        st.metric("Total Simulations", analytics['total_simulations'])
        st.metric("Average Risk Score", f"{analytics['average_risk']:.1%}")
        st.metric("Most Common Scenario", analytics['most_common_scenario'].replace("_", " ").title())

def render_live_cisa_data():
    # This function remains the same.
    st.markdown("### 🔗 LIVE CISA THREAT INTELLIGENCE")
    if not st.session_state.cisa_connected:
        st.warning("⚠️ Connect to CISA data to view live intelligence.")
        return
    cisa_alerts = st.session_state.holographic_intel.cisa_integration.fetch_cisa_alerts()
    for alert in cisa_alerts:
        with st.expander(f"{alert['severity']} - {alert['title']}"):
            st.write(f"**Date:** {alert['date']}")
            st.markdown(f"[View Alert]({alert['link']})")

def render_live_mitre_data():
    # This function remains the same.
    st.markdown("### 🎯 LIVE MITRE ATT&CK FRAMEWORK")
    if not st.session_state.mitre_connected:
        st.warning("⚠️ Connect to MITRE data to view attack framework.")
        return
    mitre_techniques = st.session_state.holographic_intel.mitre_integration.fetch_mitre_techniques()
    for technique in mitre_techniques[:5]:
        with st.expander(f"{technique['id']} - {technique['name']}"):
            st.write(f"**Tactic:** {technique['tactic']}")
            st.write(f"**Description:** {technique['description']}")

def render_global_threat_map():
    # This function remains the same.
    st.markdown("### 🌍 GLOBAL THREAT INTELLIGENCE MAP")
    countries = [
        {'country': 'United States', 'lat': 38.9, 'lon': -77.0, 'threat': 0.95},
        {'country': 'China', 'lat': 39.9, 'lon': 116.4, 'threat': 0.9},
        {'country': 'Russia', 'lat': 55.7, 'lon': 37.6, 'threat': 0.85},
    ]
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    for c in countries:
        folium.Marker([c['lat'], c['lon']], tooltip=f"{c['country']} - Threat: {c['threat']:.1%}", icon=folium.Icon(color='red')).add_to(m)
    folium_static(m, width=1000, height=500)

def render_vulnerability_intel():
    # This function remains the same.
    st.markdown("### 📊 VULNERABILITY INTELLIGENCE DASHBOARD")
    vulnerabilities = st.session_state.holographic_intel.live_data.fetch_vulnerability_data()
    for vuln in vulnerabilities[:5]:
        with st.expander(f"{vuln['cve_id']} - CVSS: {vuln['cvss_score']} - {vuln['severity']}"):
            st.write(f"**Description:** {vuln['description']}")

def render_defense_operations():
    # This function remains the same.
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

# --- NEW TAB RENDERING FUNCTIONS ---

def render_live_nexus():
    """Renders the live data feed and AI analysis bot tab."""
    st.markdown("### 🧬 LIVE DATA NEXUS & AI ANALYST")
    st.markdown("Simulating real-time event streams from across the infrastructure. The **NEXUS-7 AI Analyst** interprets data to identify threats.")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 📡 LIVE DATA INPUT STREAM")
        log_placeholder = st.empty()
        
    with col2:
        st.markdown("#### 🤖 NEXUS-7 AI ANALYST")
        analysis_placeholder = st.empty()

    log_history = "Initializing log stream...\n"
    analysis_history = "AI Analyst is online. Awaiting data...\n"
    
    log_placeholder.markdown(f'<div class="log-container">{log_history}</div>', unsafe_allow_html=True)
    analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{analysis_history}</div>', unsafe_allow_html=True)
    
    # This loop simulates live data. In a real app, this would be an async stream.
    for i in range(10): # Limit to 10 iterations for demo purposes
        new_log = get_simulated_log()
        log_history += f"{new_log}\n"
        
        new_analysis = analyze_log(new_log)
        analysis_history += f"[{datetime.now().strftime('%H:%M:%S')}] {new_analysis}\n"
        
        # Auto-scroll effect by slicing the history
        log_display = "<br>".join(log_history.split("\n")[-15:])
        analysis_display = "<br>".join(analysis_history.split("\n")[-15:])
        
        log_placeholder.markdown(f'<div class="log-container">{log_display}</div>', unsafe_allow_html=True)
        analysis_placeholder.markdown(f'<div class="log-container" style="border-color: #00ffff;">{analysis_display}</div>', unsafe_allow_html=True)
        time.sleep(random.uniform(1.5, 3.0))

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

    with col2:
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

        # --- MODE SELECTION (LOGIN) ---
        if 'mode' not in st.session_state:
            st.session_state.mode = "Locked"

        with st.sidebar:
            st.markdown("<h1 class='neuro-text'>NEXUS-7</h1>", unsafe_allow_html=True)
            st.markdown("---")
            if st.session_state.mode == "Locked":
                st.info("Enter PIN to unlock Admin Mode or proceed in Demo Mode.")
                pin = st.text_input("Admin PIN:", type="password")
                if st.button("Unlock"):
                    if pin == "100370":
                        st.session_state.mode = "Admin"
                        st.success("Admin Mode Unlocked!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Incorrect PIN.")
                if st.button("Continue in Demo Mode"):
                    st.session_state.mode = "Demo"
                    st.rerun()
            else:
                st.success(f"Mode: **{st.session_state.mode}**")
                if st.button("Lock System"):
                    st.session_state.mode = "Locked"
                    st.rerun()

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
        </div>
        """, unsafe_allow_html=True)
        
        # --- QUICK ACTIONS ---
        st.markdown("### 🚀 QUICK ACTIONS")
        cols = st.columns(5)
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
            "🧬 LIVE NEXUS & AI", # NEW
            "🎮 QUANTUM SIMULATOR",
            "👤 IDENTITY & ACCESS", # NEW
            "⚙️ AUTOMATED SOAR", # NEW
            "📂 DATA GOVERNANCE", # NEW
            "🔗 LIVE CISA DATA",
            "🎯 LIVE MITRE DATA",
            "🌍 GLOBAL THREAT MAP",
            "📊 VULNERABILITY INTEL",
            "🛡️ DEFENSE OPS"
        ])
        
        with tabs[0]: render_neural_matrix()
        with tabs[1]: render_live_nexus()
        with tabs[2]: render_quantum_simulator()
        with tabs[3]: render_identity_matrix()
        with tabs[4]: render_soar_playbooks()
        with tabs[5]: render_data_governance()
        with tabs[6]: render_live_cisa_data()
        with tabs[7]: render_live_mitre_data()
        with tabs[8]: render_global_threat_map()
        with tabs[9]: render_vulnerability_intel()
        with tabs[10]: render_defense_operations()

if __name__ == "__main__":
    main()
