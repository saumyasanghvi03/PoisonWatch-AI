import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import requests
import json
from datetime import datetime, timedelta
import random
import time
from streamlit_autorefresh import st_autorefresh

# Page configuration for cyber news theme
st.set_page_config(
    page_title="CYBER THREAT INTELLIGENCE PLATFORM | Live Data Poisoning Monitor",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for cyber news theme
st.markdown("""
<style>
    .breaking-news {
        background: linear-gradient(90deg, #ff0000, #ff6b6b);
        color: white;
        padding: 10px;
        border-radius: 5px;
        animation: blink 2s infinite;
        text-align: center;
        font-weight: bold;
        font-size: 1.2rem;
        margin-bottom: 1rem;
    }
    @keyframes blink {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .threat-level-critical {
        background-color: #ff0000;
        color: white;
        padding: 5px 10px;
        border-radius: 15px;
        font-weight: bold;
    }
    .threat-level-high {
        background-color: #ff6b00;
        color: white;
        padding: 5px 10px;
        border-radius: 15px;
        font-weight: bold;
    }
    .news-ticker {
        background-color: #1a1a1a;
        color: #00ff00;
        padding: 10px;
        border: 1px solid #00ff00;
        font-family: 'Courier New', monospace;
        overflow: hidden;
        white-space: nowrap;
    }
    .cyber-header {
        background: linear-gradient(135deg, #1a1a1a 0%, #003366 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        border-left: 5px solid #00ff00;
        margin-bottom: 2rem;
    }
    .incident-card {
        background-color: #1a1a1a;
        border: 1px solid #333;
        border-radius: 5px;
        padding: 1rem;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    .incident-card:hover {
        border-color: #00ff00;
        transform: translateY(-2px);
    }
</style>
""", unsafe_allow_html=True)

class CyberThreatIntelligence:
    def __init__(self):
        self.threat_feeds = self.initialize_threat_feeds()
        
    def initialize_threat_feeds(self):
        """Initialize simulated threat intelligence feeds"""
        return {
            'ransomware_groups': ['LockBit', 'BlackCat', 'Clop', 'BlackBasta', 'Vice Society'],
            'apt_groups': ['APT29', 'Lazarus Group', 'Equation Group', 'Sandworm Team'],
            'malware_families': ['PoisonIvy', 'CarbonStealer', 'QuantumRAT', 'DarkGate']
        }
    
    def generate_live_incidents(self):
        """Generate simulated live cyber incidents"""
        incidents = []
        current_time = datetime.now()
        
        incident_templates = [
            {
                "type": "Data Poisoning Attack",
                "targets": ["Financial AI", "Healthcare ML", "Autonomous Systems", "Fraud Detection"],
                "actors": ["Nation-State", "Cybercrime Group", "Insider Threat", "Competitor"],
                "techniques": ["Backdoor Injection", "Label Manipulation", "Model Evasion", "Training Data Corruption"]
            }
        ]
        
        for i in range(8):
            template = random.choice(incident_templates)
            incident = {
                "id": f"INC-{random.randint(10000, 99999)}",
                "timestamp": current_time - timedelta(minutes=random.randint(1, 240)),
                "type": template["type"],
                "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                "target": random.choice(template["targets"]),
                "actor": random.choice(template["actors"]),
                "technique": random.choice(template["techniques"]),
                "status": random.choice(["Active", "Contained", "Investigating"]),
                "confidence": random.randint(70, 98)
            }
            incidents.append(incident)
        
        return sorted(incidents, key=lambda x: x['timestamp'], reverse=True)
    
    def get_cyber_news_feed(self):
        """Simulate cyber news feed - in production, integrate with NewsAPI or similar"""
        news_items = [
            {
                "headline": "Major Bank's AI System Compromised by Data Poisoning Attack",
                "source": "CyberScoop",
                "timestamp": "2 hours ago",
                "category": "Breach",
                "impact": "High"
            },
            {
                "headline": "New PoisonGPT Variant Targeting Financial Institutions",
                "source": "The Record",
                "timestamp": "4 hours ago",
                "category": "Malware",
                "impact": "Critical"
            },
            {
                "headline": "CISA Issues Emergency Directive on AI System Security",
                "source": "CISA.gov",
                "timestamp": "6 hours ago",
                "category": "Advisory",
                "impact": "High"
            },
            {
                "headline": "Researchers Uncover Massive Training Data Manipulation Campaign",
                "source": "BleepingComputer",
                "timestamp": "8 hours ago",
                "category": "Research",
                "impact": "Medium"
            }
        ]
        return news_items

def main():
    # Initialize threat intelligence
    threat_intel = CyberThreatIntelligence()
    
    # Auto-refresh every 30 seconds for live data
    st_autorefresh(interval=30000, key="data_refresh")
    
    # Breaking news banner
    st.markdown('<div class="breaking-news">🚨 BREAKING: Global AI Systems Under Data Poisoning Attack - Multiple Financial Institutions Affected</div>', unsafe_allow_html=True)
    
    # Cyber news header
    st.markdown("""
    <div class="cyber-header">
        <h1 style="margin:0; color: #00ff00;">🔴 CYBER THREAT INTELLIGENCE PLATFORM</h1>
        <h3 style="margin:0; color: white;">Live Data Poisoning & AI Security Monitor</h3>
        <p style="margin:0; color: #cccccc;">Real-time monitoring of adversarial attacks on AI systems worldwide</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar with threat dashboard
    with st.sidebar:
        st.markdown("### 🛰️ LIVE THREAT DASHBOARD")
        
        # Current threat level
        st.markdown("#### Current Threat Level:")
        threat_level = random.choice(["CRITICAL", "HIGH", "ELEVATED"])
        if threat_level == "CRITICAL":
            st.markdown('<div class="threat-level-critical">🔴 CRITICAL</div>', unsafe_allow_html=True)
        elif threat_level == "HIGH":
            st.markdown('<div class="threat-level-high">🟠 HIGH</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="background-color: #ffcc00; color: black; padding: 5px 10px; border-radius: 15px; font-weight: bold;">🟡 ELEVATED</div>', unsafe_allow_html=True)
        
        st.metric("Active Incidents", "47", "+8 today")
        st.metric("Data Poisoning Cases", "23", "+5 today")
        st.metric("Global Impact", "$2.1B", "Estimated damage")
        
        st.markdown("---")
        st.markdown("### 📡 THREAT FEEDS")
        st.info("""
        **Monitoring:**
        - Dark Web Forums
        - CERT Feeds
        - Security Vendor Intel
        - Social Media Channels
        """)
    
    # Main content area
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🌐 LIVE THREAT MAP", 
        "📈 ATTACK SIMULATOR", 
        "📰 CYBER NEWS", 
        "🔍 INCIDENT INVESTIGATION",
        "🛡️ MITIGATION CENTER"
    ])
    
    with tab1:
        render_live_threat_map(threat_intel)
    
    with tab2:
        render_attack_simulator()
    
    with tab3:
        render_cyber_news(threat_intel)
    
    with tab4:
        render_incident_investigation(threat_intel)
    
    with tab5:
        render_mitigation_center()

def render_live_threat_map(threat_intel):
    """Render live global threat map"""
    
    st.markdown("### 🌐 LIVE GLOBAL THREAT MAP")
    st.markdown("*Real-time visualization of data poisoning attacks worldwide*")
    
    # Generate simulated attack data
    countries = ['USA', 'India', 'China', 'Germany', 'UK', 'Japan', 'Brazil', 'Australia', 'Russia', 'France']
    attack_data = []
    
    for country in countries:
        attacks = random.randint(5, 50)
        severity = random.choice(['Low', 'Medium', 'High', 'Critical'])
        attack_data.append({
            'country': country,
            'attacks': attacks,
            'severity': severity,
            'latitude': random.uniform(-60, 80),
            'longitude': random.uniform(-180, 180)
        })
    
    attack_df = pd.DataFrame(attack_data)
    
    # Create animated threat map
    fig = px.scatter_geo(attack_df, 
                        lat='latitude', 
                        lon='longitude',
                        size='attacks',
                        color='severity',
                        hover_name='country',
                        size_max=30,
                        title='Live Data Poisoning Attacks - Global Distribution',
                        color_discrete_map={
                            'Low': 'green',
                            'Medium': 'yellow', 
                            'High': 'orange',
                            'Critical': 'red'
                        })
    
    fig.update_layout(geo=dict(showframe=False, 
                              showcoastlines=True,
                              projection_type='equirectangular'))
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Live incident feed
    st.markdown("### 📋 LIVE INCIDENT FEED")
    incidents = threat_intel.generate_live_incidents()
    
    for incident in incidents[:5]:
        severity_color = {
            "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"
        }
        
        with st.container():
            col1, col2, col3, col4 = st.columns([1, 2, 2, 1])
            with col1:
                st.write(f"{severity_color[incident['severity']]} {incident['id']}")
            with col2:
                st.write(f"**{incident['type']}**")
                st.write(f"Target: {incident['target']}")
            with col3:
                st.write(f"Actor: {incident['actor']}")
                st.write(f"Technique: {incident['technique']}")
            with col4:
                st.write(f"Confidence: {incident['confidence']}%")
            
            st.progress(incident['confidence']/100, text=f"Investigation Progress")
            st.markdown("---")

def render_attack_simulator():
    """Render interactive attack simulator with real-world scenarios"""
    
    st.markdown("### 💀 ADVERSARIAL ATTACK SIMULATOR")
    st.markdown("*Test your defenses against real-world data poisoning techniques*")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎯 Attack Scenarios")
        scenario = st.selectbox(
            "Choose Attack Scenario:",
            [
                "Financial Fraud AI Evasion",
                "Healthcare Diagnosis Manipulation", 
                "Autonomous Vehicle Sensor Spoofing",
                "Social Media Recommendation Poisoning",
                "Supply Chain AI Compromise"
            ]
        )
        
        attack_complexity = st.slider("Attack Complexity", 1, 10, 7)
        stealth_level = st.slider("Stealth Level", 1, 10, 8)
        persistence = st.slider("Persistence", 1, 10, 6)
    
    with col2:
        st.markdown("#### 📊 Attack Impact Assessment")
        
        # Calculate impact scores
        detection_probability = max(10, 100 - (attack_complexity * 6 + stealth_level * 4))
        business_impact = (attack_complexity + stealth_level + persistence) * 3
        recovery_time = persistence * 2 + attack_complexity
        
        st.metric("Detection Probability", f"{detection_probability}%", "-15% from baseline")
        st.metric("Business Impact", f"${business_impact}M", "Estimated damage")
        st.metric("Recovery Time", f"{recovery_time} days", "+7 days average")
        
        if st.button("🚀 Launch Simulation", type="primary"):
            with st.spinner("Executing adversarial simulation..."):
                time.sleep(2)
                st.error("🚨 Simulation Complete: System compromised in 3.2 seconds")
                st.balloons()

def render_cyber_news(threat_intel):
    """Render cyber news feed with latest incidents"""
    
    st.markdown("### 📰 CYBER SECURITY NEWS FEED")
    st.markdown("*Latest updates on AI security threats and data poisoning incidents*")
    
    news_items = threat_intel.get_cyber_news_feed()
    
    for news in news_items:
        with st.container():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"#### {news['headline']}")
                st.markdown(f"*Source: {news['source']} | {news['timestamp']}*")
            with col2:
                impact_color = "red" if news['impact'] == 'Critical' else "orange" if news['impact'] == 'High' else "yellow"
                st.markdown(f'<span style="color: {impact_color}; font-weight: bold;">{news["impact"]} Impact</span>', unsafe_allow_html=True)
            
            st.markdown("---")
    
    # News ticker simulation
    st.markdown("### 📡 LIVE NEWS TICKER")
    ticker_items = [
        "ALERT: New PoisonGPT variant detected in wild - targeting financial AI systems",
        "BREAKING: Major cloud provider reports sophisticated data poisoning campaign",
        "UPDATE: CISA releases new guidelines for AI system security",
        "WARNING: Rise in insider threats targeting machine learning pipelines"
    ]
    
    ticker_html = """
    <div class="news-ticker">
        <marquee behavior="scroll" direction="left">
    """
    for item in ticker_items:
        ticker_html += f"• {item} &nbsp;&nbsp;&nbsp;&nbsp; "
    ticker_html += """
        </marquee>
    </div>
    """
    st.markdown(ticker_html, unsafe_allow_html=True)

def render_incident_investigation(threat_intel):
    """Render incident investigation workspace"""
    
    st.markdown("### 🔍 INCIDENT INVESTIGATION WORKSPACE")
    st.markdown("*Digital forensics and threat analysis for data poisoning incidents*")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 📝 Incident Analysis")
        
        # Investigation steps
        investigation_steps = [
            ("1. Incident Detection", "AI anomaly detection triggered alert"),
            ("2. Evidence Collection", "Gathering training data logs and model artifacts"),
            ("3. Attack Vector Analysis", "Identifying poisoning techniques used"),
            ("4. Impact Assessment", "Evaluating system compromise level"),
            ("5. Containment Actions", "Implementing security measures"),
            ("6. Recovery Procedures", "Restoring system integrity")
        ]
        
        for step, description in investigation_steps:
            with st.expander(f"{step} - {description}"):
                if step == "1. Incident Detection":
                    st.write("**Detection Metrics:**")
                    st.metric("Anomaly Score", "87%", "Above threshold")
                    st.metric("Confidence", "92%", "High certainty")
                elif step == "3. Attack Vector Analysis":
                    st.write("**Identified Techniques:**")
                    st.error("✅ Backdoor Injection")
                    st.error("✅ Label Flipping")
                    st.warning("⚠️ Model Evasion")
        
        # Forensic timeline
        st.markdown("#### ⏰ Forensic Timeline")
        timeline_data = {
            'Time': ['00:00', '02:15', '04:30', '06:45', '09:00'],
            'Event': ['Initial Compromise', 'Lateral Movement', 'Data Poisoning', 'Detection Trigger', 'Containment Initiated'],
            'Severity': ['Medium', 'High', 'Critical', 'High', 'Medium']
        }
        timeline_df = pd.DataFrame(timeline_data)
        st.dataframe(timeline_df, use_container_width=True)
    
    with col2:
        st.markdown("#### 🎯 Quick Actions")
        
        if st.button("🕵️ Collect Forensic Data", use_container_width=True):
            st.success("Forensic data collection initiated")
        
        if st.button("📊 Analyze Attack Pattern", use_container_width=True):
            st.success("Attack pattern analysis completed")
        
        if st.button("🚨 Isolate Compromised Systems", use_container_width=True):
            st.error("Critical systems isolated - Investigation mode activated")
        
        if st.button("📋 Generate Incident Report", use_container_width=True):
            st.info("Incident report generated and sent to CISO")
        
        st.markdown("---")
        st.markdown("#### 🔗 Threat Intelligence")
        st.write("Connected Feeds:")
        st.checkbox("MITRE ATT&CK Database", value=True)
        st.checkbox("CISA Automated Indicator Sharing", value=True)
        st.checkbox("Vendor Threat Feeds", value=True)
        st.checkbox("Dark Web Monitoring", value=True)

def render_mitigation_center():
    """Render mitigation and response center"""
    
    st.markdown("### 🛡️ ACTIVE DEFENSE CENTER")
    st.markdown("*Real-time countermeasures and security controls*")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🚀 Defense Actions")
        
        defense_actions = [
            ("Deploy Honey Models", "Set up decoy AI systems to detect attacks"),
            ("Activate Adversarial Training", "Strengthen models against poisoning"),
            ("Enable Data Provenance", "Track data lineage and sources"),
            ("Implement Model Monitoring", "Real-time anomaly detection"),
            ("Enhance Access Controls", "Restrict training data access"),
            ("Deploy Deception Technology", "Misleading data points for attackers")
        ]
        
        for action, description in defense_actions:
            if st.button(f"🛡️ {action}", key=action, use_container_width=True):
                st.success(f"✅ {action} activated")
                st.write(f"*{description}*")
    
    with col2:
        st.markdown("#### 📊 Defense Effectiveness")
        
        # Defense metrics
        metrics = [
            ("Threat Detection Rate", 87, 92),
            ("False Positive Rate", 12, 8),
            ("Response Time (minutes)", 45, 28),
            ("System Availability", 92, 96)
        ]
        
        for metric, old_val, new_val in metrics:
            delta = new_val - old_val
            st.metric(metric, f"{new_val}%", f"{delta:+d}%")
        
        st.markdown("---")
        st.markdown("#### 🎯 Security Posture")
        
        security_score = 78
        st.markdown(f"**Overall Security Score: {security_score}/100**")
        st.progress(security_score/100)
        
        if security_score >= 80:
            st.success("✅ Strong security posture maintained")
        elif security_score >= 60:
            st.warning("⚠️ Security posture needs improvement")
        else:
            st.error("🚨 Critical security improvements required")

if __name__ == "__main__":
    main()
