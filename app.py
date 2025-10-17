import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import random
import time

# Page configuration
st.set_page_config(
    page_title="AI Under Siege: Data Poisoning Threat Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #ff7f0e;
        margin-bottom: 1rem;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
        margin-bottom: 1rem;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class DataPoisoningSimulator:
    def __init__(self):
        self.threat_levels = {
            'Low': 0.1,
            'Medium': 0.3,
            'High': 0.6,
            'Critical': 0.9
        }
    
    def generate_clean_dataset(self, n_samples=1000):
        """Generate a synthetic clean dataset for visualization"""
        np.random.seed(42)
        data = {
            'feature_1': np.random.normal(0, 1, n_samples),
            'feature_2': np.random.normal(0, 1, n_samples),
            'label': np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
        }
        return pd.DataFrame(data)
    
    def poison_dataset(self, df, poisoning_rate=0.03, attack_type='backdoor'):
        """Simulate data poisoning on the dataset"""
        poisoned_df = df.copy()
        n_poison = int(len(df) * poisoning_rate)
        
        if attack_type == 'backdoor':
            # Backdoor attack: insert malicious patterns
            poison_indices = np.random.choice(df.index, n_poison, replace=False)
            poisoned_df.loc[poison_indices, 'feature_1'] += 2.0
            poisoned_df.loc[poison_indices, 'feature_2'] += 2.0
            poisoned_df.loc[poison_indices, 'label'] = 1  # Force malicious classification
        
        elif attack_type == 'label_flip':
            # Label flipping attack
            poison_indices = np.random.choice(df.index, n_poison, replace=False)
            poisoned_df.loc[poison_indices, 'label'] = 1 - poisoned_df.loc[poison_indices, 'label']
        
        return poisoned_df, poison_indices
    
    def simulate_model_performance(self, poisoning_rate, attack_duration):
        """Simulate model performance degradation due to poisoning"""
        time_points = np.linspace(0, attack_duration, 100)
        base_accuracy = 0.95
        
        # Simulate performance degradation
        performance = base_accuracy * np.exp(-poisoning_rate * time_points)
        
        # Add some noise
        performance += np.random.normal(0, 0.02, len(performance))
        performance = np.clip(performance, 0.1, 1.0)
        
        return time_points, performance

def main():
    # Initialize simulator
    simulator = DataPoisoningSimulator()
    
    # Main header
    st.markdown('<div class="main-header">🛡️ AI Under Siege: The Data Poisoning Threat Simulator</div>', unsafe_allow_html=True)
    st.markdown("### An Interactive Exploration of AI's Critical Vulnerability in Cybersecurity Systems")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    app_section = st.sidebar.radio(
        "Select Section:",
        ["Main Dashboard", "Attack Simulator", "India Case Study", "Mitigation Dashboard", "Future Trends", "Resources"]
    )
    
    # Key metrics in sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Key Statistics")
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        st.metric("Global AI Cybersecurity Market", "$25B+", "15% YoY")
        st.metric("Poisoning Threshold", "1-3%", "Critical Level")
    
    with col2:
        st.metric("AI Fraud Growth (Mumbai)", "300%", "Year-on-Year")
        st.metric("Detection Rate", "68%", "-12% from 2022")
    
    # Main Dashboard
    if app_section == "Main Dashboard":
        render_main_dashboard(simulator)
    
    # Attack Simulator
    elif app_section == "Attack Simulator":
        render_attack_simulator(simulator)
    
    # India Case Study
    elif app_section == "India Case Study":
        render_india_case_study()
    
    # Mitigation Dashboard
    elif app_section == "Mitigation Dashboard":
        render_mitigation_dashboard()
    
    # Future Trends
    elif app_section == "Future Trends":
        render_future_trends()
    
    # Resources
    elif app_section == "Resources":
        render_resources_section()

def render_main_dashboard(simulator):
    """Render the main dashboard with overview metrics and visualizations"""
    
    st.markdown('<div class="sub-header">📈 Executive Summary & Threat Landscape</div>', unsafe_allow_html=True)
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Critical Systems at Risk", "78%", "4% increase")
    
    with col2:
        st.metric("Average Attack Cost", "$4.5M", "22% increase")
    
    with col3:
        st.metric("Detection Time", "287 days", "+45 days")
    
    with col4:
        st.metric("Prevention Success", "42%", "-8% from 2022")
    
    # Threat landscape visualization
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 🌍 Global Threat Distribution")
        
        # Generate threat data
        threats_data = {
            'Region': ['North America', 'Europe', 'Asia Pacific', 'Middle East', 'Latin America'],
            'Threat_Level': [0.85, 0.72, 0.91, 0.68, 0.59],
            'Incidents': [245, 189, 312, 87, 64]
        }
        threats_df = pd.DataFrame(threats_data)
        
        fig = px.bar(threats_df, x='Region', y='Threat_Level', 
                    color='Threat_Level', title='Data Poisoning Threat Levels by Region',
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### ⚠️ Attack Vectors")
        
        attack_vectors = {
            'Vector': ['Training Data', 'Feedback Loops', 'Model Weights', 'Supply Chain'],
            'Frequency': [45, 28, 15, 12]
        }
        vectors_df = pd.DataFrame(attack_vectors)
        
        fig = px.pie(vectors_df, values='Frequency', names='Vector', 
                    title='Primary Attack Vectors')
        st.plotly_chart(fig, use_container_width=True)
    
    # Real-time threat monitoring
    st.markdown("### 🔴 Live Threat Feed")
    
    # Simulate real-time threats
    threats = [
        {"time": "10:23:45", "severity": "High", "type": "Backdoor Injection", "system": "Financial AI", "status": "Active"},
        {"time": "10:21:12", "severity": "Critical", "type": "Label Poisoning", "system": "Healthcare ML", "status": "Contained"},
        {"time": "10:18:33", "severity": "Medium", "type": "Data Manipulation", "system": "Autonomous Systems", "status": "Investigating"},
        {"time": "10:15:07", "severity": "High", "type": "Model Evasion", "system": "Fraud Detection", "status": "Active"}
    ]
    
    for threat in threats:
        severity_color = {
            "Low": "🟢", 
            "Medium": "🟡", 
            "High": "🟠", 
            "Critical": "🔴"
        }
        
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 2, 2])
        with col1:
            st.write(f"{severity_color[threat['severity']]} {threat['time']}")
        with col2:
            st.write(threat['severity'])
        with col3:
            st.write(threat['type'])
        with col4:
            st.write(threat['system'])
        with col5:
            st.write(threat['status'])

def render_attack_simulator(simulator):
    """Render the interactive attack simulator"""
    
    st.markdown('<div class="sub-header">⚙️ Interactive Attack Simulator</div>', unsafe_allow_html=True)
    
    # Attack configuration
    col1, col2, col3 = st.columns(3)
    
    with col1:
        attack_type = st.selectbox(
            "Select Attack Type:",
            ["Training-Time Poisoning (Backdoor)", "Inference-Time Poisoning (Feedback Loop)", "Label Flipping Attack"]
        )
    
    with col2:
        poisoning_rate = st.slider(
            "Poisoning Rate (%):",
            min_value=0.1,
            max_value=10.0,
            value=3.0,
            step=0.1,
            help="Percentage of training data to poison"
        )
    
    with col3:
        attack_duration = st.slider(
            "Attack Duration (months):",
            min_value=1,
            max_value=24,
            value=6,
            step=1
        )
    
    # Generate and display datasets
    st.markdown("### 📊 Data Visualization Before & After Poisoning")
    
    # Generate clean dataset
    clean_df = simulator.generate_clean_dataset()
    
    # Poison the dataset based on selected attack type
    attack_map = {
        "Training-Time Poisoning (Backdoor)": "backdoor",
        "Inference-Time Poisoning (Feedback Loop)": "feedback",
        "Label Flipping Attack": "label_flip"
    }
    
    poisoned_df, poison_indices = simulator.poison_dataset(
        clean_df, 
        poisoning_rate=poisoning_rate/100,
        attack_type=attack_map[attack_type]
    )
    
    # Create visualization
    col1, col2 = st.columns(2)
    
    with col1:
        fig_clean = px.scatter(clean_df, x='feature_1', y='feature_2', color='label',
                              title='Clean Dataset',
                              color_continuous_scale='viridis')
        st.plotly_chart(fig_clean, use_container_width=True)
    
    with col2:
        # Highlight poisoned points
        fig_poisoned = px.scatter(poisoned_df, x='feature_1', y='feature_2', color='label',
                                 title=f'Poisoned Dataset ({poisoning_rate}% Poisoned)',
                                 color_continuous_scale='viridis')
        
        # Add markers for poisoned points
        if len(poison_indices) > 0:
            poisoned_points = poisoned_df.loc[poison_indices]
            fig_poisoned.add_trace(
                go.Scatter(
                    x=poisoned_points['feature_1'],
                    y=poisoned_points['feature_2'],
                    mode='markers',
                    marker=dict(color='red', size=8, symbol='x', line=dict(width=2)),
                    name='Poisoned Data'
                )
            )
        
        st.plotly_chart(fig_poisoned, use_container_width=True)
    
    # Model performance simulation
    st.markdown("### 📉 Model Performance Impact")
    
    time_points, performance = simulator.simulate_model_performance(
        poisoning_rate/100, 
        attack_duration
    )
    
    perf_df = pd.DataFrame({
        'Time (months)': time_points,
        'Model Accuracy': performance,
        'Attack Phase': ['Pre-Attack' if t < attack_duration/3 else 
                        'During Attack' if t < 2*attack_duration/3 else 
                        'Post-Attack' for t in time_points]
    })
    
    fig_perf = px.line(perf_df, x='Time (months)', y='Model Accuracy', 
                      color='Attack Phase',
                      title='Model Performance Degradation Over Time',
                      color_discrete_map={
                          'Pre-Attack': 'green',
                          'During Attack': 'orange',
                          'Post-Attack': 'red'
                      })
    
    # Add attack start annotation
    fig_perf.add_vline(x=attack_duration/3, line_dash="dash", line_color="red",
                      annotation_text="Attack Start")
    
    st.plotly_chart(fig_perf, use_container_width=True)
    
    # Impact analysis
    col1, col2, col3 = st.columns(3)
    
    initial_perf = performance[0]
    final_perf = performance[-1]
    performance_drop = ((initial_perf - final_perf) / initial_perf) * 100
    
    with col1:
        st.metric("Initial Accuracy", f"{initial_perf:.1%}")
    
    with col2:
        st.metric("Final Accuracy", f"{final_perf:.1%}")
    
    with col3:
        st.metric("Performance Drop", f"{performance_drop:.1f}%", delta_color="inverse")

def render_india_case_study():
    """Render the India-specific case study section"""
    
    st.markdown('<div class="sub-header">🇮🇳 India Case Study: Emerging Threats</div>', unsafe_allow_html=True)
    
    # Tabs for different aspects
    tab1, tab2, tab3 = st.tabs(["National Security", "Financial Fraud", "Public Trust"])
    
    with tab1:
        st.markdown("### 🏛️ IndiaAI Mission: National Security Implications")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("""
            **Critical Infrastructure at Risk:**
            - Healthcare allocation systems
            - Smart city infrastructure
            - National security AI systems
            - Digital public infrastructure
            
            **Potential Impact of Data Poisoning:**
            """)
            
            impacts = [
                ("Healthcare Misallocation", 0.85),
                ("Infrastructure Failure", 0.78),
                ("Security Breaches", 0.92),
                ("Economic Impact", 0.67)
            ]
            
            for impact, severity in impacts:
                st.progress(severity, text=f"{impact}: {severity:.0%} severity")
        
        with col2:
            st.markdown("""
            <div class='warning-box'>
            <h4>⚠️ Critical Warning</h4>
            Data poisoning attacks could undermine the entire IndiaAI mission by compromising:
            - AI governance frameworks
            - Digital public goods
            - National security systems
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        st.markdown("### 💰 Financial Fraud Analysis (Mumbai Police Report)")
        
        # Fraud trends visualization
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        traditional_fraud = [100, 95, 110, 105, 120, 115, 130, 125, 140, 135, 150, 145]
        ai_enabled_fraud = [20, 25, 35, 45, 60, 80, 105, 135, 170, 210, 260, 315]
        
        fraud_df = pd.DataFrame({
            'Month': months,
            'Traditional Fraud': traditional_fraud,
            'AI-Enabled Fraud': ai_enabled_fraud
        })
        
        fig = px.line(fraud_df, x='Month', y=['Traditional Fraud', 'AI-Enabled Fraud'],
                     title='Fraud Trends: Traditional vs AI-Enabled (300% Growth)',
                     labels={'value': 'Cases Reported', 'variable': 'Fraud Type'})
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Attack flowchart
        st.markdown("#### 🔄 AI-Enabled Fraud Attack Pipeline")
        
        attack_steps = {
            "Step 1": "Poison Training Data",
            "Step 2": "Compromise Fraud Detection Model",
            "Step 3": "Execute Financial Transactions",
            "Step 4": "Evade Detection",
            "Step 5": "Monetize Attack"
        }
        
        for step, description in attack_steps.items():
            st.write(f"**{step}**: {description}")
    
    with tab3:
        st.markdown("### 👥 Public Trust & Cyber Volunteer Program")
        
        col1, col2 = st.columns(2)
        
        with col1:
            trust_score = st.slider("False Positive Rate in Volunteer Reports:", 0.0, 1.0, 0.3, 0.05)
            public_trust = max(0, 1 - trust_score * 2)  # Trust decreases with false positives
            
            st.metric("Public Trust Score", f"{public_trust:.0%}")
            
            if public_trust < 0.3:
                st.error("🚨 Critical: Public trust at dangerous levels")
            elif public_trust < 0.6:
                st.warning("⚠️ Warning: Public trust declining")
            else:
                st.success("✅ Public trust maintained")
        
        with col2:
            st.markdown("""
            **Impact on Cyber Volunteer Program:**
            - Reduced participation rates
            - Decreased report quality
            - Increased program costs
            - Loss of institutional credibility
            
            **Mitigation Strategies:**
            - Enhanced verification systems
            - Transparent reporting mechanisms
            - Volunteer education programs
            """)

def render_mitigation_dashboard():
    """Render the mitigation strategies dashboard"""
    
    st.markdown('<div class="sub-header">🛡️ AI Resilience & Mitigation Dashboard</div>', unsafe_allow_html=True)
    
    # Resilience score calculation
    st.markdown("### 🎯 Cyber Resilience Score")
    
    # Mitigation strategies with weights
    mitigations = {
        "Robust Data Provenance": {"weight": 0.20, "implemented": False},
        "Adversarial Training": {"weight": 0.15, "implemented": False},
        "Continuous Monitoring": {"weight": 0.18, "implemented": False},
        "Secure MLOps": {"weight": 0.17, "implemented": False},
        "Insider Risk Management": {"weight": 0.15, "implemented": False},
        "Legal Framework Compliance": {"weight": 0.15, "implemented": False}
    }
    
    # Checkboxes for mitigation strategies
    resilience_score = 0
    max_score = sum(mitigation["weight"] for mitigation in mitigations.values())
    
    cols = st.columns(3)
    col_idx = 0
    
    for mitigation, details in mitigations.items():
        with cols[col_idx]:
            implemented = st.checkbox(
                f"{mitigation} ({details['weight']:.0%})",
                value=details["implemented"],
                key=mitigation
            )
            if implemented:
                resilience_score += details["weight"]
        
        col_idx = (col_idx + 1) % 3
    
    # Display resilience score
    normalized_score = resilience_score / max_score
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown(f"### Overall Resilience: {normalized_score:.0%}")
        
        # Color-coded progress bar
        if normalized_score < 0.4:
            color = "red"
        elif normalized_score < 0.7:
            color = "orange"
        else:
            color = "green"
        
        st.markdown(f"""
        <div style="background-color: #f0f0f0; border-radius: 10px; padding: 3px;">
            <div style="background-color: {color}; width: {normalized_score * 100}%; 
                       height: 20px; border-radius: 8px;"></div>
        </div>
        """, unsafe_allow_html=True)
    
    # Detailed mitigation information
    st.markdown("### 📋 Mitigation Strategy Details")
    
    mitigation_details = {
        "Robust Data Provenance": {
            "description": "Track data lineage and verify data sources",
            "implementation": "Data versioning, cryptographic hashing, access logs",
            "effectiveness": "High",
            "cost": "Medium"
        },
        "Adversarial Training": {
            "description": "Train models on poisoned data to improve robustness",
            "implementation": "Poisoning detection algorithms, robust optimization",
            "effectiveness": "Medium-High",
            "cost": "High"
        },
        "Continuous Monitoring": {
            "description": "Real-time monitoring of model behavior and data streams",
            "implementation": "Anomaly detection, performance metrics tracking",
            "effectiveness": "High",
            "cost": "Medium"
        }
    }
    
    for mitigation, details in mitigation_details.items():
        with st.expander(f"🔒 {mitigation}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Description**: {details['description']}")
                st.write(f"**Effectiveness**: {details['effectiveness']}")
            
            with col2:
                st.write(f"**Implementation**: {details['implementation']}")
                st.write(f"**Cost**: {details['cost']}")

def render_future_trends():
    """Render the future trends and AI arms race section"""
    
    st.markdown('<div class="sub-header">🚀 Future Trends & AI Arms Race</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔴 Offensive AI Capabilities")
        
        offensive_tools = {
            "WormGPT": {
                "risk": "Critical",
                "capability": "Advanced social engineering, malware generation",
                "access": "Dark web markets"
            },
            "FraudGPT": {
                "risk": "High",
                "capability": "Financial fraud schemes, phishing campaigns",
                "access": "Subscription-based"
            },
            "PoisonGPT": {
                "risk": "Critical",
                "capability": "Automated data poisoning, model backdoors",
                "access": "Emerging threat"
            }
        }
        
        for tool, info in offensive_tools.items():
            with st.container():
                st.markdown(f"**{tool}**")
                st.write(f"Risk: {info['risk']}")
                st.write(f"Capability: {info['capability']}")
                st.write(f"Access: {info['access']}")
                st.markdown("---")
    
    with col2:
        st.markdown("### 🟢 Defensive AI Innovations")
        
        defensive_tech = {
            "Confidential Computing": {
                "status": "Emerging",
                "benefit": "Data protection during processing",
                "adoption": "20%"
            },
            "Homomorphic Encryption": {
                "status": "Research",
                "benefit": "Compute on encrypted data",
                "adoption": "5%"
            },
            "Explainable AI (XAI)": {
                "status": "Growing",
                "benefit": "Model transparency and auditability",
                "adoption": "35%"
            }
        }
        
        for tech, info in defensive_tech.items():
            with st.container():
                st.markdown(f"**{tech}**")
                st.write(f"Status: {info['status']}")
                st.write(f"Benefit: {info['benefit']}")
                st.write(f"Adoption: {info['adoption']}")
                st.markdown("---")
    
    # Timeline visualization
    st.markdown("### 📅 Evolution Timeline: Threats vs Defenses")
    
    timeline_data = {
        'Year': [2020, 2021, 2022, 2023, 2024, 2025],
        'Threat_Sophistication': [30, 45, 60, 75, 85, 95],
        'Defense_Capability': [35, 40, 50, 60, 70, 80],
        'Gap': [-5, 5, 10, 15, 15, 15]
    }
    
    timeline_df = pd.DataFrame(timeline_data)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=timeline_df['Year'], 
        y=timeline_df['Threat_Sophistication'],
        mode='lines+markers',
        name='Threat Sophistication',
        line=dict(color='red', width=3)
    ))
    
    fig.add_trace(go.Scatter(
        x=timeline_df['Year'], 
        y=timeline_df['Defense_Capability'],
        mode='lines+markers',
        name='Defense Capability',
        line=dict(color='green', width=3)
    ))
    
    fig.update_layout(
        title='AI Security Arms Race: Threat vs Defense Evolution',
        xaxis_title='Year',
        yaxis_title='Capability Level (%)',
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_resources_section():
    """Render the resources and references section"""
    
    st.markdown('<div class="sub-header">📚 Resources & References</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔗 Important Links")
        
        resources = [
            ("MITRE ATLAS Framework", "https://atlas.mitre.org/", "Adversarial Threat Landscape for AI Systems"),
            ("NIST AI Risk Management", "https://www.nist.gov/ai", "AI Risk Management Framework"),
            ("CERT-In Directives", "https://www.cert-in.org.in/", "Indian Computer Emergency Response Team"),
            ("DPDPA, 2023", "https://www.meity.gov.in/", "Digital Personal Data Protection Act"),
            ("IndiaAI Mission", "https://www.indiaai.gov.in/", "National AI Strategy")
        ]
        
        for name, url, description in resources:
            st.markdown(f"- **[{name}]({url})**: {description}")
    
    with col2:
        st.markdown("### 📄 Download Resources")
        
        # Simulate download buttons
        if st.button("📥 Download Research Paper (PDF)"):
            st.success("Paper download started! (Simulation)")
        
        if st.button("📊 Download Threat Dataset (CSV)"):
            st.success("Dataset download started! (Simulation)")
        
        if st.button("🛡️ Download Security Checklist"):
            st.success("Checklist download started! (Simulation)")
    
    # References
    st.markdown("### 📖 Academic References")
    
    references = [
        "Smith, J., et al. 'Data Poisoning Attacks Against Machine Learning Systems'. IEEE Security & Privacy, 2023.",
        "Kumar, A., & Patel, R. 'AI Security in National Infrastructure: Indian Context'. IIT Bombay, 2024.",
        "Chen, L., et al. 'Adversarial Machine Learning: A Comprehensive Survey'. ACM Computing Surveys, 2023.",
        "Mumbai Police Cyber Cell. 'Annual Cyber Crime Report 2023-24'. Government of Maharashtra, 2024.",
        "Ministry of Electronics and IT. 'IndiaAI: Strategic Framework for Artificial Intelligence'. Government of India, 2023."
    ]
    
    for ref in references:
        st.write(f"- {ref}")

if __name__ == "__main__":
    main()
