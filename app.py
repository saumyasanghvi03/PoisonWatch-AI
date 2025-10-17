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

# Set higher file descriptor limit for Unix systems
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, hard), hard))
except (ImportError, ValueError):
    pass  # Windows system or permission issue

# Page configuration for ultimate cyber theme
st.set_page_config(
    page_title="NEXUS-7 | Quantum Cyber Intelligence Platform",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Optimized Cyber CSS with reduced animations
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');
    
    .main-header {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        border: 1px solid #00ffff;
        box-shadow: 0 0 30px #00ffff33;
        margin-bottom: 1.5rem;
        position: relative;
        overflow: hidden;
        text-align: center;
    }
    
    .cyber-card {
        background: rgba(16, 16, 32, 0.95);
        border: 1px solid #00ffff;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        backdrop-filter: blur(10px);
        box-shadow: 0 0 20px #00ffff22;
    }
    
    .cyber-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, #00ffff, transparent);
    }
    
    .neon-text {
        color: #00ffff;
        text-shadow: 0 0 5px #00ffff;
        font-family: 'Orbitron', monospace;
        font-weight: 700;
    }
    
    .glow-text {
        color: #ffffff;
        text-shadow: 0 0 5px #00ffff;
        font-family: 'Rajdhani', sans-serif;
    }
    
    .matrix-text {
        font-family: 'Share Tech Mono', monospace;
        color: #00ff00;
    }
    
    .metric-glow {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #00ffff;
        border-radius: 8px;
        padding: 0.8rem;
        margin: 0.3rem;
        box-shadow: 0 0 15px #00ffff22;
    }
    
    /* Optimized data table styling */
    .dataframe {
        font-size: 0.85em !important;
    }
    
    /* Reduce animation intensity */
    .quantum-pulse {
        animation: quantum-pulse 4s infinite;
    }
    
    @keyframes quantum-pulse {
        0% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.9; transform: scale(1.02); }
        100% { opacity: 1; transform: scale(1); }
    }
</style>
""", unsafe_allow_html=True)

# Context manager for resource cleanup
@contextmanager
def managed_resource():
    try:
        yield
    finally:
        gc.collect()

class OptimizedQuantumThreatIntelligence:
    def __init__(self):
        self._threat_predictor = None
        self._attack_patterns = None
        self._forecast_cache = None
        self._cache_time = None
        
    @property
    def threat_predictor(self):
        if self._threat_predictor is None:
            self._threat_predictor = self.init_quantum_predictor()
        return self._threat_predictor
    
    @property
    def attack_patterns(self):
        if self._attack_patterns is None:
            self._attack_patterns = self.load_attack_patterns()
        return self._attack_patterns
    
    def init_quantum_predictor(self):
        """Initialize quantum-level threat prediction"""
        return {
            'quantum_entanglement_risk': random.uniform(0.7, 0.95),
            'temporal_anomaly_detection': random.uniform(0.8, 0.99),
            'neural_network_integrity': random.uniform(0.6, 0.9),
            'quantum_coherence_score': random.uniform(0.85, 0.98)
        }
    
    def load_attack_patterns(self):
        """Load advanced attack pattern database"""
        return {
            'Quantum Data Poisoning': {'risk': 0.95, 'sophistication': 0.98, 'detection_difficulty': 0.92, 'impact': 0.96},
            'AI Model Backdoor': {'risk': 0.88, 'sophistication': 0.85, 'detection_difficulty': 0.78, 'impact': 0.91},
            'Neural Network Evasion': {'risk': 0.82, 'sophistication': 0.79, 'detection_difficulty': 0.75, 'impact': 0.84},
            'Training Data Manipulation': {'risk': 0.76, 'sophistication': 0.72, 'detection_difficulty': 0.68, 'impact': 0.79}
        }
    
    def generate_quantum_forecast(self):
        """Generate quantum-level attack forecasts with caching"""
        current_time = time.time()
        if (self._forecast_cache is not None and 
            self._cache_time is not None and 
            current_time - self._cache_time < 30):  # Cache for 30 seconds
            return self._forecast_cache
            
        dates = pd.date_range(start=datetime.now(), periods=15, freq='D')  # Reduced from 30 to 15
        forecasts = []
        
        base_flux = np.sin(np.linspace(0, 4*np.pi, len(dates))) * 0.3 + 0.5
        
        for i, date in enumerate(dates):
            forecast = {
                'date': date,
                'attack_probability': max(0.1, min(0.99, base_flux[i] + random.uniform(-0.1, 0.1))),
                'quantum_instability': random.uniform(0.1, 0.8),
                'temporal_anomalies': random.randint(0, 3),  # Reduced range
                'defense_efficiency': random.uniform(0.6, 0.95)
            }
            forecasts.append(forecast)
        
        self._forecast_cache = pd.DataFrame(forecasts)
        self._cache_time = current_time
        return self._forecast_cache

class OptimizedLiveGlobalIntelligence:
    def __init__(self):
        self._country_cache = {}
        self._threat_matrix = None
        self._threats_cache = None
        self._threats_cache_time = None
        
    @property
    def threat_matrix(self):
        if self._threat_matrix is None:
            self._threat_matrix = self.init_threat_matrix()
        return self._threat_matrix
    
    def init_threat_matrix(self):
        """Initialize global threat intelligence matrix"""
        return {
            'APT_Groups': ['Lazarus', 'APT29', 'Equation', 'Sandworm'],
            'Malware_Families': ['PoisonIvy', 'CarbonStealer', 'QuantumRAT'],
            'Attack_Vectors': ['Supply Chain', 'Zero-Day', 'AI Poisoning']
        }
    
    def get_country_coordinates(self, country_name):
        """Get precise coordinates for countries"""
        if country_name in self._country_cache:
            return self._country_cache[country_name]
        
        precise_coords = {
            'United States': (38.9072, -77.0369), 'China': (39.9042, 116.4074),
            'India': (28.6139, 77.2090), 'Germany': (52.5200, 13.4050),
            'United Kingdom': (51.5074, -0.1278), 'Russia': (55.7558, 37.6173),
            'Brazil': (-15.7975, -47.8919), 'Japan': (35.6762, 139.6503),
            'Australia': (-35.2809, 149.1300), 'France': (48.8566, 2.3522),
            'Canada': (45.4215, -75.6972), 'South Korea': (37.5665, 126.9780),
            'Singapore': (1.3521, 103.8198)
        }
        
        coords = precise_coords.get(country_name, (0, 0))
        self._country_cache[country_name] = coords
        return coords
    
    def generate_live_global_threats(self):
        """Generate real-time global threat intelligence with caching"""
        current_time = time.time()
        if (self._threats_cache is not None and 
            self._threats_cache_time is not None and 
            current_time - self._threats_cache_time < 45):  # Cache for 45 seconds
            return self._threats_cache
            
        countries = [
            'United States', 'China', 'India', 'Germany', 'United Kingdom',
            'Russia', 'Brazil', 'Japan', 'Australia', 'France', 'Canada',
            'South Korea', 'Singapore'
        ]  # Reduced country list
        
        threats_data = []
        current_time_obj = datetime.now()
        
        for country in countries:
            economic_factor = random.uniform(0.3, 0.9)
            tech_infrastructure = random.uniform(0.4, 0.95)
            geopolitical_risk = random.uniform(0.2, 0.8)
            
            base_threat = (economic_factor * 0.3 + tech_infrastructure * 0.4 + geopolitical_risk * 0.3)
            threat_level = min(0.99, base_threat + random.uniform(-0.1, 0.15))
            
            recent_incidents = int(threat_level * 30 + random.randint(-5, 10))  # Reduced scale
            recent_incidents = max(3, min(50, recent_incidents))
            
            threat_profiles = {
                'United States': ['Advanced Persistent Threat', 'Ransomware', 'Supply Chain'],
                'China': ['State-Sponsored Espionage', 'Intellectual Property Theft'],
                'Russia': ['Cyber Warfare', 'Disinformation'],
                'Israel': ['Cyber Espionage', 'Zero-Day']
            }
            
            default_threats = ['Data Poisoning', 'Phishing', 'DDoS']
            active_threats = threat_profiles.get(country, default_threats)
            selected_threats = random.sample(active_threats, min(2, len(active_threats)))  # Reduced
            
            lat, lon = self.get_country_coordinates(country)
            
            threats_data.append({
                'country': country,
                'threat_level': threat_level,
                'recent_incidents': recent_incidents,
                'active_threats': ', '.join(selected_threats),
                'latitude': lat,
                'longitude': lon,
                'last_updated': current_time_obj - timedelta(minutes=random.randint(1, 60)),
                'trend': random.choice(['📈 Increasing', '📉 Decreasing', '➡️ Stable']),
                'risk_category': '🔴 Critical' if threat_level > 0.8 else '🟠 High' if threat_level > 0.6 else '🟡 Medium' if threat_level > 0.4 else '🟢 Low'
            })
        
        self._threats_cache = pd.DataFrame(threats_data)
        self._threats_cache_time = current_time
        return self._threats_cache
    
    def get_global_cyber_news(self):
        """Get cached global cyber news"""
        return [
            {
                "headline": "Quantum Computing Breakthrough: New Threats to AI Security Systems",
                "country": "Global",
                "severity": "🔴 Critical",
                "timestamp": "10 minutes ago",
                "source": "Quantum Security Journal",
                "impact": "9.8/10"
            },
            {
                "headline": "Major Financial Institution Suffers AI Model Poisoning Attack",
                "country": "United States",
                "severity": "🔴 Critical", 
                "timestamp": "25 minutes ago",
                "source": "Financial Times Cyber",
                "impact": "9.5/10"
            }
        ]

class OptimizedQuantumVisualization:
    def __init__(self):
        self._figure_cache = {}
        
    def create_quantum_network(self, nodes=15):  # Reduced nodes
        """Create optimized quantum entanglement network"""
        cache_key = f"network_{nodes}"
        if cache_key in self._figure_cache:
            return self._figure_cache[cache_key]
            
        fig = go.Figure()
        
        # Generate quantum nodes
        node_x, node_y, node_z = [], [], []
        for i in range(nodes):
            node_x.append(random.uniform(-8, 8))
            node_y.append(random.uniform(-8, 8))
            node_z.append(random.uniform(-8, 8))
        
        # Create quantum entanglement connections
        edge_x, edge_y, edge_z = [], [], []
        connections_made = 0
        max_connections = nodes * 2  # Limit connections
        
        for i in range(nodes):
            for j in range(i + 1, nodes):
                if random.random() < 0.2 and connections_made < max_connections:  # Reduced probability
                    edge_x.extend([node_x[i], node_x[j], None])
                    edge_y.extend([node_y[i], node_y[j], None])
                    edge_z.extend([node_z[i], node_z[j], None])
                    connections_made += 1
        
        if edge_x:
            fig.add_trace(go.Scatter3d(
                x=edge_x, y=edge_y, z=edge_z,
                mode='lines',
                line=dict(color='rgba(0, 255, 255, 0.4)', width=1),  # Reduced opacity and width
                hoverinfo='none',
                name='Quantum Entanglement'
            ))
        
        fig.add_trace(go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            mode='markers',
            marker=dict(
                size=8,  # Reduced size
                color=[random.uniform(0, 1) for _ in range(nodes)],
                colorscale='Viridis',
                opacity=0.7,
                line=dict(width=1, color='white')
            ),
            name='Quantum Nodes'
        ))
        
        fig.update_layout(
            title="🌌 Quantum Entanglement Network",
            scene=dict(
                xaxis_title='Quantum Field X',
                yaxis_title='Quantum Field Y', 
                zaxis_title='Quantum Field Z',
                bgcolor='rgba(0,0,0,0)'
            ),
            height=400,  # Reduced height
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            showlegend=False
        )
        
        self._figure_cache[cache_key] = fig
        return fig
    
    def create_threat_radar(self):
        """Create optimized threat radar visualization"""
        if "threat_radar" in self._figure_cache:
            return self._figure_cache["threat_radar"]
            
        categories = ['Data Poisoning', 'Model Evasion', 'Backdoor', 'Supply Chain']
        values = [random.uniform(0.6, 0.95) for _ in categories]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            fillcolor='rgba(255, 0, 0, 0.2)',
            line=dict(color='#ff0000', width=2),
            name='Threat Level'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 1], gridcolor='rgba(255,255,255,0.2)'),
                angularaxis=dict(gridcolor='rgba(255,255,255,0.2)'),
                bgcolor='rgba(0,0,0,0)'
            ),
            showlegend=False,
            title="🎯 Threat Radar",
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=300
        )
        
        self._figure_cache["threat_radar"] = fig
        return fig

class OptimizedAICommandInterface:
    def __init__(self):
        self.commands = {
            "show quantum threats": "display_quantum_threats",
            "analyze global network": "analyze_global_network", 
            "predict quantum attacks": "predict_quantum_attacks",
            "generate quantum report": "generate_quantum_report",
            "activate quantum shield": "activate_quantum_shield"
        }
        self.conversation_history = []
    
    def process_quantum_command(self, command_text):
        """Process quantum commands efficiently"""
        command = command_text.lower().strip()
        for cmd, action in self.commands.items():
            if any(word in command for word in cmd.split()):
                return cmd, action
        return None, None
    
    def add_to_conversation(self, role, message):
        """Add message to conversation history"""
        self.conversation_history.append({
            "role": role,
            "message": message,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
        if len(self.conversation_history) > 8:  # Reduced history size
            self.conversation_history.pop(0)

def create_optimized_quantum_chart():
    """Create optimized quantum state chart"""
    x = np.linspace(0, 3*np.pi, 50)  # Reduced points
    y1 = np.sin(x)
    y2 = np.cos(x)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=x, y=y1, mode='lines', name='Quantum State Ψ₁',
        line=dict(color='#00ffff', width=2)
    ))
    
    fig.add_trace(go.Scatter(
        x=x, y=y2, mode='lines', name='Quantum State Ψ₂', 
        line=dict(color='#ff00ff', width=2)
    ))
    
    fig.update_layout(
        title="🌊 Quantum Wave Functions",
        xaxis_title="Time",
        yaxis_title="Amplitude", 
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        height=300,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    
    return fig

def create_optimized_3d_simulation():
    """Create optimized 3D simulation"""
    t = np.linspace(0, 8, 30)  # Reduced points
    x = np.sin(t)
    y = np.cos(t) 
    z = t
    
    fig = go.Figure(data=[go.Scatter3d(
        x=x, y=y, z=z, mode='markers',
        marker=dict(size=6, color=z, colorscale='Viridis', opacity=0.7)
    )])
    
    fig.update_layout(
        title="🔮 Quantum Simulation",
        scene=dict(xaxis_title='X', yaxis_title='Y', zaxis_title='Z'),
        height=350,
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig

def main():
    with managed_resource():
        # Initialize optimized components
        quantum_intel = OptimizedQuantumThreatIntelligence()
        global_intel = OptimizedLiveGlobalIntelligence()
        quantum_viz = OptimizedQuantumVisualization()
        ai_commander = OptimizedAICommandInterface()
        
        # Ultimate header
        st.markdown("""
        <div class="main-header">
            <h1 class="neon-text" style="font-size: 3rem; margin: 0;">⚡ NEXUS-7 QUANTUM INTELLIGENCE</h1>
            <h3 class="glow-text" style="font-size: 1.5rem; margin: 0.5rem 0;">Next-Generation Cyber Defense Platform</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Quantum metrics dashboard
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown('<div class="metric-glow">', unsafe_allow_html=True)
            st.metric("🌌 Quantum Risk", f"{random.uniform(0.75, 0.98):.1%}", f"{random.uniform(1, 5):+.1f}%")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="metric-glow">', unsafe_allow_html=True)
            st.metric("🧠 AI Confidence", f"{random.uniform(0.85, 0.99):.1%}", f"{random.uniform(1, 4):+.1f}%")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col3:
            st.markdown('<div class="metric-glow">', unsafe_allow_html=True)
            st.metric("⚡ Threat Velocity", f"{random.randint(100, 300)}/s", f"{random.randint(5, 15)}%")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col4:
            st.markdown('<div class="metric-glow">', unsafe_allow_html=True)
            st.metric("🛡️ Quantum Shield", f"{random.uniform(0.7, 0.96):.1%}", f"{random.uniform(2, 8):+.1f}%")
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Optimized navigation with fewer tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "🚀 DASHBOARD", 
            "🌍 GLOBAL INTEL", 
            "🧠 PREDICTIONS", 
            "⚡ COMMAND"
        ])
        
        with tab1:
            render_optimized_dashboard(quantum_intel, quantum_viz)
        
        with tab2:
            render_optimized_global_intel(global_intel, quantum_viz)
        
        with tab3:
            render_optimized_predictions(quantum_intel)
        
        with tab4:
            render_optimized_command(ai_commander)

def render_optimized_dashboard(quantum_intel, quantum_viz):
    """Render optimized dashboard"""
    st.markdown("### 🚀 QUANTUM SECURITY DASHBOARD")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### ⚡ THREAT MATRIX")
        
        threats_data = []
        for i in range(8):  # Reduced number of threats
            threat_type = random.choice(['Quantum Poisoning', 'AI Backdoor', 'Neural Evasion'])
            threat_level = random.choice(['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM'])
            
            threat = {
                'ID': f"QT-{random.randint(1000, 9999)}",
                'Type': threat_type,
                'Risk': f"{random.uniform(0.7, 0.99):.1%}",
                'Status': threat_level,
                'Response': random.choice(['🛡️ Shielded', '🔍 Monitoring'])
            }
            threats_data.append(threat)
        
        threats_df = pd.DataFrame(threats_data)
        st.dataframe(threats_df, use_container_width=True, height=300)
    
    with col2:
        st.markdown("#### 🌌 SYSTEM STATUS")
        
        metrics = {
            'Entanglement Security': random.uniform(0.75, 0.95),
            'Superposition Stability': random.uniform(0.8, 0.98),
            'Coherence Integrity': random.uniform(0.7, 0.96)
        }
        
        for metric, value in metrics.items():
            st.write(f"**{metric}**")
            st.progress(value)
            st.write(f"Score: {value:.1%}")
    
    # Optimized visualizations
    st.markdown("### 🔮 QUANTUM VISUALIZATIONS")
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(quantum_viz.create_quantum_network(12), use_container_width=True)
    
    with col2:
        st.plotly_chart(create_optimized_quantum_chart(), use_container_width=True)

def render_optimized_global_intel(global_intel, quantum_viz):
    """Render optimized global intelligence"""
    st.markdown("### 🌍 GLOBAL THREAT INTELLIGENCE")
    
    # Get cached data
    threats_df = global_intel.generate_live_global_threats()
    
    # Global overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_incidents = threats_df['recent_incidents'].sum()
        st.metric("🌐 Global Incidents", f"{total_incidents}")
    
    with col2:
        avg_threat = threats_df['threat_level'].mean()
        st.metric("📊 Avg Threat Level", f"{avg_threat:.1%}")
    
    with col3:
        critical_countries = len(threats_df[threats_df['threat_level'] > 0.8])
        st.metric("🔴 Critical Countries", critical_countries)
    
    # Optimized map
    st.markdown("#### 🗺️ THREAT MAP")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    for _, country in threats_df.iterrows():
        color = 'red' if country['threat_level'] > 0.8 else 'orange' if country['threat_level'] > 0.6 else 'yellow'
        
        folium.Marker(
            [country['latitude'], country['longitude']],
            popup=f"{country['country']} - Threat: {country['threat_level']:.1%}",
            tooltip=country['country'],
            icon=folium.Icon(color=color)
        ).add_to(m)
    
    folium_static(m, width=1000, height=400)
    
    # Threat radar
    st.plotly_chart(quantum_viz.create_threat_radar(), use_container_width=True)

def render_optimized_predictions(quantum_intel):
    """Render optimized predictions"""
    st.markdown("### 🧠 QUANTUM PREDICTION ENGINE")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔮 ATTACK FORECAST")
        
        forecast_df = quantum_intel.generate_quantum_forecast()
        
        fig = px.line(forecast_df, x='date', y='attack_probability',
                     title='15-Day Attack Probability Forecast')
        
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### 🎯 THREAT PATTERNS")
        
        patterns = quantum_intel.attack_patterns
        pattern_df = pd.DataFrame(patterns).T.reset_index()
        pattern_df.columns = ['Attack Type', 'Risk', 'Sophistication', 'Detection Difficulty', 'Impact']
        
        fig = px.scatter(pattern_df, x='Sophistication', y='Impact', size='Risk',
                        title='Threat Pattern Analysis')
        
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)

def render_optimized_command(ai_commander):
    """Render optimized command interface"""
    st.markdown("### ⚡ QUANTUM COMMAND INTERFACE")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### 💬 COMMAND INPUT")
        
        command_text = st.text_input(
            "Enter Quantum Command:",
            placeholder="Type 'show quantum threats', 'analyze global network', etc."
        )
        
        if st.button("🚀 EXECUTE COMMAND", use_container_width=True):
            if command_text:
                with st.spinner("🌀 Processing..."):
                    time.sleep(1)
                    command, action = ai_commander.process_quantum_command(command_text)
                    if command:
                        st.success(f"Executed: '{command}'")
                        ai_commander.add_to_conversation("AI", f"Executed: {command}")
                    else:
                        st.error("Command not recognized")
            else:
                st.warning("Please enter a command")
    
    with col2:
        st.markdown("#### 🤖 CONVERSATION")
        
        for msg in ai_commander.conversation_history[-4:]:
            if msg["role"] == "AI":
                st.markdown(f"**🤖 NEXUS-7:** {msg['message']}")
            else:
                st.markdown(f"**👤 User:** {msg['message']}")

if __name__ == "__main__":
    main()
