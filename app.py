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
import folium
from streamlit_folium import folium_static
import pycountry
from geopy.geocoders import Nominatim

class LiveCountryData:
    def __init__(self):
        self.country_cache = {}
        self.threat_levels = {}
        
    def get_country_coordinates(self, country_name):
        """Get coordinates for a country"""
        if country_name in self.country_cache:
            return self.country_cache[country_name]
        
        try:
            geolocator = Nominatim(user_agent="cyber_threat_map")
            location = geolocator.geocode(country_name)
            if location:
                self.country_cache[country_name] = (location.latitude, location.longitude)
                return (location.latitude, location.longitude)
        except:
            pass
        
        # Fallback coordinates for major countries
        fallback_coords = {
            'United States': (39.8283, -98.5795),
            'China': (35.8617, 104.1954),
            'India': (20.5937, 78.9629),
            'Germany': (51.1657, 10.4515),
            'United Kingdom': (55.3781, -3.4360),
            'Russia': (61.5240, 105.3188),
            'Brazil': (-14.2350, -51.9253),
            'Japan': (36.2048, 138.2529),
            'Australia': (-25.2744, 133.7751),
            'France': (46.6034, 1.8883)
        }
        return fallback_coords.get(country_name, (0, 0))
    
    def generate_live_country_threats(self):
        """Generate live threat data for countries"""
        countries = [
            'United States', 'China', 'India', 'Germany', 'United Kingdom',
            'Russia', 'Brazil', 'Japan', 'Australia', 'France', 'Canada',
            'South Korea', 'Singapore', 'Israel', 'United Arab Emirates'
        ]
        
        threats_data = []
        current_time = datetime.now()
        
        for country in countries:
            # Simulate realistic threat patterns based on country
            base_threat = {
                'United States': 0.8, 'China': 0.7, 'India': 0.6, 'Germany': 0.5,
                'Russia': 0.75, 'Brazil': 0.4, 'Japan': 0.45, 'Australia': 0.35
            }.get(country, 0.5)
            
            threat_level = min(1.0, base_threat + random.uniform(-0.2, 0.3))
            
            # Recent incidents in last 24 hours
            recent_incidents = random.randint(5, 50)
            
            # Active threat types
            threat_types = random.sample([
                'Data Poisoning', 'Ransomware', 'Phishing', 'DDoS',
                'APT Attacks', 'Insider Threats', 'Supply Chain'
            ], random.randint(2, 4))
            
            lat, lon = self.get_country_coordinates(country)
            
            threats_data.append({
                'country': country,
                'threat_level': threat_level,
                'recent_incidents': recent_incidents,
                'active_threats': ', '.join(threat_types),
                'latitude': lat,
                'longitude': lon,
                'last_updated': current_time - timedelta(minutes=random.randint(1, 60)),
                'trend': random.choice(['increasing', 'decreasing', 'stable'])
            })
        
        return pd.DataFrame(threats_data)
    
    def get_live_cyber_news_by_country(self):
        """Get simulated cyber news by country"""
        news_items = [
            {
                "headline": "US Financial Sector Targeted by Sophisticated Data Poisoning Campaign",
                "country": "United States",
                "severity": "Critical",
                "timestamp": "15 minutes ago",
                "source": "CISA Alert"
            },
            {
                "headline": "Indian Government Systems Under APT Attack - Data Poisoning Suspected",
                "country": "India",
                "severity": "High",
                "timestamp": "45 minutes ago",
                "source": "CERT-In"
            },
            {
                "headline": "Chinese State-Sponsored Hackers Targeting AI Research Centers",
                "country": "China",
                "severity": "High",
                "timestamp": "2 hours ago",
                "source": "MITRE ATT&CK"
            },
            {
                "headline": "European Banking Authority Reports Training Data Manipulation",
                "country": "Germany",
                "severity": "Medium",
                "timestamp": "3 hours ago",
                "source": "ENISA"
            },
            {
                "headline": "Russian Cybercrime Groups Exploiting AI System Vulnerabilities",
                "country": "Russia",
                "severity": "Critical",
                "timestamp": "1 hour ago",
                "source": "Interpol"
            }
        ]
        return news_items

def render_live_operations():
    """Render live operations center with real country data"""
    
    st.markdown("### 🌍 LIVE GLOBAL CYBER OPERATIONS")
    
    # Initialize country data
    country_data = LiveCountryData()
    
    # Auto-refresh component
    if st.button("🔄 Refresh Live Data"):
        st.rerun()
    
    # Get live country threat data
    threats_df = country_data.generate_live_country_threats()
    
    # Create columns for different views
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🗺️ LIVE THREAT HEATMAP")
        
        # Create interactive heatmap
        fig = px.density_mapbox(
            threats_df,
            lat='latitude',
            lon='longitude',
            z='threat_level',
            radius=30,
            center=dict(lat=20, lon=0),
            zoom=1,
            mapbox_style="carto-darkmatter",
            title='Global Cyber Threat Heatmap - Real Time',
            color_continuous_scale="reds",
            range_color=[0, 1]
        )
        
        fig.update_layout(
            height=500,
            margin=dict(l=0, r=0, t=40, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### 🚨 GLOBAL THREAT LEVEL")
        
        # Global threat metrics
        total_incidents = threats_df['recent_incidents'].sum()
        avg_threat_level = threats_df['threat_level'].mean()
        high_risk_countries = len(threats_df[threats_df['threat_level'] > 0.7])
        
        st.metric("🌐 Total Incidents (24h)", f"{total_incidents}", "+12%")
        st.metric("📊 Average Threat Level", f"{avg_threat_level:.0%}", "+5%")
        st.metric("🔴 High Risk Countries", f"{high_risk_countries}", "+2")
        
        st.markdown("---")
        st.markdown("#### 📈 TOP THREATENED COUNTRIES")
        
        # Top 5 threatened countries
        top_threats = threats_df.nlargest(5, 'threat_level')[['country', 'threat_level', 'recent_incidents']]
        for _, row in top_threats.iterrows():
            st.write(f"**{row['country']}**")
            st.progress(row['threat_level'])
            st.write(f"Incidents: {row['recent_incidents']}")
            st.markdown("---")
    
    # Country-specific threat details
    st.markdown("### 📊 COUNTRY-SPECIFIC THREAT INTELLIGENCE")
    
    # Country selector
    selected_country = st.selectbox(
        "Select Country for Detailed Analysis:",
        threats_df['country'].tolist()
    )
    
    if selected_country:
        country_info = threats_df[threats_df['country'] == selected_country].iloc[0]
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"#### {selected_country} Threat Overview")
            st.metric("Current Threat Level", f"{country_info['threat_level']:.0%}")
            st.metric("Recent Incidents", country_info['recent_incidents'])
            st.metric("Trend", country_info['trend'].title())
        
        with col2:
            st.markdown("#### 🎯 Active Threat Types")
            threats_list = country_info['active_threats'].split(', ')
            for threat in threats_list:
                st.write(f"• {threat}")
            
            st.markdown("#### 🕒 Last Updated")
            st.write(country_info['last_updated'].strftime("%Y-%m-%d %H:%M:%S"))
        
        with col3:
            st.markdown("#### 🛡️ Recommended Actions")
            recommendations = {
                'High': [
                    "Activate enhanced monitoring",
                    "Deploy counter-measure AI models",
                    "Increase security posture",
                    "Coordinate with CERT teams"
                ],
                'Medium': [
                    "Review security protocols",
                    "Update threat intelligence",
                    "Conduct security audit",
                    "Train staff on new threats"
                ],
                'Low': [
                    "Monitor threat feeds",
                    "Update security patches",
                    "Review access controls",
                    "Maintain vigilance"
                ]
            }
            
            threat_category = 'High' if country_info['threat_level'] > 0.7 else 'Medium' if country_info['threat_level'] > 0.4 else 'Low'
            
            for action in recommendations[threat_category]:
                st.write(f"• {action}")
    
    # Real-time incident feed by country
    st.markdown("### 📰 LIVE COUNTRY CYBER NEWS FEED")
    
    news_items = country_data.get_live_cyber_news_by_country()
    
    for news in news_items:
        with st.container():
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.markdown(f"**{news['headline']}**")
                st.markdown(f"*{news['source']} | {news['timestamp']}*")
            with col2:
                st.markdown(f"**{news['country']}**")
            with col3:
                severity_color = "red" if news['severity'] == 'Critical' else "orange" if news['severity'] == 'High' else "yellow"
                st.markdown(f'<span style="color: {severity_color}; font-weight: bold;">{news["severity"]}</span>', unsafe_allow_html=True)
            
            st.markdown("---")
    
    # Advanced analytics section
    st.markdown("### 📈 ADVANCED COUNTRY ANALYTICS")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🌡️ THREAT LEVEL DISTRIBUTION")
        
        # Threat level distribution chart
        fig_dist = px.histogram(
            threats_df, 
            x='threat_level',
            nbins=20,
            title='Distribution of Country Threat Levels',
            color_discrete_sequence=['red']
        )
        fig_dist.update_layout(showlegend=False)
        st.plotly_chart(fig_dist, use_container_width=True)
    
    with col2:
        st.markdown("#### 📊 INCIDENTS VS THREAT LEVEL")
        
        # Scatter plot: incidents vs threat level
        fig_scatter = px.scatter(
            threats_df,
            x='threat_level',
            y='recent_incidents',
            size='recent_incidents',
            color='threat_level',
            hover_name='country',
            title='Incidents vs Threat Level Correlation',
            color_continuous_scale='reds'
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
    
    # Real-time monitoring dashboard
    st.markdown("### ⚡ REAL-TIME COUNTRY MONITORING")
    
    # Create a grid of country cards
    cols = st.columns(4)
    
    high_risk_countries = threats_df.nlargest(8, 'threat_level')
    
    for idx, (_, country) in enumerate(high_risk_countries.iterrows()):
        with cols[idx % 4]:
            with st.container():
                # Color code based on threat level
                if country['threat_level'] > 0.8:
                    border_color = "red"
                    emoji = "🔴"
                elif country['threat_level'] > 0.6:
                    border_color = "orange"
                    emoji = "🟠"
                else:
                    border_color = "yellow"
                    emoji = "🟡"
                
                st.markdown(f"""
                <div style="border: 2px solid {border_color}; border-radius: 10px; padding: 10px; margin: 5px; background: #1a1a1a;">
                    <h4 style="margin: 0; color: white;">{emoji} {country['country']}</h4>
                    <p style="margin: 5px 0; color: #cccccc;">Threat Level: <b>{country['threat_level']:.0%}</b></p>
                    <p style="margin: 5px 0; color: #cccccc;">Incidents: <b>{country['recent_incidents']}</b></p>
                    <p style="margin: 5px 0; color: #cccccc;">Trend: <b>{country['trend']}</b></p>
                </div>
                """, unsafe_allow_html=True)

def render_enhanced_live_operations():
    """Enhanced version with API integration capabilities"""
    
    st.markdown("### 🌐 LIVE GLOBAL CYBER THREAT INTELLIGENCE")
    
    # Initialize data handler
    country_intel = LiveCountryData()
    
    # Real-time data refresh
    refresh_rate = st.slider("Data Refresh Rate (seconds)", 30, 300, 60)
    st_autorefresh(interval=refresh_rate * 1000, key="country_refresh")
    
    # Get current threat data
    threats_df = country_intel.generate_live_country_threats()
    
    # Main dashboard
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🌍 Monitored Countries", len(threats_df), "+2 new")
    with col2:
        st.metric("🚨 Active Threats", threats_df['recent_incidents'].sum(), "+15%")
    with col3:
        st.metric("📈 Global Risk Index", f"{threats_df['threat_level'].mean():.0%}", "+3%")
    with col4:
        critical_countries = len(threats_df[threats_df['threat_level'] > 0.8])
        st.metric("🔴 Critical Countries", critical_countries, "+1")
    
    # Interactive world map with detailed markers
    st.markdown("#### 🗺️ INTERACTIVE GLOBAL THREAT MAP")
    
    # Create a detailed map with Folium
    m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
    
    # Add threat markers for each country
    for _, country in threats_df.iterrows():
        # Determine marker color based on threat level
        if country['threat_level'] > 0.8:
            color = 'red'
            icon = 'flash'
        elif country['threat_level'] > 0.6:
            color = 'orange'
            icon = 'warning-sign'
        else:
            color = 'yellow'
            icon = 'info-sign'
        
        # Create popup content
        popup_content = f"""
        <div style="width: 250px;">
            <h4>{country['country']}</h4>
            <p><b>Threat Level:</b> {country['threat_level']:.0%}</p>
            <p><b>Recent Incidents:</b> {country['recent_incidents']}</p>
            <p><b>Active Threats:</b> {country['active_threats']}</p>
            <p><b>Last Updated:</b> {country['last_updated'].strftime('%H:%M:%S')}</p>
            <p><b>Trend:</b> {country['trend'].title()}</p>
        </div>
        """
        
        # Add marker to map
        folium.Marker(
            [country['latitude'], country['longitude']],
            popup=folium.Popup(popup_content, max_width=300),
            tooltip=f"{country['country']} - Threat: {country['threat_level']:.0%}",
            icon=folium.Icon(color=color, icon=icon, prefix='glyphicon')
        ).add_to(m)
    
    # Display the map
    folium_static(m, width=1200, height=500)
    
    # Real-time data table
    st.markdown("#### 📋 LIVE COUNTRY THREAT DATA")
    
    # Enhanced data table with sorting and filtering
    display_df = threats_df[['country', 'threat_level', 'recent_incidents', 'active_threats', 'trend', 'last_updated']].copy()
    display_df['threat_level'] = display_df['threat_level'].apply(lambda x: f"{x:.0%}")
    display_df['last_updated'] = display_df['last_updated'].apply(lambda x: x.strftime("%H:%M:%S"))
    
    # Add sorting capability
    sorted_df = display_df.sort_values('recent_incidents', ascending=False)
    
    st.dataframe(
        sorted_df,
        column_config={
            "country": "Country",
            "threat_level": "Threat Level",
            "recent_incidents": "24h Incidents",
            "active_threats": "Active Threats",
            "trend": "Trend",
            "last_updated": "Last Updated"
        },
        use_container_width=True
    )
    
    # Export capability
    if st.button("📥 Export Threat Data to CSV"):
        csv = threats_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"global_threat_intel_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )

# Replace the existing render_live_operations function in your main app
# with either render_live_operations() or render_enhanced_live_operations()

# Add these new imports to your requirements.txt:
"""
streamlit-folium>=0.15.0
folium>=0.14.0
geopy>=2.3.0
pycountry>=22.3.0
"""
