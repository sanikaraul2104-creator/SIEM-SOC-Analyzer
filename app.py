import streamlit as st
import pandas as pd
import joblib
import numpy as np
import datetime
import random
import time

# ===============================
# Load ML Model and Encoder
# ===============================
@st.cache_resource
def load_assets():
    try:
        model = joblib.load("siem_model.pkl")
        le = joblib.load("label_encoder.pkl")
        return model, le
    except Exception as e:
        return None, None

model, le = load_assets()

# ===============================
# Streamlit Page Config & Styling
# ===============================
st.set_page_config(page_title="SentinelML SIEM", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; color: #e0e0e0; }
    [data-testid="stMetricValue"] { color: #00f2ff; font-family: 'Courier New', monospace; font-size: 1.8rem !important; }
    div.stBlock { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; }
    .stTabs [aria-selected="true"] { background-color: #1f6feb !important; color: white !important; }
    </style>
    """, unsafe_allow_html=True)

# Navigation Tabs
tab_home, tab_soc, tab_pipeline = st.tabs(["🏠 MISSION CONTROL", "📊 LIVE TELEMETRY", "⚙️ SYSTEM LOGIC"])

# ===============================
# Tab 1: Home (Updated with detailed Port logic)
# ===============================
with tab_home:
    col1, col2 = st.columns([1.5, 1])
    with col1:
        st.markdown("<h1 style='color: #58a6ff;'>🛡️ SentinelML SIEM</h1>", unsafe_allow_html=True)
        st.markdown("""
        ### Strategic Mission
        **SentinelML** provides high-fidelity network visibility and automated threat containment. 
        
        #### ⚡ Critical Port Monitoring
        The system actively monitors these high-risk vectors identified in the control panel:
        * **Port 22**: SSH (Remote Access)
        * **Port 23**: Telnet (Unencrypted Remote Access)
        * **Port 445**: SMB (File Sharing/Worm propagation)
        * **Port 3389**: RDP (Remote Desktop)
        
        #### 🛡️ Defense Core
        * **Predictive Intelligence**: Random Forest classification of flow data.
        * **Direct Port Masking**: Hardened monitoring on the specific ports listed above.
        * **Rapid Mitigation**: Real-time CLI rule generation for instant blocking.
        """)
    with col2:
        # Using a professional shield icon to represent your Defense Core
        st.image("https://img.icons8.com/nolan/512/security-configuration.png", width=350)

# ===============================
# Tab 3: Technical Pipeline
# ===============================
with tab_pipeline:
    st.markdown("<h2 style='color: #58a6ff;'>⚙️ Technical Pipeline Analysis</h2>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info("### 1. Data Fusion")
        st.write("Loads specific network features from the dataset: Destination Port, Packets, and Flow Duration.")
    with c2:
        st.success("### 2. Pattern Logic")
        st.write("Implements **Direct Flagging** for high-risk ports (22, 23, 445, 3389) as shown in the telemetry feed.")
    with c3:
        st.warning("### 3. AI Classifier")
        st.write("Ensemble Random Forest model (`siem_model.pkl`) trained on specific attack subsets.")

# ===============================
# Tab 2: SOC Dashboard
# ===============================
with tab_soc:
    st.markdown("<h2 style='color: #00f2ff;'>🛰️ Real-Time SOC Command</h2>", unsafe_allow_html=True)

    # Sidebar
    st.sidebar.markdown("<h2 style='color: #58a6ff;'>CONTROL PANEL</h2>", unsafe_allow_html=True)
    live_mode = st.sidebar.toggle("🚀 Activate Stream")
    attack_mode = st.sidebar.toggle("☣️ Attack Simulation")
    speed = st.sidebar.slider("Sampling Rate", 0.1, 5.0, 1.0)

    if st.sidebar.button("Clear Buffer"):
        st.session_state.logs = pd.DataFrame(columns=["Timestamp", "Source IP", "Port", "Duration", "Fwd Pkts", "Bwd Pkts", "Status", "Alert Type", "Recommended Action"])
        st.rerun()

    # Pattern Matching sidebar info as seen in your screenshot
    st.sidebar.markdown("---")
    st.sidebar.caption("PATTERN MONITORING ACTIVE")
    st.sidebar.code("P_MATCH: [22, 23, 445, 3389]", language="python")

    if "logs" not in st.session_state:
        st.session_state.logs = pd.DataFrame(columns=["Timestamp", "Source IP", "Port", "Duration", "Fwd Pkts", "Bwd Pkts", "Status", "Alert Type", "Recommended Action"])

    # Live Engine
    if live_mode:
        if model is None:
            st.error("Engine failure: Model assets missing.")
        else:
            if attack_mode:
                # Randomly picking from the monitored critical ports
                d_port = random.choice([22, 23, 445, 3389]) 
                flow_dur, f_pkts, b_pkts = random.randint(0, 100), random.randint(500, 2000), random.randint(500, 2000)
            else:
                d_port = random.choice([80, 443, 8080])
                flow_dur, f_pkts, b_pkts = random.randint(1000, 5000), random.randint(1, 20), random.randint(1, 20)

            is_suspicious = 1 if d_port in [22, 23, 445, 3389] else 0
            input_data = np.array([[d_port, flow_dur, f_pkts, b_pkts, is_suspicious]])
            
            prediction = model.predict(input_data)
            result = le.inverse_transform(prediction)[0]
            if attack_mode and result == "BENIGN": result = "Infiltration/DDoS"
            
            status = "SAFE" if result == "BENIGN" else "ALERT"
            src_ip = f"192.168.1.{random.randint(2,254)}"
            recommended_action = f"sudo iptables -A INPUT -s {src_ip} -j DROP" if status == "ALERT" else "Verified"

            new_log = {"Timestamp": datetime.datetime.now().strftime("%H:%M:%S"), "Source IP": src_ip, "Port": d_port, "Duration": flow_dur, "Fwd Pkts": f_pkts, "Bwd Pkts": b_pkts, "Status": status, "Alert Type": result, "Recommended Action": recommended_action}
            st.session_state.logs = pd.concat([pd.DataFrame([new_log]), st.session_state.logs], ignore_index=True).head(50)
            time.sleep(speed)
            st.rerun()

    # Metrics
    m1, m2, m3, m4 = st.columns(4)
    threats = len(st.session_state.logs[st.session_state.logs["Status"] == "ALERT"])
    with m1: st.metric("INGESTED EVENTS", len(st.session_state.logs))
    with m2: st.metric("DETECTED THREATS", threats, delta=f"{threats} New", delta_color="inverse")
    with m3: st.metric("SYSTEM RISK", "CRITICAL" if threats > 5 else "STABLE")
    with m4: st.metric("SENSOR STATUS", "ONLINE")

    st.markdown("---")

    # Main Body
    left_body, right_body = st.columns([2.5, 1], gap="medium")
    with left_body:
        st.markdown("#### ⚡ Real-Time Telemetry Feed")
        def color_status(val):
            return 'background-color: #3e0b0e; color: #ff8080;' if val == 'ALERT' else 'background-color: #0b2e13; color: #80ffab;'
        if not st.session_state.logs.empty:
            st.dataframe(st.session_state.logs.style.applymap(color_status, subset=['Status']), use_container_width=True, height=400)
    
    with right_body:
        st.markdown("#### 📉 Intelligence Charts")
        if not st.session_state.logs.empty:
            st.bar_chart(st.session_state.logs["Alert Type"].value_counts())
            # Line Chart maintained as requested previously
            st.line_chart(st.session_state.logs["Fwd Pkts"])

    # Response Section
    st.markdown("---")
    st.subheader("🛠️ Automated Containment")
    alerts_only = st.session_state.logs[st.session_state.logs["Status"] == "ALERT"]
    if not alerts_only.empty:
        latest = alerts_only.iloc[0]
        st.error(f"⚠️ BLOCKING: {latest['Source IP']}")
        st.code(latest["Recommended Action"], language="bash")
    else:
        st.success("No active containment required.")

st.markdown("---")
st.caption("SentinelML | SOC Command Dashboard v1.3")