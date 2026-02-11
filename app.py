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
    model = joblib.load("siem_model.pkl")
    le = joblib.load("label_encoder.pkl")
    return model, le

model, le = load_assets()

# ===============================
# Streamlit Page Config
# ===============================
st.set_page_config(page_title="Pro SIEM Platform", page_icon="🛡️", layout="wide")

st.title("🛡️ Enterprise SIEM Analyzer")
st.markdown("### Real-time Security Operations Center (SOC) Dashboard")

# ===============================
# Sidebar – Threat Simulation
# ===============================
st.sidebar.header("🕹️ SIEM Control Panel")
live_mode = st.sidebar.toggle("🚀 Start Live Ingestion")
attack_mode = st.sidebar.toggle("☣️ Simulate Active Attack")
speed = st.sidebar.slider("Ingestion Speed (sec)", 0.5, 5.0, 2.0)

if st.sidebar.button("Clear Logs"):
    st.session_state.logs = st.session_state.logs.iloc[0:0]
    st.rerun()

if "logs" not in st.session_state:
    st.session_state.logs = pd.DataFrame(
        columns=["Timestamp", "Source IP", "Port", "Duration", "Fwd Pkts", "Bwd Pkts", "Status", "Alert Type", "Recommended Action"]
    )

# ===============================
# Live Engine Logic
# ===============================
if live_mode:
    if attack_mode:
        d_port = random.choice([22, 23, 445, 3389]) 
        flow_dur, f_pkts, b_pkts = random.randint(0, 100), random.randint(500, 2000), random.randint(500, 2000)
    else:
        d_port = random.choice([80, 443])
        flow_dur, f_pkts, b_pkts = random.randint(1000, 5000), random.randint(1, 20), random.randint(1, 20)

    # PATTERN MATCHING: Direct flag feature for prediction
    is_suspicious = 1 if d_port in [22, 23, 445, 3389] else 0
    input_data = np.array([[d_port, flow_dur, f_pkts, b_pkts, is_suspicious]])
    
    prediction = model.predict(input_data)
    result = le.inverse_transform(prediction)[0]

    if attack_mode and result == "BENIGN":
        result = "Infiltration/DDoS"
    
    status = "SAFE" if result == "BENIGN" else "ALERT"
    src_ip = f"192.168.1.{random.randint(2,254)}"
    recommended_action = f"sudo iptables -A INPUT -s {src_ip} -j DROP" if status == "ALERT" else "Traffic Verified"

    new_log = {
        "Timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "Source IP": src_ip, "Port": d_port, "Duration": flow_dur,
        "Fwd Pkts": f_pkts, "Bwd Pkts": b_pkts, "Status": status,
        "Alert Type": result, "Recommended Action": recommended_action
    }
    
    st.session_state.logs = pd.concat([pd.DataFrame([new_log]), st.session_state.logs], ignore_index=True).head(50)
    time.sleep(speed)
    st.rerun()

# ===============================
# Dashboard Metrics
# ===============================
st.markdown("## 📊 SOC Operational Overview")
m1, m2, m3, m4 = st.columns(4)
threats = len(st.session_state.logs[st.session_state.logs["Status"] == "ALERT"])

with m1: st.metric("Events Ingested", len(st.session_state.logs))
with m2: st.metric("Active Alerts", threats, delta=f"{threats} Threats", delta_color="inverse")
with m3: st.metric("Risk Level", "CRITICAL" if threats > 10 else "STABLE")
with m4: st.metric("Sensor Status", "ACTIVE")

st.markdown("---")

# ===============================
# Main Dashboard Body
# ===============================
left_body, right_body = st.columns([2.2, 1], gap="medium")

with left_body:
    st.subheader("📜 Real-Time Event Stream")
    def color_status(val):
        return 'background-color: #930000; color: white;' if val == 'ALERT' else 'background-color: #004d00; color: white;'
    
    if not st.session_state.logs.empty:
        st.dataframe(st.session_state.logs.style.applymap(color_status, subset=['Status']), use_container_width=True, height=500)
    else:
        st.info("System Ready. Please start ingestion from the sidebar.")

with right_body:
    st.subheader("📊 Threat Analytics")
    if not st.session_state.logs.empty:
        st.bar_chart(st.session_state.logs["Alert Type"].value_counts(), height=200)
        st.area_chart(st.session_state.logs["Fwd Pkts"], height=200)

# ===============================
# Incident Response Section
# ===============================
st.markdown("---")
st.subheader("🛠️ Incident Response & Mitigation")
sol_col1, sol_col2 = st.columns([1, 1], gap="large")

with sol_col1:
    if not st.session_state.logs.empty:
        mit_stats = st.session_state.logs["Status"].value_counts()
        st.bar_chart(mit_stats)

with sol_col2:
    st.write("**🚀 Automated Response CLI (Latest Alert)**")
    alerts_only = st.session_state.logs[st.session_state.logs["Status"] == "ALERT"]
    if not alerts_only.empty:
        st.warning(f"Threat Detected: {alerts_only.iloc[0]['Source IP']}")
        st.code(alerts_only.iloc[0]["Recommended Action"], language="bash")
    else:
        st.success("No active threats detected.")

st.markdown("---")
st.caption("Mini SIEM Platform | SOC Analytics Project")