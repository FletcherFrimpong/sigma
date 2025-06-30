import streamlit as st
import requests

st.set_page_config(
    page_title="Detection Rule Canvas",
    page_icon="🛡️",
    layout="wide"
)

if 'step' not in st.session_state:
    st.session_state.step = 1
if 'threat_description' not in st.session_state:
    st.session_state.threat_description = ''
if 'extracted_summary' not in st.session_state:
    st.session_state.extracted_summary = ''
if 'platforms' not in st.session_state:
    st.session_state.platforms = []
if 'rules' not in st.session_state:
    st.session_state.rules = {}

st.sidebar.title("Detection Rule Canvas Wizard")
st.sidebar.markdown("Step-by-step detection rule generation and analysis.")
st.sidebar.markdown("---")
st.sidebar.caption("© 2024 Detection Rule Canvas")

# --- Step 1: Upload or Enter Threat Intel ---
if st.session_state.step == 1:
    st.header("Step 1: Upload or Enter Threat Intelligence")
    uploaded_file = st.file_uploader("Upload threat intel file (PDF, JSON, MD, TXT)", type=["pdf", "json", "md", "txt"])
    st.markdown("**Or paste threat description below:**")
    threat_description = st.text_area("Threat Description", st.session_state.threat_description, height=150)
    col1, col2 = st.columns([1,1])
    with col1:
        if uploaded_file is not None:
            if st.button("Extract Threat Intel"):
                with st.spinner("Extracting threat intel..."):
                    try:
                        response = requests.post(
                            "http://localhost:8000/extract",
                            files={"file": (uploaded_file.name, uploaded_file.getvalue())},
                            timeout=60
                        )
                        if response.status_code == 200:
                            st.session_state.extracted_summary = response.json()["summary"]
                            st.session_state.step = 2
                            st.rerun()
                        else:
                            st.error(f"Error: {response.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")
        else:
            if st.button("Next"):
                st.session_state.threat_description = threat_description
                st.session_state.step = 2
                st.rerun()

# --- Step 2: Review/Edit Threat Description ---
elif st.session_state.step == 2:
    st.header("Step 2: Review & Edit Threat Description")
    if st.session_state.extracted_summary:
        st.info("Extracted from file:")
        st.session_state.threat_description = st.text_area("Threat Description", st.session_state.extracted_summary, height=150)
    else:
        st.session_state.threat_description = st.text_area("Threat Description", st.session_state.threat_description, height=150)
    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Back"):
            st.session_state.step = 1
            st.rerun()
    with col2:
        if st.button("Next"):
            st.session_state.step = 3
            st.rerun()

# --- Step 3: Select Platforms ---
elif st.session_state.step == 3:
    st.header("Step 3: Select Platforms")
    st.session_state.platforms = st.multiselect(
        "Choose platforms to generate rules for:",
        ["Sigma", "Azure Sentinel (KQL)", "CrowdStrike (Falcon)", "SentinelOne (SQL)", "Splunk (SPL)"],
        default=st.session_state.platforms or ["Sigma"]
    )
    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Back"):
            st.session_state.step = 2
            st.rerun()
    with col2:
        if st.button("Generate Detection Rules"):
            if not st.session_state.threat_description or not st.session_state.platforms:
                st.warning("Please provide a threat description and select at least one platform.")
            else:
                with st.spinner("Generating rules..."):
                    try:
                        response = requests.post(
                            "http://localhost:8000/generate",
                            json={"threat_description": st.session_state.threat_description, "platforms": st.session_state.platforms},
                            timeout=60
                        )
                        if response.status_code == 200:
                            st.session_state.rules = response.json()["rules"]
                            st.session_state.step = 4
                            st.rerun()
                        else:
                            st.error(f"Error: {response.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")

# --- Step 4: View Generated Rules and Advanced Actions ---
elif st.session_state.step == 4:
    st.header("Step 4: View Generated Rules & Advanced Actions")
    for platform, rule in st.session_state.rules.items():
        st.markdown(f"### {platform} Rule")
        st.code(rule, language="yaml" if platform == "Sigma" else "text")
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        with col1:
            st.download_button(
                label=f"Download",
                data=rule,
                file_name=f"{platform.lower().replace(' ', '_')}_rule.txt"
            )
        with col2:
            if st.button(f"Analyze Quality ({platform})", key=f"analyze_{platform}"):
                with st.spinner("Analyzing rule quality..."):
                    try:
                        resp = requests.post(
                            "http://localhost:8000/analyze",
                            json={"rule": rule, "platform": platform},
                            timeout=60
                        )
                        if resp.status_code == 200:
                            st.info(resp.json()["analysis"])
                        else:
                            st.error(f"Error: {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")
        with col3:
            if st.button(f"MITRE Tags ({platform})", key=f"mitre_{platform}"):
                with st.spinner("Suggesting MITRE ATT&CK tags..."):
                    try:
                        resp = requests.post(
                            "http://localhost:8000/mitre_tags",
                            json={"rule": rule},
                            timeout=60
                        )
                        if resp.status_code == 200:
                            st.info(resp.json()["mitre_tags"])
                        else:
                            st.error(f"Error: {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")
        with col4:
            log_sample = st.text_area(f"Log Sample for Simulation ({platform})", key=f"log_{platform}")
            if st.button(f"Simulate ({platform})", key=f"simulate_{platform}"):
                with st.spinner("Simulating rule..."):
                    try:
                        resp = requests.post(
                            "http://localhost:8000/simulate",
                            json={"rule": rule, "log_sample": log_sample},
                            timeout=60
                        )
                        if resp.status_code == 200:
                            match = resp.json()["match"]
                            if match:
                                st.success("Rule matches the log sample!")
                            else:
                                st.warning("Rule does NOT match the log sample.")
                        else:
                            st.error(f"Error: {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")
        with col5:
            if st.button(f"Show History ({platform})", key=f"history_{platform}"):
                with st.spinner("Fetching rule history..."):
                    try:
                        resp = requests.post(
                            "http://localhost:8000/history",
                            json={"rule_id": st.session_state.threat_description, "rule": rule, "platform": platform},
                            timeout=60
                        )
                        if resp.status_code == 200:
                            versions = resp.json()["versions"]
                            if versions:
                                for v in versions:
                                    st.info(f"{v['timestamp']}:\n{v['rule']}")
                            else:
                                st.info("No history found for this rule.")
                        else:
                            st.error(f"Error: {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to backend: {e}")
        with col6:
            if st.button(f"Export ({platform})", key=f"export_{platform}"):
                with st.spinner("Exporting rule..."):
                    try:
                        params = {"rule": rule, "platform": platform}
                        export_url = f"http://localhost:8000/export"
                        st.markdown(f"[Download Exported Rule]({export_url}?rule={rule}&platform={platform})", unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"Failed to export rule: {e}")
    st.markdown("---")
    if st.button("Back"):
        st.session_state.step = 3
        st.rerun() 