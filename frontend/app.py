import streamlit as st
import requests

st.set_page_config(
    page_title="Detection Rule Canvas",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar for project info
with st.sidebar:
    st.title("Detection Rule Canvas")
    st.markdown("""
    <small>
    Generate detection rules for any platform using AI.<br>
    <b>Multi-platform, modern, and open source.</b>
    </small>
    """, unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("""
    <b>How to use:</b>
    1. Enter a threat description or upload a file
    2. Select one or more platforms
    3. Click 'Generate Detection Rules'
    4. Download or copy your rules
    """)
    st.markdown("---")
    st.caption("© 2024 Detection Rule Canvas")

# Custom CSS for a modern look
st.markdown(
    """
    <style>
    .main { background-color: #f4f6fa; }
    .stButton>button {
        background-color: #2563eb;
        color: white;
        border-radius: 6px;
        padding: 0.5em 1.5em;
        font-weight: 600;
        transition: background 0.2s;
    }
    .stButton>button:hover {
        background-color: #1e40af;
        color: #fff;
    }
    .stTextArea textarea {
        border-radius: 6px;
        border: 1.5px solid #cbd5e1;
        background: #fff;
    }
    .stMultiSelect>div {
        border-radius: 6px !important;
    }
    .stDownloadButton>button {
        background-color: #10b981;
        color: white;
        border-radius: 6px;
        font-weight: 600;
    }
    .stDownloadButton>button:hover {
        background-color: #059669;
        color: #fff;
    }
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.header("1. Input Threat Intelligence")
threat_description = st.text_area(
    "Describe the threat or paste threat intel here",
    height=150,
    help="Provide a detailed description or paste threat intelligence data."
)
uploaded_file = st.file_uploader(
    "Or upload a threat intel file (PDF, JSON, Markdown)",
    type=["pdf", "json", "md"]
)

st.header("2. Select Platforms")
platforms = st.multiselect(
    "Choose platforms to generate rules for:",
    ["Sigma", "Azure Sentinel (KQL)", "CrowdStrike (Falcon)", "SentinelOne (SQL)", "Splunk (SPL)"],
    default=["Sigma"]
)

if uploaded_file is not None:
    st.info("File upload is not yet implemented for AI generation. Please paste threat intel above.")

st.markdown("<br>", unsafe_allow_html=True)

if st.button("Generate Detection Rules"):
    if not threat_description or not platforms:
        st.warning("Please provide a threat description and select at least one platform.")
    else:
        with st.spinner("Generating rules..."):
            try:
                response = requests.post(
                    "http://localhost:8000/generate",
                    json={"threat_description": threat_description, "platforms": platforms},
                    timeout=60
                )
                if response.status_code == 200:
                    rules = response.json()["rules"]
                    for platform, rule in rules.items():
                        st.subheader(f"{platform} Rule")
                        st.code(rule, language="yaml" if platform == "Sigma" else "text")
                        st.download_button(
                            label=f"Download {platform} Rule",
                            data=rule,
                            file_name=f"{platform.lower().replace(' ', '_')}_rule.txt"
                        )
                else:
                    st.error(f"Error: {response.text}")
            except Exception as e:
                st.error(f"Failed to connect to backend: {e}") 