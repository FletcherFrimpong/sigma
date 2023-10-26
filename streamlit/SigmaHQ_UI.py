import streamlit as st
import os
from PIL import Image


st.set_page_config(
    page_title="SigmaHQ Rule Creation",
    layout="wide",
    initial_sidebar_state="expanded",
)
custom_css = """
    <style>
        body {
            background-color: #10252F;
        }
    </style>
    """

st.markdown(custom_css, unsafe_allow_html=True)
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)


if "init" not in st.session_state:
    st.session_state["init"] = False
if "parent_dir" not in st.session_state:
    st.session_state["parent_dir"] = ""


cwd = os.getcwd()
if cwd != st.session_state["parent_dir"] and st.session_state["init"] == True:
    os.chdir(st.session_state["parent_dir"])
else:
    st.session_state["init"] = True
    st.session_state["parent_dir"] = cwd

st.markdown(
    """

        #### Welcome to SigmaHQ GUI 🚀
        #### This tool is built specifically to easily create and update Sigma Security Content.
        #### **👈🏽 Click the 🕵🏽 Sigma Content Creation on the left** to create or update existing Sigma Analytics

    """
)

col1, col2, col3 = st.columns([0.2, 0.5, 0.2])

with col1:
    pass

with col2:
    st.markdown(
        """
        ### Want to learn more?

        - Check out [SigmaHQ.io](https://sigmahq.io/)
        - Deepen your Sigma knowledge by jumping into our [documentation](https://sigmahq.io/docs/guide/getting-started.html)
        - Get insights about Sigma from the core maintainers by following our [blog](https://blog.sigmahq.io/)
        - Having issues? Sumbit a [new issue
          ](https://github.com/SigmaHQ/issues)
        """
    )
with col3:
    pass


col4, col5, col6 = st.columns([0.2, 0.6, 0.2])

with col5:
    image = Image.open("streamlit/sigma_logo_dark.png")
    st.image(image, width=300)
