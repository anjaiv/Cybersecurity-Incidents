import streamlit as st

try:
    from .main import analyze_full
except ImportError:
    from main import analyze_full


st.title("Phishing Email Analysis System")
st.write("Enter an email to analyze:")

email_input = st.text_area("Email text")

if st.button("Analyze"):
    if email_input:
        result = analyze_full(email_input)

        st.subheader("ML Prediction")
        st.write(result["ml_result"])
        st.write(f"Confidence: {result['confidence'] * 100:.0f}%")
        st.write(f"Threat level: {result['threat_level']}")

        st.subheader("LLM Analysis")
        st.text(result["llm_result"])
    else:
        st.warning("Please enter an email.")
