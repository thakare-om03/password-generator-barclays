import streamlit as st
import pandas as pd
import logging
import base64
import requests

# Import project modules
from src.policy_manager import PolicyManager
from src.password_analyzer import PasswordAnalyzer
from src.advanced_analyzer import AdvancedPasswordAnalyzer, SecurityMetrics
from src.password_generator import PasswordGenerator, PasswordSuggestion
from src.ai_explainer import AIExplainer
from src.password_hasher import PasswordHasher

# --- Configuration & Initialization ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---
def get_barclays_logo():
    """Get Barclays logo as base64 for embedding in HTML"""
    try:
        logo_url = "https://logos-world.net/wp-content/uploads/2021/08/Barclays-Symbol.png"
        response = requests.get(logo_url)
        response.raise_for_status()
        return base64.b64encode(response.content).decode()
    except Exception as e:
        logging.error(f"Failed to load logo: {e}")
        return None

def display_policy_checks(checks):
    """Displays policy check results with clean design."""
    all_passed = checks.get('all_passed', False)
    if all_passed:
        st.success("✅ Policy Compliant")
    else:
        st.warning("⚠️ Policy Requirements")
        details = st.session_state.analysis_results.get('detailed_policy_checks', checks)
        for check, passed in details.items():
            if check == 'all_passed' or check.startswith('require_'):
                continue
            icon = "✓" if passed else "✗"
            color = "#28a745" if passed else "#dc3545"  # green/red colors
            st.markdown(f"<span style='color:{color}; font-size:18px'>{icon}</span> {check.replace('_',' ').title()}", unsafe_allow_html=True)

def display_advanced_metrics(metrics: SecurityMetrics):
    """Displays advanced analysis metrics."""
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Entropy", f"{metrics.entropy:.1f} bits")
    with col2:
        breach_label = (
            "⚠️ Check failed" if metrics.breach_count == -1 else 
            f"{metrics.breach_count} breaches" if metrics.breach_count > 0 else 
            "0 breaches"
        )
        st.metric("Breach Status", breach_label)
    with col3:
        compliance = "✓ Compliant" if metrics.policy_compliant else "✗ Non-compliant"
        st.metric("Advanced Policy", compliance)
    
    if not metrics.policy_compliant and metrics.policy_violations:
        with st.expander("View policy violations"):
            for violation in metrics.policy_violations:
                st.warning(violation)
    
    with st.expander("View crack time estimates"):
        df_crack_times = pd.DataFrame(
            metrics.crack_time_estimates.items(),
            columns=['Attack Scenario', 'Estimated Time']
        )
        st.table(df_crack_times.set_index('Attack Scenario'))

def display_pattern_analysis(patterns):
    """Displays detected patterns."""
    if patterns:
        st.subheader("Detected Patterns")
        for pattern in patterns:
            st.info(f"• {pattern}")
    else:
        st.success("✅ No common patterns detected")

def display_ml_analysis(ml_results):
    """Displays ML prediction results."""
    score = ml_results.get('strength_score', 0.0)
    st.subheader("ML Prediction")
    st.progress(float(score))
    st.write(f"Strength Score: {score:.2f}")

def display_suggestions(suggestions: list[PasswordSuggestion]):
    """
    Displays password suggestions in a grid layout (two columns).
    Clicking a suggestion automatically sets it as the selected password
    and triggers analysis.
    """
    if not suggestions:
        return

    col1, col2 = st.columns(2)
    
    for i, suggestion in enumerate(suggestions):
        col = col1 if i % 2 == 0 else col2
        with col:
            st.write("---")
            st.code(suggestion.password)
            st.caption(f"Entropy: {suggestion.entropy:.1f} bits | {suggestion.description}")
            if st.button("Use & Analyze", key=f"suggest_{i}", help="Apply this suggestion and analyze", 
                         type="primary"):
                st.session_state.selected_password = suggestion.password
                st.session_state.analyze_selected = True
                st.rerun()

def analyze_password_and_update_state(password, password_analyzer, advanced_analyzer, ai_explainer, policy_manager, password_generator):
    """Analyzes a password and updates all session state variables with the results."""
    st.session_state.password_input = password
    try:
        st.session_state.analysis_results = password_analyzer.analyze_password(password)
        st.session_state.advanced_metrics = advanced_analyzer.analyze_password(password)
        full_context = {
            **st.session_state.analysis_results,
            "advanced_metrics": st.session_state.advanced_metrics.__dict__,
            "policy": policy_manager.get_policy()
        }
        st.session_state.ai_feedback = ai_explainer.generate_feedback(full_context)
        
        basic_policy_passed = st.session_state.analysis_results.get('policy_checks', {}).get('all_passed', False)
        advanced_policy_passed = st.session_state.advanced_metrics.policy_compliant if st.session_state.advanced_metrics else False
        if not basic_policy_passed or not advanced_policy_passed:
            analysis_with_password = st.session_state.analysis_results.copy()
            analysis_with_password['original_password'] = password
            st.session_state.suggestions = password_generator.generate_suggestions(analysis_with_password)
        else:
            st.session_state.suggestions = []

        st.session_state.analysis_complete = True
        st.session_state.analyze_selected = False
    except Exception as e:
        st.error(f"An error occurred during analysis: {e}")
        logging.error("Analysis failed.", exc_info=True)
        st.session_state.analysis_complete = False

# --- Main Application Logic ---
def main():
    st.set_page_config(
        page_title="Barclays Secure Password Generator",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Custom CSS for a Barclays-themed landing page and buttons
    st.markdown("""
    <style>
    body { font-family: 'Segoe UI', sans-serif; }
    .logo-container { text-align: center; margin: 2rem 0; }
    .logo-container img { height: 150px; }
    .landing-title { text-align: center; color: #00aeef; font-size: 3rem; margin-bottom: 1rem; }
    .landing-subtitle { text-align: center; color: #555; font-size: 1.5rem; margin-bottom: 2rem; }
    .stButton > button { 
        background-color: #00aeef; 
        color: white; 
        border: none; 
        border-radius: 4px; 
        font-weight: 600; 
        margin-top: 0.5rem; 
        padding: 0.5rem 1rem;
        transition: background-color 0.2s ease;
    }
    .stButton > button:hover { 
        background-color: #0088c9; 
    }
    .footer { text-align: center; color: #6c757d; margin-top: 2rem; font-size: 0.85rem; }
    </style>
    """, unsafe_allow_html=True)
    
    # Display large logo and centered title as landing page header
    logo_base64 = get_barclays_logo()
    if logo_base64:
        st.markdown(f"""
            <div class="logo-container">
                <img src="data:image/png;base64,{logo_base64}" alt="Barclays Logo">
            </div>
        """, unsafe_allow_html=True)
    st.markdown('<div class="landing-title">GenAI-Enhanced Secure Password Generator</div>', unsafe_allow_html=True)
    st.markdown('<div class="landing-subtitle">Analyze, enhance, and generate secure passwords with AI assistance</div>', unsafe_allow_html=True)

    @st.cache_resource
    def load_modules():
        try:
            policy_manager = PolicyManager()
            password_analyzer = PasswordAnalyzer(policy_manager)
            advanced_analyzer = AdvancedPasswordAnalyzer(policy_manager)
            ai_explainer = AIExplainer()
            password_generator = PasswordGenerator(policy_manager, ai_explainer)
            password_hasher = PasswordHasher()
            return {
                "policy_manager": policy_manager,
                "password_analyzer": password_analyzer,
                "advanced_analyzer": advanced_analyzer,
                "password_generator": password_generator,
                "ai_explainer": ai_explainer,
                "password_hasher": password_hasher
            }
        except Exception as e:
            st.error(f"Fatal Error during initialization: {e}")
            logging.error("Initialization failed.", exc_info=True)
            st.stop()

    modules = load_modules()
    policy_manager = modules["policy_manager"]
    password_analyzer = modules["password_analyzer"]
    advanced_analyzer = modules["advanced_analyzer"]
    password_generator = modules["password_generator"]
    ai_explainer = modules["ai_explainer"]
    password_hasher = modules["password_hasher"]

    # Initialize session state variables
    for key in [
        'analysis_complete', 'analysis_results', 'advanced_metrics', 'ai_feedback', 
        'suggestions', 'final_password', 'password_hashed', 'password_input', 
        'selected_password', 'analyze_selected'
    ]:
        if key not in st.session_state:
            if key in ['analysis_complete', 'password_hashed', 'analyze_selected']:
                st.session_state[key] = False
            elif key == 'suggestions':
                st.session_state[key] = []
            elif key == 'analysis_results':
                st.session_state[key] = {}
            elif key == 'advanced_metrics':
                st.session_state[key] = None
            else:
                st.session_state[key] = ""

    # --- Password Input Section ---
    st.subheader("Enter Password")
    password_input = st.text_input(
        "Password to analyze",
        type="password",
        value=st.session_state.selected_password or st.session_state.password_input,
        placeholder="Type or paste your password here"
    )
    analyze_button = st.button("Analyze")
    
    # If user selected a suggestion previously
    if st.session_state.analyze_selected and st.session_state.selected_password:
        with st.spinner("Analyzing selected password..."):
            analyze_password_and_update_state(
                st.session_state.selected_password,
                password_analyzer,
                advanced_analyzer,
                ai_explainer,
                policy_manager,
                password_generator
            )
        st.rerun()

    # Manual analysis button
    if analyze_button and password_input:
        with st.spinner("Analyzing password strength..."):
            analyze_password_and_update_state(
                password_input,
                password_analyzer,
                advanced_analyzer,
                ai_explainer,
                policy_manager,
                password_generator
            )

    # --- Display Analysis Results ---
    if st.session_state.analysis_complete:
        basic_policy_passed = st.session_state.analysis_results.get('policy_checks', {}).get('all_passed', False)
        advanced_policy_passed = st.session_state.advanced_metrics.policy_compliant if st.session_state.advanced_metrics else False
        is_strong_password = basic_policy_passed and advanced_policy_passed
        
        if is_strong_password:
            st.success("Strong password that meets all security requirements")
        else:
            st.warning("Password does not meet all security requirements")

        st.header("Security Analysis")
        st.subheader("Basic Security Checks")
        display_policy_checks(st.session_state.analysis_results.get('policy_checks', {}))
        display_pattern_analysis(st.session_state.analysis_results.get('pattern_analysis', {}).get('patterns_found', []))
        
        st.subheader("Advanced Security Metrics")
        if st.session_state.advanced_metrics:
            display_advanced_metrics(st.session_state.advanced_metrics)
        else:
            st.info("No advanced metrics available")

        st.subheader("ML-Based Analysis")
        display_ml_analysis(st.session_state.analysis_results.get('ml_analysis', {}))
        
        st.header("AI-Powered Feedback")
        st.info(st.session_state.ai_feedback)

        st.header("Suggested Strong Passwords")
        if st.session_state.suggestions:
            display_suggestions(st.session_state.suggestions)
        else:
            if is_strong_password:
                st.success("Your password already meets all security requirements. No suggestions needed.")
            else:
                st.info("Generating password suggestions...")

        # --- Confirm Password Section ---
        if not st.session_state.password_hashed:
            st.header("Confirm Your Password")
            final_pwd = st.session_state.selected_password or st.session_state.password_input
            st.session_state.final_password = final_pwd
            st.code(final_pwd or "No password selected")

            final_basic_analysis = password_analyzer.analyze_password(final_pwd)
            final_advanced_metrics = advanced_analyzer.analyze_password(final_pwd)
            final_basic_ok = final_basic_analysis.get('policy_checks', {}).get('all_passed', False)
            final_advanced_ok = final_advanced_metrics.policy_compliant

            if final_basic_ok and final_advanced_ok:
                st.success("This password meets all security requirements")
                confirm_disabled = False
            else:
                st.error("This password does not meet security requirements")
                confirm_disabled = True
            
            confirm_button = st.button(
                "CONFIRM PASSWORD",
                disabled=confirm_disabled or not final_pwd
            )
            if confirm_button and final_pwd:
                try:
                    with st.spinner("Securing your password..."):
                        hashed_password = password_hasher.hash_password(final_pwd)
                    st.session_state.password_hashed = True
                    st.success("✅ Password Set Successfully! Your password has been securely hashed and stored.")
                    st.balloons()
                    
                    st.session_state.password_input = ""
                    st.session_state.final_password = ""
                    st.session_state.selected_password = ""

                    if st.button("SET ANOTHER PASSWORD"):
                        st.session_state.analysis_complete = False
                        st.session_state.password_hashed = False
                        st.rerun()
                except Exception as e:
                    st.error(f"An error occurred: {e}")
                    logging.error("Password hashing failed.", exc_info=True)
                    st.session_state.password_hashed = False

    # --- Footer ---
    st.markdown('<div class="footer">Barclays Secure Password Generator Platform v1.0</div>', unsafe_allow_html=True)
    with st.expander("Password Policy Information"):
        st.json(policy_manager.get_policy())

if __name__ == "__main__":
    main()
