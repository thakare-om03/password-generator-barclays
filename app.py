# ------------- app.py -------------
# Remove TF dependencies if not strictly needed by other parts (BERT uses torch/tf backend)
# import os
# os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
# import tensorflow.compat.v1 as tf
# tf.disable_v2_behavior()

import streamlit as st
import pandas as pd
import logging # Use logging

# Import project modules
from src.policy_manager import PolicyManager
from src.password_analyzer import PasswordAnalyzer
from src.advanced_analyzer import AdvancedPasswordAnalyzer, SecurityMetrics
from src.password_generator import PasswordGenerator, PasswordSuggestion
from src.ai_explainer import AIExplainer
from src.password_hasher import PasswordHasher # Import hasher

# --- Configuration & Initialization ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def display_policy_checks(checks):
    """Displays policy check results nicely."""
    st.write("**Policy Compliance:**")
    all_passed = checks.get('all_passed', False)
    status = "✅ Compliant" if all_passed else "❌ Non-Compliant"
    st.write(f"Status: {status}")

    if not all_passed:
        st.write("Violations:")
        # Use detailed checks if available, otherwise fallback
        details = st.session_state.analysis_results.get('detailed_policy_checks', checks)
        for check, passed in details.items():
             # Skip internal 'all_passed' key if present in details
             if check == 'all_passed' or check.startswith('require_'): continue
             if not passed:
                  st.warning(f"- Requirement not met: **{check.replace('_',' ').title()}**")


def display_advanced_metrics(metrics: SecurityMetrics):
    """Displays advanced analysis metrics."""
    st.metric("Entropy Score", f"{metrics.entropy:.1f} bits")

    if metrics.breach_count == -1:
        st.warning("⚠️ Could not check data breaches (API error).")
    elif metrics.breach_count > 0:
        st.error(f"❌ Found in **{metrics.breach_count:,}** known data breaches!")
    else:
        st.success("✅ Not found in known data breaches.")

    # Display Advanced Policy Compliance (Entropy & Breaches)
    if not metrics.policy_compliant:
         st.write("**Advanced Policy Violations:**")
         for violation in metrics.policy_violations:
              st.warning(f"- {violation}")

    st.write("**Estimated Crack Times:**")
    # Use pandas for better table formatting
    df_crack_times = pd.DataFrame(
        metrics.crack_time_estimates.items(),
        columns=['Attack Scenario', 'Estimated Time']
    )
    st.table(df_crack_times.set_index('Attack Scenario'))


def display_pattern_analysis(patterns):
    """Displays detected patterns."""
    st.write("**Detected Patterns/Weaknesses:**")
    if patterns:
        for pattern in patterns:
            st.warning(f"- {pattern}")
    else:
        st.info("✅ No common patterns detected.")


def display_ml_analysis(ml_results):
    """Displays ML prediction results."""
    st.write("**ML Strength Prediction:**")
    score = ml_results.get('strength_score', 0.0)
    is_strong = ml_results.get('is_strong_prediction', False)
    strength_label = "Strong" if is_strong else "Weak"
    st.progress(score) # Visual progress bar
    st.write(f"Predicted Strength: **{strength_label}** (Score: {score:.2f})")
    if 'error' in ml_results:
         st.error(f"ML Analysis Error: {ml_results['error']}")


def display_ai_feedback(feedback):
    """Displays AI-generated feedback."""
    st.write("### 💡 AI-Powered Feedback")
    with st.expander("Show AI Explanation", expanded=False):
        st.markdown(feedback) # Use markdown for better formatting potential


def display_suggestions(suggestions: list[PasswordSuggestion]):
    """Displays password suggestions."""
    st.write("### ✨ Suggested Strong Passwords")
    st.info("These suggestions meet the security policy. Choose one or create your own strong password.")

    cols = st.columns(len(suggestions))
    for i, suggestion in enumerate(suggestions):
        with cols[i]:
            st.code(f"{suggestion.password}")
            st.caption(f"{suggestion.description}\nEntropy: {suggestion.entropy:.1f} bits")
            # Add button to select suggestion
            if st.button(f"Select Option {i+1}", key=f"select_{i}"):
                st.session_state.selected_password = suggestion.password
                st.success(f"Option {i+1} selected. Confirm below.")
                # Force rerun to update UI state
                st.experimental_rerun()

# --- Main Application Logic ---

def main():
    st.set_page_config(page_title="Barclays Password Security", page_icon="🔒", layout="wide")
    st.title("🔒 Barclays GenAI-Enhanced Password Security")
    st.markdown("""
        Enter a password to check its strength against security policy.
        The system provides detailed analysis, AI-powered feedback, and strong suggestions.
    """)

    # --- Initialization (cached to improve performance) ---
    @st.cache_resource
    def load_modules():
        try:
            policy_manager = PolicyManager()
            password_analyzer = PasswordAnalyzer(policy_manager)
            advanced_analyzer = AdvancedPasswordAnalyzer(policy_manager)
            password_generator = PasswordGenerator(policy_manager)
            ai_explainer = AIExplainer() # Consider larger model if available
            password_hasher = PasswordHasher()
            return {
                "policy_manager": policy_manager,
                "password_analyzer": password_analyzer,
                "advanced_analyzer": advanced_analyzer,
                "password_generator": password_generator,
                "ai_explainer": ai_explainer,
                "password_hasher": password_hasher
            }
        except (FileNotFoundError, ImportError, IOError, Exception) as e:
             st.error(f"Fatal Error during initialization: {e}. Please ensure models are trained and dependencies installed.")
             logging.error("Initialization failed.", exc_info=True)
             st.stop() # Stop execution if core components fail

    modules = load_modules()
    policy_manager = modules["policy_manager"]
    password_analyzer = modules["password_analyzer"]
    advanced_analyzer = modules["advanced_analyzer"]
    password_generator = modules["password_generator"]
    ai_explainer = modules["ai_explainer"]
    password_hasher = modules["password_hasher"]

    # --- Session State Management ---
    if 'analysis_complete' not in st.session_state:
        st.session_state.analysis_complete = False
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = {}
    if 'advanced_metrics' not in st.session_state:
        st.session_state.advanced_metrics = None
    if 'ai_feedback' not in st.session_state:
        st.session_state.ai_feedback = ""
    if 'suggestions' not in st.session_state:
        st.session_state.suggestions = []
    if 'final_password' not in st.session_state:
        st.session_state.final_password = "" # Track user's final choice
    if 'password_hashed' not in st.session_state:
        st.session_state.password_hashed = False
    if 'password_input' not in st.session_state:
        st.session_state.password_input = ""
    if 'selected_password' not in st.session_state:
        st.session_state.selected_password = ""


    # --- Password Input and Analysis ---
    password = st.text_input(
        "Enter your desired password:",
        type="password",
        key="password_input_field" # Use key to potentially reset
        # value=st.session_state.password_input # Persist input across runs if desired
    )

    analyze_button = st.button("Analyze Password", type="primary")

    if analyze_button and password:
        st.session_state.analysis_complete = False # Reset flags on new analysis
        st.session_state.password_hashed = False
        st.session_state.selected_password = "" # Clear previous selection
        st.session_state.password_input = password # Store current input

        with st.spinner("🔬 Analyzing password strength..."):
            try:
                 # Basic Analysis
                 st.session_state.analysis_results = password_analyzer.analyze_password(password)
                 # Advanced Analysis
                 st.session_state.advanced_metrics = advanced_analyzer.analyze_password(password)
                 # Combine results for AI Explainer context
                 full_context = {
                      **st.session_state.analysis_results,
                      "advanced_metrics": st.session_state.advanced_metrics.__dict__, # Convert dataclass to dict
                      "policy": policy_manager.get_policy() # Pass policy for context
                 }
                 # AI Feedback
                 st.session_state.ai_feedback = ai_explainer.generate_feedback(full_context)
                 # Suggestions (generate only if weak based on policy/entropy)
                 basic_policy_passed = st.session_state.analysis_results.get('policy_checks', {}).get('all_passed', False)
                 advanced_policy_passed = st.session_state.advanced_metrics.policy_compliant if st.session_state.advanced_metrics else False

                 if not basic_policy_passed or not advanced_policy_passed:
                      st.session_state.suggestions = password_generator.generate_suggestions(st.session_state.analysis_results)
                 else:
                      st.session_state.suggestions = [] # Don't show suggestions if strong enough

                 st.session_state.analysis_complete = True
            except Exception as e:
                 st.error(f"An error occurred during analysis: {e}")
                 logging.error("Analysis failed.", exc_info=True)
                 st.session_state.analysis_complete = False


    # --- Display Analysis Results ---
    if st.session_state.analysis_complete:
        st.divider()
        st.subheader("📊 Security Analysis Report")

        col1, col2 = st.columns([0.6, 0.4]) # Adjust column ratios

        with col1: # Main analysis results
            st.write("#### Overall Assessment")
            basic_policy_passed = st.session_state.analysis_results.get('policy_checks', {}).get('all_passed', False)
            advanced_policy_passed = st.session_state.advanced_metrics.policy_compliant if st.session_state.advanced_metrics else False
            if basic_policy_passed and advanced_policy_passed:
                 st.success("✅ Strong Password: Meets all security policy requirements.")
            else:
                 st.warning("⚠️ Weak Password: Does not meet all security policy requirements.")

            display_policy_checks(st.session_state.analysis_results.get('policy_checks', {}))
            if st.session_state.advanced_metrics:
                 display_advanced_metrics(st.session_state.advanced_metrics)
            display_pattern_analysis(st.session_state.analysis_results.get('pattern_analysis', {}).get('patterns_found', []))
            display_ml_analysis(st.session_state.analysis_results.get('ml_analysis', {}))

        with col2: # AI Feedback and Suggestions
            display_ai_feedback(st.session_state.ai_feedback)

            if st.session_state.suggestions:
                display_suggestions(st.session_state.suggestions)

        st.divider()

        # --- Password Confirmation and Hashing ---
        st.subheader("🔑 Final Password Confirmation")

        # Determine the password to confirm
        if st.session_state.selected_password:
            st.session_state.final_password = st.session_state.selected_password
            st.info(f"You selected suggestion: `{st.session_state.final_password}`")
        else:
            st.session_state.final_password = st.session_state.password_input # Use user's input if no suggestion selected
            if st.session_state.analysis_complete: # Only prompt if analysis was run
                 st.info(f"You entered: `{st.session_state.final_password}`")

        # Re-validate the final choice before allowing confirmation
        final_basic_analysis = password_analyzer.analyze_password(st.session_state.final_password)
        final_advanced_metrics = advanced_analyzer.analyze_password(st.session_state.final_password)
        final_basic_ok = final_basic_analysis.get('policy_checks', {}).get('all_passed', False)
        final_advanced_ok = final_advanced_metrics.policy_compliant

        if final_basic_ok and final_advanced_ok:
            st.success("This password meets all security requirements.")
            confirm_button_disabled = False
        else:
            st.error("This password does not meet all security requirements. Please choose a suggestion or modify your password.")
            confirm_button_disabled = True


        confirm_button = st.button(
             "Confirm and Set Password",
             disabled=confirm_button_disabled or not st.session_state.final_password or st.session_state.password_hashed
        )

        if confirm_button and st.session_state.final_password:
            try:
                with st.spinner("Hashing password..."):
                     hashed_password = password_hasher.hash_password(st.session_state.final_password)
                # --- !!! IMPORTANT !!! ---
                # In a real application, this hashed_password would now be sent
                # securely to the backend system/API to update the user's record
                # in the database. DO NOT store it in Streamlit's session state long-term.
                # For demonstration, we just display success.
                # -------------------------
                st.session_state.password_hashed = True
                st.success("✅ Password securely hashed and set successfully!")
                st.code(f"Hashed Password (for demo): {hashed_password[:15]}...") # Show partial hash for demo
                st.balloons()
                # Clear sensitive state after success
                st.session_state.password_input = ""
                st.session_state.final_password = ""
                st.session_state.selected_password = ""
                st.session_state.analysis_complete = False

            except Exception as e:
                 st.error(f"An error occurred during hashing: {e}")
                 logging.error("Hashing failed.", exc_info=True)
                 st.session_state.password_hashed = False

        if st.session_state.password_hashed:
             st.info("Password process complete. You can analyze another password.")


    # --- Footer / Policy Display ---
    st.divider()
    with st.expander("View Current Password Policy"):
        st.json(policy_manager.get_policy())


if __name__ == "__main__":
    main()