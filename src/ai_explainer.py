import os
import subprocess
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set Ollama model and storage path
DEFAULT_MODEL = "llama3.2"
OLLAMA_HOME_DIR = "F:\\Projects\\ollama_models"  # Custom path for Ollama models

class AIExplainer:
    def __init__(self, model_name=DEFAULT_MODEL):
        """
        Initializes the AI Explainer using Ollama for local inference.
        Args:
            model_name (str): The name of the local Ollama model to use.
        """
        self.model_name = model_name
        
        # Set custom Ollama path
        os.environ["OLLAMA_MODELS"] = OLLAMA_HOME_DIR
        logging.info(f"Setting Ollama models path to: {OLLAMA_HOME_DIR}")
        
        self.ollama_installed = self._check_ollama_installed()
        
        if not self.ollama_installed:
            logging.error("Ollama is not installed or not in PATH. Please install it from https://ollama.com/")
            return
        
        self._check_and_download_model()

    def _check_ollama_installed(self):
        """Check if Ollama is installed by running `ollama list`."""
        try:
            env = os.environ.copy()
            subprocess.run(["ollama", "list"], check=True, capture_output=True, text=True, env=env)
            return True
        except FileNotFoundError:
            return False
        except subprocess.CalledProcessError:
            return False

    def _check_and_download_model(self):
        """Ensure the specified model is available locally."""
        env = os.environ.copy()
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, env=env)
        if self.model_name not in result.stdout:
            logging.info(f"Model {self.model_name} not found locally. Downloading to {OLLAMA_HOME_DIR}...")
            subprocess.run(["ollama", "pull", self.model_name], check=True, env=env)
        else:
            logging.info(f"Model {self.model_name} is already available locally.")

    def generate_feedback(self, analysis_results):
        """
        Generates natural language feedback based on password security analysis.
        Args:
            analysis_results (dict): Dictionary containing password security details.
        Returns:
            str: AI-generated feedback or fallback message.
        """
        if not self.ollama_installed:
            return "AI feedback generation is unavailable. Please review the security analysis manually."
        
        try:
            system_prompt = "You are a password security assistant providing professional feedback."
            user_input = """
            Please analyze this password security report:
            
            Policy Compliance: {policy_compliance}
            Entropy: {entropy} bits
            Breach Count: {breach_count}
            Patterns Detected: {patterns}
            ML Strength Score: {ml_score}
            
            Provide: 1) Overall assessment, 2) Key issues, 3) Improvement advice.
            """.format(
                policy_compliance="All requirements met" if analysis_results.get('policy_checks', {}).get('all_passed', False) else "Some requirements missing",
                entropy=analysis_results.get('advanced_metrics', {}).get('entropy', 'N/A'),
                breach_count=analysis_results.get('advanced_metrics', {}).get('breach_count', 'N/A'),
                patterns=", ".join(analysis_results.get('pattern_analysis', {}).get('patterns_found', [])) or "None",
                ml_score=analysis_results.get('ml_analysis', {}).get('strength_score', 'N/A')
            )
            
            prompt = f"{system_prompt}\n\n{user_input}"
            
            # Call Ollama model to generate response with custom environment
            env = os.environ.copy()
            result = subprocess.run([
                "ollama", "run", self.model_name, prompt
            ], capture_output=True, text=True, env=env)
            
            response = result.stdout.strip()
            
            return response if response else "Unable to generate AI feedback. Please review the security analysis manually."
        
        except Exception as e:
            logging.error(f"Error during AI feedback generation: {e}", exc_info=True)
            return "AI feedback could not be generated due to an error."
            
    def enhance_password(self, password, original_analysis):
        """
        Use the AI model to generate personalized, stronger versions of the user's password.
        
        Args:
            password (str): The original password
            original_analysis (dict): Analysis results of the original password
            
        Returns:
            str: An enhanced version of the password
        """
        if not self.ollama_installed or not password:
            return None
            
        try:
            # Extract key insights from the analysis
            policy_issues = []
            if original_analysis.get('policy_checks'):
                for check, passed in original_analysis.get('policy_checks').items():
                    if check != 'all_passed' and not passed:
                        policy_issues.append(check)
            
            patterns = original_analysis.get('pattern_analysis', {}).get('patterns_found', [])
            
            system_prompt = "You are a password enhancement assistant. You generate secure variations of passwords while maintaining some recognizable elements."
            user_input = f"""
            Original password: {password}
            
            Issues to fix:
            - Policy issues: {', '.join(policy_issues) if policy_issues else 'None'}
            - Patterns detected: {', '.join(patterns) if patterns else 'None'}
            
            Create a more secure version of this password by:
            1. Replacing some characters with similar-looking special characters or numbers
            2. Adding complexity while keeping some original elements recognizable
            3. Making it at least 12 characters long
            4. Including uppercase, lowercase, numbers, and special characters
            
            Return ONLY the enhanced password, nothing else.
            """
            
            prompt = f"{system_prompt}\n\n{user_input}"
            
            # Call Ollama model
            env = os.environ.copy()
            result = subprocess.run([
                "ollama", "run", self.model_name, prompt
            ], capture_output=True, text=True, env=env)
            
            enhanced_password = result.stdout.strip()
            
            # Clean up the result (sometimes models output additional text)
            # Look for a line that looks like a password (no spaces, reasonable length)
            lines = enhanced_password.split('\n')
            for line in lines:
                clean_line = line.strip()
                if clean_line and ' ' not in clean_line and 8 <= len(clean_line) <= 30:
                    enhanced_password = clean_line
                    break
            
            return enhanced_password
            
        except Exception as e:
            logging.error(f"Error during AI password enhancement: {e}", exc_info=True)
            return None