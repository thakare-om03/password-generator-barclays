# ------------- src/ai_explainer.py -------------
from transformers import pipeline, set_seed
import warnings
import logging # Use logging instead of print for errors

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings("ignore", message="Setting `pad_token_id` to `eos_token_id`") # Suppress specific warning

class AIExplainer:
    def __init__(self, model_name='distilgpt2'): # Changed default to a smaller, faster model
        """
        Initializes the AI Explainer.
        Args:
            model_name (str): The name of the Hugging Face transformer model to use.
                              'gpt2' or 'distilgpt2' are options. Larger models like
                              'gpt-3.5-turbo' via API would require different setup.
        """
        self.model_name = model_name
        self.generator = None
        try:
            # Increased max_length for more detailed feedback
            # Consider adding truncation=True if needed, but might cut off explanations
            self.generator = pipeline(
                'text-generation',
                model=self.model_name,
                max_new_tokens=200 # Use max_new_tokens instead of max_length for better control
            )
            logging.info(f"AI Explainer initialized successfully with model: {self.model_name}")
        except Exception as e:
            logging.error(f"AI Explainer initialization error with model '{self.model_name}': {e}", exc_info=True)
            self.generator = None # Ensure generator is None if init fails

    def generate_feedback(self, analysis_results):
        """
        Generates natural language feedback based on comprehensive analysis results.
        Args:
            analysis_results (dict): A dictionary containing results from
                                     PasswordAnalyzer and AdvancedPasswordAnalyzer.
        Returns:
            str: AI-generated feedback string, or an error/fallback message.
        """
        if self.generator is None:
            logging.warning("AI Explainer generator not available.")
            return "AI feedback generation is currently unavailable. Please rely on the structured analysis results."

        try:
            # --- Build a Detailed Prompt ---
            prompt = "Analyze the following password security report and provide actionable feedback:\n\n"
            prompt += "## Password Analysis Report ##\n"

            # Policy Checks
            prompt += "\n### Policy Compliance ###\n"
            policy_checks = analysis_results.get('policy_checks', {})
            detailed_policy = analysis_results.get('detailed_policy_checks', {})
            all_policy_passed = policy_checks.get('all_passed', False)
            if all_policy_passed:
                 prompt += "- ✅ All basic policy requirements met.\n"
            else:
                 prompt += "- ❌ Basic policy requirements NOT met:\n"
                 for check, passed in detailed_policy.items():
                      if not passed:
                           prompt += f"    - Missing requirement: {check}\n"

            # Advanced Checks (Entropy, Breaches) - Add if available in analysis_results
            advanced_metrics = analysis_results.get('advanced_metrics', {})
            entropy = advanced_metrics.get('entropy')
            breach_count = advanced_metrics.get('breach_count')
            min_entropy_policy = analysis_results.get('policy', {}).get('min_entropy', 60) # Get from policy if passed in
            max_breach_policy = analysis_results.get('policy', {}).get('max_breach_count', 0)

            prompt += "\n### Advanced Security Metrics ###\n"
            if entropy is not None:
                entropy_passed = entropy >= min_entropy_policy
                prompt += f"- Entropy Score: {entropy:.1f} bits ({'✅ Meets' if entropy_passed else '❌ Below'} minimum of {min_entropy_policy})\n"
            if breach_count is not None:
                breach_passed = breach_count <= max_breach_policy
                if breach_passed:
                    prompt += "- ✅ Not found in known data breaches.\n"
                else:
                    prompt += f"- ❌ Found in {breach_count:,} known data breaches!\n"

            # Pattern Analysis
            patterns = analysis_results.get('pattern_analysis', {}).get('patterns_found', [])
            prompt += "\n### Detected Patterns & Weaknesses ###\n"
            if patterns:
                prompt += "- Common patterns/weaknesses detected:\n"
                for pattern in patterns:
                    prompt += f"    - {pattern}\n"
            else:
                prompt += "- No common patterns detected.\n"

            # ML Analysis (Optional inclusion in prompt)
            ml_analysis = analysis_results.get('ml_analysis', {})
            ml_score = ml_analysis.get('strength_score')
            if ml_score is not None:
                prompt += f"- ML Strength Prediction Score: {ml_score:.2f}\n"


            # --- Instructions for the AI ---
            prompt += "\n## AI Feedback Request ##\n"
            prompt += "Based *only* on the report above, please provide:\n"
            prompt += "1.  A brief overall summary of the password's security posture.\n"
            prompt += "2.  Specific, actionable recommendations to address the identified weaknesses (like missing requirements, low entropy, breaches, or patterns). Explain *why* these changes improve security.\n"
            prompt += "3.  Avoid suggesting completely new passwords, focus on improving the analyzed characteristics.\n"
            prompt += "Keep the feedback concise and easy to understand.\n\n"
            prompt += "AI Feedback:"
            # --- End Prompt ---

            # Set seed for potential reproducibility if needed
            # set_seed(42)

            # Generate text
            response = self.generator(prompt, num_return_sequences=1)[0]['generated_text']

            # Extract only the part after "AI Feedback:"
            feedback = response.split("AI Feedback:")[-1].strip()

            # Basic cleanup (remove potential repetition of the prompt)
            if feedback.startswith("Based only on the report above"):
                 feedback = "Apologies, the AI repeated the request. Please review the structured analysis for details."

            return feedback if feedback else "AI model returned an empty response."

        except Exception as e:
            logging.error(f"Error during AI feedback generation: {e}", exc_info=True)
            return f"Unable to generate AI feedback due to an internal error ({type(e).__name__})."

# Example usage:
if __name__ == '__main__':
    # Create dummy analysis results for testing
    dummy_results = {
        'policy_checks': {'length': True, 'lower': True, 'upper': False, 'digit': True, 'special': False, 'all_passed': False},
        'detailed_policy_checks': {'Length': True, 'Lowercase': True, 'Uppercase': False, 'Digit': True, 'Special': False},
        'pattern_analysis': {'patterns_found': ["Common pattern: word followed by numbers", "Contains common word: 'password'"], 'character_diversity': 0.6},
        'ml_analysis': {'strength_score': 0.15, 'is_strong_prediction': False},
        'advanced_metrics': {'entropy': 45.2, 'breach_count': 3, 'complexity_score': 0.1},
        'policy': {'min_entropy': 60, 'max_breach_count': 0} # Include policy for context
    }

    print("--- Initializing AI Explainer ---")
    explainer = AIExplainer() # Uses distilgpt2 by default
    print("\n--- Generating Feedback ---")
    feedback = explainer.generate_feedback(dummy_results)
    print("\n--- AI Feedback ---")
    print(feedback)