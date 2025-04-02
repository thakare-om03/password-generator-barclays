# 🔒 Barclays GenAI-Enhanced Password Security

A comprehensive password security solution that combines traditional policy checks with AI-powered analysis, feedback, and secure password generation. This application helps users create strong passwords that meet security requirements while providing detailed insights into password vulnerabilities.

## Overview

This Streamlit-based application provides a robust password security solution that:
- Analyzes passwords against security policy requirements
- Detects common patterns and vulnerabilities
- Calculates entropy and estimated crack times
- Checks if passwords have appeared in data breaches
- Generates AI-powered security feedback
- Suggests strong policy-compliant passwords
- Uses bcrypt for secure password hashing

## Features

### Password Analysis
- **Policy Compliance Check**: Verifies passwords against configurable security requirements
- **Pattern Detection**: Identifies common patterns that weaken passwords
- **Machine Learning Analysis**: Uses a trained classifier to predict password strength
- **Breach Detection**: Checks if passwords appear in known data breaches via the HaveIBeenPwned API
- **Entropy Calculation**: Measures password randomness and estimates crack times

### AI-Enhanced Features
- **AI-Powered Feedback**: Generates natural language explanations of password weaknesses
- **Smart Password Suggestions**: Creates diverse, policy-compliant password options
- **Contextual Security Metrics**: Provides comprehensive security assessments

### Security
- **Secure Password Hashing**: Uses industry-standard bcrypt algorithm
- **Policy Customization**: Allows configuring security requirements via YAML

## Installation

### Prerequisites
- Python 3.8+
- Access to the internet (for breach checking API)
- (Optional) GPU for better performance with transformer models

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/thakare-om03/password-generator-barclays.git
   cd password-generator-barclays
   git checkout om
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Place a password dataset in the data directory:
   ```bash
   # Download a password dataset like rockyou.txt
   # Warning: Contains real breached passwords, handle securely
   mkdir -p data
   # Place rockyou.txt in the data directory
   ```

4. (Optional) Train the ML model:
   ```bash
   python train_model.py
   ```

## Usage

1. Start the Streamlit application:
   ```bash
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL shown in your terminal (typically http://localhost:8501)

3. Use the application:
   - Enter a password to analyze
   - Review detailed security analysis
   - Explore AI-generated feedback
   - Choose from suggested strong passwords
   - Confirm and set your password

## Architecture

### Components

#### Web Interface (`app.py`)
The main Streamlit application that provides the user interface and coordinates the various components.

#### Policy Management (`src/policy_manager.py`)
Manages password policy requirements loaded from the configuration file.

#### Password Analysis
- **Basic Analyzer** (`src/password_analyzer.py`): Performs policy checks and pattern detection
- **Advanced Analyzer** (`src/advanced_analyzer.py`): Calculates entropy, estimates crack times, and checks for breaches
- **ML Model**: Predicts password strength using TF-IDF vectorization and Logistic Regression

#### AI Features
- **AI Explainer** (`src/ai_explainer.py`): Generates natural language feedback using transformer models
- **Password Generator** (`src/password_generator.py`): Creates strong password suggestions meeting policy requirements

#### Security
- **Password Hasher** (`src/password_hasher.py`): Implements secure password hashing using bcrypt

### Directory Structure
```
└── password-generator-barclays/
    ├── README.md                  # This documentation
    ├── app.py                     # Main Streamlit application
    ├── requirements.txt           # Python dependencies
    ├── train_model.py             # Script to train the ML model
    ├── config/
    │   └── policy.yml             # Password policy configuration
    ├── data/
    │   └── rockyou.txt            # Password dataset (not included)
    ├── models/
    │   ├── password_classifier.pkl # Trained ML model
    │   └── tfidf_vectorizer.pkl   # TF-IDF vectorizer
    └── src/
        ├── advanced_analyzer.py   # Advanced security metrics
        ├── ai_explainer.py        # AI-powered feedback generation
        ├── password_analyzer.py   # Basic password analysis
        ├── password_generator.py  # Password suggestion generation
        ├── password_hasher.py     # Secure password hashing
        └── policy_manager.py      # Policy loading and management
```

## Customizing Password Policy

The password policy can be customized by editing the `config/policy.yml` file:

```yaml
password_policy:
  min_length: 12                 # Minimum password length
  require_upper: true            # Require uppercase letters
  require_lower: true            # Require lowercase letters
  require_digits: true           # Require numbers
  require_special: true          # Require special characters
  max_breach_count: 0            # Maximum allowed breach occurrences
  min_entropy: 60                # Minimum required entropy (bits)
  special_chars: '!@#$%^&*(),.?":{}|<>'  # Allowed special characters
```

## Training the ML Model

The application includes a machine learning model to predict password strength. To train the model:

1. Obtain a password dataset (e.g., RockYou.txt)
2. Place the dataset in the `data/` directory
3. Run the training script:
   ```bash
   python train_model.py
   ```

The script will:
- Load weak passwords from the dataset
- Generate strong password examples based on policy requirements
- Create "tricky" weak passwords that might look strong
- Extract features using TF-IDF vectorization
- Train a Logistic Regression classifier
- Save the model and vectorizer to the `models/` directory

## Security Considerations

1. **Data Privacy**: This application never sends plaintext passwords to external services. Breach checking uses the k-anonymity model of the HaveIBeenPwned API.

2. **Password Storage**: Passwords are hashed using bcrypt with a secure work factor. In a production environment, these would be sent to a backend system.

3. **Transformer Models**: The application uses transformer models for AI features, which may transfer data to GPU memory. Ensure your environment meets security requirements.

4. **Demo Mode**: Some features may display sensitive information for demonstration purposes. Modify for production use.

## Advanced Features

### Entropy Calculation

The application calculates password entropy based on character set diversity and length, providing a quantitative measure of password strength.

### Breach Checking

The application checks if passwords have appeared in known data breaches using the HaveIBeenPwned API's k-anonymity model, which ensures passwords are never sent in full to the service.

### AI-Powered Feedback

The application uses transformer models to analyze password characteristics and generate natural language feedback explaining:
- Overall security assessment
- Specific weaknesses identified
- Actionable recommendations for improvement