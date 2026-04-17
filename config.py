"""
Configuration module for Cloud Security System.
Loads settings from environment variables.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).parent

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
CLOUDTRAIL_NAME = os.getenv('CLOUDTRAIL_NAME', 'default')

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///cloud_security.db')

# Flask Configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')

# Model Configuration
MODEL_DIR = BASE_DIR / 'models'
MODEL_PATH = MODEL_DIR / 'isolation_forest.pkl'
SCALER_PATH = MODEL_DIR / 'scaler.pkl'

# Data Configuration
DATA_DIR = BASE_DIR / 'data'
RAW_DATA_DIR = DATA_DIR / 'raw'
PROCESSED_DATA_DIR = DATA_DIR / 'processed'

# ML Model Parameters
ISOLATION_FOREST_PARAMS = {
    'n_estimators': 100,
    'contamination': 0.05,
    'random_state': 42,
    'max_samples': 'auto'
}

# Feature Engineering Parameters
ROLLING_WINDOW_HOURS = 1
FAILED_LOGIN_WINDOW_HOURS = 1

# Risk Scoring Multipliers
PRIVILEGE_ESCALATION_MULTIPLIER = 1.5
GEO_DEVIATION_MULTIPLIER = 1.2

# Severity Thresholds
SEVERITY_THRESHOLDS = {
    'Critical': 80,
    'High': 60,
    'Medium': 40,
    'Low': 0
}

# CloudTrail Polling Interval (seconds)
POLLING_INTERVAL = 30

# Create directories if they don't exist
MODEL_DIR.mkdir(parents=True, exist_ok=True)
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
