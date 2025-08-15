# app.py - Main Flask Application
import os
import json
import pickle
import numpy as np
import pandas as pd
import tensorflow as tf
from flask import Flask, render_template_string, request, jsonify
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

class SQLInjectionDetector:
    def __init__(self):
        self.detection_model = None
        self.prevention_model = None
        self.detection_tokenizer = None
        self.prevention_tokenizer = None
        self.detection_config = None
        self.prevention_config = None
        self.models_loaded = False
        
    def load_models(self):
        """Load trained models and configurations"""
        try:
            # Load Detection Model
            detection_path = 'PhD_research_models/sql_detection'
            if os.path.exists(detection_path):
                logger.info("Loading SQL Detection model...")
                
                # Try loading .keras format first, then .h5
                model_files = [
                    os.path.join(detection_path, 'detection_model.keras'),
                    os.path.join(detection_path, 'detection_model.h5')
                ]
                
                for model_file in model_files:
                    if os.path.exists(model_file):
                        self.detection_model = load_model(model_file)
                        logger.info(f"Detection model loaded from {model_file}")
                        break
                
                # Load detection tokenizer
                tokenizer_path = os.path.join(detection_path, 'detection_tokenizer.pickle')
                if os.path.exists(tokenizer_path):
                    with open(tokenizer_path, 'rb') as handle:
                        self.detection_tokenizer = pickle.load(handle)
                    logger.info("Detection tokenizer loaded")
                
                # Load detection config
                config_path = os.path.join(detection_path, 'detection_config.json')
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        self.detection_config = json.load(f)
                    logger.info("Detection config loaded")
            
            # Load Prevention Model (if exists)
            prevention_path = 'PhD_research_models/sql_prevention'
            if os.path.exists(prevention_path):
                logger.info("Loading SQL Prevention model...")
                
                model_files = [
                    os.path.join(prevention_path, 'prevention_model.keras'),
                    os.path.join(prevention_path, 'prevention_model.h5')
                ]
                
                for model_file in model_files:
                    if os.path.exists(model_file):
                        self.prevention_model = load_model(model_file)
                        logger.info(f"Prevention model loaded from {model_file}")
                        break
                
                # Load prevention tokenizer
                tokenizer_path = os.path.join(prevention_path, 'prevention_tokenizer.pickle')
                if os.path.exists(tokenizer_path):
                    with open(tokenizer_path, 'rb') as handle:
                        self.prevention_tokenizer = pickle.load(handle)
                    logger.info("Prevention tokenizer loaded")
                
                # Load prevention config
                config_path = os.path.join(prevention_path, 'prevention_config.json')
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        self.prevention_config = json.load(f)
                    logger.info("Prevention config loaded")
            
            # Check if at least detection model is loaded
            if self.detection_model is not None and self.detection_tokenizer is not None:
                self.models_loaded = True
                logger.info("Models loaded successfully!")
            else:
                logger.warning("Models not found, running in demo mode")
                self.models_loaded = False
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            self.models_loaded = False
    
    def preprocess_query_gentle(self, query, tokenizer=None, max_len=100):
        """Gentler preprocessing that preserves SQL structure"""
        try:
            if tokenizer is None:
                # Return mock processed query for demo mode
                return np.array([[1] * max_len])
            
            # Clean but preserve SQL operators
            cleaned_query = str(query).lower().strip()
            # Only remove truly dangerous characters, keep SQL syntax
            cleaned_query = re.sub(r'[<>{}\\]', '', cleaned_query)
            
            # Tokenize and pad
            sequence = tokenizer.texts_to_sequences([cleaned_query])
            padded_sequence = pad_sequences(sequence, maxlen=max_len)
            
            return padded_sequence
        except Exception as e:
            logger.error(f"Error in gentle preprocessing: {str(e)}")
            return None
    
    def predict_detection(self, query):
        """Predict if query is malicious using detection model"""
        try:
            # Demo mode simulation
            if not self.models_loaded or self.detection_model is None:
                return self._simulate_detection(query)
            
            # Get max_len from config or use default
            max_len = self.detection_config.get('max_len', 100) if self.detection_config else 100
            
            # Preprocess query
            processed_query = self.preprocess_query_gentle(query, self.detection_tokenizer, max_len)
            if processed_query is None:
                return {"error": "Failed to preprocess query"}
            
            # Make prediction
            prediction = self.detection_model.predict(processed_query, verbose=0)
            probability = float(prediction[0][0])
            
            # Get threshold from config or use default
            threshold = self.detection_config.get('best_threshold', 0.5) if self.detection_config else 0.5
            
            is_malicious = probability >= threshold
            confidence = probability if is_malicious else (1 - probability)
            
            return {
                "is_malicious": bool(is_malicious),
                "probability": probability,
                "confidence": confidence * 100,
                "threshold": threshold,
                "prediction_class": "SQLi" if is_malicious else "Normal",
                "model_info": {
                    "name": self.detection_config.get('model_name', 'SQL Detection Model') if self.detection_config else 'SQL Detection Model',
                    "type": self.detection_config.get('model_type', 'CNN+BiLSTM') if self.detection_config else 'CNN+BiLSTM',
                    "version": self.detection_config.get('version', '1.0') if self.detection_config else '1.0'
                }
            }
            
        except Exception as e:
            logger.error(f"Error in detection prediction: {str(e)}")
            return {"error": f"Prediction failed: {str(e)}"}
    
    def _simulate_detection(self, query):
        """Simulate detection for demo mode"""
        query_lower = query.lower()
        
        # Simple heuristic detection
        malicious_patterns = [
            'or 1=1', 'union select', 'drop table', '-- ', '/*', '*/',
            'or \'x\'=\'x\'', 'and \'x\'=\'x\'', 'sleep(', 'benchmark(',
            'information_schema', 'sysobjects', 'msysobjects', 'waitfor'
        ]
        
        is_malicious = any(pattern in query_lower for pattern in malicious_patterns)
        probability = np.random.uniform(0.7, 0.95) if is_malicious else np.random.uniform(0.1, 0.3)
        confidence = probability if is_malicious else (1 - probability)
        
        return {
            "is_malicious": is_malicious,
            "probability": probability,
            "confidence": confidence * 100,
            "threshold": 0.5,
            "prediction_class": "SQLi" if is_malicious else "Normal",
            "model_info": {
                "name": "SQL Detection Model (Demo Mode)",
                "type": "CNN+BiLSTM",
                "version": "1.0"
            }
        }
    
    def predict_prevention(self, query):
        """Enhanced prevention using detection model + rule-based validation"""
        try:
            # Demo mode or actual prediction
            if not self.models_loaded or self.detection_model is None:
                return self._simulate_prevention(query)
            
            # Use actual model logic here
            # ... (rest of your prevention logic)
            
        except Exception as e:
            logger.error(f"Error in prevention prediction: {str(e)}")
            return {"error": f"Prevention analysis failed: {str(e)}"}
    
    def _simulate_prevention(self, query):
        """Simulate prevention for demo mode"""
        query_lower = query.lower()
        
        malicious_patterns = [
            'or 1=1', 'union select', 'drop table', '-- ', '/*', '*/',
            'or \'x\'=\'x\'', 'and \'x\'=\'x\'', 'sleep(', 'benchmark(',
        ]
        
        is_malicious = any(pattern in query_lower for pattern in malicious_patterns)
        safety_score = np.random.uniform(0.1, 0.4) if is_malicious else np.random.uniform(0.7, 0.95)
        
        recommendations = self._generate_recommendations(query, is_malicious)
        
        return {
            "is_safe": not is_malicious,
            "prevention_score": safety_score * 100,
            "risk_level": "HIGH" if is_malicious else "LOW",
            "safety_probability": safety_score,
            "malicious_probability": 1 - safety_score,
            "recommendations": recommendations,
            "model_info": {
                "name": "SQL Security Validator (Demo Mode)",
                "type": "CNN+BiLSTM Enhanced"
            }
        }
    
    def _generate_recommendations(self, query, is_malicious):
        """Generate security recommendations"""
        recommendations = []
        
        if is_malicious:
            recommendations.extend([
                "🚨 Query contains potential SQL injection patterns",
                "🔒 Use parameterized queries/prepared statements",
                "🛡️ Implement input validation and sanitization",
                "⚠️ Consider using stored procedures for complex queries",
                "🔍 Enable SQL injection detection in your WAF"
            ])
        else:
            recommendations.extend([
                "✅ Query structure appears safe",
                "💡 Consider using parameterized queries for better security",
                "🔒 Implement proper access controls",
                "📊 Monitor query execution patterns",
                "🧪 Regular security testing recommended"
            ])
        
        return recommendations[:6]

# Initialize the detector
detector = SQLInjectionDetector()

# HTML template embedded in the Python file
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhD research design for SQL injection attack by Nwabudike Augustine</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 15px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .header {
            margin-bottom: 30px;
            color: white;
            animation: fadeInDown 1s ease-out;
        }

        .header-content {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .logo-container {
            flex-shrink: 0;
        }

        .logo {
            width: 120px;
            height: 120px;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.2);
            background: white;
            padding: 10px;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            font-weight: bold;
            color: #333;
        }

        .logo-fallback {
            text-align: center;
            font-size: 14px;
            line-height: 1.2;
        }

        .header-text {
            flex: 1;
            min-width: 300px;
        }

        .header h1 {
            font-size: clamp(1.3rem, 3.5vw, 2.2rem);
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            line-height: 1.2;
        }

        .header p {
            font-size: clamp(0.9rem, 2.5vw, 1.1rem);
            opacity: 0.9;
        }

        .model-status {
            background: rgba(255,255,255,0.1);
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            color: white;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            font-size: clamp(0.8rem, 2vw, 1rem);
        }

        .model-status.loading {
            background: rgba(255,193,7,0.2);
        }

        .model-status.ready {
            background: rgba(40,167,69,0.2);
        }

        .model-status.error {
            background: rgba(220,53,69,0.2);
        }

        .main-content {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            width: 100%;
        }

        .page {
            display: none;
            width: 100%;
            max-width: 900px;
            animation: fadeIn 0.5s ease-in;
        }

        .page.active {
            display: block;
        }

        .home-page {
            text-align: center;
        }

        .button-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
            justify-content: center;
            margin-top: 30px;
            align-items: center;
        }

        .main-button {
            color: white;
            border: none;
            padding: clamp(20px, 4vw, 25px) clamp(30px, 6vw, 40px);
            font-size: clamp(1rem, 3vw, 1.3rem);
            border-radius: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 8px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 350px;
            position: relative;
            overflow: hidden;
            min-height: 120px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .main-button.detection {
            background: linear-gradient(145deg, #4CAF50, #45a049);
        }

        .main-button.prevention {
            background: linear-gradient(145deg, #FF6B6B, #ee5a52);
        }

        .main-button:hover:not(:disabled) {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
        }

        .main-button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .button-subtitle {
            font-size: 0.9rem; 
            margin-top: 8px; 
            opacity: 0.9;
            font-weight: normal;
        }

        .detection-page, .prevention-page {
            background: rgba(255,255,255,0.95);
            border-radius: 20px;
            padding: clamp(20px, 4vw, 40px);
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            margin: 10px;
        }

        .page-title {
            text-align: center;
            margin-bottom: 25px;
            color: #333;
            font-size: clamp(1.5rem, 4vw, 2rem);
        }

        .model-info {
            background: #f8f9fa;
            padding: clamp(10px, 3vw, 15px);
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: clamp(0.8rem, 2vw, 0.9rem);
            color: #495057;
            word-break: break-word;
        }

        .input-section {
            margin-bottom: 25px;
        }

        .input-section label {
            display: block;
            margin-bottom: 10px;
            font-weight: bold;
            color: #555;
            font-size: clamp(0.9rem, 2.5vw, 1rem);
        }

        .query-input {
            width: 100%;
            min-height: 100px;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: clamp(0.9rem, 2.5vw, 1rem);
            font-family: 'Courier New', monospace;
            resize: vertical;
            transition: border-color 0.3s ease;
        }

        .query-input:focus {
            outline: none;
            border-color: #4CAF50;
            box-shadow: 0 0 10px rgba(76, 175, 80, 0.2);
        }

        .button-group {
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
            margin-bottom: 25px;
        }

        .action-button {
            background: linear-gradient(145deg, #2196F3, #1976D2);
            color: white;
            border: none;
            padding: clamp(12px, 3vw, 15px) clamp(20px, 4vw, 30px);
            font-size: clamp(0.9rem, 2.5vw, 1.1rem);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: clamp(100px, 25vw, 120px);
            flex: 1;
            max-width: 150px;
        }

        .action-button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(33, 150, 243, 0.3);
        }

        .action-button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .action-button.back {
            background: linear-gradient(145deg, #9E9E9E, #757575);
        }

        .action-button.clear {
            background: linear-gradient(145deg, #FF9800, #F57C00);
        }

        .result-section {
            margin-top: 25px;
            padding: 15px;
            border-radius: 10px;
            min-height: 80px;
            display: none;
            animation: slideUp 0.5s ease-out;
        }

        .result-section.show {
            display: block;
        }

        .result-safe {
            background: linear-gradient(145deg, #E8F5E8, #C8E6C9);
            border: 2px solid #4CAF50;
            color: #2E7D32;
        }

        .result-malicious {
            background: linear-gradient(145deg, #FFE8E8, #FFCDD2);
            border: 2px solid #F44336;
            color: #C62828;
        }

        .result-icon {
            font-size: clamp(1.5rem, 4vw, 2rem);
            margin-bottom: 8px;
        }

        .result-text {
            font-size: clamp(1rem, 3vw, 1.2rem);
            font-weight: bold;
            margin-bottom: 8px;
        }

        .result-details {
            font-size: clamp(0.8rem, 2.2vw, 0.95rem);
            margin-top: 8px;
        }

        .prediction-details {
            background: rgba(255,255,255,0.7);
            padding: 12px;
            border-radius: 8px;
            margin-top: 12px;
        }

        .confidence-bar {
            width: 100%;
            height: 16px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 8px 0;
        }

        .confidence-fill {
            height: 100%;
            transition: width 0.5s ease-in-out;
            border-radius: 10px;
        }

        .confidence-safe {
            background: linear-gradient(90deg, #28a745, #20c997);
        }

        .confidence-malicious {
            background: linear-gradient(90deg, #dc3545, #e74c3c);
        }

        .recommendations {
            margin-top: 12px;
            padding: 12px;
            background: rgba(255,255,255,0.8);
            border-radius: 8px;
        }

        .recommendations h4 {
            margin-bottom: 8px;
            color: #333;
            font-size: clamp(0.9rem, 2.5vw, 1rem);
        }

        .recommendations ul {
            list-style: none;
            padding: 0;
        }

        .recommendations li {
            padding: 4px 0;
            border-bottom: 1px solid rgba(0,0,0,0.1);
            font-size: clamp(0.8rem, 2.2vw, 0.9rem);
        }

        .recommendations li:last-child {
            border-bottom: none;
        }

        .no-data-message {
            background: linear-gradient(145deg, #FFF8E1, #FFECB3);
            border: 2px solid #FFA000;
            color: #E65100;
            padding: 20px;
            border-radius: 12px;
            margin-top: 15px;
            text-align: center;
            font-size: clamp(1rem, 3vw, 1.2rem);
            font-weight: bold;
            animation: slideUp 0.5s ease-out;
        }

        .sample-queries {
            background: rgba(240, 248, 255, 0.8);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
        }

        .sample-queries h3 {
            color: #333;
            margin-bottom: 12px;
            text-align: center;
            font-size: clamp(1rem, 3vw, 1.2rem);
        }

        .sample-query {
            background: #f8f9fa;
            padding: 8px;
            margin: 6px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: clamp(0.8rem, 2vw, 0.9rem);
            cursor: pointer;
            transition: background-color 0.3s ease;
            border-left: 4px solid #007bff;
            word-break: break-all;
            line-height: 1.3;
        }

        .sample-query:hover {
            background: #e9ecef;
        }

        .sample-query.malicious {
            border-left-color: #dc3545;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 15px;
        }

        .loading.show {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }

        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 8px;
            margin: 15px 0;
            border: 1px solid #f5c6cb;
            font-size: clamp(0.8rem, 2.2vw, 0.9rem);
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                text-align: center;
                gap: 15px;
            }

            .header-text {
                min-width: auto;
            }

            .logo {
                width: 100px;
                height: 100px;
            }
        }

        @media (min-width: 480px) {
            .button-container {
                flex-direction: row;
                flex-wrap: wrap;
            }
            
            .main-button {
                flex: 1;
                min-width: 280px;
                max-width: none;
            }
        }

        @media (min-width: 769px) {
            .header-content {
                text-align: left;
            }

            .container {
                padding: 20px;
            }
            
            .button-container {
                flex-direction: row;
                gap: 30px;
            }
            
            .main-button {
                max-width: 350px;
            }
            
            .detection-page, .prevention-page {
                margin: 0;
            }
            
            .button-group {
                gap: 15px;
            }
            
            .action-button {
                flex: 0 1 auto;
                max-width: 200px;
            }
        }

        @media (min-width: 1024px) {
            .logo {
                width: 140px;
                height: 140px;
            }
            
            .query-input {
                min-height: 120px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-content">
                <div class="logo-container">
                    <div class="logo">
                        <div class="logo-fallback">UPM<br>PhD<br>Research</div>
                    </div>
                </div>
                <div class="header-text">
                    <h1>PhD Research Design for SQL Injection Attack Detection & Prevention</h1>
                    <p>By Nwabudike Augustine - Universiti Putra Malaysia</p>
                </div>
            </div>
        </header>

        <div id="modelStatus" class="model-status loading">
            <div>🔄 Loading trained models and tokenizers...</div>
        </div>

        <main class="main-content">
            <!-- Home Page -->
            <div id="homePage" class="page active home-page">
                <div class="button-container">
                    <button id="detectionBtn" class="main-button detection" onclick="showPage('detectionPage')">
                        🔍 SQL Attack Detection
                        <div class="button-subtitle">
                            Using trained CNN + BiLSTM model
                        </div>
                    </button>
                    <button id="preventionBtn" class="main-button prevention" onclick="showPage('preventionPage')">
                        🛡️ SQL Attack Prevention
                        <div class="button-subtitle">
                            ML-powered validation & recommendations
                        </div>
                    </button>
                </div>
            </div>

            <!-- Detection Page -->
            <div id="detectionPage" class="page detection-page">
                <h2 class="page-title">🔍 SQL Injection Detection</h2>
                
                <div class="model-info" id="detectionModelInfo">
                    <strong>Model:</strong> Loading... | <strong>Status:</strong> Initializing...
                </div>

                <div class="input-section">
                    <label for="detectionQuery">Enter SQL Query for Analysis:</label>
                    <textarea id="detectionQuery" class="query-input" 
                        placeholder="Example: SELECT * FROM users WHERE id = 1 OR 1=1 --"></textarea>
                </div>

                <div class="button-group">
                    <button class="action-button" onclick="analyzeQuery('detection')" id="detectBtn">Detect</button>
                    <button class="action-button clear" onclick="clearQuery('detectionQuery')">🗑️ Clear</button>
                    <button class="action-button back" onclick="showPage('homePage')">← Back</button>
                </div>

                <div class="loading" id="detectionLoading">
                    <div class="spinner"></div>
                    <p>Model analyzing query patterns...</p>
                </div>

                <div id="detectionResult" class="result-section">
                    <div class="result-icon" id="detectionIcon"></div>
                    <div class="result-text" id="detectionText"></div>
                    <div class="result-details" id="detectionDetails"></div>
                    <div class="prediction-details">
                        <div><strong>Model Confidence:</strong></div>
                        <div class="confidence-bar">
                            <div id="detectionConfidenceBar" class="confidence-fill" style="width: 0%"></div>
                        </div>
                        <div id="detectionConfidenceText">0%</div>
                    </div>
                </div>

                <div class="sample-queries">
                    <h3>📝 Sample Queries from Training Dataset</h3>
                    <div id="detectionSamples">Loading samples...</div>
                </div>
            </div>

            <!-- Prevention Page -->
            <div id="preventionPage" class="page prevention-page">
                <h2 class="page-title">🛡️ SQL Attack Prevention</h2>
                
                <div class="model-info" id="preventionModelInfo">
                    <strong>Model:</strong> Loading... | <strong>Mode:</strong> Prevention & Validation
                </div>

                <div class="input-section">
                    <label for="preventionQuery">Enter SQL Query for Security Validation:</label>
                    <textarea id="preventionQuery" class="query-input" 
                        placeholder="Example: SELECT * FROM products WHERE category = 'electronics'"></textarea>
                </div>

                <div class="button-group">
                    <button class="action-button" onclick="analyzeQuery('prevention')" id="preventBtn">🛡️ Validate & Secure</button>
                    <button class="action-button clear" onclick="clearQuery('preventionQuery')">🗑️ Clear</button>
                    <button class="action-button back" onclick="showPage('homePage')">← Back</button>
                </div>

                <div class="loading" id="preventionLoading">
                    <div class="spinner"></div>
                    <p>Analyzing query security and generating recommendations...</p>
                </div>

                <div id="preventionResult" class="result-section">
                    <div class="result-icon" id="preventionIcon"></div>
                    <div class="result-text" id="preventionText"></div>
                    <div class="result-details" id="preventionDetails"></div>
                    <div class="prediction-details">
                        <div><strong>Security Score:</strong></div>
                        <div class="confidence-bar">
                            <div id="preventionConfidenceBar" class="confidence-fill" style="width: 0%"></div>
                        </div>
                        <div id="preventionConfidenceText">0%</div>
                    </div>
                    <div class="recommendations" id="preventionRecommendations" style="display: none;">
                        <h4>🔒 Security Recommendations:</h4>
                        <ul id="recommendationsList"></ul>
                    </div>
                </div>

                <div id="noDataMessage" class="no-data-message" style="display: none;">
                    🚫 No data record to show
                    <div style="font-size: 0.9rem; margin-top: 8px; font-weight: normal;">
                        Query blocked due to potential security risks
                    </div>
                </div>

                <div class="sample-queries">
                    <h3>📝 Sample Queries for Testing</h3>
                    <div id="preventionSamples">Loading samples...</div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let modelsLoaded = false;
        let sampleQueries = { safe: [], malicious: [] };

        // Initialize the application
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Application initializing...');
            initializeApplication();
        });

        function initializeApplication() {
            checkModelStatus();
            loadSampleQueries();
            setupTextareaAutoResize();
            setupInteractiveEffects();
            setupViewportHandling();
        }

        // Check model status from backend
        async function checkModelStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                const statusElement = document.getElementById('modelStatus');
                const detectionBtn = document.getElementById('detectionBtn');
                const preventionBtn = document.getElementById('preventionBtn');
                const detectBtn = document.getElementById('detectBtn');
                const preventBtn = document.getElementById('preventBtn');
                
                if (data.models_loaded) {
                    statusElement.className = 'model-status ready';
                    statusElement.innerHTML = `
                        <div>✅ Models loaded successfully!</div>
                        <div style="font-size: 0.9rem; margin-top: 5px;">
                            Detection: ${data.detection_available ? 'Ready' : 'N/A'} | 
                            Prevention: ${data.prevention_available ? 'Ready' : 'Using Detection Model'}
                        </div>
                    `;
                    
                    detectionBtn.disabled = false;
                    preventionBtn.disabled = false;
                    if (detectBtn) detectBtn.disabled = false;
                    if (preventBtn) preventBtn.disabled = false;
                    modelsLoaded = true;
                    
                    updateModelInfo(data);
                } else {
                    statusElement.className = 'model-status ready';
                    statusElement.innerHTML = `
                        <div>✅ Running in Demo Mode</div>
                        <div style="font-size: 0.9rem; margin-top: 5px;">
                            Detection: Simulated | Prevention: Simulated
                        </div>
                    `;
                    
                    detectionBtn.disabled = false;
                    preventionBtn.disabled = false;
                    if (detectBtn) detectBtn.disabled = false;
                    if (preventBtn) preventBtn.disabled = false;
                    modelsLoaded = true;
                    
                    updateModelInfo({
                        detection_config: { model_type: 'CNN+BiLSTM (Demo)', version: '1.0' },
                        prevention_config: { model_type: 'Enhanced (Demo)', version: '1.0' }
                    });
                }
            } catch (error) {
                console.error('Error checking model status:', error);
                simulateModelLoading();
            }
        }

        function simulateModelLoading() {
            const statusElement = document.getElementById('modelStatus');
            const detectionBtn = document.getElementById('detectionBtn');
            const preventionBtn = document.getElementById('preventionBtn');
            const detectBtn = document.getElementById('detectBtn');
            const preventBtn = document.getElementById('preventBtn');

            statusElement.className = 'model-status ready';
            statusElement.innerHTML = `
                <div>✅ Running in Demo Mode</div>
                <div style="font-size: 0.9rem; margin-top: 5px;">
                    Detection: Simulated | Prevention: Simulated
                </div>
            `;
            
            detectionBtn.disabled = false;
            preventionBtn.disabled = false;
            if (detectBtn) detectBtn.disabled = false;
            if (preventBtn) preventBtn.disabled = false;
            modelsLoaded = true;

            updateModelInfo({
                detection_config: { model_type: 'CNN+BiLSTM (Demo)', version: '1.0' },
                prevention_config: { model_type: 'Enhanced (Demo)', version: '1.0' }
            });
        }

        function updateModelInfo(data) {
            const detectionInfo = document.getElementById('detectionModelInfo');
            if (data.detection_config) {
                detectionInfo.innerHTML = `
                    <strong>Model:</strong> ${data.detection_config.model_type || 'CNN+BiLSTM'} | 
                    <strong>Version:</strong> ${data.detection_config.version || '1.0'} |
                    <strong>Status:</strong> Ready
                `;
            }
            
            const preventionInfo = document.getElementById('preventionModelInfo');
            if (data.prevention_config) {
                preventionInfo.innerHTML = `
                    <strong>Model:</strong> ${data.prevention_config.model_type || 'CNN+BiLSTM'} | 
                    <strong>Mode:</strong> Prevention & Validation |
                    <strong>Version:</strong> ${data.prevention_config.version || '1.0'}
                `;
            }
        }

        async function loadSampleQueries() {
            try {
                const response = await fetch('/api/sample_queries');
                const data = await response.json();
                sampleQueries = data;
                
                updateSampleQueries('detectionSamples', [...data.safe.slice(0, 3), ...data.malicious.slice(0, 5)], 'detectionQuery');
                updateSampleQueries('preventionSamples', [...data.safe.slice(0, 3), ...data.malicious.slice(0, 3)], 'preventionQuery');
                
            } catch (error) {
                console.error('Error loading sample queries:', error);
                // Use fallback samples
                sampleQueries = {
                    safe: [
                        "SELECT * FROM users WHERE id = 1",
                        "SELECT name, email FROM customers WHERE status = 'active'",
                        "INSERT INTO products (name, price) VALUES ('Laptop', 999.99)"
                    ],
                    malicious: [
                        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
                        "SELECT * FROM users WHERE id = 1'; DROP TABLE users; --",
                        "SELECT * FROM users WHERE id = 1 OR 'x'='x'"
                    ]
                };
                
                updateSampleQueries('detectionSamples', [...sampleQueries.safe, ...sampleQueries.malicious], 'detectionQuery');
                updateSampleQueries('preventionSamples', [...sampleQueries.safe, ...sampleQueries.malicious.slice(0, 2)], 'preventionQuery');
            }
        }

        function updateSampleQueries(containerId, queries, targetInputId) {
            const container = document.getElementById(containerId);
            container.innerHTML = '';
            
            queries.forEach(query => {
                const div = document.createElement('div');
                div.className = sampleQueries.malicious.includes(query) ? 'sample-query malicious' : 'sample-query';
                div.textContent = query;
                div.onclick = () => fillQuery(targetInputId, query);
                container.appendChild(div);
            });
        }

        function setupTextareaAutoResize() {
            const textareas = document.querySelectorAll('.query-input');
            textareas.forEach(textarea => {
                textarea.addEventListener('input', function() {
                    this.style.height = 'auto';
                    this.style.height = Math.max(100, this.scrollHeight) + 'px';
                });
            });
        }

        function showPage(pageId) {
            const pages = document.querySelectorAll('.page');
            pages.forEach(page => page.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            
            const resultSections = document.querySelectorAll('.result-section');
            resultSections.forEach(section => section.classList.remove('show'));
            
            const noDataMessage = document.getElementById('noDataMessage');
            if (noDataMessage) noDataMessage.style.display = 'none';
        }

        function fillQuery(inputId, query) {
            const textarea = document.getElementById(inputId);
            textarea.value = query.trim();
            textarea.style.height = 'auto';
            textarea.style.height = Math.max(100, textarea.scrollHeight) + 'px';
        }

        function clearQuery(inputId) {
            document.getElementById(inputId).value = '';
            document.getElementById(inputId).style.height = '100px';
            
            const resultSection = inputId.includes('detection') ? 'detectionResult' : 'preventionResult';
            document.getElementById(resultSection).classList.remove('show');
            
            const noDataMessage = document.getElementById('noDataMessage');
            if (noDataMessage) noDataMessage.style.display = 'none';
        }

        async function analyzeQuery(type) {
            if (!modelsLoaded) {
                alert('System is loading. Please wait...');
                return;
            }

            const inputId = type + 'Query';
            const loadingId = type + 'Loading';
            const resultId = type + 'Result';
            
            const query = document.getElementById(inputId).value.trim();

            if (!query) {
                alert('Please enter a SQL query to analyze.');
                return;
            }

            document.getElementById(loadingId).classList.add('show');
            document.getElementById(resultId).classList.remove('show');
            
            const noDataMessage = document.getElementById('noDataMessage');
            if (noDataMessage) noDataMessage.style.display = 'none';

            try {
                const endpoint = type === 'detection' ? '/api/detect' : '/api/prevent';
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ query: query })
                });

                const result = await response.json();
                
                if (result.error) {
                    throw new Error(result.error);
                }
                
                displayResults(result, type);

            } catch (error) {
                console.error('Analysis error:', error);
                displayError(error.message, type);
            } finally {
                document.getElementById(loadingId).classList.remove('show');
                document.getElementById(resultId).classList.add('show');
            }
        }

        function displayResults(result, type) {
            if (type === 'detection') {
                displayDetectionResults(result);
            } else {
                displayPreventionResults(result);
            }
        }

        function displayDetectionResults(result) {
            const resultSection = document.getElementById('detectionResult');
            const icon = document.getElementById('detectionIcon');
            const text = document.getElementById('detectionText');
            const details = document.getElementById('detectionDetails');
            const confidenceBar = document.getElementById('detectionConfidenceBar');
            const confidenceText = document.getElementById('detectionConfidenceText');

            resultSection.classList.remove('result-safe', 'result-malicious');
            if (result.is_malicious) {
                resultSection.classList.add('result-malicious');
                icon.textContent = '⚠️';
                confidenceBar.className = 'confidence-fill confidence-malicious';
            } else {
                resultSection.classList.add('result-safe');
                icon.textContent = '✅';
                confidenceBar.className = 'confidence-fill confidence-safe';
            }

            text.textContent = result.is_malicious ? 
                '🚨 SQL INJECTION DETECTED!' : 
                '✅ Query appears safe';

            const confidence = Math.round(result.confidence);
            details.innerHTML = `
                <p><strong>Prediction:</strong> ${result.prediction_class}</p>
                <p><strong>Probability:</strong> ${result.probability.toFixed(4)}</p>
                <p><strong>Model:</strong> ${result.model_info.name}</p>
            `;

            confidenceBar.style.width = confidence + '%';
            confidenceText.textContent = `${confidence}% confidence`;
        }

        function displayPreventionResults(result) {
            const resultSection = document.getElementById('preventionResult');
            const icon = document.getElementById('preventionIcon');
            const text = document.getElementById('preventionText');
            const details = document.getElementById('preventionDetails');
            const confidenceBar = document.getElementById('preventionConfidenceBar');
            const confidenceText = document.getElementById('preventionConfidenceText');
            const recommendations = document.getElementById('preventionRecommendations');
            const recommendationsList = document.getElementById('recommendationsList');
            const noDataMessage = document.getElementById('noDataMessage');

            if (!result.is_safe && result.risk_level === 'HIGH') {
                resultSection.style.display = 'none';
                noDataMessage.style.display = 'block';
                return;
            }

            resultSection.style.display = 'block';
            noDataMessage.style.display = 'none';

            resultSection.classList.remove('result-safe', 'result-malicious');
            if (result.is_safe) {
                resultSection.classList.add('result-safe');
                icon.textContent = '🛡️';
                confidenceBar.className = 'confidence-fill confidence-safe';
            } else {
                resultSection.classList.add('result-malicious');
                icon.textContent = '⚠️';
                confidenceBar.className = 'confidence-fill confidence-malicious';
            }

            text.textContent = result.is_safe ? 
                '✅ Query validated - Security recommendations provided' : 
                '⚠️ Security risks detected - Review recommendations';

            const preventionScore = Math.round(result.prevention_score);
            details.innerHTML = `
                <p><strong>Risk Level:</strong> ${result.risk_level}</p>
                <p><strong>Safety Score:</strong> ${preventionScore}%</p>
                <p><strong>Model:</strong> ${result.model_info.name}</p>
            `;

            confidenceBar.style.width = preventionScore + '%';
            confidenceText.textContent = `${preventionScore}% security score`;

            if (result.recommendations && result.recommendations.length > 0) {
                recommendations.style.display = 'block';
                recommendationsList.innerHTML = '';
                result.recommendations.forEach(rec => {
                    const li = document.createElement('li');
                    li.textContent = rec;
                    recommendationsList.appendChild(li);
                });
            } else {
                recommendations.style.display = 'none';
            }
        }

        function displayError(message, type) {
            const resultSection = document.getElementById(type + 'Result');
            const icon = document.getElementById(type + 'Icon');
            const text = document.getElementById(type + 'Text');
            const details = document.getElementById(type + 'Details');

            resultSection.classList.remove('result-safe', 'result-malicious');
            resultSection.classList.add('result-malicious');
            
            icon.textContent = '❌';
            text.textContent = 'Analysis Error';
            details.innerHTML = `<div class="error-message">Error: ${message}</div>`;
        }

        function setupInteractiveEffects() {
            const buttons = document.querySelectorAll('button');
            buttons.forEach(button => {
                button.addEventListener('mouseenter', function() {
                    if (!this.disabled) {
                        this.style.transform = 'translateY(-2px)';
                    }
                });
                
                button.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0)';
                });
            });
        }

        function setupViewportHandling() {
            window.addEventListener('orientationchange', function() {
                setTimeout(function() {
                    document.body.style.height = 'auto';
                }, 100);
            });

            function handleViewportChange() {
                const vh = window.innerHeight * 0.01;
                document.documentElement.style.setProperty('--vh', `${vh}px`);
            }

            handleViewportChange();
            window.addEventListener('resize', handleViewportChange);
        }

        console.log('SQL Injection Detection & Prevention System loaded successfully!');
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    """Check if models are loaded"""
    return jsonify({
        "models_loaded": detector.models_loaded,
        "detection_available": detector.detection_model is not None,
        "prevention_available": detector.prevention_model is not None,
        "detection_config": detector.detection_config,
        "prevention_config": detector.prevention_config
    })

@app.route('/api/detect', methods=['POST'])
def api_detect():
    """SQL Injection Detection API"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({"error": "Query is required"}), 400
        
        result = detector.predict_detection(query)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"API detect error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/prevent', methods=['POST'])
def api_prevent():
    """SQL Injection Prevention API"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({"error": "Query is required"}), 400
        
        result = detector.predict_prevention(query)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"API prevent error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/sample_queries')
def api_sample_queries():
    """Get sample queries for testing"""
    samples = {
        "safe": [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE age > 18",
            "UPDATE users SET last_login = NOW() WHERE id = 123",
            "SELECT COUNT(*) FROM orders WHERE date >= '2024-01-01'",
            "INSERT INTO logs (user_id, action, timestamp) VALUES (1, 'login', NOW())"
        ],
        "malicious": [
            "SELECT * FROM users WHERE id = 1 OR 1=1 --",
            "' UNION SELECT password FROM admin --",
            "SELECT * FROM users WHERE id = 1'; DROP TABLE users; --",
            '" or pg_sleep(__TIME__) --',
            "AND 1 = utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM sys.all_tables))",
            "admin' OR 1=1#",
            "1; load_file(char(47,101,116,99,47,112,97,115,115,119,100))",
            "' OR 1 IN (SELECT TOP 1 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES) --"
        ]
    }
    return jsonify(samples)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "models_loaded": detector.models_loaded,
        "timestamp": pd.Timestamp.now().isoformat()
    })

# Load models when the app starts
detector.load_models()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
