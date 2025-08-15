import os
import json
import pickle
import numpy as np
import pandas as pd
import tensorflow as tf
from flask import Flask, render_template, request, jsonify, send_from_directory
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

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
                logger.error("Failed to load detection model or tokenizer")
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            self.models_loaded = False
    
    def preprocess_query_gentle(self, query, tokenizer, max_len=100):
        """Gentler preprocessing that preserves SQL structure"""
        try:
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
        if not self.models_loaded or self.detection_model is None:
            return {"error": "Detection model not loaded"}
        
        try:
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
    
    def assess_query_safety(self, query):
        """Rule-based safety assessment (0=unsafe, 1=very safe)"""
        query_lower = query.lower().strip()
        safety_score = 0.5  # Start neutral
        
        # Positive indicators (increase safety)
        if re.match(r'^\s*(select|insert|update|delete)', query_lower):
            safety_score += 0.2  # Starts with valid SQL keyword
        
        if not re.search(r'(union|or\s+1\s*=\s*1|drop|truncate)', query_lower):
            safety_score += 0.2  # No obvious injection patterns
        
        if not ('--' in query or '/*' in query):
            safety_score += 0.1  # No SQL comments
        
        if re.search(r'where\s+\w+\s*=\s*[\d\'\"]', query_lower):
            safety_score += 0.1  # Has proper WHERE conditions
        
        # Negative indicators (decrease safety)
        if re.search(r'or\s+1\s*=\s*1', query_lower):
            safety_score -= 0.4  # Classic injection
        
        if 'union select' in query_lower:
            safety_score -= 0.3  # Union-based injection
        
        if re.search(r';.*drop|;.*delete|;.*truncate', query_lower):
            safety_score -= 0.5  # Stacked queries with dangerous commands
        
        if query_lower.count("'") % 2 != 0:
            safety_score -= 0.2  # Unmatched quotes
        
        return max(0, min(1, safety_score))  # Clamp between 0 and 1
    
    def get_prevention_risk_level(self, combined_risk):
        """Risk levels based on combined assessment"""
        if combined_risk < 0.2:
            return "Very Low"
        elif combined_risk < 0.3:
            return "Low"
        elif combined_risk < 0.5:
            return "Medium"
        elif combined_risk < 0.7:
            return "High"
        else:
            return "Critical"
    
    def generate_prevention_recommendations(self, query, combined_risk):
        """Generate prevention-focused recommendations"""
        recommendations = []
        query_lower = query.lower()
        
        # Always include best practices
        recommendations.append("🔐 Use parameterized queries/prepared statements")
        
        # Pattern-based recommendations
        if "'" in query or '"' in query:
            recommendations.append("🔒 Replace string literals with parameters")
        
        if re.search(r'where\s+\w+\s*=\s*[\'\"]\w+[\'\"]', query_lower):
            recommendations.append("✅ Good: Using WHERE clause with parameters")
        
        if "or" in query_lower:
            recommendations.append("⚠️ Review OR conditions for potential injection")
        
        if "union" in query_lower:
            recommendations.append("🚫 Validate UNION operations carefully")
        
        if combined_risk < 0.3:
            recommendations.extend([
                "✅ Query structure appears safe",
                "📱 Consider using ORM for added security",
                "🔍 Implement input validation as additional layer"
            ])
        else:
            recommendations.extend([
                "⚠️ Query needs security review",
                "🛡️ Implement strict input validation",
                "👤 Apply principle of least privilege",
                "📊 Enable SQL injection monitoring"
            ])
        
        return recommendations[:6]
    
    def predict_prevention(self, query):
        """Enhanced prevention using detection model + rule-based validation"""
        if not self.models_loaded or self.detection_model is None:
            return {"error": "Detection model not loaded"}
        
        try:
            # First, get detection prediction (but don't over-preprocess)
            max_len = self.detection_config.get('max_len', 100) if self.detection_config else 100
            
            # Use gentler preprocessing for prevention
            processed_query = self.preprocess_query_gentle(query, self.detection_tokenizer, max_len)
            if processed_query is None:
                return {"error": "Failed to preprocess query"}
            
            prediction = self.detection_model.predict(processed_query, verbose=0)
            malicious_probability = float(prediction[0][0])
            
            # Rule-based safety assessment
            safety_score = self.assess_query_safety(query)
            
            # Combine ML prediction with rule-based assessment
            # Weight: 60% rule-based, 40% ML for prevention
            combined_risk = (0.4 * malicious_probability) + (0.6 * (1 - safety_score))
            
            # More lenient threshold for prevention
            is_safe = combined_risk < 0.3  # Much more lenient than 0.5
            prevention_score = (1 - combined_risk) * 100
            
            # Generate comprehensive recommendations
            recommendations = self.generate_prevention_recommendations(query, combined_risk)
            
            return {
                "is_safe": is_safe,
                "malicious_probability": malicious_probability,
                "safety_probability": 1 - combined_risk,
                "risk_level": self.get_prevention_risk_level(combined_risk),
                "recommendations": recommendations,
                "prevention_score": prevention_score,
                "assessment_details": {
                    "ml_threat_score": malicious_probability,
                    "rule_based_safety": safety_score,
                    "combined_risk": combined_risk
                },
                "model_info": {
                    "name": "Hybrid Prevention System",
                    "mode": "ML Detection + Rule-Based Validation"
                }
            }
            
        except Exception as e:
            logger.error(f"Error in prevention prediction: {str(e)}")
            return {"error": f"Prevention analysis failed: {str(e)}"}

    def get_risk_level(self, malicious_probability):
        """Determine risk level based on MALICIOUS probability"""
        if malicious_probability < 0.2:
            return "Low"
        elif malicious_probability < 0.5:
            return "Medium" 
        elif malicious_probability < 0.8:
            return "High"
        else:
            return "Critical"

    def generate_recommendations(self, query, is_malicious, malicious_probability):
        """Generate security recommendations based on query analysis"""
        recommendations = []
        
        query_lower = query.lower()
        
        # Pattern-based recommendations
        if "'" in query or '"' in query:
            recommendations.append("🔒 Use parameterized queries to prevent string injection")
        
        if "or" in query_lower and "=" in query:
            recommendations.append("⚠️ Validate logical operators in WHERE clauses")
        
        if "union" in query_lower:
            recommendations.append("🚫 Restrict UNION operations or validate table access")
        
        if "--" in query or "/*" in query:
            recommendations.append("💬 Remove or sanitize SQL comments")
        
        if "drop" in query_lower or "delete" in query_lower:
            recommendations.append("🛡️ Implement strict access controls for DDL/DML operations")
        
        if ";" in query and len(query.split(";")) > 2:
            recommendations.append("📝 Execute single statements only, avoid batch queries")
        
        # General recommendations based on risk level
        if is_malicious or malicious_probability > 0.3:
            recommendations.extend([
                "🔍 Implement input validation and sanitization",
                "🔐 Use prepared statements with bound parameters",
                "👤 Apply principle of least privilege for database access",
                "📊 Enable SQL injection detection monitoring"
            ])
        else:
            recommendations.extend([
                "✅ Query appears safe, but always use prepared statements",
                "🔒 Implement consistent input validation",
                "📱 Consider using ORM frameworks for additional security"
            ])
        
        return recommendations[:6]  # Limit to 6 recommendations

# Initialize the detector
detector = SQLInjectionDetector()

@app.route('/')
def index():
    """Main page"""
    return render_template('templates/index.html')

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

# Load models when the app starts
detector.load_models()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
