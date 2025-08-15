#!/usr/bin/env python3
"""
Debug script to diagnose SQL injection model loading issues
Run this script to check what's wrong with your model files
"""

import os
import json
import pickle
import sys
from pathlib import Path

def check_directory_structure():
    """Check if the required directories and files exist"""
    print("🔍 Checking directory structure...")
    
    base_dir = "PhD_research_models"
    detection_dir = os.path.join(base_dir, "sql_detection")
    prevention_dir = os.path.join(base_dir, "sql_prevention")
    
    print(f"📁 Base directory: {base_dir}")
    print(f"   Exists: {os.path.exists(base_dir)}")
    
    if os.path.exists(base_dir):
        print(f"   Contents: {os.listdir(base_dir)}")
    
    print(f"\n📁 Detection directory: {detection_dir}")
    print(f"   Exists: {os.path.exists(detection_dir)}")
    
    if os.path.exists(detection_dir):
        print(f"   Contents: {os.listdir(detection_dir)}")
        
        # Check for required files
        required_files = [
            'detection_model.keras',
            'detection_model.h5', 
            'detection_tokenizer.pickle',
            'detection_config.json'
        ]
        
        print("\n   Required files check:")
        for file in required_files:
            file_path = os.path.join(detection_dir, file)
            exists = os.path.exists(file_path)
            size = os.path.getsize(file_path) if exists else 0
            print(f"   ✅ {file}: {exists} ({size} bytes)" if exists else f"   ❌ {file}: {exists}")
    
    print(f"\n📁 Prevention directory: {prevention_dir}")
    print(f"   Exists: {os.path.exists(prevention_dir)}")
    
    if os.path.exists(prevention_dir):
        print(f"   Contents: {os.listdir(prevention_dir)}")
        
        # Check for required files
        required_files = [
            'prevention_model.keras',
            'prevention_model.h5',
            'prevention_tokenizer.pickle', 
            'prevention_config.json'
        ]
        
        print("\n   Required files check:")
        for file in required_files:
            file_path = os.path.join(prevention_dir, file)
            exists = os.path.exists(file_path)
            size = os.path.getsize(file_path) if exists else 0
            print(f"   ✅ {file}: {exists} ({size} bytes)" if exists else f"   ❌ {file}: {exists}")

def test_model_loading():
    """Test loading each component individually"""
    print("\n🧪 Testing individual component loading...")
    
    # Test detection model loading
    detection_dir = "PhD_research_models/sql_detection"
    
    if os.path.exists(detection_dir):
        print(f"\n📊 Testing Detection Model Loading:")
        
        # Try loading model files
        model_files = [
            os.path.join(detection_dir, 'detection_model.keras'),
            os.path.join(detection_dir, 'detection_model.h5')
        ]
        
        for model_file in model_files:
            if os.path.exists(model_file):
                print(f"   🔄 Attempting to load: {model_file}")
                try:
                    import tensorflow as tf
                    model = tf.keras.models.load_model(model_file)
                    print(f"   ✅ Successfully loaded model from {model_file}")
                    print(f"   📏 Model summary: {model.input_shape} -> {model.output_shape}")
                    break
                except Exception as e:
                    print(f"   ❌ Failed to load {model_file}: {str(e)}")
        
        # Test tokenizer loading
        tokenizer_path = os.path.join(detection_dir, 'detection_tokenizer.pickle')
        if os.path.exists(tokenizer_path):
            print(f"   🔄 Attempting to load tokenizer: {tokenizer_path}")
            try:
                with open(tokenizer_path, 'rb') as handle:
                    tokenizer = pickle.load(handle)
                print(f"   ✅ Successfully loaded tokenizer")
                print(f"   📝 Vocab size: {len(tokenizer.word_index) if hasattr(tokenizer, 'word_index') else 'Unknown'}")
            except Exception as e:
                print(f"   ❌ Failed to load tokenizer: {str(e)}")
        
        # Test config loading
        config_path = os.path.join(detection_dir, 'detection_config.json')
        if os.path.exists(config_path):
            print(f"   🔄 Attempting to load config: {config_path}")
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                print(f"   ✅ Successfully loaded config")
                print(f"   ⚙️ Config keys: {list(config.keys())}")
            except Exception as e:
                print(f"   ❌ Failed to load config: {str(e)}")

def check_python_environment():
    """Check Python environment and dependencies"""
    print("\n🐍 Checking Python Environment:")
    print(f"   Python version: {sys.version}")
    
    required_packages = [
        'tensorflow',
        'numpy', 
        'pandas',
        'flask',
        'pickle'
    ]
    
    for package in required_packages:
        try:
            if package == 'pickle':
                import pickle
                version = "built-in"
            else:
                module = __import__(package)
                version = getattr(module, '__version__', 'unknown')
            print(f"   ✅ {package}: {version}")
        except ImportError:
            print(f"   ❌ {package}: Not installed")

def check_file_permissions():
    """Check if files have proper read permissions"""
    print("\n🔐 Checking File Permissions:")
    
    paths_to_check = [
        "PhD_research_models",
        "PhD_research_models/sql_detection",
        "PhD_research_models/sql_prevention"
    ]
    
    for path in paths_to_check:
        if os.path.exists(path):
            readable = os.access(path, os.R_OK)
            print(f"   {'✅' if readable else '❌'} {path}: {'Readable' if readable else 'Not readable'}")
            
            # Check individual files
            if os.path.isdir(path):
                for file in os.listdir(path):
                    file_path = os.path.join(path, file)
                    if os.path.isfile(file_path):
                        readable = os.access(file_path, os.R_OK)
                        size = os.path.getsize(file_path)
                        print(f"     {'✅' if readable else '❌'} {file}: {'Readable' if readable else 'Not readable'} ({size} bytes)")

def suggest_fixes():
    """Suggest potential fixes based on findings"""
    print("\n💡 Suggested Fixes:")
    
    detection_dir = "PhD_research_models/sql_detection"
    prevention_dir = "PhD_research_models/sql_prevention"
    
    fixes = []
    
    # Check if directories exist
    if not os.path.exists("PhD_research_models"):
        fixes.append("❌ Create 'PhD_research_models' directory in your project root")
    
    if not os.path.exists(detection_dir):
        fixes.append("❌ Create 'PhD_research_models/sql_detection' directory")
    
    # Check for model files
    if os.path.exists(detection_dir):
        has_model = any(os.path.exists(os.path.join(detection_dir, f)) 
                       for f in ['detection_model.keras', 'detection_model.h5'])
        if not has_model:
            fixes.append("❌ Add a model file: 'detection_model.keras' or 'detection_model.h5' in sql_detection/")
        
        if not os.path.exists(os.path.join(detection_dir, 'detection_tokenizer.pickle')):
            fixes.append("❌ Add 'detection_tokenizer.pickle' in sql_detection/")
        
        if not os.path.exists(os.path.join(detection_dir, 'detection_config.json')):
            fixes.append("⚠️ Consider adding 'detection_config.json' in sql_detection/ (optional but recommended)")
    
    # Add general fixes
    fixes.extend([
        "🔧 Ensure all model files are not corrupted (check file sizes > 0)",
        "🔧 Verify TensorFlow version compatibility with your saved models", 
        "🔧 Make sure you're running the script from the correct directory",
        "🔧 Check file permissions (especially on Linux/Mac)",
        "🔧 Try regenerating the models if they seem corrupted"
    ])
    
    for i, fix in enumerate(fixes, 1):
        print(f"   {i}. {fix}")

def create_minimal_test_files():
    """Create minimal test files to verify the loading mechanism"""
    print("\n🧪 Creating minimal test files...")
    
    # Create directories
    os.makedirs("PhD_research_models/sql_detection", exist_ok=True)
    
    # Create a minimal config file
    config = {
        "model_name": "Test Detection Model",
        "model_type": "CNN+BiLSTM",
        "version": "1.0",
        "max_len": 100,
        "best_threshold": 0.5
    }
    
    config_path = "PhD_research_models/sql_detection/detection_config.json"
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"   ✅ Created test config: {config_path}")
    except Exception as e:
        print(f"   ❌ Failed to create config: {e}")
    
    print("   ⚠️ You still need to provide actual model and tokenizer files")
    print("   💡 These must be generated from your training process")

if __name__ == "__main__":
    print("🚀 SQL Injection Model Loading Diagnostic Tool")
    print("=" * 50)
    
    check_directory_structure()
    check_file_permissions()
    check_python_environment()
    test_model_loading()
    suggest_fixes()
    
    print("\n" + "=" * 50)
    
    response = input("\n❓ Would you like me to create minimal test files? (y/n): ")
    if response.lower() in ['y', 'yes']:
        create_minimal_test_files()
    
    print("\n🎯 Run this diagnostic to identify the specific issue with your model loading!")