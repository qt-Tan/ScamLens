import os
import joblib

# Load model
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "model.pkl")
model = joblib.load(model_path)

def predict_scam(text):
    """Given input text, return scam probability and keywords."""
    if not text.strip():
        return None
    
    # Prediction probability (0 to 1)
    prob = model.predict_proba([text])[0][1]
    
    # Extract terms that the model considers indicative of scam (highest TF-IDF weights)
    feature_names = model.named_steps['tfidfvectorizer'].get_feature_names_out()
    coefs = model.named_steps['multinomialnb'].feature_log_prob_[1]
    
    # Simple extraction of terms present in the text
    top_terms = [word for word in feature_names if word in text.lower()][:3]
    
    return {
        "probability": prob,
        "top_terms": top_terms
    }

def to_finding(ml_result):
    """Convert model result to the format expected by the main program."""
    if not ml_result or ml_result["probability"] < 0.5:
        return None
        
    return {
        "key": "ml_cue",
        "type": "🧠 ML Model Detection",
        "evidence": ", ".join(ml_result["top_terms"]) or "Pattern matching",
        "all_matches": ml_result["top_terms"],
        "explanation": f"The local ML model found this text has a {ml_result['probability']:.0%} probability of being a scam based on historical patterns.",
        "severity": "Medium"  # Set to Medium, used in conjunction with rules
    }