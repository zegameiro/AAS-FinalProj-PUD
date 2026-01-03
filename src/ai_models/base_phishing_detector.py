from src.url_feature_extractor import URLFeatureExtractor
from src.constants import *

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, f1_score
from tqdm import tqdm
from abc import ABC, abstractmethod

import polars as pl
import numpy as np
import joblib

class BasePhishingDetector(ABC):
    """Base class for phishing URL detectors with common functionality."""

    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.classifier = None
        self.feature_names = None
        self.scaler = None

    @abstractmethod
    def _create_classifier(self):
        """Creat and return the classifier instance. Must be implemented by subclasses"""
        pass

    @abstractmethod
    def _get_model_name(self):
        """Return the name of the model for display purposes."""
        pass    

    def prepare_data(self, urls: list[str], labels, scale: bool = False) -> tuple:
        """Convert URLs and labels to feature matrix"""

        print("Extracting features from URLs...")
        features_list = self.feature_extractor.extract_features_batch(urls)
        print(f"Extracted {len(features_list[0])} features.")
        df = pl.DataFrame(features_list)

        if self.feature_names is None:
            self.feature_names = df.columns

        x = df[self.feature_names].to_numpy()
        y = np.array(labels)

        # Scale features if needed
        if scale and self.scaler is not None:
            x = self.scaler.fit_transform(x) if not hasattr(self.scaler, 'mean_') else self.scaler.transform(x)

        return x, y
    
    def train(self, urls: list[str], labels, test_size = 0.2, **kwargs) -> tuple:
        """Train the classifier"""

        # Prepare data (subclasses can override scale behavior)
        scale = kwargs.get('scale', False)
        x, y = self.prepare_data(urls, labels, scale=scale)

        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_dist = dict(zip(unique, counts))
        print(f"\nClass distribution: {class_dist}")

        if len(unique) == 2:
            imbalance_ratio = max(counts) / min(counts)
            print(f"Imabalance ratio: {imbalance_ratio:.2f}")

        # Split data
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=test_size, random_state=42, stratify=y)

        # Train
        print(f"\n Training {self._get_model_name()} on {len(x_train)} samples...")
        self._print_model_params()
        self.classifier.fit(x_train, y_train)

        self._evaluate(x_test, y_test, x, y)

    def _print_model_params(self):
        """Print model-specific parameters. Subclasses can override."""
        pass

    def _evaluate(self, x_test, y_test, x_full, y_full):
        """Evaluate the trained model"""
        y_pred = self.classifier.predict(x_test)
        y_proba = self.classifier.predict_proba(x_test)[:, 1]

        print(f"\n=== {self._get_model_name()} Training Results ===")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(f"F1-Score: {f1_score(y_test, y_pred):.4f}")
        print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        print(f"True Negatives: {cm[0][0]}, False Positives: {cm[0][1]}")
        print(f"False Negatives: {cm[1][0]}, True Positives: {cm[1][1]}")

        # Cross-validation
        print("\n=== Cross-Validation (5-fold) ===")
        cv_scores = cross_val_score(self.classifier, x_full, y_full, cv=5, scoring='f1', n_jobs=-1)
        print(f"F1 Scores: {cv_scores}")
        print(f"Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

        # Model-specific evaluation
        self._model_specific_evaluation()

    def _model_specific_evaluation(self):
        """Hook for subclasses to implement model-specific evaluation."""
        pass

    def predict(self, urls):
        """Predict if URLs are phishing or legitimate"""
        scale = hasattr(self,"scaler") and self.scaler is not None
        x, _ = self.prepare_data(urls, labels=[0]*len(urls), scale=scale)
        predictions = self.classifier.predict(x)
        probabilities = self.classifier.predict_proba(x)

        results = []

        for url, pred, proba in tqdm(zip(urls, predictions, probabilities), total=len(urls), desc="Predicting", unit="url"):
            homoglyph_warnings = self._check_homoglyph_warning(url)

            results.append({
                'url': url,
                'prediction': 'Phishing' if pred == 1 else 'Legitimate',
                'confidence': proba[pred],
                'phishing_probability': proba[1],
                'legitimate_probability': proba[0],
                'homoglyph_warning': homoglyph_warnings
            })
        return results

    def _check_homoglyph_warning(self, url):
        """Generate warning message if homoglyphs detected"""
        warnings = []
        
        # Check for homoglyphs
        homoglyphs_found = []
        for char in url:
            if char in HOMOGLYPH_MAP:
                normal_char = HOMOGLYPH_MAP[char]
                homoglyphs_found.append(f"'{char}' (looks like '{normal_char}')")
        
        if homoglyphs_found:
            warnings.append(f"Suspicious characters: {', '.join(homoglyphs_found[:5])}")
        
        # Check for punycode
        if 'xn--' in url:
            warnings.append("Contains punycode encoding (xn--)")
        
        # Check for mixed charsets
        if self.feature_extractor._has_mixed_charset(url):
            warnings.append("Mixed character sets detected")
        
        # Check for brand impersonation
        domain = url.split('/')[2] if len(url.split('/')) > 2 else ''
        if self.feature_extractor._check_brand_in_subdomain(domain):
            warnings.append("Brand name detected in subdomain (possible phishing)")
        
        return warnings if warnings else None
    
    def save_model(self, filepath):
        """Save trained model to disk"""
        model_data = {
            'classifier': self.classifier,
            'feature_names': self.feature_names
        }
        
        # Add scaler if present
        if self.scaler is not None:
            model_data['scaler'] = self.scaler
            
        joblib.dump(model_data, filepath)
        print(f"{self._get_model_name()} model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.classifier = data['classifier']
        self.feature_names = data['feature_names']
        
        # Load scaler if present
        if 'scaler' in data:
            self.scaler = data['scaler']
            
        print(f"{self._get_model_name()} model loaded from {filepath}")