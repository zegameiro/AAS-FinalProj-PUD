from src.url_feature_extractor import URLFeatureExtractor
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, f1_score
from src.constants import *
from tqdm import tqdm
import pandas as pd
import numpy as np
import joblib

class PhishingURLDetector:
    """Random Forest classifier for phishing URL detection"""

    def __init__(self, n_estimators: int = 100, random_state: int = 42) -> None:
        self.feature_extractor = URLFeatureExtractor()
        self.classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced'  # Handle imbalanced datasets
        )
        self.feature_names = None

    def prepare_data(self, urls: list[str], labels) -> tuple:
        """Convert URLs and labels to feature matrix"""
        print("Extracting features...")
        features_list = self.feature_extractor.extract_features_batch(urls)
        df = pd.DataFrame(features_list)

        if self.feature_names is None:
            self.feature_names = df.columns.tolist()

        x = df[self.feature_names].values
        y = np.array(labels)

        return x, y
    
    def train(self, urls: list[str], labels, test_size=0.2) -> None:
        """Train the Random Forest Classifier"""

        x, y = self.prepare_data(urls, labels)

        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_dist = dict(zip(unique, counts))
        print(f"\nClass distribution: {class_dist}")
        if len(unique) == 2:
            imbalance_ratio = max(counts) / min(counts)
            print(f"Imbalance ratio: {imbalance_ratio:.2f}")

        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=test_size, random_state=42, stratify=y
        )

        print(f"\nTraining on {len(x_train)} samples...")
        self.classifier.fit(x_train, y_train)

        # Evaluate on test set
        y_pred = self.classifier.predict(x_test)
        y_proba = self.classifier.predict_proba(x_test)[:, 1]

        print("\n=== Training Results ===")
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
        cv_scores = cross_val_score(self.classifier, x, y, cv=5, scoring='f1')
        print(f"F1 Scores: {cv_scores}")
        print(f"Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

        # Feature importance
        self._print_feature_importance()

        return x_test, y_test, y_pred

    def predict(self, urls):
        """Predict if URLs are phishing or legitimate"""

        x, _ = self.prepare_data(urls, labels=[0]*len(urls))
        predictions = self.classifier.predict(x)
        probabilities = self.classifier.predict_proba(x)

        results = []
        for url, pred, proba in tqdm(zip(urls, predictions, probabilities), total=len(urls), desc="Predicting", unit="url"):
            # Add homoglyph warning
            homoglyph_warning = self._check_homoglyph_warning(url)

            results.append({
                'url': url,
                'prediction': 'Phishing' if pred == 1 else 'Legitimate',
                'confidence': proba[pred],
                'phishing_probability': proba[1],
                'legitimate_probability': proba[0],
                'homoglyph_warning': homoglyph_warning
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
    
    def _print_feature_importance(self, top_n=15):
        """Print top N most important features"""
        importances = self.classifier.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print(f"\n=== Top {top_n} Most Important Features ===")
        for i in range(min(top_n, len(self.feature_names))):
            idx = indices[i]
            print(f"{i+1}. {self.feature_names[idx]}: {importances[idx]:.4f}")

    def save_model(self, filepath):
        """Save trained model to disk"""
        joblib.dump({
            'classifier': self.classifier,
            'feature_names': self.feature_names
        }, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.classifier = data['classifier']
        self.feature_names = data['feature_names']
        print(f"Model loaded from {filepath}")