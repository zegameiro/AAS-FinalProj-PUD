from src.url_feature_extractor import URLFeatureExtractor
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, f1_score
from sklearn.preprocessing import StandardScaler
from src.constants import *
from tqdm import tqdm
import polars as pl
import numpy as np
import joblib

class KNNPhishingDetector:

    def __init__(self, n_neighbors: int = 5, weights: str= 'distance', metric: str = 'minkowski', n_jobs: int = -1) -> None:
        self.feature_extractor = URLFeatureExtractor()
        self.scaler = StandardScaler()
        self.classifier = KNeighborsClassifier(
            n_neighbors=n_neighbors,
            weights=weights,  # 'distance' gives closer neighbors more weight
            metric=metric,    # 'minkowski' with p=2 is Euclidean distance
            p=2,              # Power parameter for Minkowski metric
            algorithm='auto', # Automatically choose best algorithm (ball_tree, kd_tree, brute)
            n_jobs=n_jobs     # Use all CPU cores
        )
        self.feature_names = None

    def prepare_data(self, urls: list[str], labels, scale: bool = True) -> tuple:
        print("Extracting features...")
        features_list = self.feature_extractor.extract_features_batch(urls)
        df = pl.DataFrame(features_list)

        if self.feature_names is None:
            self.feature_names = df.columns

        x = df[self.feature_names].to_numpy()
        y = np.array(labels)
        
        if scale:
            x = self.scaler.fit_transform(x) if not hasattr(self.scaler, 'mean_') else self.scaler.transform(x)

        return x, y
    
    def tune_hyperparameters(self, x_train, y_train):
        """Find optimal hyperparameters using GridSearchCV"""
        print("\n=== Tuning Hyperparameters ===")
        
        param_grid = {
            'n_neighbors': [3, 5, 7, 9, 11, 15],
            'weights': ['uniform', 'distance'],
            'metric': ['euclidean', 'manhattan', 'minkowski']
        }
        
        grid_search = GridSearchCV(
            KNeighborsClassifier(n_jobs=-1),
            param_grid,
            cv=5,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(x_train, y_train)
        
        print(f"\nBest parameters: {grid_search.best_params_}")
        print(f"Best F1 score: {grid_search.best_score_:.4f}")
        
        # Update classifier with best parameters
        self.classifier = grid_search.best_estimator_
        
        return grid_search.best_params_
    
    def train(self, urls: list[str], labels, test_size=0.2, tune_params=False) -> None:
        """Train the KNN Classifier"""

        # Fit scaler and prepare data
        x, y = self.prepare_data(urls, labels, scale=True)

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
        
        # Optional hyperparameter tuning
        if tune_params:
            self.tune_hyperparameters(x_train, y_train)

        print(f"\nTraining KNN on {len(x_train)} samples...")
        print(f"KNN Parameters: n_neighbors={self.classifier.n_neighbors}, weights={self.classifier.weights}, metric={self.classifier.metric}")
        
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
        cv_scores = cross_val_score(self.classifier, x, y, cv=5, scoring='f1', n_jobs=-1)
        print(f"F1 Scores: {cv_scores}")
        print(f"Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

        return x_test, y_test, y_pred

    def predict(self, urls):
        """Predict if URLs are phishing or legitimate"""

        x, _ = self.prepare_data(urls, labels=[0]*len(urls), scale=True)
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

    def save_model(self, filepath):
        """Save trained model to disk"""
        joblib.dump({
            'classifier': self.classifier,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, filepath)
        print(f"KNN Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.classifier = data['classifier']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        print(f"KNN Model loaded from {filepath}")
