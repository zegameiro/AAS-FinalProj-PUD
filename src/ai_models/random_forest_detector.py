from src.ai_models.base_phishing_detector import BasePhishingDetector
from sklearn.ensemble import RandomForestClassifier
import numpy as np

class RandomForestDetector(BasePhishingDetector):
    """Random Forest classifier for phishing URL detection"""

    def __init__(self, n_estimators: int = 100, random_state: int = 42, **kwargs):
        super().__init__()
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.kwargs = kwargs
        self.classifier = self._create_classifier()

    def _create_classifier(self):
        """Create and return the Random Forest classifier instance."""
        return RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
            max_depth=self.kwargs.get('max_depth', 30),
            min_samples_split=self.kwargs.get('min_samples_split', 5),
            min_samples_leaf=self.kwargs.get('min_samples_leaf', 2),
            max_features=self.kwargs.get('max_features', 'sqrt'),
            class_weight='balanced'
        )
    
    def _get_model_name(self):
        return "Random Forest"
    
    def _print_model_params(self):
        """Print Random Forest parameters"""
        print(f"RF Parameters: n_estimators={self.classifier.n_estimators}, "
              f"max_depth={self.classifier.max_depth}, "
              f"min_samples_split={self.classifier.min_samples_split}")
        
    def _model_specific_evaluation(self):
        """Print feature importance for Random Forest"""
        self._print_feature_importance()

    def _print_feature_importance(self, top_n=15):
        """Print top N most important features"""
        importances = self.classifier.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print(f"\n=== Top {top_n} Most Important Features ===")
        for i in range(min(top_n, len(self.feature_names))):
            idx = indices[i]
            print(f"{i+1}. {self.feature_names[idx]}: {importances[idx]:.4f}")
