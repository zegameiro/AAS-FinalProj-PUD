from src.ai_models.base_phishing_detector import BasePhishingDetector
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.preprocessing import StandardScaler

class KNNPhishingDetector(BasePhishingDetector):
    """K-Nearest Neighbors classifier for phishing URL detection"""

    def __init__(self, n_neighbors: int = 5, weights: str = 'distance', 
                 metric: str = 'minkowski', n_jobs: int = -1):
        super().__init__()
        self.n_neighbors = n_neighbors
        self.weights = weights
        self.metric = metric
        self.n_jobs = n_jobs
        self.scaler = StandardScaler()  # KNN needs feature scaling
        self.classifier = self._create_classifier()

    def _create_classifier(self):
        """Create KNN classifier"""
        return KNeighborsClassifier(
            n_neighbors=self.n_neighbors,
            weights=self.weights,
            metric=self.metric,
            p=2,
            algorithm='auto',
            n_jobs=self.n_jobs
        )

    def _get_model_name(self):
        """Return model name"""
        return "K-Nearest Neighbors"

    def _print_model_params(self):
        """Print KNN parameters"""
        print(f"KNN Parameters: n_neighbors={self.classifier.n_neighbors}, "
              f"weights={self.classifier.weights}, "
              f"metric={self.classifier.metric}")

    def prepare_data(self, urls: list[str], labels, scale: bool = True) -> tuple:
        """Override to always scale for KNN"""
        return super().prepare_data(urls, labels, scale=True)

    def _pre_train_hook(self, x_train, y_train, **kwargs):
        """Handle hyperparameter tuning if requested"""
        if kwargs.get('tune_params', False):
            self._tune_hyperparameters(x_train, y_train)

    def _tune_hyperparameters(self, x_train, y_train):
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

    def train(self, urls: list[str], labels, test_size=0.2, tune_params=False) -> tuple:
        """Train KNN with optional hyperparameter tuning"""
        return super().train(urls, labels, test_size=test_size, 
                           scale=True, tune_params=tune_params)