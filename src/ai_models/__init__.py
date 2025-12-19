from enum import Enum

from src.ai_models.base_phishing_detector import BasePhishingDetector
from src.ai_models.knn_detector import KNNDetector
from src.ai_models.random_forest_detector import RandomForestDetector


class Classifier(Enum):
    KNN = "knn"
    RANDOM_FOREST = "random_forest"

class Action(Enum):
    TRAINING = "training"
    PREDICT = "predict"

def get_classifier(classifier: Classifier,action: Action) -> BasePhishingDetector:
    match classifier:
        case Classifier.KNN:
            model = KNNDetector()
            model_loader = "models/phishing_detector_knn.pkl"
        case Classifier.RANDOM_FOREST:
            model = RandomForestDetector()
            model_loader = "models/phishing_detector_rf.pkl"
    
    match action:
        case Action.TRAINING:
            pass
        case Action.PREDICT:
            model.load_model(model_loader)
    
    return model