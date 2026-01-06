from src.ai_models.knn_detector import KNNDetector
from src.ai_models.random_forest_detector import RandomForestDetector
from src.services.dataset_loader import fulldataset
from src.services.dataset_loader.dataset_loader import DataType
import random

def evaluate_on_test_set(detector, test_urls, test_labels, model_name: str):
    """Evaluate detector on test dataset"""
    print(f"\n=== Testing on {model_name} ===")
    results = detector.predict(test_urls)
    
    # Calculate accuracy on test dataset
    correct = 0
    for result, true_label in zip(results, test_labels):
        predicted_label = 1 if result['prediction'] == 'Phishing' else 0
        if predicted_label == true_label:
            correct += 1
    
    accuracy = correct / len(test_labels) * 100
    print(f"\n {model_name} Accuracy: {accuracy:.2f}%")
    print(f"Correct: {correct}/{len(test_labels)}")
    
    # Show some example predictions
    print(f"\n=== Sample Predictions from {model_name} ===")
    for i in range(min(10, len(results))):
        result = results[i]
        true_label = test_labels[i]
        true_class = "Phishing" if true_label == 1 else "Legitimate"
        correct_symbol = "✓" if result['prediction'] == true_class else "✗"
        
        print(f"\n{correct_symbol} URL: {result['url'][:60]}...")
        print(f"  True: {true_class} | Predicted: {result['prediction']} | Confidence: {result['confidence']:.4f}")
        if result['homoglyph_warning']:
            print(f"    Warnings: {', '.join(result['homoglyph_warning'])}")

def main():
    
    urls, labels = fulldataset.get_urls_and_labels()
    
    print(f"\nTotal URLs loaded: {len(urls)}")
    print(f"Phishing URLs: {sum(labels)}")
    print(f"Benign URLs: {len(labels) - sum(labels)}")
    print(f"Phishing ratio: {sum(labels)/len(labels)*100:.2f}%")

    train_set, eval_set = fulldataset.split_train_eval(
        train_percentage=0.85  # 85% for training, 15% for testing
    )

    train_urls = [entry.url for entry in train_set]
    train_labels = [1 if entry.data_type == DataType.PHISHING else 0 for entry in train_set]

    test_urls = [entry.url for entry in eval_set]
    test_labels = [1 if entry.data_type == DataType.PHISHING else 0 for entry in eval_set]

    print("\n" + "="*60)
    print("Choose Algorithm:")
    print("1. Random Forest")
    print("2. K-Nearest Neighbors (KNN)")
    print("3. Both (compare performance)")
    print("="*60)
    
    choice = input("Enter choice (1/2/3) [default: 3]: ").strip() or "3"
    
    if choice in ['1', '3']:
        print("\n" + "="*60)
        print("TRAINING RANDOM FOREST")
        print("="*60)
        rf_detector = RandomForestDetector(n_estimators=200)
        rf_detector.train(train_urls, train_labels, test_size=0.2)
        rf_detector.save_model('models/phishing_detector_rf.pkl')
        evaluate_on_test_set(rf_detector, test_urls, test_labels, "Random Forest")
    
    if choice in ['2', '3']:
        print("\n" + "="*60)
        print("TRAINING K-NEAREST NEIGHBORS")
        print("="*60)
        
        tune = input("\nPerform hyperparameter tuning? (y/n) [default: n]: ").strip().lower() == 'y'
        
        knn_detector = KNNDetector(n_neighbors=7, weights='distance')
        knn_detector.train(train_urls, train_labels, test_size=0.2, tune_params=tune)
        knn_detector.save_model('models/phishing_detector_knn.pkl')
        evaluate_on_test_set(knn_detector, test_urls, test_labels, "KNN")


if __name__ == "__main__":
    main()