from src.ai_models.knn_detector import KNNDetector
from src.ai_models.random_forest_detector import RandomForestDetector
from src.services.dataset_loader.dataset_loader import DatasetLoader
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
                print(f"  ⚠️  Warnings: {', '.join(result['homoglyph_warning'])}")

def main():
    # Set random seed for reproducibility
    random.seed(42)
    
    # Load data
    print("Loading dataset...")
    dataset_loader = DatasetLoader()
    urls, labels = dataset_loader.get_urls_and_labels()
    
    print(f"\nTotal URLs loaded: {len(urls)}")
    print(f"Phishing URLs: {sum(labels)}")
    print(f"Benign URLs: {len(labels) - sum(labels)}")
    print(f"Phishing ratio: {sum(labels)/len(labels)*100:.2f}%")

    # Split into training and test sets (NO OVERLAP!)
    train_urls, train_labels, test_urls, test_labels = dataset_loader.split_train_test_datasets(
        test_size=0.15,  # 15% for testing, 85% for training
        balance_test=True,  # Balance test set classes
        random_seed=42
    )
    
    # Save test dataset for later use
    dataset_loader.save_test_dataset(test_urls, test_labels, 'test_dataset.csv')

    # Choose which algorithm to use
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
        # Train ONLY on training set (with internal validation split)
        rf_detector.train(train_urls, train_labels, test_size=0.2)
        rf_detector.save_model('models/phishing_detector_rf.pkl')
        # Evaluate on the held-out test set
        evaluate_on_test_set(rf_detector, test_urls, test_labels, "Random Forest")
    
    if choice in ['2', '3']:
        print("\n" + "="*60)
        print("TRAINING K-NEAREST NEIGHBORS")
        print("="*60)
        
        # Ask if user wants hyperparameter tuning
        tune = input("\nPerform hyperparameter tuning? (y/n) [default: n]: ").strip().lower() == 'y'
        
        knn_detector = KNNDetector(n_neighbors=7, weights='distance')
        # Train ONLY on training set (with internal validation split)
        knn_detector.train(train_urls, train_labels, test_size=0.2, tune_params=tune)
        knn_detector.save_model('models/phishing_detector_knn.pkl')
        # Evaluate on the held-out test set
        evaluate_on_test_set(knn_detector, test_urls, test_labels, "KNN")


if __name__ == "__main__":
    main()