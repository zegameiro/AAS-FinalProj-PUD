from src.ai_models.knn_detector import KNNPhishingDetector
from src.ai_models.random_forest_detector import RandomForestDetector
import polars as pl
from tqdm import tqdm
import random

def retrieve_urls_labels():
    urls = []
    labels = []
    df = pl.read_csv('data/dataset.csv')
    
    # Remove duplicates
    df = df.unique(subset=['URL'])
    
    for row in tqdm(df.iter_rows(named=True), desc="Loading dataset"):
        url = row['URL']
        label = 1 if int(row['label']) == 0 else 0
        
        # Basic URL validation
        if url and isinstance(url, str) and len(url) > 0:
            urls.append(url)
            labels.append(label)
    
    return urls, labels

def split_train_test_datasets(urls, labels, test_size=0.2, balance_test=True):
    """
    Split dataset into training and test sets WITHOUT overlap.
    
    Args:
        urls: List of all URLs
        labels: List of all labels
        test_size: Fraction or absolute number for test set
        balance_test: Whether to balance the test set classes
    
    Returns:
        tuple: (train_urls, train_labels, test_urls, test_labels)
    """
    # Separate phishing and legitimate URLs
    phishing_indices = [i for i, label in enumerate(labels) if label == 1]
    legitimate_indices = [i for i, label in enumerate(labels) if label == 0]
    
    # Determine test set size
    if test_size < 1:
        # Fraction
        n_test_phishing = int(len(phishing_indices) * test_size)
        n_test_legitimate = int(len(legitimate_indices) * test_size)
    else:
        # Absolute number
        if balance_test:
            n_test_phishing = int(test_size / 2)
            n_test_legitimate = int(test_size / 2)
        else:
            # Maintain class distribution
            phishing_ratio = len(phishing_indices) / len(labels)
            n_test_phishing = int(test_size * phishing_ratio)
            n_test_legitimate = int(test_size * (1 - phishing_ratio))
    
    # Randomly sample test indices
    random.shuffle(phishing_indices)
    random.shuffle(legitimate_indices)
    
    test_phishing_indices = phishing_indices[:n_test_phishing]
    test_legitimate_indices = legitimate_indices[:n_test_legitimate]
    
    train_phishing_indices = phishing_indices[n_test_phishing:]
    train_legitimate_indices = legitimate_indices[n_test_legitimate:]
    
    # Combine and create final datasets
    test_indices = test_phishing_indices + test_legitimate_indices
    train_indices = train_phishing_indices + train_legitimate_indices
    
    # Shuffle test set
    random.shuffle(test_indices)
    
    # Extract URLs and labels
    train_urls = [urls[i] for i in train_indices]
    train_labels = [labels[i] for i in train_indices]
    test_urls = [urls[i] for i in test_indices]
    test_labels = [labels[i] for i in test_indices]
    
    # Print statistics
    print(f"\n=== Dataset Split ===")
    print(f"Training set: {len(train_urls)} samples")
    print(f"  - Phishing: {sum(train_labels)} ({sum(train_labels)/len(train_labels)*100:.1f}%)")
    print(f"  - Legitimate: {len(train_labels) - sum(train_labels)} ({(len(train_labels) - sum(train_labels))/len(train_labels)*100:.1f}%)")
    print(f"\nTest set: {len(test_urls)} samples")
    print(f"  - Phishing: {sum(test_labels)} ({sum(test_labels)/len(test_labels)*100:.1f}%)")
    print(f"  - Legitimate: {len(test_labels) - sum(test_labels)} ({(len(test_labels) - sum(test_labels))/len(test_labels)*100:.1f}%)")
    
    # Verify no overlap
    train_set = set(train_urls)
    test_set = set(test_urls)
    overlap = train_set.intersection(test_set)
    if overlap:
        print(f"\n⚠️  WARNING: Found {len(overlap)} overlapping URLs!")
    else:
        print(f"\n✓ No overlap between training and test sets")
    
    return train_urls, train_labels, test_urls, test_labels

def save_test_dataset(test_urls, test_labels, filename='data/test_dataset.csv'):
    """Save test dataset to CSV file"""
    df = pl.DataFrame({
        'URL': test_urls,
        'label': test_labels
    })
    df.write_csv(filename)
    print(f"Test dataset saved to: {filename}")

def evaluate_on_test_set(detector, test_urls, test_labels, dataset_name="Test"):
    """Evaluate detector on test dataset"""
    print(f"\n=== Testing on {dataset_name} Dataset ===")
    results = detector.predict(test_urls)
    
    # Calculate accuracy on test dataset
    correct = 0
    for result, true_label in zip(results, test_labels):
        predicted_label = 1 if result['prediction'] == 'Phishing' else 0
        if predicted_label == true_label:
            correct += 1
    
    accuracy = correct / len(test_labels) * 100
    print(f"\n{dataset_name} Dataset Accuracy: {accuracy:.2f}%")
    print(f"Correct: {correct}/{len(test_labels)}")
    
    # Show some example predictions
    print(f"\n=== Sample Predictions from {dataset_name} Dataset ===")
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
    urls, labels = retrieve_urls_labels()
    
    print(f"\nTotal URLs loaded: {len(urls)}")
    print(f"Phishing URLs: {sum(labels)}")
    print(f"Benign URLs: {len(labels) - sum(labels)}")
    print(f"Phishing ratio: {sum(labels)/len(labels)*100:.2f}%")

    # Split into training and test sets (NO OVERLAP!)
    train_urls, train_labels, test_urls, test_labels = split_train_test_datasets(
        urls, 
        labels, 
        test_size=0.15,  # 15% for testing, 85% for training
        balance_test=True  # Balance test set classes
    )
    
    # Save test dataset for later use
    save_test_dataset(test_urls, test_labels, 'test_dataset.csv')

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
        
        knn_detector = KNNPhishingDetector(n_neighbors=7, weights='distance')
        # Train ONLY on training set (with internal validation split)
        knn_detector.train(train_urls, train_labels, test_size=0.2, tune_params=tune)
        knn_detector.save_model('models/phishing_detector_knn.pkl')
        # Evaluate on the held-out test set
        evaluate_on_test_set(knn_detector, test_urls, test_labels, "KNN")


if __name__ == "__main__":
    main()