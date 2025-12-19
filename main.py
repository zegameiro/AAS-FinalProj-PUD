from src.phishing_url_detector import PhishingURLDetector
from src.knn_phishing_detector import KNNPhishingDetector
import polars as pl
from tqdm import tqdm
import random

def retrieve_urls_labels():
    urls = []
    labels = []
    df = pl.read_csv('archive/dataset.csv')
    
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

def create_test_dataset(urls, labels, n_samples=20, balance=True, save_to_file=None):
    """
    Create a test dataset from the main dataset.
    
    Args:
        urls: List of all URLs
        labels: List of all labels
        n_samples: Number of samples to include in test set (default: 20)
        balance: Whether to balance phishing/legitimate samples (default: True)
        save_to_file: Optional filename to save test dataset (e.g., 'test_dataset.csv')
    
    Returns:
        tuple: (test_urls, test_labels)
    """

    # Separate phishing and legitimate URLs
    phishing_urls = [url for url, label in zip(urls, labels) if label == 1]
    legitimate_urls = [url for url, label in zip(urls, labels) if label == 0]
    
    test_urls = []
    test_labels = []
    
    if balance:
        # Get equal numbers of each class
        n_per_class = n_samples // 2
        
        # Randomly sample from each class
        sampled_phishing = random.sample(phishing_urls, min(n_per_class, len(phishing_urls)))
        sampled_legitimate = random.sample(legitimate_urls, min(n_per_class, len(legitimate_urls)))
        
        test_urls.extend(sampled_phishing)
        test_labels.extend([1] * len(sampled_phishing))
        
        test_urls.extend(sampled_legitimate)
        test_labels.extend([0] * len(sampled_legitimate))
    else:
        # Maintain original class distribution
        indices = random.sample(range(len(urls)), min(n_samples, len(urls)))
        test_urls = [urls[i] for i in indices]
        test_labels = [labels[i] for i in indices]
    
    # Shuffle the test set
    combined = list(zip(test_urls, test_labels))
    random.shuffle(combined)
    test_urls, test_labels = zip(*combined)
    test_urls = list(test_urls)
    test_labels = list(test_labels)
    
    # Print statistics
    print(f"\n=== Test Dataset Created ===")
    print(f"Total samples: {len(test_urls)}")
    print(f"Phishing: {sum(test_labels)} ({sum(test_labels)/len(test_labels)*100:.1f}%)")
    print(f"Legitimate: {len(test_labels) - sum(test_labels)} ({(len(test_labels) - sum(test_labels))/len(test_labels)*100:.1f}%)")
    
    # Save to file if requested
    if save_to_file:
        df = pl.DataFrame({
            'URL': test_urls,
            'label': test_labels
        })
        df.write_csv(save_to_file)
        print(f"Test dataset saved to: {save_to_file}")
    
    return test_urls, test_labels

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

    # Create test dataset from the main dataset
    test_urls, test_labels = create_test_dataset(
        urls, 
        labels, 
        n_samples=100,
        balance=True,
        save_to_file='test_dataset.csv'
    )

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
        rf_detector = PhishingURLDetector(n_estimators=200)
        rf_detector.train(urls, labels, test_size=0.2)
        rf_detector.save_model('phishing_detector_rf.pkl')
        evaluate_on_test_set(rf_detector, test_urls, test_labels, "Random Forest")
    
    if choice in ['2', '3']:
        print("\n" + "="*60)
        print("TRAINING K-NEAREST NEIGHBORS")
        print("="*60)
        
        # Ask if user wants hyperparameter tuning
        tune = input("\nPerform hyperparameter tuning? (y/n) [default: n]: ").strip().lower() == 'y'
        
        knn_detector = KNNPhishingDetector(n_neighbors=7, weights='distance')
        knn_detector.train(urls, labels, test_size=0.2, tune_params=tune)
        knn_detector.save_model('phishing_detector_knn.pkl')
        evaluate_on_test_set(knn_detector, test_urls, test_labels, "KNN")


if __name__ == "__main__":
    main()