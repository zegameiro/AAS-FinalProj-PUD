from src.services.dataset_loader import fulldataset
from src.phishing_url_detector import PhishingURLDetector

def main():
    # Load data from DatasetLoader
    print("Loading dataset...")
    urls, labels = fulldataset.get_urls_and_labels()
    
    print(f"Total URLs loaded: {len(urls)}")
    print(f"Phishing URLs: {sum(labels)}")
    print(f"Benign URLs: {len(labels) - sum(labels)}")

    # Initialize and train the phishing URL detector
    print("\nInitializing Random Forest detector...")
    detector = PhishingURLDetector(n_estimators=100)
    
    # Train with 20% test split
    detector.train(urls, labels, test_size=0.2)

    # Save model
    # detector.save_model('phishing_detector.pkl')

    # Test predictions on sample URLs
    test_urls = [
        "https://secure-login-verify.com/account",
        "https://www.python.org/downloads",
        "https://аррӏе.com/signin",
        "https://paypaⅼ.com/login",
        "https://g00gle.com/verify",
        "https://www.google.com",
        "http://paypal-secure.verification-update.com/login",
    ]

    print("\n=== Test Predictions ===")
    results = detector.predict(test_urls)
    for result in results:
        print(f"\nURL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.4f}")
        if result['homoglyph_warning']:
            print(f"⚠️  Warnings: {result['homoglyph_warning']}")


if __name__ == "__main__":
    main()