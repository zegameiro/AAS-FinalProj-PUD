from src.services.dataset_loader import fulldataset



from src.phishing_url_detector import PhishingURLDetector

def main():
    phishing_urls = [
        "http://paypal-secure.verification-update.com/login",
        "http://192.168.1.1/banking/login.php",
        "https://account-verify.secure-amazon.net/update",
        "http://free-prize-winner.claim-now.tk/confirm",
        "https://аpple.com/login",
        "https://g00gle.com/verify",
    ]

    legitimate_urls = [
        "https://www.google.com",
        "https://github.com/user/repo",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://stackoverflow.com/questions/12345"
    ]

    # Prepare training data
    urls = phishing_urls + legitimate_urls
    labels = [1]*len(phishing_urls) + [0]*len(legitimate_urls)

    # Initialize and train the phishing URL detector
    detector = PhishingURLDetector(n_estimators=100)
    detector.train(urls, labels, test_size=0.3)

    # Save model
    # detector.save_model('phishing_detector.pkl')

    # Test predictions
    test_urls = [
        "https://secure-login-verify.com/account",
        "https://www.python.org/downloads",
        "https://аррӏе.com/signin",
        "https://paypaⅼ.com/login",
        "https://g00gle.com/verify",
        "https://www.google.com",
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
