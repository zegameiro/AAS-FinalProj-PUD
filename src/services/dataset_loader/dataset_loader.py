from src.models import DataType, UrlEntry
from src.constants import SPAM_URL

from pathlib import Path
from io import StringIO
from tqdm import tqdm

import requests
import os
import polars as pl
import json
import random

class DatasetLoader:
    dataset_present = False
    dataset: list[UrlEntry]

    def __init__(self):
        if os.path.isdir("data"):
            self.dataset_present = True
        self.get_data()

    def __get_phishtank_data(self, url: str) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        
        try:
            print(f"Fetching PhishTank data from {url}...")
            data = requests.get(url, timeout=30)
            data.raise_for_status()  # Raise exception for bad status codes
            
            # Debug: Check if we got actual CSV data
            if len(data.text) < 100:
                print(f"Warning: Response seems too short ({len(data.text)} bytes)")
                print(f"Response: {data.text[:200]}")
            
            csv_data = StringIO(data.text)
            
            # Try to read CSV with error handling
            try:
                df = pl.read_csv(csv_data)
                print(f"Successfully loaded {len(df)} PhishTank URLs")
            except Exception as csv_error:
                print(f"Error parsing PhishTank CSV: {csv_error}")
                print(f"First 500 chars of response: {data.text[:500]}")
                # Return empty list if PhishTank data fails
                df = pl.DataFrame()
            
            for entry in tqdm(df.iter_rows(named=True), desc="Loading PhishTank data", unit="url"):
                entry_url = entry["url"]
                url_entry = UrlEntry(url=entry_url, data_type=DataType.PHISHING)
                entry_list.append(url_entry)
        
        except requests.RequestException as e:
            print(f"Error fetching PhishTank data: {e}")
            print("Falling back to local PhishTank data if available...")

            with open('data/spam.json', 'r') as f:
                spam_data = json.load(f)
                for entry_str in tqdm(spam_data, desc="Loading local PhishTank data", unit="url"):
                    entry = json.loads(entry_str)  # Parse the JSON string
                    entry_url = entry["url"]
                    url_entry = UrlEntry(url=entry_url, data_type=DataType.PHISHING)
                    entry_list.append(url_entry)
        
        # Extract phishing URLs from dataset.csv
        try:
            df_local = pl.read_csv('data/dataset.csv')
            df_local = df_local.unique(subset=['URL'])
            for row in tqdm(df_local.iter_rows(named=True), desc="Loading local dataset", unit="url"):
                if int(row['label']) == 0:  # Phishing label
                    url_1 = row['URL']
                    url_entry = UrlEntry(url=url_1, data_type=DataType.PHISHING)
                    entry_list.append(url_entry)
            print(f"Loaded {len([r for r in df_local.iter_rows(named=True) if int(r['label']) == 0])} phishing URLs from local dataset")
        except Exception as e:
            print(f"Error loading local dataset: {e}")
        
        return entry_list

    def __get_benign_data(self) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        
        try:
            with open('data/non_spam_url_filter.txt', 'r') as file:
                for line in file:
                    url_1 = line.strip()
                    if url_1:  # Skip empty lines
                        url_entry = UrlEntry(url=url_1, data_type=DataType.BENIGN)
                        entry_list.append(url_entry)
            print(f"Loaded {len(entry_list)} benign URLs from local file")
        except Exception as e:
            print(f"Error loading benign data: {e}")
        
        return entry_list
    
    def __get_project_root(self) -> Path:
        p = Path(__file__).resolve()
        for parent in p.parents:
            if (parent / "pyproject.toml").exists():
                return parent
        raise RuntimeError("Project root not found")

    def get_urls_and_labels(self) -> tuple[list[str], list[int]]:
        """
        Extract URLs and labels from the dataset.
        Returns tuple of (urls, labels) where labels are 1 for PHISHING, 0 for BENIGN
        """
        urls = []
        labels = []
        
        for entry in self.dataset:
            urls.append(entry.url)
            # Convert DataType to binary label: 1 for PHISHING, 0 for BENIGN
            labels.append(1 if entry.data_type == DataType.PHISHING else 0)
        
        return urls, labels

    def get_data(self) -> None:
        spam_list: list[UrlEntry] = self.__get_phishtank_data(SPAM_URL)
        benign_list: list[UrlEntry] = self.__get_benign_data()

        data_dir = self.__get_project_root() / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        with open(data_dir / "spam_final.json", "w", encoding="utf-8") as f:
            json.dump([e.model_dump_json() for e in spam_list], f, indent=2)

        with open(data_dir / "benign.json", "w", encoding="utf-8") as f:
            json.dump([e.model_dump_json() for e in benign_list], f, indent=2)

        self.dataset: list[UrlEntry] = spam_list + benign_list
        
        print(f"\n=== Dataset Loaded ===")
        print(f"Total URLs: {len(self.dataset)}")
        print(f"Phishing URLs: {len(spam_list)}")
        print(f"Benign URLs: {len(benign_list)}")

    def split_train_test_datasets(self, test_size=0.2, balance_test=True, random_seed=42):
        """
        Split dataset into training and test sets WITHOUT overlap.
        
        Args:
            test_size: Fraction or absolute number for test set
            balance_test: Whether to balance the test set classes
            random_seed: Random seed for reproducibility
        
        Returns:
            tuple: (train_urls, train_labels, test_urls, test_labels)
        """
        # Set random seed
        random.seed(random_seed)
        
        # Get URLs and labels from dataset
        urls, labels = self.get_urls_and_labels()
        
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

    def save_test_dataset(self, test_urls, test_labels, filename='data/test_dataset.csv'):
        """Save test dataset to CSV file"""
        df = pl.DataFrame({
            'URL': test_urls,
            'label': test_labels
        })
        df.write_csv(filename)
        print(f"Test dataset saved to: {filename}")

    def evaluate_on_test_set(self, detector, test_urls, test_labels, dataset_name="Test"):
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