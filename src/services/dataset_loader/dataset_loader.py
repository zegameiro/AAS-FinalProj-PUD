from src.models import DataType, UrlEntry

from pathlib import Path
from tqdm import tqdm

import os
import polars as pl
import json
import random

class DatasetLoader:
    dataset_present = False
    dataset: list[UrlEntry]

    def __init__(self):
        self.counter = 0
        if os.path.isdir("data"):
            self.dataset_present = True
        self.get_data()

    def __get_phishtank_data(self) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        url_set = set()

        # Prefer a pre-saved spam.json if available
        spam_json_path = os.path.join("data", "spam.json")
        if os.path.exists(spam_json_path):
            try:
                with open(spam_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for item in data:
                    record = json.loads(item)
                    url_1 = record.get("url") 

                    if not url_1:
                        continue

                    if url_1 in url_set:
                        continue

                    entry_list.append(UrlEntry(id=record.get("id"), url=url_1, data_type=DataType.PHISHING))
                    url_set.add(url_1)

                print(f"Loaded {len(entry_list)} phishing URLs from local spam.json")
                return entry_list
            except Exception as e:
                print(f"Error loading local spam.json: {e}")

        # If spam.json not available, try online-valid.json and dataset.csv
        local_online_exists = os.path.exists(os.path.join("data", "online-valid.json"))
        local_dataset_exists = os.path.exists(os.path.join("data", "dataset.csv"))

        if local_online_exists:
            try:
                with open(os.path.join("data", "online-valid.json"), "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data:
                    # attempt to extract url field from each record
                    if isinstance(item, dict):
                        url_1 = item.get("url")
                    else:
                        url_1 = str(item).strip()

                    if not url_1:
                        continue
                    if url_1 in url_set:
                        continue
                    entry_list.append(UrlEntry(id=self.counter, url=url_1, data_type=DataType.PHISHING))
                    url_set.add(url_1)
                    self.counter += 1

                print(f"Loaded {len(entry_list)} phishing URLs from local online-valid.json")
            except Exception as e:
                print(f"Error loading online-valid.json: {e}")

        if local_dataset_exists:
            try:
                df = pl.read_csv(os.path.join("data", "dataset.csv"))
                df_local = df.unique(subset=["URL"])
                for row in tqdm(df_local.iter_rows(named=True), desc="Loading dataset.csv", unit="url"):
                    if int(row['label']) == 0: # its phishing
                        url_1 = row['URL'].strip()
                        if url_1 in url_set:
                            continue
                        entry_list.append(UrlEntry(id=self.counter, url=url_1, data_type=DataType.PHISHING))
                        url_set.add(url_1)
                        self.counter += 1

                print(f"Loaded {len(entry_list)} phishing URLs from local dataset.csv")
            except Exception as e:
                print(f"Error loading dataset.csv: {e}")

        return entry_list

    def __get_benign_data(self) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        
        if os.path.exists('data/benign.json'):
            try:
                with open('data/benign.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    record = json.loads(item)
                    url_1 = record.get("url") 

                    if not url_1:
                        continue

                    entry_list.append(UrlEntry(id=record.get("id"), url=url_1, data_type=DataType.BENIGN))

                print(f"Loaded {len(entry_list)} benign URLs from local benign.json")
                return entry_list
            except Exception as e:
                print(f"Error loading local benign.json: {e}")
        
        try:
            with open('data/non_spam_url_filtered.txt', 'r') as file:
                for line in file:
                    url_1 = line.strip()
                    if url_1:  # Skip empty lines
                        url_entry = UrlEntry(id=self.counter, url=url_1, data_type=DataType.BENIGN)
                        entry_list.append(url_entry)
                        self.counter += 1
            print(f"Loaded {len(entry_list)} benign URLs from local file")
        except Exception as e:
            print(f"Error loading non_spam_url_filter.txt: {e}")
        
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
        spam_list: list[UrlEntry] = self.__get_phishtank_data()
        benign_list: list[UrlEntry] = self.__get_benign_data()

        data_dir = self.__get_project_root() / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        if not os.path.exists(data_dir / "spam.json"):
            with open(data_dir / "spam.json", "w", encoding="utf-8") as f:
                json.dump([e.model_dump_json() for e in spam_list], f, indent=2)

        if not os.path.exists(data_dir / "benign.json"):
            with open(data_dir / "benign.json", "w", encoding="utf-8") as f:
                json.dump([e.model_dump_json() for e in benign_list], f, indent=2)

        self.dataset: list[UrlEntry] = spam_list + benign_list
        
        print(f"\n=== Dataset Loaded ===")
        print(f"Total URLs: {len(self.dataset)}")
        print(f"Phishing URLs: {len(spam_list)}")
        print(f"Benign URLs: {len(benign_list)}")

    def check_url_duplicates(self) -> None:

        phishing_urls = [e.url for e in self.dataset if e.data_type == DataType.PHISHING]
        benign_urls = [e.url for e in self.dataset if e.data_type == DataType.BENIGN]

        phishing_set = set(phishing_urls)
        benign_set = set(benign_urls)

        # Internal duplicates
        phishing_dupes = len(phishing_urls) - len(phishing_set)
        benign_dupes = len(benign_urls) - len(benign_set)

        # Cross-class overlap
        cross_overlap = phishing_set.intersection(benign_set)

        # Report
        print("\n=== URL Duplication Report ===")
        print(f"Total phishing URLs: {len(phishing_urls)}")
        print(f"Unique phishing URLs: {len(phishing_set)}")
        print(f"Duplicate phishing URLs: {phishing_dupes}\n")

        print(f"\nTotal benign URLs: {len(benign_urls)}")
        print(f"Unique benign URLs: {len(benign_set)}")
        print(f"Duplicate benign URLs: {benign_dupes}")

        # Print duplicates if any
        if benign_dupes > 0:
            print("\nWARNING Example duplicate benign URLs:")
            seen = set()
            for url in benign_urls:
                if url in seen:
                    print(f"  - {url}")
                else:
                    seen.add(url)

        print(f"\nCross-class overlaps (phishing == benign): {len(cross_overlap)}")

        if cross_overlap:
            print("\nWARNING Example overlapping URLs:")
            for url in list(cross_overlap)[:10]:
                print(f"  - {url}")

        return cross_overlap

    def split_train_eval(
        self,
        train_percentage: float = 0.8
    ) -> tuple[list[UrlEntry], list[UrlEntry]]:

        if not 0 < train_percentage < 1:
            raise ValueError("train_percentage must be between 0 and 1")

        cross_overlaps = self.check_url_duplicates()
        if cross_overlaps:
            self.dataset = [
                e for e in self.dataset
                if not (e.url in cross_overlaps and e.data_type == DataType.BENIGN)
            ]
            print(f"Removed {len(cross_overlaps)} overlapping URLs from benign class.")

        # Separate by class
        phishing_entries = [e for e in self.dataset if e.data_type == DataType.PHISHING]
        benign_entries = [e for e in self.dataset if e.data_type == DataType.BENIGN]

        # Shuffle each class independently
        random.shuffle(phishing_entries)
        random.shuffle(benign_entries)

        # Compute split sizes
        phishing_train_size = int(len(phishing_entries) * train_percentage)
        benign_train_size = int(len(benign_entries) * train_percentage)

        # Split each class
        phishing_train = phishing_entries[:phishing_train_size]
        phishing_eval = phishing_entries[phishing_train_size:]

        benign_train = benign_entries[:benign_train_size]
        benign_eval = benign_entries[benign_train_size:]

        # Combine classes
        train_dataset = phishing_train + benign_train
        eval_dataset = phishing_eval + benign_eval

        # Final shuffle so model doesn't see ordered classes
        random.shuffle(train_dataset)
        random.shuffle(eval_dataset)

        # Safety check: ensure no overlap
        train_urls = {e.url for e in train_dataset}
        eval_urls = {e.url for e in eval_dataset}

        if train_urls & eval_urls:
            raise RuntimeError("Train and evaluation datasets overlap!")

        print("\n=== Dataset Split ===")
        print(f"Train size: {len(train_dataset)}")
        print(f"  Phishing: {len(phishing_train)} | Benign: {len(benign_train)}")
        print(f"Eval size: {len(eval_dataset)}")
        print(f"  Phishing: {len(phishing_eval)} | Benign: {len(benign_eval)}")

        return train_dataset, eval_dataset