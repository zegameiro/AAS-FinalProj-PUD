from src.models import DataType,UrlEntry
import requests
import os
from io import StringIO
from tqdm import tqdm
import polars as pl
import json
from pathlib import Path

SPAM_URL = "http://data.phishtank.com/data/online-valid.csv"
BENIGN_URL = "https://downloads.majestic.com/majestic_million.csv"

class DatasetLoader:
    dataset_present = False
    dataset: list[UrlEntry]

    def __init__(self):
        if os.path.isdir("data"):
            self.dataset_present = True
        self.getData()

    def __getPhishTankData(self, url: str) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        data = requests.get(url)
        csv_data = StringIO(data.text)
        df = pl.read_csv(csv_data)
        for entry in tqdm(df.iter_rows(named=True), desc="Loading PhishTank data", unit="url"):
            entry_url = entry["url"]
            url_entry = UrlEntry(url=entry_url,data_type=DataType.PHISHING)
            entry_list.append(url_entry)
        
        return entry_list

    def __getBenignData(self, url: str) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        data = requests.get(url)
        csv_data = StringIO(data.text)
        df = pl.read_csv(csv_data)

        for row in tqdm(df.iter_rows(named=True), desc="Loading Benign data", unit="url"):
            entry_url = row["Domain"]
            entry_url = "https://" + entry_url
            url_entry = UrlEntry(url=entry_url,data_type=DataType.BENIGN)
            entry_list.append(url_entry)
        
        return entry_list
    
    def __get_project_root(self) -> Path:
        p = Path(__file__).resolve()
        for parent in p.parents:
            if (parent / "pyproject.toml").exists():
                return parent
        raise RuntimeError("Project root not found")

    def getData(self) -> None:
        spam_list: list[UrlEntry] = self.__getPhishTankData(SPAM_URL)
        benign_list: list[UrlEntry] = self.__getBenignData(BENIGN_URL)

        data_dir = self.__get_project_root() / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        with open(data_dir / "spam.json", "w", encoding="utf-8") as f:
            json.dump([e.model_dump_json() for e in spam_list], f, indent=2)

        with open(data_dir / "benign.json", "w", encoding="utf-8") as f:
            json.dump([e.model_dump_json() for e in benign_list], f, indent=2)

        self.dataset: list[UrlEntry] = spam_list + benign_list

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



