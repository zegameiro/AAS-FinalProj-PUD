from pydantic import BaseModel,HttpUrl
from enum import Enum
import requests
import os
from io import StringIO
import polars as pl

SPAM_URL = "http://data.phishtank.com/data/online-valid.csv"
BENIGN_URL = "https://downloads.majestic.com/majestic_million.csv"

class DataType(Enum):
    PHISHING = "phishing"
    BENIGN = "Benign"

class UrlEntry(BaseModel):
    url: str
    data_type: DataType

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
        for entry in df.iter_rows(named=True):
            entry_url = entry["url"]
            url_entry = UrlEntry(url=entry_url,data_type=DataType.PHISHING)
            entry_list.append(url_entry)
        
        return entry_list

    def __getBenignData(self, url: str) -> list[UrlEntry]:
        entry_list: list[UrlEntry] = []
        data = requests.get(url)
        csv_data = StringIO(data.text)
        df = pl.read_csv(csv_data)

        for row in df.iter_rows(named=True):
            entry_url = row["Domain"]
            entry_url = "http://" + entry_url
            url_entry = UrlEntry(url=entry_url,data_type=DataType.PHISHING)
            entry_list.append(url_entry)
        
        return entry_list

    def getData(self) -> None:
        spam_list: list[UrlEntry] = self.__getPhishTankData(SPAM_URL)
        benign_list: list[UrlEntry] = self.__getBenignData(BENIGN_URL)

        self.dataset: list[UrlEntry] = spam_list + benign_list



