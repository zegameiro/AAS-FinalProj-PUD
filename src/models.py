from pydantic import BaseModel
from enum import Enum


class DataType(Enum):
    PHISHING = "phishing"
    BENIGN = "Benign"

class UrlEntry(BaseModel):
    url: str
    data_type: DataType