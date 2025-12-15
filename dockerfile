FROM mcr.microsoft.com/playwright/python:v1.56.0-noble

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock ./

RUN pip install --no-cache-dir crawlee playwright

RUN pip install uv && uv sync

RUN python -m playwright install chromium

COPY . .

CMD ["uv", "run", "crawl.py"]
