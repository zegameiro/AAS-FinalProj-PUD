import asyncio
from crawlee.crawlers import PlaywrightCrawler
from crawlee.configuration import Configuration
from urllib.parse import urlparse
from datetime import timedelta
from src.models import UrlEntry
import json

MAX_DEPTH = 3
allowed_domains = {
    "wikipedia.org",
    "bbc.com",
    "nytimes.com",
    "harvard.edu",
    "who.int",
}

collected_urls = set()

def is_allowed(url: str) -> bool:
    try:
        domain = urlparse(url).netloc
        return any(domain.endswith(d) for d in allowed_domains)
    except:
        return False

async def main():
    with open("data/benign.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    # urls = [UrlEntry(**item).url for item in data]
    urls = [UrlEntry(**json.loads(item)).url for item in data]

    crawler = PlaywrightCrawler(
        max_requests_per_crawl=5000,
        request_handler_timeout=timedelta(seconds=30),
        configuration=Configuration(disable_browser_sandbox=True)
    )

    @crawler.router.default_handler
    async def handle(context):
        url = context.request.url
        print("Crawled:", url)

        # Extract links
        links = await context.page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => e.href)"
        )
        with open("/app/data/non_spam_urls.txt", "a") as f:
            last = ""
            for u in links:
                if u != last:
                    f.write(u + "\n")
                last = u

    await crawler.run(urls)

asyncio.run(main())

