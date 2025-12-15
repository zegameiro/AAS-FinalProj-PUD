import asyncio
from crawlee.crawlers import PlaywrightCrawler
from crawlee.configuration import Configuration
from urllib.parse import urlparse
from datetime import timedelta

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

        for link in links:
            if is_allowed(link):
                # Add to crawl queue in Python Crawlee
                # await context.crawl_queue.add(link)
                collected_urls.add(link)

    await crawler.run([
        "https://www.wikipedia.org",
        "https://www.bbc.com",
        "https://www.nytimes.com",
    ])

    # Save dataset
    with open("non_spam_urls.txt", "w") as f:
        for u in sorted(collected_urls):
            f.write(u + "\n")
            print(u)

asyncio.run(main())

