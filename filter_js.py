
with open("data/non_spam_urls.txt","r") as f:
    with open("data/non_spam_url_filter.txt","w") as output:
        for line in f:
            if line.startswith("http"):
                output.write(line)
