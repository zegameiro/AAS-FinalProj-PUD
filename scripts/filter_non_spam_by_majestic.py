import csv
from urllib.parse import urlparse
from tqdm import tqdm

def get_domain_from_url(url):
    """
    Extracts the hostname (e.g. developers.minds.com) from a URL.
    """
    # Note: We strip inside the loop now to handle the 'seen' check earlier
    if not url:
        return ""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""

def is_domain_or_subdomain_in_set(url_domain, reference_set):
    """
    Efficiently checks if url_domain or any of its parent domains 
    exist in the reference_set using suffix matching.
    """
    if not url_domain:
        return False
        
    parts = url_domain.split('.')
    
    # range(0, len(parts) - 1) ensures we don't check the TLD alone (e.g. 'com')
    # Loop example for 'developers.minds.com':
    # 1. checks 'developers.minds.com'
    # 2. checks 'minds.com'
    for i in range(len(parts) - 1):
        sub_to_check = ".".join(parts[i:])
        if sub_to_check in reference_set:
            return True
            
    return False

def filter_by_domain(csv_path, check_file_path):
    reference_domains = set()
    
    # 1. Load Reference Domains
    print("Loading reference domains...")
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 3:
                domain = row[2].strip().lower()
                reference_domains.add(domain)
                
    print(f"Loaded {len(reference_domains)} unique reference domains.")

    # 2. Process URLs
    print("Checking file...")
    matches = []
    seen_urls = set()  # OPTIMIZATION: Tracks duplicates
    
    with open(check_file_path, 'r', encoding='utf-8') as f:
        for line in tqdm(f, desc="Processing lines"):
            line = line.strip()
            
            # Basic validation
            if not line or not line.startswith("http"):
                continue

            # OPTIMIZATION: Check for duplicates immediately
            if line in seen_urls:
                continue
            seen_urls.add(line)
            
            # Extract domain
            url_domain = get_domain_from_url(line)
            
            # Check against database
            if is_domain_or_subdomain_in_set(url_domain, reference_domains):
                matches.append(line)
            else:
                # Performance Note: Avoid printing every mismatch if the file is large.
                # It slows down processing significantly.
                # print(f"No match for: {line}") 
                pass

    print(f"Found {len(matches)} unique matches.")
    
    # 3. Write results
    output_file = 'data/non_spam_url_filtered.txt'
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write('\n'.join(matches))
    print(f"Saved results to {output_file}")
        
    return matches

if __name__ == "__main__":
    # improved robustness for file paths
    try:
        filter_by_domain('data/majestic_million.csv', 'data/non_spam_urls.txt')
    except FileNotFoundError as e:
        print(f"Error: Could not find file - {e}")