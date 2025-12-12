from urllib.parse import urlparse
from src.constants import * 
import numpy as np
import re
from tqdm import tqdm

class URLFeatureExtractor:
    """Extract lexical features from URLs for phishing detection."""

    def extract_features(self, url: str) -> dict[str, int]:
        """Extract all lexical features from a given URL."""

        features: dict[str, int] = {}

        for key, char in URL_PROPERTIES.items():
            features[key] = url.count(char)

        # Digit counts
        for c in url:
            if c.isdigit():
                features['digit_count'] = features.get('digit_count', 0) + 1
            elif c.isalpha():
                features['letter_count'] = features.get('letter_count', 0) + 1

        if 'digit_count' not in features:
            features['digit_count'] = 0
        if 'letter_count' not in features:
            features['letter_count'] = 0

        # Entropy Calculation
        features['entropy'] = self._calculate_entropy(url)

        # Subdomain count
        domain = urlparse(url).netloc
        features['subdomain_count'] = domain.count('.') - 1 if domain else 0

        # Protocol features
        features['has_https'] = int(url.startswith('https://'))
        features['has_http'] = int(url.startswith('http://'))

        # IP address in URL
        features['has_ip'] = int(self._has_ip_address(domain))

        # Suspicious words
        url_lower = url.lower()
        features['suspicious_word_count'] = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)

        # Double slash in path
        features['double_slash_in_path'] = 1 if '//' in urlparse(url).path else 0

        # Length ratios
        if features['url_length'] > 0:
            features['digit_ratio'] = features['digit_count'] / features['url_length']
            features['letter_ratio'] = features['letter_count'] / features['url_length']
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0

        # Domain token length
        domain_tokens = domain.split('.')
        features['avg_domain_token_length'] = np.mean([len(t) for t in domain_tokens]) if domain_tokens else 0
        features['max_domain_token_length'] = max([len(t) for t in domain_tokens]) if domain_tokens else 0

        # Path token length
        path_tokens = [t for t in urlparse(url).path.split('/') if t]
        features['path_token_count'] = len(path_tokens)
        features['avg_path_token_length'] = np.mean([len(t) for t in path_tokens]) if path_tokens else 0
        
        # Longest word length
        words = re.findall(r'[a-zA-Z]+', url)
        features['longest_word_length'] = max([len(w) for w in words]) if words else 0
        features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
        
        # Homoglyph detection (IDN homograph attack)
        features['homoglyph_count'] = self._count_homoglyphs(url)
        features['has_homoglyphs'] = 1 if features['homoglyph_count'] > 0 else 0
        features['non_ascii_count'] = sum(1 for c in url if ord(c) > 127)
        features['unicode_ratio'] = features['non_ascii_count'] / features['url_length'] if features['url_length'] > 0 else 0
        
        # Punycode detection (xn-- prefix indicates encoded international domain)
        features['has_punycode'] = 1 if 'xn--' in domain else 0
        
        # Mixed character sets (suspicious mixing)
        features['has_mixed_charset'] = 1 if self._has_mixed_charset(url) else 0

        return features

    def _count_homoglyphs(self, text):
        """Count suspicious homoglyph characters"""
        count = 0
        for char in text:
            if char in HOMOGLYPH_MAP:
                count += 1
        return count
    
    def _has_mixed_charset(self, text):
        """Detect mixing of different character sets (Latin, Cyrillic, Greek)"""
        has_latin = any('a' <= c.lower() <= 'z' for c in text)
        has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in text)
        has_greek = any('\u0370' <= c <= '\u03FF' for c in text)
        
        # Suspicious if mixing character sets
        charset_count = sum([has_latin, has_cyrillic, has_greek])
        return charset_count > 1

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain contains an IP address"""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(domain))
    
    def extract_features_batch(self, urls):
        """Extract features for multiple URLs"""
        return [self.extract_features(url) for url in tqdm(urls, desc="Extracting features", unit="url")]