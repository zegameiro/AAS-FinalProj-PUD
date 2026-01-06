from urllib.parse import urlparse
from src.constants import * 
import numpy as np
import re
from tqdm import tqdm
from collections import Counter

class URLFeatureExtractor:
    """Extract lexical features from URLs for phishing detection."""

    def extract_features(self, url: str) -> dict[str, int]:
        """Extract all lexical features from a given URL."""

        features: dict[str, int] = {}
        features['url_length'] = len(url)

        # Character counts
        for key, char in URL_PROPERTIES.items():
            features[key] = url.count(char)

        # Digit and letter counts
        features['digit_count'] = sum(1 for c in url if c.isdigit())
        features['letter_count'] = sum(1 for c in url if c.isalpha())
        features['uppercase_count'] = sum(1 for c in url if c.isupper())

        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Entropy Calculation
        features['entropy'] = self._calculate_entropy(domain)
        
        # Domain features
        dot_count = domain.count('.')
        features['subdomain_count'] = max(0, dot_count - 1) if dot_count > 0 else 0
        
        # Protocol features
        features['has_https'] = int(url.startswith('https://'))
        features['has_http'] = int(url.startswith('http://'))
        
        # IP address in URL
        features['has_ip'] = int(self._has_ip_address(domain))
        
        # Port number detection
        domain_parts = domain.split(':')
        features['has_port'] = int(len(domain_parts) > 1 and domain_parts[-1].isdigit())
        
        # TLD features
        tld = self._extract_tld(domain)
        features['has_suspicious_tld'] = int(any(tld.endswith(st) for st in SUSPICIOUS_TLDS))
        features['has_trusted_tld'] = int(any(tld.endswith(tt) for tt in TRUSTED_TLDS))
        features['tld_length'] = len(tld.replace('.', ''))

        # Suspicious words
        domain_lower = domain.lower()
        path_lower = path.lower()
        
        # Count in domain
        domain_suspicious = sum(2 for word in SUSPICIOUS_WORDS if word in domain_lower)
        # Count in path
        path_suspicious = sum(1 for word in SUSPICIOUS_WORDS if word in path_lower)
        
        features['suspicious_word_count'] = domain_suspicious + path_suspicious

        # Double slash in path
        features['double_slash_in_path'] = int('//' in path)

        # Length ratios
        if features['url_length'] > 0:
            features['digit_ratio'] = features['digit_count'] / features['url_length']
            features['letter_ratio'] = features['letter_count'] / features['url_length']
            features['special_char_ratio'] = (features['url_length'] - features['digit_count'] - features['letter_count']) / features['url_length']
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0
            features['special_char_ratio'] = 0

        # Domain token analysis
        domain_tokens = [t for t in domain.split('.') if t]
        features['domain_token_count'] = len(domain_tokens)
        features['avg_domain_token_length'] = np.mean([len(t) for t in domain_tokens]) if domain_tokens else 0
        features['max_domain_token_length'] = max([len(t) for t in domain_tokens]) if domain_tokens else 0

        # Path analysis - use ratios instead of absolute lengths
        path_tokens = [t for t in path.split('/') if t]
        features['path_token_count'] = len(path_tokens)
        features['avg_path_token_length'] = np.mean([len(t) for t in path_tokens]) if path_tokens else 0
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
        # Add ratio of path to total URL
        features['path_to_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0
        
        # Query string analysis
        features['query_length'] = len(query)
        features['query_param_count'] = query.count('&') + 1 if query else 0
        # Ratio of query to total URL
        features['query_to_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0
        # Domain length ratio
        features['domain_to_url_ratio'] = len(domain) / len(url) if len(url) > 0 else 0
        
        # Fragment presence
        features['has_fragment'] = int(bool(parsed.fragment))
        
        # Word analysis
        words = re.findall(r'[a-zA-Z]+', url)
        features['longest_word_length'] = max([len(w) for w in words]) if words else 0
        features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
        
        # Homoglyph detection
        features['homoglyph_count'] = self._count_homoglyphs(url)
        features['has_homoglyphs'] = int(features['homoglyph_count'] > 0)
        features['non_ascii_count'] = sum(1 for c in url if ord(c) > 127)
        features['unicode_ratio'] = features['non_ascii_count'] / features['url_length'] if features['url_length'] > 0 else 0
        
        # Punycode detection (xn-- prefix indicates encoded international domain)
        features['has_punycode'] = int('xn--' in domain)
        
        # Mixed character sets
        features['has_mixed_charset'] = int(self._has_mixed_charset(url))
        
        # URL encoding detection
        features['encoded_char_count'] = url.count('%')
        features['encoding_ratio'] = features['encoded_char_count'] / features['url_length'] if features['url_length'] > 0 else 0
        
        # Brand impersonation detection
        features['brand_in_subdomain'] = int(self._check_brand_in_subdomain(domain))
        features['brand_in_path'] = int(any(brand in path_lower for brand in KNOWN_BRANDS))
        features['levenshtein_to_brand'] = self._min_levenshtein_distance(domain)
        
        # URL shortener detection
        features['is_url_shortener'] = int(any(shortener in domain for shortener in URL_SHORTENERS))
        
        # Obfuscation patterns
        features['consecutive_consonants'] = self._max_consecutive_consonants(url)
        features['consecutive_digits'] = self._max_consecutive_digits(url)
        features['vowel_consonant_ratio'] = self._vowel_consonant_ratio(url)
        
        # Statistical features
        features['char_diversity'] = len(set(url)) / features['url_length'] if features['url_length'] > 0 else 0
        
        # Redirect indicators
        protocol_count = url.count('http://') + url.count('https://')
        features['redirect_count'] = max(0, protocol_count - 1)

        return features

    def _extract_tld(self, domain):
        """Extract TLD from domain (handles .co.uk, .com, etc.)"""
        if not domain:
            return ''
        # Remove port if present
        domain_clean = domain.split(':')[0]
        parts = domain_clean.split('.')
        
        if len(parts) < 2:
            return '.' + parts[-1] if parts else ''
        
        # Check for two-part TLDs like .co.uk, .com.br, .ac.uk
        if len(parts) >= 2 and len(parts[-1]) <= 3 and len(parts[-2]) <= 3:
            return '.' + '.'.join(parts[-2:])
        
        return '.' + parts[-1]

    def _check_brand_in_subdomain(self, domain):
        """Check if brand name appears in subdomain (phishing indicator)"""
        domain_lower = domain.lower()
        parts = domain_lower.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            return any(brand in subdomain for brand in KNOWN_BRANDS)
        return False

    def _min_levenshtein_distance(self, domain):
        """Calculate minimum Levenshtein distance to known brands"""
        if not domain:
            return 100
        
        # Extract domain name without TLD (e.g., 'google' from 'google.com')
        # Remove port first
        domain_clean = domain.split(':')[0]
        parts = domain_clean.split('.')
        
        # For multi-part TLDs (.co.uk), use the part before TLD
        if len(parts) >= 3 and len(parts[-1]) <= 3 and len(parts[-2]) <= 3:
            domain_name = parts[-3]  # e.g., 'example' from 'example.co.uk'
        elif len(parts) >= 2:
            domain_name = parts[-2]  # e.g., 'google' from 'google.com'
        else:
            domain_name = parts[0] if parts else ''
        
        # Clean and compare
        domain_name = re.sub(r'[^a-z]', '', domain_name.lower())
        if not domain_name:
            return 100
        
        min_dist = 100
        for brand in KNOWN_BRANDS:
            dist = self._levenshtein(domain_name, brand)
            if dist < min_dist:
                min_dist = dist
        return min_dist

    def _levenshtein(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def _max_consecutive_consonants(self, text):
        """Find maximum consecutive consonants (keyboard smashing indicator)"""
        consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
        max_count = 0
        current_count = 0
        for char in text:
            if char in consonants:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def _max_consecutive_digits(self, text):
        """Find maximum consecutive digits"""
        max_count = 0
        current_count = 0
        for char in text:
            if char.isdigit():
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def _vowel_consonant_ratio(self, text):
        """Calculate vowel to consonant ratio"""
        vowels = 'aeiouAEIOU'
        consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
        vowel_count = sum(1 for c in text if c in vowels)
        consonant_count = sum(1 for c in text if c in consonants)
        if consonant_count == 0:
            return 0
        return vowel_count / consonant_count

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
        """Calculate Shannon entropy of text (higher = more random/suspicious)"""
        if not text or len(text) == 0:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calculate probabilities and entropy
        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                prob = count / text_len
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain contains an IP address"""
        # Remove port if present
        domain_clean = domain.split(':')[0]
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
        return bool(ipv4_pattern.match(domain_clean) or ipv6_pattern.match(domain_clean))
    
    def extract_features_batch(self, urls):
        """Extract features for multiple URLs"""
        return [self.extract_features(url) for url in tqdm(urls, desc="Extracting features", unit="url")]