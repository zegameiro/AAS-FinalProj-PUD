SUSPICIOUS_WORDS = [
    'login', 'signin', 'account', 'update', 'verify', 'secure',
    'banking', 'confirm', 'password', 'admin', 'paypal', 'ebay'
]

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 
    'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
    'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'ӏ': 'l',
    
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'γ': 'y', 'δ': 'd', 'ε': 'e',
    'ζ': 'z', 'η': 'n', 'θ': 'o', 'ι': 'i', 'κ': 'k',
    'λ': 'l', 'μ': 'u', 'ν': 'v', 'ξ': 'e', 'ο': 'o',
    'π': 'n', 'ρ': 'p', 'σ': 'o', 'τ': 't', 'υ': 'u',
    'φ': 'f', 'χ': 'x', 'ψ': 'w', 'ω': 'w',
    
    # Numeric lookalikes
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't',
    
    # Special Unicode lookalikes
    'ℯ': 'e', 'ⅰ': 'i', 'ⅼ': 'l', 'ⅿ': 'm', 'ⅳ': 'iv',
    'ǝ': 'e', 'ɑ': 'a', 'ɔ': 'c', 'ɗ': 'd', 'ɛ': 'e',
    'ɡ': 'g', 'ɥ': 'h', 'ɪ': 'i', 'ʝ': 'j', 'ʞ': 'k',
    'ɯ': 'm', 'ɰ': 'm', 'ɴ': 'n', 'ɵ': 'o', 'ʀ': 'r',
    'ʂ': 's', 'ʇ': 't', 'ʋ': 'v', 'ʍ': 'w', 'ʏ': 'y',
    'ʐ': 'z',
    
    # Mathematical symbols
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e',
    '𝗮': 'a', '𝗯': 'b', '𝗰': 'c', '𝗱': 'd', '𝗲': 'e',
    '𝒂': 'a', '𝒃': 'b', '𝒄': 'c', '𝒅': 'd', '𝒆': 'e',
}

URL_PROPERTIES = {
    'url_length': '.',
    'dash_count': '-',
    'underscore_count': '_',
    'slash_count': '/',
    'question_count': '?',
    'equal_count': '=',
    'at_count': '@',
    'ampersand_count': '&',
    'exclamation_count': '!',
    'space_count': ' ',
    'tilde_count': '~',
    'comma_count': ',',
    'plus_count': '+',
    'asterisk_count': '*',
    'hash_count': '#',
    'dollar_count': '$',
    'percent_count': '%',
}