import re
from urllib.parse import urlparse, parse_qs
import ipaddress
import math

def calculate_tld_length(tld):
    return len(tld) if tld else 0

def get_tld(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-1]
    except:
        pass
    return ''

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    features = {}
    
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)
    
    features['IsDomainIP'] = 0
    try:
        ipaddress.ip_address(domain)
        features['IsDomainIP'] = 1
    except:
        pass
    
    features['TLD'] = get_tld(url)
    
    char_types = []
    prev_type = None
    for char in url:
        if char.isdigit():
            ctype = 'digit'
        elif char.isalpha():
            ctype = 'letter'
        else:
            ctype = 'special'
        if prev_type and prev_type != ctype:
            char_types.append(1)
        prev_type = ctype
    features['CharContinuationRate'] = sum(char_types) / (len(url) + 1)
    
    common_tlds = {'com': 0.95, 'org': 0.90, 'net': 0.88, 'edu': 0.85, 'gov': 0.90,
                   'io': 0.70, 'co': 0.75, 'info': 0.60, 'biz': 0.55, 'xyz': 0.50,
                   'tk': 0.30, 'ml': 0.25, 'ga': 0.25, 'cf': 0.25, 'gq': 0.20,
                   'top': 0.40, 'pw': 0.35, 'cc': 0.40, 'ru': 0.50, 'cn': 0.45}
    tld = get_tld(url).lower()
    features['TLDLegitimateProb'] = common_tlds.get(tld, 0.50)
    
    char_freq = {}
    for char in url:
        char_freq[char] = char_freq.get(char, 0) + 1
    features['URLCharProb'] = sum(v/len(url) for v in char_freq.values()) / (len(char_freq) + 1)
    
    features['TLDLength'] = calculate_tld_length(get_tld(url))
    
    features['NoOfSubDomain'] = max(0, domain.count('.') - 1)
    
    obfuscation_chars = ['%', '\\x', '&#']
    features['HasObfuscation'] = 1 if any(c in url for c in obfuscation_chars) else 0
    features['NoOfObfuscatedChar'] = sum(url.count(c) for c in obfuscation_chars)
    features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / (len(url) + 1)
    
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / (len(url) + 1)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / (len(url) + 1)
    
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    
    other_special = sum(1 for c in url if not c.isalnum() and c not in '=&?')
    features['NoOfOtherSpecialCharsInURL'] = other_special
    features['SpacialCharRatioInURL'] = other_special / (len(url) + 1)
    
    features['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0
    
    lines = url.split('\n')
    features['LargestLineLength'] = max(len(line) for line in lines) if lines else 0
    
    features['HasTitle'] = 0
    features['DomainTitleMatchScore'] = 0.5
    features['URLTitleMatchScore'] = 0.5
    features['HasFavicon'] = 0
    features['Robots'] = 1
    features['IsResponsive'] = 1
    features['NoOfURLRedirect'] = url.count('redirect=') + url.lower().count('redirect')
    features['NoOfSelfRedirect'] = 0
    features['HasDescription'] = 1
    features['NoOfPopup'] = 0
    features['NoOfiFrame'] = 0
    features['HasExternalFormSubmit'] = 0
    features['HasSocialNet'] = 1
    features['HasSubmitButton'] = 1
    features['HasHiddenFields'] = 0
    
    features['HasPasswordField'] = 1 if 'password' in url.lower() else 0
    
    features['Bank'] = 1 if any(w in url.lower() for w in ['bank', 'banking', 'wellsfargo', 'chase', 'citi', 'capitalone', 'usbank']) else 0
    features['Pay'] = 1 if any(w in url.lower() for w in ['paypal', 'payment', 'pay', 'checkout', 'stripe', 'square']) else 0
    features['Crypto'] = 1 if any(w in url.lower() for w in ['crypto', 'bitcoin', 'btc', 'ethereum', 'wallet', 'binance']) else 0
    
    features['HasCopyrightInfo'] = 1
    features['NoOfEmptyRef'] = 0
    
    return features

def get_feature_vector(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    features = extract_features(url)
    
    valid_tlds = ['100', '101', '103', '106', '107', '108', '110', '111', '116',
       '117', '12', '120', '123', '125', '126:8080', '128', '13', '130',
       '133:8080', '134', '136', '140', '145', '146', '148', '150', '154',
       '155', '158', '160', '161', '162', '163', '165', '166', '167',
       '171', '173', '177', '178', '181', '182', '184', '185',
       '188:10003', '189', '196', '197', '198', '199', '20', '203', '206',
       '21', '210', '211', '211:8383', '214', '220', '222', '223', '225',
       '231', '232', '233', '234', '235', '237', '238', '24', '240',
       '240:8087', '242', '243', '249:8080', '252', '254:30332', '26',
       '27', '30', '33', '38', '39', '41', '42', '47', '52', '63', '67',
       '68:8080', '69', '71', '78', '80', '80:8085', '84', '86', '87',
       '94', '95', 'ac', 'academy', 'ad', 'ae', 'aero', 'af', 'africa',
       'ag', 'agency', 'ai', 'al', 'am', 'amsterdam', 'ao', 'app', 'ar',
       'archi', 'art', 'as', 'asia', 'associates', 'at', 'au', 'audio',
       'autos', 'aw', 'ax', 'az', 'ba', 'band', 'bank', 'bar',
       'barcelona', 'basketball', 'bayern', 'bb', 'bd', 'be', 'beer',
       'berlin', 'best', 'bet', 'bf', 'bg', 'bh', 'bi', 'bid', 'bike',
       'bio', 'biz', 'blog', 'bm', 'bn', 'bo', 'bond', 'boutique', 'br',
       'bs', 'bt', 'build', 'builders', 'business', 'buzz', 'bw', 'by',
       'bz', 'ca', 'cab', 'cafe', 'cam', 'camera', 'camp', 'capital',
       'car', 'cards', 'care', 'careers', 'casa', 'cash', 'cat', 'cc',
       'cc:8443', 'cd', 'center', 'cern', 'cf', 'cfd', 'ch', 'chat',
       'church', 'ci', 'citic', 'city', 'ck', 'cl', 'cleaning', 'click',
       'clothing', 'cloud', 'club', 'cm', 'cn', 'co', 'coach', 'codes',
       'coffee', 'college', 'com', 'com:2096', 'com:443', 'com:9595',
       'community', 'company', 'condos', 'consulting', 'cool', 'coop',
       'corsica', 'cr', 'crs', 'cu', 'cv', 'cx', 'cy', 'cymru', 'cyou',
       'cz', 'date', 'de', 'dental', 'design', 'dev', 'diamonds',
       'digital', 'direct', 'dj', 'dk', 'dm', 'do', 'dog', 'download',
       'dz', 'earth', 'ec', 'eco', 'edu', 'education', 'ee', 'eg',
       'email', 'energy', 'es', 'et', 'eu', 'eus', 'events', 'exchange',
       'expert', 'express', 'farm', 'fashion', 'fi', 'film', 'finance',
       'fit', 'fitness', 'fj', 'fk', 'fm', 'fo', 'foundation', 'fr',
       'fr:443', 'fun', 'fund', 'ga', 'gal', 'gallery', 'game', 'games',
       'gay', 'gd', 'gdn', 'ge', 'gf', 'gg', 'gh', 'gi', 'gift', 'gives',
       'gl', 'gle', 'global', 'gmbh', 'golf', 'goog', 'google', 'gov',
       'gp', 'gq', 'gr', 'green', 'group', 'gs', 'gt', 'guide', 'guitars',
       'guru', 'gy', 'hair', 'hamburg', 'health', 'healthcare', 'help',
       'hk', 'hn', 'holdings', 'holiday', 'homes', 'host', 'hosting',
       'house', 'hr', 'ht', 'hu', 'icu', 'id', 'ie', 'il', 'im', 'immo',
       'in', 'industries', 'info', 'ink', 'institute', 'int',
       'international', 'io', 'iq', 'ir', 'is', 'ist', 'istanbul', 'it',
       'je', 'jm', 'jo', 'jobs', 'jp', 'ke', 'kg', 'kh', 'ki', 'kim',
       'kitchen', 'koeln', 'kr', 'krd', 'kred', 'kw', 'ky', 'kz', 'la',
       'land', 'lat', 'law', 'lb', 'lc', 'legal', 'lgbt', 'li', 'life',
       'lighting', 'limited', 'limo', 'link', 'live', 'lk', 'loan', 'lol',
       'london', 'love', 'lr', 'ls', 'lt', 'ltd', 'lu', 'lundbeck', 'lv',
       'ly', 'ma', 'madrid', 'market', 'marketing', 'markets', 'mba',
       'mc', 'md', 'me', 'media', 'menu', 'mg', 'mil', 'mk', 'ml', 'mm',
       'mma', 'mn', 'mo', 'mobi', 'moe', 'mom', 'money', 'monster',
       'moscow', 'movie', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum',
       'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nagoya', 'name', 'navy', 'nc',
       'net', 'network', 'neustar', 'news', 'nf', 'ng', 'ngo', 'ni',
       'ninja', 'nl', 'no', 'np', 'nr', 'nrw', 'ntt', 'nu', 'nyc', 'nz',
       'om', 'one', 'online', 'ooo', 'org', 'ovh', 'pa', 'page', 'paris',
       'party', 'pe', 'pet', 'pf', 'pg', 'ph', 'photo', 'photography',
       'photos', 'pics', 'pk', 'pl', 'place', 'plus', 'pm', 'pn', 'post',
       'press', 'pro', 'promo', 'ps', 'pt', 'pub', 'pw', 'py', 'qa',
       'quest', 'racing', 'radio', 're', 'red', 'rentals', 'repair',
       'report', 'rest', 'review', 'reviews', 'rip', 'ro', 'rocks', 'rs',
       'ru', 'rugby', 'ruhr', 'run', 'rw', 'sa', 'salon', 'sb', 'sbs',
       'sc', 'school', 'science', 'scot', 'sd', 'se', 'services', 'sexy',
       'sg', 'sh', 'shoes', 'shop', 'show', 'si', 'site', 'sk', 'ski',
       'skin', 'sm', 'sn', 'so', 'social', 'software', 'solutions', 'soy',
       'space', 'sport', 'sr', 'st', 'store', 'stream', 'studio', 'study',
       'su', 'supply', 'support', 'sv', 'sx', 'sy', 'systems', 'sz',
       'taipei', 'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'team', 'tech',
       'technology', 'tel', 'tf', 'tg', 'th', 'tips', 'tirol', 'tj', 'tk',
       'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'top', 'tours',
       'town', 'toys', 'tr', 'trade', 'training', 'travel', 'tt', 'tv',
       'tw', 'tz', 'ua', 'ug', 'uk', 'uno', 'us', 'uy', 'uz', 'va', 'vc',
       've', 'vegas', 'ventures', 'vet', 'vg', 'vi', 'video', 'vip',
       'vlaanderen', 'vn', 'vu', 'wales', 'watch', 'weber', 'website',
       'wiki', 'win', 'wine', 'work', 'works', 'world', 'ws', 'wtf',
       'xn--90ais', 'xn--c1avg', 'xn--mk1bu44c', 'xn--p1acf', 'xn--p1ai',
       'xyz', 'yachts', 'ye', 'yoga', 'youtube', 'yt', 'za', 'zm', 'zone',
       'zw']
    
    feature_order = [
        'URLLength', 'DomainLength', 'IsDomainIP', 'TLD', 'CharContinuationRate',
        'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 'NoOfSubDomain',
        'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
        'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
        'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
        'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS',
        'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore',
        'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive',
        'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup',
        'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
        'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto',
        'HasCopyrightInfo', 'NoOfEmptyRef'
    ]
    
    result = []
    for f in feature_order:
        if f == 'TLD':
            tld = features.get('TLD', '').lower()
            result.append(tld if tld in valid_tlds else 'com')
        else:
            result.append(features.get(f, 0))
    
    return result
