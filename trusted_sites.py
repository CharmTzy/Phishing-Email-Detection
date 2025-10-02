import pandas as pd
import re
from collections import defaultdict
import tldextract

def normalize_domain(domain):
    """Return base domain (eTLD+1) like 'linux.ie' from 'www.linux.ie'."""
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return domain.lower()

def extract_domains(text):
    """Extract domains from URLs and email addresses, normalized to base domain"""
    if pd.isna(text) or not text:
        return []
    
    domains = []
    
    # Extract from URLs
    url_pattern = r'https?://([^/\s,]+)'
    url_matches = re.findall(url_pattern, str(text), re.IGNORECASE)
    domains.extend([normalize_domain(d) for d in url_matches])
    
    # Extract from email addresses
    email_pattern = r'[\w.-]+@([\w.-]+\.\w+)'
    email_matches = re.findall(email_pattern, str(text), re.IGNORECASE)
    domains.extend([normalize_domain(d) for d in email_matches])
    
    return domains

def calculate_legitimacy_score(domain_stats):
    """Calculate legitimacy score for a domain (0-100)"""
    score = 50  # Start neutral
    
    # Known legitimate domains (tech, open source, academic)
    known_legit = [
        'sourceforge.net', 'linux.ie', 'slashnull.org', 'github.com',
        'microsoft.com', 'google.com', 'apache.org', 'kernel.org',
        'gnu.org', 'debian.org', 'ubuntu.com', 'redhat.com'
    ]
    
    if any(legit in domain_stats['domain'] for legit in known_legit):
        score += 40
    
    # Spam indicators
    spam_indicators = [
        'geocities.com', 'mailexcite.com', 'hotmail.com',
        'aol.com', 'free', 'promo', 'deal'
    ]
    
    if any(spam in domain_stats['domain'] for spam in spam_indicators):
        score -= 30
    
    # More legitimate emails (ham) than spam
    if domain_stats['in_ham'] > domain_stats['in_spam']:
        score += 25
    elif domain_stats['in_spam'] > domain_stats['in_ham']:
        score -= 25
    
    # Single occurrence in spam is suspicious
    if domain_stats['count'] == 1 and domain_stats['in_spam'] == 1:
        score -= 20
    
    # Domain TLD characteristics
    if re.search(r'\.(org|edu|gov)$', domain_stats['domain']):
        score += 15
    
    # Commercial domains in legitimate context
    if re.search(r'\.(com|net)$', domain_stats['domain']) and domain_stats['in_ham'] > 0:
        score += 5
    
    return max(0, min(100, score))

def analyze_domains(csv_file):
    """Main function to analyze domains from CSV"""
    
    df = pd.read_csv(csv_file)
    
    # Dictionary to store domain statistics
    domain_stats = defaultdict(lambda: {
        'domain': '',
        'count': 0,
        'in_spam': 0,
        'in_ham': 0,
        'sources': set()
    })
    
    # Analyze each row
    for idx, row in df.iterrows():
        label = str(row['label'])
        
        # Extract domains from multiple fields
        all_domains = []
        all_domains.extend(extract_domains(row.get('urls', '')))
        all_domains.extend(extract_domains(row.get('body', '')))
        all_domains.extend(extract_domains(row.get('from', '')))
        all_domains.extend(extract_domains(row.get('to', '')))
        
        # Remove duplicates
        unique_domains = set(all_domains)
        
        for domain in unique_domains:
            if domain:
                stats = domain_stats[domain]
                stats['domain'] = domain
                stats['count'] += 1
                
                if label == '1':
                    stats['in_spam'] += 1
                else:
                    stats['in_ham'] += 1
                
                # Store source field
                if row.get('from') and domain in str(row.get('from')):
                    stats['sources'].add('from')
                if row.get('urls') and domain in str(row.get('urls')):
                    stats['sources'].add('urls')
    
    # Calculate legitimacy scores
    results = []
    for domain, stats in domain_stats.items():
        score = calculate_legitimacy_score(stats)
        results.append({
            'domain': stats['domain'],
            'legitimacy_score': score,
            'total_occurrences': stats['count'],
            'in_spam': stats['in_spam'],
            'in_ham': stats['in_ham'],
            'sources': ', '.join(sorted(stats['sources'])),
            'category': 'legitimate' if score >= 70 else ('uncertain' if score >= 40 else 'spam')
        })
    
    # Sort by legitimacy score
    results.sort(key=lambda x: x['legitimacy_score'], reverse=True)
    
    return pd.DataFrame(results)

def get_legitimate_domains(csv_file, threshold=70):
    """Extract only legitimate domains above threshold"""
    all_domains = analyze_domains(csv_file)
    legitimate = all_domains[all_domains['legitimacy_score'] >= threshold]
    return legitimate

def getSiteList(filepath="legitimate_domains.csv"):
    """
    Load trusted domains dynamically from the legitimacy analysis output.
    """
    df = pd.read_csv(filepath)
    # Just return the list of domains
    return df['domain'].tolist()

def extract_email_domain(sender):
    """
    Extract domain from email address like 'Name <user@example.com>'
    """
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender)
    if match:
        return match.group(1).lower()
    return None

# Main execution
if __name__ == "__main__":
    # Analyze the dataset
    csv_file = "Datasets/cleaned_SA.csv" 
    
    print("Analyzing domains...")
    results = analyze_domains(csv_file)
    
    # Display all results
    print("\n=== All Domains (sorted by legitimacy) ===")
    print(results.to_string(index=False))
    
    # Get legitimate domains only
    legitimate_domains = get_legitimate_domains(csv_file, threshold=70)
    
    print("\n\n=== LEGITIMATE DOMAINS (Score >= 70) ===")
    print(legitimate_domains.to_string(index=False))
    
    # Save to CSV
    results.to_csv('domain_analysis_full.csv', index=False)
    legitimate_domains.to_csv('legitimate_domains.csv', index=False)
    
    print(f"\n\nTotal domains analyzed: {len(results)}")
    print(f"Legitimate domains found: {len(legitimate_domains)}")
    print(f"\nResults saved to:")
    print("  - domain_analysis_full.csv")
    print("  - legitimate_domains.csv")
    
    # Print legitimate domain list
    print("\n=== Legitimate Domain List ===")
    for domain in legitimate_domains['domain'].values:
        print(f"  • {domain}")

