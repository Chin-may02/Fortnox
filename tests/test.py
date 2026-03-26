import pandas as pd
import numpy as np
from collections import Counter
import re
import os

def diagnose_dataset(csv_file):
    """Comprehensive dataset diagnosis to identify labeling issues"""
    
    print("=" * 60)
    print("PHISHING DATASET DIAGNOSTIC REPORT")
    print("=" * 60)
    
    try:
        df = pd.read_csv(csv_file)
        print(f"✓ Dataset loaded successfully: {len(df)} total records")
    except FileNotFoundError:
        print(f"❌ ERROR: File '{csv_file}' not found!")
        return
    except Exception as e:
        print(f"❌ ERROR loading file: {e}")
        return
    
    print(f"\nColumns: {list(df.columns)}")
    print(f"Missing values: {df.isnull().sum().sum()}")
    
    print(f"\n📊 LABEL DISTRIBUTION:")
    label_counts = df['Label'].value_counts()
    print(label_counts)
    print(f"Balance ratio: {label_counts.min()}/{label_counts.max()} = {label_counts.min()/label_counts.max():.3f}")
    
    print(f"\n🔍 SUSPICIOUS LABELING ANALYSIS:")
    
    legitimate_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 
        'apple.com', 'youtube.com', 'wikipedia.org', 'github.com',
        'stackoverflow.com', 'reddit.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'netflix.com', 'paypal.com', 'ebay.com',
        'claude.ai', 'openai.com', 'anthropic.com'
    ]
    
    mislabeled_legit = []
    for domain in legitimate_domains:
        matches = df[df['URL'].str.contains(domain, case=False, na=False)]
        bad_matches = matches[matches['Label'] == 'bad']
        if len(bad_matches) > 0:
            mislabeled_legit.extend(bad_matches['URL'].tolist())
    
    if mislabeled_legit:
        print(f"❌ CRITICAL: Found {len(mislabeled_legit)} legitimate domains labeled as 'bad':")
        for url in mislabeled_legit[:10]:
            print(f"   • {url}")
        if len(mislabeled_legit) > 10:
            print(f"   ... and {len(mislabeled_legit) - 10} more")
        print("   THIS IS WHY YOUR MODEL IS BROKEN!")
    else:
        print("✓ No obvious legitimate domains found in 'bad' labels")
    
    print(f"\n📈 URL PATTERN ANALYSIS:")
    
    good_urls = df[df['Label'] == 'good']['URL']
    bad_urls = df[df['Label'] == 'bad']['URL']
    
    good_lengths = good_urls.str.len()
    bad_lengths = bad_urls.str.len()
    
    print(f"Good URLs - Avg length: {good_lengths.mean():.1f}, Median: {good_lengths.median():.1f}")
    print(f"Bad URLs - Avg length: {bad_lengths.mean():.1f}, Median: {bad_lengths.median():.1f}")
    
    good_with_protocol = sum(1 for url in good_urls if any(p in str(url).lower() for p in ['http://', 'https://']))
    bad_with_protocol = sum(1 for url in bad_urls if any(p in str(url).lower() for p in ['http://', 'https://']))
    
    print(f"Good URLs with protocol: {good_with_protocol}/{len(good_urls)} ({good_with_protocol/len(good_urls)*100:.1f}%)")
    print(f"Bad URLs with protocol: {bad_with_protocol}/{len(bad_urls)} ({bad_with_protocol/len(bad_urls)*100:.1f}%)")
    
    if good_with_protocol == 0 and bad_with_protocol == 0:
        print("ℹ️ INFO: Dataset contains URLs without protocols (http/https) - this is normal")
    
    print(f"\n🌐 DOMAIN ANALYSIS:")
    
    def extract_domain(url):
        try:
            if 'http' not in url:
                url = 'http://' + url
            from urllib.parse import urlparse
            return urlparse(url).netloc.lower()
        except:
            return url.split('/')[0].lower()
    
    good_domains = [extract_domain(url) for url in good_urls if pd.notna(url)]
    bad_domains = [extract_domain(url) for url in bad_urls if pd.notna(url)]
    
    print("Top 10 domains labeled as 'good':")
    good_domain_counts = Counter(good_domains)
    for domain, count in good_domain_counts.most_common(10):
        print(f"   {domain}: {count}")
    
    print("\nTop 10 domains labeled as 'bad':")
    bad_domain_counts = Counter(bad_domains)
    for domain, count in bad_domain_counts.most_common(10):
        print(f"   {domain}: {count}")
    
    good_set = set(good_domains)
    bad_set = set(bad_domains)
    conflicting = good_set.intersection(bad_set)
    
    if conflicting:
        print(f"\n❌ CRITICAL: {len(conflicting)} domains appear in BOTH 'good' and 'bad' categories:")
        for domain in list(conflicting)[:10]:
            good_count = good_domain_counts[domain]
            bad_count = bad_domain_counts[domain]
            print(f"   {domain}: {good_count} good, {bad_count} bad")
        print("   This indicates severe labeling inconsistency!")
    
    print(f"\n🔍 SAMPLE ANALYSIS:")
    print("Sample 'good' URLs:")
    for url in good_urls.head(5):
        print(f"   ✓ {url}")
    
    print("\nSample 'bad' URLs:")
    for url in bad_urls.head(5):
        print(f"   ❌ {url}")
    
    print(f"\n💡 RECOMMENDATIONS:")
    if mislabeled_legit:
        print("1. ❌ URGENT: Your dataset has severe labeling errors")
        print("2. 🔄 Clean the dataset or use a different, verified dataset")
        print("3. 🚫 Do NOT use this dataset for training until fixed")
    else:
        print("1. ✓ No obvious mislabeling detected")
        print("2. 📊 Check if the dataset is balanced and representative")
    
    print("\n🔗 Suggested verified datasets:")
    print("   • PhishTank (phishtank.com)")
    print("   • UCI Phishing Websites Dataset")
    print("   • Kaggle verified phishing datasets")
    
    return df

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, '..', 'data')
    raw_csv = os.path.join(data_dir, 'phishing_site_urls.csv')
    cleaned_csv = os.path.join(data_dir, 'phishing_site_urls_cleaned.csv')

    df = diagnose_dataset(raw_csv)
    
    print(f"\n🧹 CLEANING SUGGESTIONS:")
    print("Run this code to create a cleaned dataset:")
    legitimate_patterns = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'youtube.com', 'wikipedia.org', 'github.com',
        'claude.ai', 'openai.com', 'anthropic.com'
    ]

    cleaned_df = df.copy()
    for pattern in legitimate_patterns:
        mask = ~(cleaned_df['URL'].str.contains(pattern, case=False, na=False) & 
                (cleaned_df['Label'] == 'bad'))
        cleaned_df = cleaned_df[mask]

    print(f"Original: {len(df)} rows")
    print(f"Cleaned: {len(cleaned_df)} rows")
    print(f"Removed: {len(df) - len(cleaned_df)} problematic entries")

    cleaned_df.to_csv(cleaned_csv, index=False)