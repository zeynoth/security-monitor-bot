import requests
import logging
import schedule
import time
import random
import os
import json
from bs4 import BeautifulSoup
from telegram import Bot, InputMediaPhoto
from telegram.constants import ParseMode
from datetime import datetime
import pytz
from tqdm import tqdm
import colorlog
from pprint import pprint
from nitter_scraper import NitterScraper

# Configure logging with colorlog
log_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger()

# Set up colorlog for different log levels
log_handler = colorlog.StreamHandler()
log_handler.setFormatter(colorlog.ColoredFormatter(log_format))
logger.addHandler(log_handler)

# Set your Telegram bot token and chat ID and your Discord webhook URL
WEBHOOK_URL = os.getenv('WEBHOOK_URL') # Your Discord Webhook URL
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN') # Your Telegram Bot Token
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID') # Your Telegram Chat ID


# Hashtags for Medium, X (Twitter), and Reddit scraping
hashtags = [
    "owasp", "penetration-testing", "bug-hunting", "web-vulnerabilities", "xss", "sql-injection", 
    "appsec", "bug-bounty", "hacking", "cybersecurity", "infosec", "ethicalhacking", "redteam", 
    "blueTeam", "securityresearch", "vulnerability", "pentest", "hacker", "cyberattack", 
    "securecoding", "threatintelligence", "osint", "darkweb", "malware", "securityawareness", 
    "vuln", "exploit", "networksecurity", "privacy", "firewall", "encryption", "dataprotection", 
    "passwordsecurity", "zero-day", "ransomware", "phishing", "scada", "iotsecurity", 
    "cloudsecurity", "penetrationtesting", "cyberresilience", "ethicalhacker", "hackingtools", 
    "cyberdefense", "digitalforensics", "incidentresponse", "redteamers", "blueteamers", 
    "cve", "bugbountytips", "webappsecurity", "securitytesting", "malwareanalysis", "databreach", 
    "cryptography", "secops", "bughunter", "exploitdev", "exploitwriting", "payloads", 
    "networkpenetrationtesting", "applicationsecurity", "cyberwarfare", "informationsecurity", 
    "hackingnews", "securitybugs", "bountyhunter", "bugbountyprogram", "blackhat", 
    "defcon", "darknet", "socialengineering", "phishingattack", "cyberethics", "systemsecurity", 
    "dos", "ddos", "api-security", "secdevops", "webappvulns", "mobileappsecurity", 
    "cyberattackprevention", "penetrationtest", "firewallsecurity", "informationsharing", 
    "intrusiondetection", "networkdefense", "ciso", "infoseccommunity", "hackernews", 
    "ethicalhackers", "webpenetrationtesting", "securenetwork", "securityresearcher", "openbugbounty", 
    "exploitdevelopment", "websecurity", "bugbountytips", "datasecurity", "offensivecybersecurity", 
    "securitymonitoring", "cybersecurityawareness", "rce", "lfi", "sqli", "csrf", "xssattack", 
    "rcexploit", "path-traversal", "command-injection", "xssvulnerabilities", "csrfvulnerability", 
    "local-file-inclusion", "remote-code-execution", "sqliattack", "auth-bypass", "authz-bypass", 
    "insecure-deserialization", "xml-injection", "ddosvulnerability", "api-penetrationtesting", 
    "http-headers", "session-fixation", "subdomain-takeover", "buffer-overflow", "heap-spraying", 
    "smurf-attack", "bypass-csrf", "subdomain-enumeration", "reverse-shell", "webshell", 
    "hardening-web-apps", "insecure-http-methods", "dns-poisoning", "code-injection", "ntlm-relay", 
    "webshells", "os-command-injection", "access-control-issues", "ldap-injection", "api-vulnerabilities", 
    "input-validation", "broken-authentication", "broken-cryptography", "dns-spoofing", "iot-exploits", 
    "service-denial", "ssl-tls-vulnerabilities", "privilege-escalation", "race-condition", 
    "multi-factor-authentication", "security-headers", "remote-file-inclusion", "denial-of-service", 
    "brute-force-attack", "man-in-the-middle", "buffer-overflow-attack", "web-application-firewall", 
    "password-cracking", "keylogger", "insecure-encryption", "fuzz-testing", "sqlmap", "jwt-exploit", 
    "unauthorized-access", "debugging-flaws", "browser-hacking", "cookie-poisoning", "unauthenticated-access", 
    "information-leakage", "misconfigured-permissions", "command-injection-vulnerability", "clickjacking", 
    "cache-poisoning", "broken-links", "zombie-botnet", "trojan-horse", "ethical-hacker-tools", 
    "penetration-testing-tools", "file-upload-vulnerabilities", "timing-attack", "xsrf", "zip-slip", 
    "ajax-vulnerabilities", "unsafe-reflection", "session-fixation-attack", "server-side-request-forgery", 
    "csrf-attack", "spf-dkim-dmarc", "session-hijacking", "hmac", "sid-stealing", "spoofing-attack", 
    "cross-site-attack", "click-fraud", "client-side-injection", "cookie-hijacking", "mobile-vulnerabilities", 
    "mobile-phishing", "encrypted-traffic-hacking", "android-vulnerabilities", "ios-vulnerabilities", 
    "application-tampering", "web-app-attack", "mobile-app-attack", "web-app-bug-bounty", 
    "website-hacking", "browser-exploit", "xml-exploits", "dangerous-default-settings", 
    "botnet-attack", "sqli-payload", "unauthorized-privileges", "domain-spoofing", "script-injection", 
    "cross-origin-resource-sharing", "ssl-certificate-errors", "websocket-vulnerabilities", 
    "buffer-overflow-exploit", "toctou-attack", "time-based-sql-injection", "tcp-dump", "caching-vulnerabilities", 
    "app-vulnerability-scan", "security-lifecycle", "patch-management", "data-leakage", "poisoning-attack", 
    "phishing-scam", "ldap-attack", "protocol-vulnerabilities", "spoofing-defense", "stealth-hacking", 
    "internet-of-things-vulnerability", "iot-botnets", "smb-exploitation", "http-response-splitting", 
    "reverse-engineering-tools", "xss-exploit", "browser-exploits", "lfi-exploit", "api-fuzzing", 
    "automation-in-hacking", "elevation-of-privileges", "timing-analysis", "api-key-leakage", 
    "application-layer-attack", "buffer-exploit", "security-logging", "microservice-vulnerabilities", 
    "sensitive-data-exposure", "input-sanitization", "misconfigured-database", "persistent-xss", 
    "user-agent-manipulation", "dynamic-analysis", "python-exploit", "log-injection", "insecure-api", 
    "spike-detection", "active-directory-exploitation", "open-redirect", "json-injection", "excessive-logging", 
    "dns-rebinding", "caching-attack", "reverse-engineer", "clickjacking-protection", "parameter-pollution", 
    "api-bypass", "certificate-pinning", "java-deserialization", "whitelisting-bypass", 
    "cloud-misconfigurations", "external-service-interaction", "secret-management", "buffer-overflow-attack", 
    "restful-api-vulnerability", "cybersecurity-testing", "dns-dos", "over-the-air-exploits", "shellshock-exploit", 
    "bugbounty", "bugbountytips", "bughunter", "bugbountyhunter", "bugbountypost", "bugbountyhunting", 
    "bugbountytips", "bugbountylife", "bugbountyresearcher", "bugbountyprograms", "bugbountytutorial", 
    "bugbountyopportunity", "bugbountyreport", "bugbountysuccess", "bugbountyresources", "bugbountyexploit", 
    "bugbountyplatform", "bugbountykills", "bugbountytipsandtricks", "bugbountyninja", "bugbountyresearch", 
    "bugbountydiscovery", "bugbountytipsandtricks", "bugbountyhacker", "bugbountytools", "bugbountyscout", 
    "bugbountybug", "bugbountyvulnerability", "bugbountyhunter", "bugbountytutorial", "bugbountytips2025", 
    "bugbountyexploitdev", "bugbountysolutions", "bugbountystories", "bugbountytracking", "bugbountygrind", 
    "bugbountyplatforms", "bugbountysuccessstories", "bugbountylearning", "bugbountyhalloffame", 
    "bugbountysubmission", "bugbountyappsec", "bugbountytalk", "bugbountyresearcher", "bugbountymethods", 
    "bugbountyadvice", "bugbountyprogram", "bugbountystory", "bugbountyposts", "bugbountyeverywhere", 
    "bugbountytipsandtricks", "bugbountykills", "bugbountydiscovery", "bugbountyexploitdev", "bugbountyhacks"
]


# ASCII Art Options
ascii_art_options = [
    '''
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿
⣿⣿⡏⠁⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⣶⣶⣶⣶⣦⣤⡄⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿
⣿⣿⣷⣄⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡧⠇⢀⣤⣶⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣾⣮⣭⣿⡻⣽⣒⠀⣤⣜⣭⠐⢐⣒⠢⢰⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣏⣿⣿⣿⣿⣿⣿⡟⣾⣿⠂⢈⢿⣷⣞⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣷⣶⣾⡿⠿⣿⠗⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⠋⠉⠑⠀⠀⢘⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⠟⢹⣿⣿⡇⢀⣶⣶⠴⠶⠀⠀⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⡿⠀⠀⢸⣿⣿⠀⠀⠣⠀⠀⠀⠀⠀⡟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠹⣿⣧⣀⠀⠀⠀⠀⡀⣴⠁⢘⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿
⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⠗⠂⠄⠀⣴⡟⠀⠀⡃⠀⠉⠉⠟⡿⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠾⠛⠂⢹⠀⠀⠀⢡⠀⠀⠀⠀⠀⠙⠛⠿⢿

    '''
]

# Global variable to store URLs of the posts
stored_urls = set()

# Retry settings for request
MAX_RETRIES = 3
BACKOFF_TIME = 2  # seconds

# Set the timezone
TIMEZONE = pytz.timezone('UTC')

# Function to implement exponential backoff retries

def fetch_url(url, max_retries=5, backoff_factor=1.5):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; badass-bot/1.0)"
    }
    retries = 0
    
    while retries < max_retries:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx, 5xx)
            return response  # Success! Return the response content

        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                wait_time = backoff_factor ** retries
                print(f"🔥 Rate limited (429). Retry #{retries+1} after {wait_time:.1f} seconds...")
                time.sleep(wait_time)
                retries += 1
            else:
                # Other HTTP errors, raise immediately
                raise

        except requests.exceptions.RequestException as e:
            # Network error or something else, raise or handle as needed
            raise
    
    raise Exception(f"Failed to fetch {url} after {max_retries} retries due to rate limiting.")

# Function to get URLs from Medium
def get_medium_urls(url):
    res = fetch_url(url)
    if not res:
        return set()

    soup = BeautifulSoup(res.content, "html.parser")
    links = soup.find_all("a", href=True)
    urls = set()
    for link in links:
        href = link["href"]
        if href.startswith("https://medium.com/") and "/@medium/" not in href:
            urls.add(href)
    return urls

# Function to get URLs from X (Twitter)
def get_twitter_urls():
    urls = set()

    try:
        with NitterScraper() as nitter:
            for hashtag in hashtags:
                try:
                    # Grab the freshest 5 tweets, no mercy
                    tweets = nitter.get_hashtag_tweets(hashtag)
                    for tweet in tweets[:5]:
                        urls.add(tweet.url)
                except Exception as e:
                    logger.error(f"[🔥 ERROR] Failed to fetch tweets for #{hashtag}: {e}")
    except Exception as e:
        logger.critical(f"[💥 FATAL] Could not initialize NitterScraper: {e}")

    return urls

# Function to get Reddit posts
#def get_reddit_urls(keyword, limit=5):
#    url = f"https://api.pushshift.io/reddit/search/submission/?q={keyword}&size={limit}&sort=desc&sort_type=created_utc"
#    try:
#        res = requests.get(url, timeout=10)
#        res.raise_for_status()
#        data = res.json()
#        urls = set()
#        for post in data.get('data', []):
#            if 'url' in post:
#                urls.add(post['url'])
#        return urls
#    except Exception as e:
#        logger.error(f"Error fetching Pushshift data for keyword '{keyword}': {e}")
#        return set()
#reddit_urls = set()
#for keyword in hashtags:
#    reddit_urls.update(get_reddit_urls(keyword))


# Function to get all URLs from all platforms
def get_urls_from_all_sources():
    medium_urls = get_medium_urls("https://medium.com/tag/owasp/latest")
    twitter_urls = get_twitter_urls()
   # reddit_urls = get_reddit_urls()
    
    all_urls = medium_urls.union(twitter_urls)
    #.union(reddit_urls)
    return all_urls

# Function to extract content (first 3 lines) from a Medium post
def extract_content_from_url(url):
    res = fetch_url(url)
    if not res:
        return "No content available."
    
    soup = BeautifulSoup(res.content, "html.parser")
    paragraphs = soup.find_all("p")
    
    content = "\n".join([para.get_text() for para in paragraphs[:3]])  # Get first 3 paragraphs
    return content

# Function to extract the image from a URL if available
def extract_image_from_url(url):
    res = fetch_url(url)
    if not res:
        return None
    
    soup = BeautifulSoup(res.content, "html.parser")
    image_tag = soup.find("meta", property="og:image")
    
    if image_tag and 'content' in image_tag.attrs:
        return image_tag['content']
    
    return None

# Send message to Discord with ASCII Art and content
def send_discord_message(webhook_url, message, title=None, image_url=None):
    logger.info("Sending message to Discord...")
    try:
        art = random.choice(ascii_art_options)  # Randomly choose an ASCII art
        data = {
            "embeds": [{
                "title": title or "New Post on Multiple Platforms",
                "description": f"{art}\n{message}",
                "color": random.randint(0, 16777215),  # Random color
                "url": message,
                "footer": {
                    "text": "Security Updates by Bot"
                }
            }]
        }
        
        if image_url:
            data["embeds"][0]["image"] = {"url": image_url}
        
        res = requests.post(webhook_url, json=data)
        res.raise_for_status()  # Raise an exception for 4xx/5xx responses
    except requests.RequestException as e:
        logger.error(f"Error sending message: {e}")

# Send message to Telegram with ASCII Art and content
def send_telegram_message(message, image_url=None):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logger.error("Telegram token or chat ID not set! Cannot send Telegram message.")
        return
    else:
        logger.info("Sending message to Telegram...")
    try:
        bot = Bot(token=TELEGRAM_TOKEN)
        art = random.choice(ascii_art_options)  # Random ASCII Art
        if image_url:
            bot.send_photo(
                chat_id=TELEGRAM_CHAT_ID,
                photo=image_url,
                caption=f"{art}\n{message}",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=f"{art}\n{message}",
                parse_mode=ParseMode.MARKDOWN
            )
    except Exception as e:
        logger.error(f"Error sending message to Telegram: {e}")

# Main bot loop
def check_for_updates():
    global stored_urls
    new_urls = get_urls_from_all_sources()
    logger.info(f"Fetched {len(new_urls)} total URLs")
    new_posts = new_urls - stored_urls
    logger.info(f"New posts count: {len(new_posts)}")
    
    # Initialize progress bar with tqdm
    with tqdm(total=len(new_urls), desc="Processing new posts") as pbar:
        # Identify only the new URLs
        new_posts = new_urls - stored_urls
        if new_posts:
            logger.info(f"Found {len(new_posts)} new post(s)!")
            stored_urls.update(new_posts)  # Update stored URLs to include the new ones

            for url in new_posts:
                message = f"New post found: {url}"
                title = "New Post"  # Placeholder title
                content = extract_content_from_url(url)  # Extract first 3 lines of content
                image_url = extract_image_from_url(url)  # Extract image (if any)
                
                # Send message to both Discord and Telegram
                send_discord_message(WEBHOOK_URL, f"{content}\n\n{message}", title, image_url)
                send_telegram_message(f"{content}\n\n{message}", image_url)
                pbar.update(1)
        else:
            logger.info("No new posts found.")

# Schedule updates
def schedule_updates(interval_minutes=20):
    schedule.every(interval_minutes).minutes.do(check_for_updates)

# Load previously stored URLs from a file
def load_stored_urls():
    if os.path.exists('stored_urls.json'):
        with open('stored_urls.json', 'r') as file:
            return set(json.load(file))
    return set()

# Save URLs to a file
def save_stored_urls():
    with open('stored_urls.json', 'w') as file:
        json.dump(list(stored_urls), file)

# Main bot loop
if __name__ == '__main__':
    test_message = "This is a test message from your bot."
    send_discord_message(WEBHOOK_URL, test_message, title="Test Message")
    send_telegram_message(test_message)
    stored_urls = load_stored_urls()  # Load stored URLs from file on start
    schedule_updates(interval_minutes=10)  # Adjust this interval as needed
    cycles = 0
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
            cycles +=1
            if cycles % 30 == 0:  # Save every ~5 mins (if interval is 10 sec)
                save_stored_urls()
    except KeyboardInterrupt:
        logger.info("Bot interrupted, saving stored URLs.")
        save_stored_urls()  # Save URLs when stopping the bot
    # Test sending messages manually once on startup:
    test_message = "This is a test message from your bot."
    send_discord_message(WEBHOOK_URL, test_message, title="Test Message")
    send_telegram_message(test_message)
