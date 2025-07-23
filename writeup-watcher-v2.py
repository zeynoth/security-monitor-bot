import requests
import logging
import schedule
import time
import random
import asyncio
from telegram import Bot
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
from ntscraper import Nitter
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import traceback

# Configure logging with colorlog
log_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger()

# Set up colorlog for different log levels
log_handler = colorlog.StreamHandler()
log_handler.setFormatter(colorlog.ColoredFormatter(log_format))
logger.addHandler(log_handler)

# Set your Telegram bot token and chat ID and your Discord webhook URL
WEBHOOK_URL = os.getenv('WEBHOOK_URL')  # Your Discord Webhook URL
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')  # Your Telegram Bot Token
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')  # Your Telegram Chat ID

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

# Global variables to store URLs, posts, and cache
twitter_urls = set()
medium_urls = set()
stored_urls = set()
medium_posts = []
medium_cache = {}  # Cache for Medium pages

# Cache settings
CACHE_FILE = 'medium_cache.json'
CACHE_EXPIRY = 3600  # 1 hour in seconds

# Retry settings for request
MAX_RETRIES = 3
BACKOFF_TIME = 2  # seconds

# Set the timezone
TIMEZONE = pytz.timezone('UTC')

# Hacker/Walter White-inspired message
HACKER_MESSAGE = (
    "I am the one who hacks! A fresh cybersecurity gem has surfaced from the digital underworld. "
    "Check this out and tread carefully: {link}\n\n"
    "{content}\n\n"
    "Read more: {link}\n"
    "Tags: {tags}"
)

# Function to load cache from file
def load_cache():
    global medium_cache
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            medium_cache = json.load(file)
    return medium_cache

# Function to save cache to file
def save_cache():
    with open(CACHE_FILE, 'w') as file:
        json.dump(medium_cache, file)

# Function to implement exponential backoff retries with caching
def fetch_url(url, max_retries=5, backoff_factor=1.5):
    global medium_cache
    current_time = time.time()
    
    # Check cache
    if url in medium_cache and (current_time - medium_cache[url]["timestamp"]) < CACHE_EXPIRY:
        logger.info(f"Using cached response for {url}")
        return type('Response', (), {'content': medium_cache[url]["content"].encode(), 'raise_for_status': lambda: None})()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    retries = 0
    
    while retries < max_retries:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            # Cache the response
            medium_cache[url] = {
                "content": response.text,
                "timestamp": current_time
            }
            save_cache()
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                wait_time = backoff_factor ** retries
                logger.warning(f"🔥 Rate limited (429). Retry #{retries + 1} after {wait_time:.1f} seconds...")
                time.sleep(wait_time)
                retries += 1
            else:
                logger.error(f"HTTP error {response.status_code}: {e}")
                raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise
    logger.error(f"Failed to fetch {url} after {max_retries} retries due to rate limiting.")
    raise Exception(f"Failed to fetch {url} after {max_retries} retries due to rate limiting.")

# Function to get URLs and posts from Medium
def get_medium_urls_and_posts(url="https://medium.com/tag/owasp/latest"):
    global medium_urls, medium_posts
    try:
        res = fetch_url(url)
        if not res:
            return set(), []
        
        soup = BeautifulSoup(res.content, "html.parser")
        links = soup.find_all("a", href=True)
        urls = set()
        posts = []

        # Collect URLs
        for link in links:
            href = link["href"]
            if href.startswith("https://medium.com/") and "/@medium/" not in href:
                urls.add(href)

        # Collect posts
        for article in soup.find_all("article"):
            try:
                title = article.find("h2")
                title_text = title.text.strip() if title else "No title"
                link_tag = article.find("a", href=True)
                link = "https://medium.com" + link_tag["href"] if link_tag else None
                
                if link:
                    # Fetch post content
                    post_res = fetch_url(link)
                    post_soup = BeautifulSoup(post_res.content, "html.parser")
                    paragraphs = post_soup.find_all("p")
                    content = "\n".join([para.get_text() for para in paragraphs[:3]])
                    
                    # Extract image (post or author profile)
                    image_tag = post_soup.find("meta", property="og:image")
                    image_url = image_tag["content"] if image_tag and "content" in image_tag.attrs else None
                    if not image_url:
                        author_img = post_soup.find("img", {"class": "avatar"})
                        image_url = author_img["src"] if author_img and "src" in author_img.attrs else None
                    
                    # Extract author
                    author = post_soup.find("a", {"class": "author"})
                    author_name = author.text.strip() if author else "Unknown Author"
                    
                    # Dynamic hashtag filtering
                    content_lower = content.lower()
                    relevant_hashtags = [f"#{tag}" for tag in hashtags if tag.lower() in content_lower]
                    tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #BugBounty #EthicalHacking"
                    
                    posts.append({
                        "title": title_text,
                        "link": link,
                        "content": content,
                        "image_url": image_url,
                        "author": author_name,
                        "tags": tags
                    })
                    logger.info(f"Found post: {title_text} - {link}")
            except Exception as e:
                logger.error(f"Error parsing article: {e}")
                continue

        logger.info(f"Successfully fetched {len(posts)} posts and {len(urls)} URLs from Medium.")
        return urls, posts
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Medium data: {e}")
        return set(), []
    except Exception as e:
        logger.error(f"Error parsing Medium data: {e}")
        return set(), []

# Function to get URLs from X (Twitter)
def get_twitter_urls(max_concurrent=5):
    urls = set()
    nitter_instances = [
        "https://nitter.net",
        "https://nitter.snopyta.org",
        "https://nitter.1d4.us",
    ]
    
    async def scrape_hashtag(scraper, hashtag):
        try:
            logger.info(f"🔫 Blasting #{hashtag} with Nitter firepower...")
            tweets_data = await asyncio.get_event_loop().run_in_executor(
                None, partial(scraper.get_tweets, hashtag, mode='hashtag', number=5)
            )
            for tweet in tweets_data['tweets'][:5]:
                urls.add(tweet['link'])
                logger.debug(f"🎯 Sniped tweet: {tweet['link']}")
            return True
        except Exception as e:
            logger.error(f"[🔥 ERROR] #{hashtag} took a hit: {e}\n{traceback.format_exc()}")
            return False

    async def main_scrape():
        scraper = None
        instance = random.choice(nitter_instances)
        try:
            scraper = Nitter(log_level=1, skip_instance_check=False)
            scraper.set_instance(instance)
            logger.info(f"⚡ Locked onto Nitter instance: {instance}")
            with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                tasks = [scrape_hashtag(scraper, hashtag) for hashtag in hashtags]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if r is True)
                logger.info(f"🏆 Mission stats: {success_count}/{len(hashtags)} hashtags scraped successfully")
        except Exception as e:
            logger.critical(f"[💥 FATAL] Nitter initialization obliterated: {e}\n{traceback.format_exc()}")
        finally:
            if scraper:
                scraper.close()
                logger.info("🧹 Cleaned up Nitter resources like a pro.")

    asyncio.run(main_scrape())
    logger.info(f"💪 Harvested {len(urls)} unique tweet URLs. Ready for domination!")
    return urls

# Function to get all URLs from all platforms
def get_urls_from_all_sources():
    global twitter_urls, medium_urls, medium_posts
    medium_urls, medium_posts = get_medium_urls_and_posts()
    twitter_urls = get_twitter_urls()
    all_urls = medium_urls.union(twitter_urls)
    return all_urls

# Function to extract content (first 3 lines) from a URL
def extract_content_from_url(url):
    res = fetch_url(url)
    if not res:
        return "No content available."
    soup = BeautifulSoup(res.content, "html.parser")
    paragraphs = soup.find_all("p")
    content = "\n".join([para.get_text() for para in paragraphs[:3]])
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
    author_img = soup.find("img", {"class": "avatar"})
    return author_img["src"] if author_img and "src" in author_img.attrs else None

# Send message to Discord with hacker message and content
def send_discord_message(webhook_url, message, title=None, image_url=None):
    logger.info("Sending message to Discord...")
    try:
        timestamp = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %Z")
        description = f"{message}\n\nPosted at: {timestamp}"
        if len(description) > 4000:
            description = description[:3990] + "..."
        data = {
            "embeds": [{
                "title": title or "New Post on Multiple Platforms",
                "description": description,
                "color": random.randint(0, 16777215),
                "footer": {"text": "Security Updates by Bot"}
            }]
        }
        if image_url:
            data["embeds"][0]["image"] = {"url": image_url}
        res = requests.post(webhook_url, json=data)
        res.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Error sending message to Discord: {e}")

# Send message to Telegram with hacker message and content
async def send_telegram_message(message, image_url=None):
    logger.info("Sending message to Telegram...")
    try:
        bot = Bot(token=os.getenv("TELEGRAM_TOKEN"))
        if image_url:
            await bot.send_photo(
                chat_id=os.getenv("TELEGRAM_CHAT_ID"),
                photo=image_url,
                caption=message,
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await bot.send_message(
                chat_id=os.getenv("TELEGRAM_CHAT_ID"),
                text=message,
                parse_mode=ParseMode.MARKDOWN
            )
    except Exception as e:
        logger.error(f"Error sending message to Telegram: {e}")

# Load previously stored URLs, posts, and cache from files
def load_stored_urls_and_posts():
    global twitter_urls, medium_urls, stored_urls, medium_posts, medium_cache
    twitter_urls = set()
    medium_urls = set()
    stored_urls = set()
    medium_posts = []
    
    if os.path.exists('twitter_urls.json'):
        with open('twitter_urls.json', 'r') as file:
            twitter_urls = set(json.load(file))
    
    if os.path.exists('medium_urls.json'):
        with open('medium_urls.json', 'r') as file:
            medium_urls = set(json.load(file))
    
    if os.path.exists('stored_urls.json'):
        with open('stored_urls.json', 'r') as file:
            stored_urls = set(json.load(file))
    
    if os.path.exists('medium_posts.json'):
        with open('medium_posts.json', 'r') as file:
            medium_posts = json.load(file)
    
    load_cache()
    return stored_urls

# Save URLs, posts, and cache to files
def save_stored_urls_and_posts():
    with open('twitter_urls.json', 'w') as file:
        json.dump(list(twitter_urls), file)
    with open('medium_urls.json', 'w') as file:
        json.dump(list(medium_urls), file)
    with open('stored_urls.json', 'w') as file:
        json.dump(list(stored_urls), file)
    with open('medium_posts.json', 'w') as file:
        json.dump(medium_posts, file)
    save_cache()

# Main bot loop
def check_for_updates():
    global twitter_urls, medium_urls, stored_urls, medium_posts
    new_urls = get_urls_from_all_sources()
    logger.info(f"Fetched {len(new_urls)} total URLs and {len(medium_posts)} Medium posts")
    new_posts = new_urls - stored_urls
    logger.info(f"New posts count: {len(new_posts)}")
    
    with tqdm(total=len(new_urls), desc="Processing new posts") as pbar:
        if new_posts:
            logger.info(f"Found {len(new_posts)} new post(s)!")
            stored_urls.update(new_posts)
            
            # Process Medium posts
            for post in medium_posts:
                if post["link"] in new_posts:
                    message = HACKER_MESSAGE.format(
                        link=post["link"],
                        content=post["content"] or "No content available.",
                        tags=post["tags"]
                    )
                    title = post["title"]
                    image_url = post["image_url"]
                    
                    send_discord_message(WEBHOOK_URL, message, title, image_url)
                    asyncio.run(send_telegram_message(message, image_url))
                    pbar.update(1)
            
            # Process Twitter URLs (fallback to basic message)
            for url in new_posts:
                if url in twitter_urls:
                    content = extract_content_from_url(url)
                    # Dynamic hashtag filtering for Twitter
                    content_lower = content.lower()
                    relevant_hashtags = [f"#{tag}" for tag in hashtags if tag.lower() in content_lower]
                    tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #BugBounty #EthicalHacking"
                    message = HACKER_MESSAGE.format(
                        link=url,
                        content=content,
                        tags=tags
                    )
                    title = "New Tweet"
                    image_url = extract_image_from_url(url)
                    
                    send_discord_message(WEBHOOK_URL, message, title, image_url)
                    asyncio.run(send_telegram_message(message, image_url))
                    pbar.update(1)
        else:
            logger.info("No new posts found.")

# Schedule updates
def schedule_updates(interval_minutes=20):
    schedule.every(interval_minutes).minutes.do(check_for_updates)

# Main bot loop
if __name__ == '__main__':
    test_message = HACKER_MESSAGE.format(
        link="https://example.com",
        content="This is a test post from the digital underworld.",
        tags="#Cybersecurity #BugBounty #EthicalHacking"
    )
    send_discord_message(WEBHOOK_URL, test_message, title="Test Message")
    asyncio.run(send_telegram_message(test_message))
    stored_urls = load_stored_urls_and_posts()
    schedule_updates(interval_minutes=10)
    cycles = 0
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
            cycles += 1
            if cycles % 30 == 0:
                save_stored_urls_and_posts()
    except KeyboardInterrupt:
        logger.info("Bot interrupted, saving stored URLs, posts, and cache.")
        save_stored_urls_and_posts()
