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
from telegram.constants import ParseMode
from datetime import datetime
import pytz
from tqdm import tqdm
import colorlog
from ntscraper import Nitter
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import traceback
import aiohttp
import filelock

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
    "owasp", "Cross-Site-Scripting", "penetration-testing", "bug-hunting", "web-vulnerabilities", "xss", "sql-injection",
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
    "bugbountytips", "bughunter", "bugbountyprograms", "bugbountytutorial",
    "bugbountyopportunity", "bugbountyreport", "bugbountysuccess", "bugbountyresources", "bugbountyexploit",
    "bugbountyplatform", "bugbountykills", "bugbountytipsandtricks", "bugbountyninja", "bugbountyresearch",
    "bugbountydiscovery", "bugbountyhacker", "bugbountytools", "bugbountyscout",
    "bugbountybug", "bugbountyvulnerability", "bugbountyhunter", "bugbountytutorial", "bugbountytips2025",
    "bugbountyexploitdev", "bugbountysolutions", "bugbountystories", "bugbountytracking", "bugbountygrind",
    "bugbountyplatforms", "bugbountysuccessstories", "bugbountylearning", "bugbountyhalloffame",
    "bugbountysubmission", "bugbountyappsec", "bugbountytalk", "bugbountyresearcher", "bugbountymethods",
    "bugbountyadvice", "bugbountyprogram", "bugbountystory", "bugbountyposts", "bugbountyeverywhere",
    "bugbountytipsandtricks", "bugbountykills", "bugbountydiscovery", "bugbountyexploitdev", "bugbountyhacks"
]
PRIORITY_KEYWORDS = [
    "exploit", "vulnerability", "hack", "breach", "leak", "malware", "ransomware", "spyware",
    "trojan", "rootkit", "phishing", "social engineering", "zero-day", "0day", "backdoor",
    "ddos", "botnet", "payload", "obfuscation", "command and control", "c2", "keylogger",
    "credential theft", "password dump", "privilege escalation", "lateral movement", "exfiltration",
    "sql injection", "xss", "cross-site scripting", "csrf", "session hijacking", "clickjacking",
    "buffer overflow", "heap spray", "format string", "directory traversal", "remote code execution",
    "rce", "lpe", "arbitrary code", "shellcode", "dns tunneling", "ip spoofing", "mac spoofing",
    "mitm", "man in the middle", "reconnaissance", "footprinting", "nmap", "metasploit",
    "burp suite", "wireshark", "packet sniffing", "spoof", "inject", "injection", "compromise",
    "breached data", "brute force", "dictionary attack", "rainbow table", "hash cracking",
    "crack", "bypass", "evasion", "firewall bypass", "ids evasion", "port scan", "scanning",
    "enumeration", "information disclosure", "threat", "attack vector", "exposure", "cve",
    "cisa alert", "cirt", "ioc", "indicator of compromise", "tactics", "techniques", "procedures",
    "ttp", "kill chain", "mitre", "att&ck", "threat actor", "apt", "state-sponsored", "cyberwar",
    "cybercrime", "dark web", "underground", "black hat", "red team", "penetration testing",
    "pentest", "vuln", "vulns", "cwe", "exploit-db", "exploit kit", "exploit pack", "weaponize",
    "dropper", "stager", "loader", "malicious", "shell", "reverse shell", "bind shell",
    "remote shell", "telnet", "ssh brute", "ftp attack", "x11 attack", "vnc intrusion",
    "remote desktop exploit", "rdp", "admin access", "unauthorized access", "privilege abuse",
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
MAX_RETRIES = 4
BACKOFF_TIME = 10  # seconds
LOCK_TIMEOUT = 30  # File lock timeout
LOCK_RETRIES = 5  # Increased number of retries for file lock

# Set the timezone
TIMEZONE = pytz.timezone('UTC')

# Hacker/Walter White-inspired messages
HACKER_MESSAGE = (
    "New Medium Post!\n"
    "{title}\n"
    "{description}\n"
    "{link}\n"
    "✍️ {author}"
)

PRIORITY_HACKER_MESSAGE = (
    "🔥 ALERT: CRITICAL CYBER THREAT DETECTED! 🔥\n"
    "{title}\n"
    "{description}\n"
    "{link}\n"
    "✍️ {author}"
)

# Async HTTP fetch with caching
async def fetch_url_async(url, session, max_retries=MAX_RETRIES, backoff_factor=BACKOFF_TIME):
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
            async with session.get(url, headers=headers, timeout=30) as response:
                response.raise_for_status()
                content = await response.text()
                
                # Store in memory cache
                medium_cache[url] = {
                    "content": content,
                    "timestamp": current_time
                }
                return type('Response', (), {'content': content.encode(), 'raise_for_status': lambda: None})()
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                wait_time = backoff_factor ** retries
                logger.warning(f"🔥 Rate limited (429). Retry #{retries + 1} after {wait_time:.1f} seconds...")
                await asyncio.sleep(wait_time)
                retries += 1
            else:
                logger.error(f"HTTP error {e.status}: {e}")
                raise
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {e}")
            raise
    logger.error(f"Failed to fetch {url} after {max_retries} retries due to rate limiting.")
    raise Exception(f"Failed to fetch {url} after {max_retries} retries due to rate limiting.")

# Function to initialize empty JSON file
def initialize_json_file(file_path, is_cache=False):
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as file:
                        json.dump({} if is_cache else [], file)
                    logger.info(f"Initialized empty JSON file: {file_path}")
                else:
                    try:
                        with open(file_path, 'r') as file:
                            json.load(file)
                    except json.JSONDecodeError:
                        logger.warning(f"Repairing corrupted JSON file: {file_path}")
                        with open(file_path, 'w') as file:
                            json.dump({} if is_cache else [], file)
                break
        except filelock.Timeout:
            jitter = random.uniform(0, 0.5)
            logger.warning(f"Failed to acquire lock for {file_path} (attempt {attempt + 1}/{LOCK_RETRIES})")
            if attempt == LOCK_RETRIES - 1:
                logger.error(f"Failed to acquire lock for {file_path} after {LOCK_RETRIES} attempts")
                raise
            time.sleep(1 + jitter)

# Function to load cache from file
def load_cache():
    global medium_cache
    initialize_json_file(CACHE_FILE, is_cache=True)
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{CACHE_FILE}.lock", timeout=LOCK_TIMEOUT):
                try:
                    with open(CACHE_FILE, 'r') as file:
                        medium_cache = json.load(file)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to load {CACHE_FILE}: {e}. Initializing empty cache.")
                    medium_cache = {}
                break
        except filelock.Timeout:
            jitter = random.uniform(0, 0.5)
            logger.warning(f"Failed to acquire lock for {CACHE_FILE} (attempt {attempt + 1}/{LOCK_RETRIES})")
            if attempt == LOCK_RETRIES - 1:
                logger.error(f"Failed to acquire lock for {CACHE_FILE} after {LOCK_RETRIES} attempts")
                raise
            time.sleep(1 + jitter)
    return medium_cache

# Function to save cache to file
def save_cache():
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{CACHE_FILE}.lock", timeout=LOCK_TIMEOUT):
                with open(CACHE_FILE, 'w') as file:
                    json.dump(medium_cache, file)
                logger.info(f"Saved {CACHE_FILE} successfully")
                break
        except filelock.Timeout:
            jitter = random.uniform(0, 0.5)
            logger.warning(f"Failed to acquire lock for {CACHE_FILE} (attempt {attempt + 1}/{LOCK_RETRIES})")
            if attempt == LOCK_RETRIES - 1:
                logger.error(f"Failed to save {CACHE_FILE}: Failed to acquire lock after {LOCK_RETRIES} attempts")
                raise
            time.sleep(1 + jitter)
        except Exception as e:
            logger.error(f"Failed to save {CACHE_FILE}: {e}")
            raise

# Async generator for Medium URLs and posts
async def get_medium_urls_and_posts_async():
    global medium_urls, medium_posts
    medium_urls = set()
    medium_posts = []

    # برای هر تگ، سه نوع URL می‌سازیم: recommended، latest و archive
    base_urls = [
        "https://medium.com/tag/{tag}/recommended",
        "https://medium.com/tag/{tag}/latest",
        "https://medium.com/tag/{tag}/archive"
    ]

    async with aiohttp.ClientSession() as session:
        for tag in hashtags:
            urls = set()  # تعریف urls برای هر تگ
            for base_url in base_urls:
                url = base_url.format(tag=tag)
                logger.info(f"Fetching Medium data from {url}")
                try:
                    res = await fetch_url_async(url, session)
                    if not res:
                        logger.warning(f"No response received from {url}")
                        continue

                    soup = BeautifulSoup(res.content, "html.parser")
                    # پیدا کردن تگ‌های <a> مربوط به پست‌ها با کلاس خاص
                    post_links = soup.find_all("a", class_="ag ah ai hl ak al am an ao ap aq ar as at au")

                    for link in post_links:
                        try:
                            # استخراج عنوان از <h2>
                            title_tag = link.find("h2")
                            title = title_tag.text.strip() if title_tag else "No title"

                            # استخراج توضیحات از <h3>
                            desc_tag = link.find("h3")
                            description = desc_tag.text.strip() if desc_tag else "No description"

                            # استخراج لینک پست
                            href = link.get("href", "")
                            if href and href.startswith("/@"):
                                post_url = f"https://medium.com{href.split('?')[0]}"  # حذف پارامترهای اضافی
                                urls.add(post_url)
                                medium_urls.add(post_url)
                                yield {"type": "url", "data": post_url}  # Yield URL immediately
                                logger.debug(f"Found Medium URL: {post_url}")

                                # پیدا کردن نام نویسنده
                                author_tag = link.find_previous("a", class_="ag ah ai hl ak al am an ao ap aq ar as ni ac r")
                                author = author_tag.find("p").text.strip() if author_tag and author_tag.find("p") else "Unknown Author"

                                # گرفتن محتوای پست (برای فیلتر کردن با کلمات کلیدی)
                                post_res = await fetch_url_async(post_url, session)
                                if not post_res:
                                    logger.warning(f"No response received for post {post_url}")
                                    continue
                                post_soup = BeautifulSoup(post_res.content, "html.parser")
                                paragraphs = post_soup.find_all("p")
                                content = "\n".join([para.get_text() for para in paragraphs[:3]])

                                # گرفتن تصویر (اولویت: تصویر پست، سپس تصویر نویسنده)
                                image_tag = post_soup.find("meta", property="og:image")
                                image_url = image_tag["content"] if image_tag and "content" in image_tag.attrs else None
                                if not image_url:
                                    author_img = post_soup.find("img", {"class": "avatar"})
                                    image_url = author_img["src"] if author_img and "src" in author_img.attrs else None

                                # فیلتر کردن هشتگ‌ها
                                content_lower = content.lower()
                                relevant_hashtags = [f"#{htag}" for htag in hashtags if htag.lower() in content_lower]
                                tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #BugBounty #EthicalHacking"

                                # بررسی کلمات کلیدی اولویت‌دار
                                is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)

                                # ساخت پیام
                                message = (
                                    PRIORITY_HACKER_MESSAGE.format(
                                        title=title,
                                        description=description,
                                        link=post_url,
                                        author=author
                                    ) if is_priority else HACKER_MESSAGE.format(
                                        title=title,
                                        description=description,
                                        link=post_url,
                                        author=author
                                    )
                                )

                                post = {
                                    "title": title,
                                    "link": post_url,
                                    "content": content,
                                    "image_url": image_url,
                                    "author": author,
                                    "tags": tags,
                                    "is_priority": is_priority,
                                    "message": message
                                }
                                medium_posts.append(post)
                                yield {"type": "post", "data": post}  # Yield post immediately
                                logger.debug(f"Found Medium post: {title} ({post_url})")

                        except Exception as e:
                            logger.error(f"Error parsing article: {e}")
                            continue

                    logger.info(f"Fetched {len(urls)} Medium URLs for tag {tag}")
                except Exception as e:
                    logger.error(f"Error fetching Medium data from {url}: {e}\n{traceback.format_exc()}")
                    continue

# Function to get URLs from X (Twitter)
async def get_twitter_urls_async(max_concurrent=3):
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
                yield {"type": "url", "data": tweet['link']}  # Yield URL immediately
                logger.debug(f"🎯 Sniped tweet: {tweet['link']}")
        except Exception as e:
            logger.error(f"[🔥 ERROR] Failed to scrape #{hashtag}: {e}\n{traceback.format_exc()}")

    scraper = None
    instance = random.choice(nitter_instances)
    try:
        scraper = Nitter(log_level=1, skip_instance_check=False)
        scraper.set_instance(instance)
        logger.info(f"⚡ Locked onto Nitter instance: {instance}")
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            tasks = [scrape_hashtag(scraper, hashtag) for hashtag in hashtags]
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info(f"🏆 Mission stats: Scraped {len(urls)} tweets from {len(hashtags)} hashtags")
    except Exception as e:
        logger.critical(f"[💥 FATAL] Nitter initialization obliterated: {e}\n{traceback.format_exc()}")
    finally:
        if scraper:
            scraper.close()
            logger.info("🧹 Cleaned up Nitter resources like a pro.")

    global twitter_urls
    twitter_urls.update(urls)

# Async generator for all URLs and posts
async def get_urls_from_all_sources_async():
    logger.info("Starting to fetch URLs from all sources")
    async for item in get_medium_urls_and_posts_async():
        yield item
    twitter_generator = get_twitter_urls_async()
    async for item in twitter_generator:
        yield item
    logger.info("Finished fetching URLs from all sources")

# Function to extract content (first 3 lines) from a URL
async def extract_content_from_url_async(url, session):
    logger.info(f"Extracting content from {url}")
    try:
        res = await fetch_url_async(url, session)
        if not res:
            logger.warning(f"No content available for {url}")
            return "No content available."
        soup = BeautifulSoup(res.content, "html.parser")
        paragraphs = soup.find_all("p")
        content = "\n".join([para.get_text() for para in paragraphs[:3]])
        return content
    except Exception as e:
        logger.error(f"Failed to extract content from {url}: {e}")
        return "No content available."

# Function to extract the image from a URL if available
async def extract_image_from_url_async(url, session):
    logger.info(f"Extracting image from {url}")
    try:
        res = await fetch_url_async(url, session)
        if not res:
            logger.warning(f"No image available for {url}")
            return None
        soup = BeautifulSoup(res.content, "html.parser")
        image_tag = soup.find("meta", property="og:image")
        if image_tag and 'content' in image_tag.attrs:
            return image_tag['content']
        author_img = soup.find("img", {"class": "avatar"})
        return author_img["src"] if author_img and "src" in author_img.attrs else None
    except Exception as e:
        logger.error(f"Failed to extract image from {url}: {e}")
        return None

# Send message to Discord with hacker message and content
def send_discord_message(webhook_url, message, title=None, image_url=None, is_priority=False):
    logger.info("Sending message to Discord...")
    try:
        timestamp = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %Z")
        description = f"{message}\n\nPosted at: {timestamp}"
        if len(description) > 4000:
            description = description[:3990] + "..."
        data = {
            "embeds": [{
                "title": title or ("🚨 High-Priority Alert" if is_priority else "New Post on Multiple Platforms"),
                "description": description,
                "color": 0xFF0000 if is_priority else random.randint(0, 16777215),
                "footer": {"text": "Security Updates by CyberSentry"}
            }]
        }
        if image_url:
            data["embeds"][0]["image"] = {"url": image_url}
        res = requests.post(webhook_url, json=data)
        res.raise_for_status()
        logger.info("Successfully sent message to Discord")
    except requests.RequestException as e:
        logger.error(f"Error sending message to Discord: {e}")

# Send message to Telegram with hacker message and content
async def send_telegram_message(message, image_url=None, is_priority=False):
    logger.info("Sending message to Telegram...")
    try:
        bot = Bot(token=os.getenv("TELEGRAM_TOKEN"))
        final_message = f"🚨 *High-Priority Alert* 🚨\n{message}" if is_priority else message
        if image_url:
            await bot.send_photo(
                chat_id=os.getenv("TELEGRAM_CHAT_ID"),
                photo=image_url,
                caption=final_message,
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await bot.send_message(
                chat_id=os.getenv("TELEGRAM_CHAT_ID"),
                text=final_message,
                parse_mode=ParseMode.MARKDOWN
            )
        logger.info("Successfully sent message to Telegram")
    except Exception as e:
        logger.error(f"Error sending message to Telegram: {e}")

# Load previously stored URLs, posts, and cache from files
def load_stored_urls_and_posts():
    global twitter_urls, medium_urls, stored_urls, medium_posts, medium_cache
    twitter_urls = set()
    medium_urls = set()
    stored_urls = set()
    medium_posts = []
    
    for file_path in ['twitter_urls.json', 'medium_urls.json', 'stored_urls.json', 'medium_posts.json']:
        initialize_json_file(file_path)
        for attempt in range(LOCK_RETRIES):
            try:
                with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                    try:
                        with open(file_path, 'r') as file:
                            data = json.load(file)
                            if file_path == 'twitter_urls.json':
                                twitter_urls = set(data)
                            elif file_path == 'medium_urls.json':
                                medium_urls = set(data)
                            elif file_path == 'stored_urls.json':
                                stored_urls = set(data)
                            elif file_path == 'medium_posts.json':
                                medium_posts = data
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to load {file_path}: {e}. Initializing empty data.")
                        if file_path == 'medium_posts.json':
                            medium_posts = []
                        else:
                            globals()[file_path.split('.')[0]] = set()
                        with open(file_path, 'w') as file:
                            json.dump([], file)
                    break
            except filelock.Timeout:
                jitter = random.uniform(0, 0.5)
                logger.warning(f"Failed to acquire lock for {file_path} (attempt {attempt + 1}/{LOCK_RETRIES})")
                if attempt == LOCK_RETRIES - 1:
                    logger.error(f"Failed to acquire lock for {file_path} after {LOCK_RETRIES} attempts")
                    raise
                time.sleep(1 + jitter)
    
    load_cache()
    logger.info(f"Loaded {len(twitter_urls)} Twitter URLs, {len(medium_urls)} Medium URLs, {len(stored_urls)} stored URLs, {len(medium_posts)} Medium posts")
    return stored_urls

# Save URLs, posts, and cache to files
def save_stored_urls_and_posts():
    for file_path, data in [
        ('twitter_urls.json', list(twitter_urls)),
        ('medium_urls.json', list(medium_urls)),
        ('stored_urls.json', list(stored_urls)),
        ('medium_posts.json', medium_posts)
    ]:
        for attempt in range(LOCK_RETRIES):
            try:
                with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                    with open(file_path, 'w') as file:
                        json.dump(data, file)
                    logger.info(f"Saved {file_path} successfully")
                    break
            except filelock.Timeout:
                jitter = random.uniform(0, 0.5)
                logger.warning(f"Failed to acquire lock for {file_path} (attempt {attempt + 1}/{LOCK_RETRIES})")
                if attempt == LOCK_RETRIES - 1:
                    logger.error(f"Failed to save {file_path}: Failed to acquire lock after {LOCK_RETRIES} attempts")
                    raise
                time.sleep(1 + jitter)
            except Exception as e:
                logger.error(f"Failed to save {file_path}: {e}")
                raise
    save_cache()

# Main bot loop with real-time notifications
async def check_for_updates_async():
    global twitter_urls, medium_urls, stored_urls, medium_posts
    new_urls = set()
    
    logger.info("Starting update check")
    async with aiohttp.ClientSession() as session:
        async for item in get_urls_from_all_sources_async():
            try:
                if item["type"] == "url":
                    url = item["data"]
                    new_urls.add(url)
                    if url not in stored_urls:
                        stored_urls.add(url)
                        if url in twitter_urls:
                            content = await extract_content_from_url_async(url, session)
                            content_lower = content.lower()
                            relevant_hashtags = [f"#{tag}" for tag in hashtags if tag.lower() in content_lower]
                            tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #BugBounty #EthicalHacking"
                            is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)
                            message = PRIORITY_HACKER_MESSAGE.format(
                                title="New Tweet",
                                description=content,
                                link=url,
                                author="Unknown"  # Twitter posts may not have an author in this context
                            ) if is_priority else HACKER_MESSAGE.format(
                                title="New Tweet",
                                description=content,
                                link=url,
                                author="Unknown"
                            )
                            title = "New Tweet"
                            image_url = await extract_image_from_url_async(url, session)
                            send_discord_message(WEBHOOK_URL, message, title, image_url, is_priority)
                            await send_telegram_message(message, image_url, is_priority)
                elif item["type"] == "post":
                    post = item["data"]
                    if post["link"] not in stored_urls:
                        stored_urls.add(post["link"])
                        medium_posts.append(post)
                        send_discord_message(WEBHOOK_URL, post["message"], post["title"], post["image_url"], post["is_priority"])
                        await send_telegram_message(post["message"], post["image_url"], post["is_priority"])
            except Exception as e:
                logger.error(f"Error processing item {item}: {e}")
                continue
    
    logger.info(f"Fetched {len(new_urls)} total URLs and {len(medium_posts)} Medium posts")
    logger.info(f"New posts count: {len(new_urls - stored_urls)}")
    save_stored_urls_and_posts()  # Save cache at the end of the cycle

# Schedule updates
def schedule_updates(interval_minutes=5):
    async def run_async():
        try:
            await check_for_updates_async()
        except Exception as e:
            logger.error(f"Error in check_for_updates_async: {e}\n{traceback.format_exc()}")
    schedule.every(interval_minutes).minutes.do(lambda: asyncio.run(run_async()))

# Main bot loop
if __name__ == '__main__':
    test_message = HACKER_MESSAGE.format(
        title="Test Post",
        description="This is a test post from the digital underworld.",
        link="https://example.com",
        author="Test Author"
    )
    send_discord_message(WEBHOOK_URL, test_message, title="Test Message")
    asyncio.run(send_telegram_message(test_message))
    stored_urls = load_stored_urls_and_posts()
    schedule_updates(interval_minutes=5)
    cycles = 0
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
            cycles += 1
            if cycles % 30 == 0:
                logger.info("Periodic save triggered")
                save_stored_urls_and_posts()
    except KeyboardInterrupt:
        logger.info("Bot interrupted, saving stored URLs, posts, and cache.")
        save_stored_urls_and_posts()
    except Exception as e:
        logger.error(f"Unexpected error in main loop: {e}\n{traceback.format_exc()}")
        save_stored_urls_and_posts()
