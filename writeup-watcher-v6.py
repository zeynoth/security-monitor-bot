# -*- coding: utf-8 -*-
import requests
import logging
import schedule
import time
import random
import asyncio
from telegram import Bot
import os
import orjson
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
from urllib.parse import urlparse, quote, urlencode, parse_qs
import shutil
import redis
from deep_translator import GoogleTranslator

# Configure logging with colorlog
log_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.DEBUG, format=log_format)
logger = logging.getLogger()

# Set up colorlog for different log levels
log_handler = colorlog.StreamHandler()
log_handler.setFormatter(colorlog.ColoredFormatter(log_format))
logger.addHandler(log_handler)

# Add file handler for log rotation
from logging.handlers import RotatingFileHandler
file_handler = RotatingFileHandler('bot.log', maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(colorlog.ColoredFormatter(log_format))
logger.addHandler(file_handler)

# JSON log handler for structured logging
json_log_handler = RotatingFileHandler('bot_json.log', maxBytes=10*1024*1024, backupCount=5)
json_log_handler.setFormatter(logging.Formatter('{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'))
logger.addHandler(json_log_handler)

# Set your Telegram bot token, chat ID, Discord webhook URL, and Redis (optional)
WEBHOOK_URL = os.getenv('WEBHOOK_URL')
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')  # Optional Redis
LANGUAGE = os.getenv('NOTIFICATION_LANGUAGE', 'en')  # Default to English

# Initialize Redis (if available)
try:
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    logger.info("Connected to Redis cache")
except redis.RedisError:
    redis_client = None
    logger.warning("Redis not available, falling back to file-based cache")

# Initialize Translator
translator = GoogleTranslator(source='auto', target=LANGUAGE)

# Hashtags for Medium, X (Twitter), and Reddit scraping
hashtags = [
    "owasp", "bugbounty", "cybersecurity", "xss", "sql-injection",
    "pentest", "ethicalhacking", "vulnerability", "hackthebox", "ctf"
]
PRIORITY_KEYWORDS = [
    "exploit", "vulnerability", "hack", "breach", "leak", "rce", "xss", "sqli", "csrf"
]

# Global variables to store URLs, posts, and cache
twitter_urls = set()
medium_urls = set()
reddit_urls = set()
stored_urls = set()
medium_posts = []
reddit_posts = []
medium_cache = {}  # Cache for Medium/Reddit pages

# Cache settings
CACHE_FILE = 'medium_cache.json'
CACHE_EXPIRY = 3600  # 1 hour in seconds
LOCK_TIMEOUT = 60  # File lock timeout
LOCK_RETRIES = 15  # Increased number of retries for file lock

# Set the timezone
TIMEZONE = pytz.timezone('UTC')

# Hacker/Walter White-inspired messages
HACKER_MESSAGE = (
    "🔔 New Post Detected!\n"
    "📜 *{title}*\n"
    "📝 {description}\n"
    "🔗 {link}\n"
    "✍️ {author}\n"
    "🏷️ {tags}"
)
PRIORITY_HACKER_MESSAGE = (
    "🔥 CRITICAL CYBER THREAT DETECTED! 🔥\n"
    "📜 *{title}*\n"
    "📝 {description}\n"
    "🔗 {link}\n"
    "✍️ {author}\n"
    "🏷️ {tags}"
)

# Truncate message to avoid exceeding limits
def truncate_message(message, max_length=2000):
    return message[:max_length - 3] + "..." if len(message) > max_length else message

# Translate message to target language
def translate_message(message, target_lang='en'):
    if target_lang != 'en':
        try:
            return translator.translate(message)
        except Exception as e:
            logger.error(f"Translation failed: {e}")
            return message
    return message

# Async HTTP fetch with caching and URL validation
async def fetch_url_async(url, session, max_retries=4, backoff_factor=10):
    current_time = time.time()
    cache_key = f"cache:{url}"
    
    # Validate and encode URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            logger.error(f"Invalid URL format: {url}")
            raise ValueError(f"Invalid URL: {url}")
        safe_url = parsed_url.scheme + "://" + parsed_url.netloc + quote(parsed_url.path)
        if parsed_url.query:
            safe_url += "?" + urlencode(dict(parse_qs(parsed_url.query)))
        logger.debug(f"Attempting to fetch URL: {safe_url}")
    except Exception as e:
        logger.error(f"Failed to parse URL {url}: {e}")
        raise

    # Check Redis cache
    if redis_client:
        cached = redis_client.get(cache_key)
        if cached:
            logger.info(f"Using Redis cache for {safe_url}")
            return type('Response', (), {'content': cached.encode(), 'raise_for_status': lambda: None})()

    # Check file-based cache
    if safe_url in medium_cache and (current_time - medium_cache[safe_url]["timestamp"]) < CACHE_EXPIRY:
        logger.info(f"Using file cache for {safe_url}")
        return type('Response', (), {'content': medium_cache[safe_url]["content"].encode(), 'raise_for_status': lambda: None})()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    for attempt in range(max_retries):
        try:
            async with session.get(safe_url, headers=headers, timeout=30) as response:
                response.raise_for_status()
                content = await response.text()
                
                # Store in Redis cache
                if redis_client:
                    redis_client.setex(cache_key, CACHE_EXPIRY, content)
                    logger.info(f"Cached {safe_url} in Redis")
                
                # Store in file-based cache
                medium_cache[safe_url] = {
                    "content": content,
                    "timestamp": current_time
                }
                logger.info(f"Fetched {safe_url} successfully")
                return type('Response', (), {'content': content.encode(), 'raise_for_status': lambda: None})()
        except aiohttp.ClientResponseError as e:
            if e.status in [429, 502, 503]:
                wait_time = backoff_factor * (2 ** attempt) + random.uniform(0, 0.1)
                logger.warning(f"Retry {attempt + 1}/{max_retries} for {safe_url} after {wait_time:.1f}s (status: {e.status})")
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"HTTP error {e.status}: {e}")
                raise
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {e}")
            raise
    logger.error(f"Failed to fetch {safe_url} after {max_retries} retries")
    raise Exception(f"Failed to fetch {safe_url} after {max_retries} retries")

# Function to initialize empty JSON file
def initialize_json_file(file_path, is_cache=False):
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                if os.path.exists(file_path):
                    shutil.copy(file_path, f"{file_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                if not os.path.exists(file_path):
                    with open(file_path, 'wb') as f:
                        f.write(orjson.dumps({} if is_cache else []))
                    logger.info(f"Initialized empty JSON file: {file_path}")
                else:
                    try:
                        with open(file_path, 'rb') as f:
                            orjson.loads(f.read())
                    except orjson.JSONDecodeError:
                        logger.warning(f"Repairing corrupted JSON file: {file_path}")
                        with open(file_path, 'wb') as f:
                            f.write(orjson.dumps({} if is_cache else []))
                break
        except filelock.Timeout:
            jitter = random.uniform(0, 0.5)
            logger.warning(f"Failed to acquire lock for {file_path} (attempt {attempt + 1}/{LOCK_RETRIES})")
            if attempt == LOCK_RETRIES - 1:
                logger.error(f"Failed to acquire lock for {file_path} after {LOCK_RETRIES} attempts")
                raise
            time.sleep(1 + jitter)

# Function to load cache from file or Redis
def load_cache():
    global medium_cache
    initialize_json_file(CACHE_FILE, is_cache=True)
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{CACHE_FILE}.lock", timeout=LOCK_TIMEOUT):
                if os.path.exists(CACHE_FILE):
                    with open(CACHE_FILE, 'rb') as f:
                        medium_cache = orjson.loads(f.read())
                    logger.info(f"Loaded {len(medium_cache)} cache entries from {CACHE_FILE}")
                else:
                    logger.info(f"{CACHE_FILE} does not exist, initializing empty cache")
                    medium_cache = {}
                    with open(CACHE_FILE, 'wb') as f:
                        f.write(orjson.dumps({}))
                break
        except filelock.Timeout:
            jitter = random.uniform(0, 0.5)
            logger.warning(f"Failed to acquire lock for {CACHE_FILE} (attempt {attempt + 1}/{LOCK_RETRIES})")
            if attempt == LOCK_RETRIES - 1:
                logger.error(f"Failed to acquire lock for {CACHE_FILE} after {LOCK_RETRIES} attempts")
                raise
            time.sleep(1 + jitter)
        except orjson.JSONDecodeError as e:
            logger.error(f"Failed to load {CACHE_FILE}: {e}. Initializing empty cache.")
            medium_cache = {}
            with open(CACHE_FILE, 'wb') as f:
                f.write(orjson.dumps({}))
    return medium_cache

# Function to save cache to file
def save_cache():
    for attempt in range(LOCK_RETRIES):
        try:
            with filelock.FileLock(f"{CACHE_FILE}.lock", timeout=LOCK_TIMEOUT):
                with open(CACHE_FILE, 'wb') as f:
                    f.write(orjson.dumps(medium_cache))
                logger.info(f"Saved {len(medium_cache)} cache entries to {CACHE_FILE}")
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

    base_urls = ["https://medium.com/tag/{tag}/latest"]
    async with aiohttp.ClientSession() as session:
        for tag in tqdm(hashtags, desc="Scraping Medium tags", colour="green"):
            urls = set()
            for base_url in base_urls:
                try:
                    url = base_url.format(tag=quote(tag))
                    logger.info(f"Fetching Medium data from {url}")
                    res = await fetch_url_async(url, session)
                    if not res:
                        logger.warning(f"No response received from {url}")
                        continue

                    soup = BeautifulSoup(res.content, "lxml")
                    post_links = soup.find_all("a", class_="ag ah ai hl ak al am an ao ap aq ar as at au") or \
                                 soup.find_all("article")

                    for link in post_links:
                        try:
                            title_tag = link.find("h2")
                            title = title_tag.text.strip() if title_tag else "No title"
                            desc_tag = link.find("h3")
                            description = desc_tag.text.strip() if desc_tag else "No description"
                            href = link.get("href", "")
                            if href and href.startswith("/@"):
                                post_url = f"https://medium.com{href.split('?')[0]}"
                                urls.add(post_url)
                                medium_urls.add(post_url)
                                yield {"type": "url", "data": post_url}
                                logger.debug(f"Found Medium URL: {post_url}")

                                author_tag = link.find_previous("a", class_="ag ah ai hl ak al am an ao ap aq ar as ni ac r")
                                author = author_tag.find("p").text.strip() if author_tag and author_tag.find("p") else "Unknown Author"

                                post_res = await fetch_url_async(post_url, session)
                                if not post_res:
                                    logger.warning(f"No response received for post {post_url}")
                                    continue
                                post_soup = BeautifulSoup(post_res.content, "lxml")
                                paragraphs = post_soup.find_all("p")
                                content = "\n".join([para.get_text() for para in paragraphs[:3]])

                                image_tag = post_soup.find("meta", property="og:image")
                                image_url = image_tag["content"] if image_tag and "content" in image_tag.attrs else None
                                if not image_url:
                                    author_img = post_soup.find("img", {"class": "avatar"})
                                    image_url = author_img["src"] if author_img and "src" in author_img.attrs else None

                                content_lower = content.lower()
                                relevant_hashtags = [f"#{htag}" for htag in hashtags if htag.lower() in content_lower]
                                tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #BugBounty"

                                is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)

                                message = (
                                    PRIORITY_HACKER_MESSAGE.format(
                                        title=title,
                                        description=description,
                                        link=post_url,
                                        author=author,
                                        tags=tags
                                    ) if is_priority else HACKER_MESSAGE.format(
                                        title=title,
                                        description=description,
                                        link=post_url,
                                        author=author,
                                        tags=tags
                                    )
                                )
                                message = translate_message(message, LANGUAGE)

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
                                yield {"type": "post", "data": post}
                                logger.debug(f"Found Medium post: {title} ({post_url})")

                        except Exception as e:
                            logger.error(f"Error parsing article: {e}")
                            continue

                    logger.info(f"Fetched {len(urls)} Medium URLs for tag {tag}")
                except Exception as e:
                    logger.error(f"Error fetching Medium data from {url}: {e}\n{traceback.format_exc()}")
                    continue

# Async generator for Reddit URLs and posts
async def get_reddit_urls_and_posts_async():
    global reddit_urls, reddit_posts
    reddit_urls = set()
    reddit_posts = []

    base_urls = ["https://www.reddit.com/r/{subreddit}/new/"]
    subreddits = ["cybersecurity", "netsec", "bugbounty", "hacking"]
    
    async with aiohttp.ClientSession() as session:
        for subreddit in tqdm(subreddits, desc="Scraping Reddit subs", colour="red"):
            urls = set()
            for base_url in base_urls:
                try:
                    url = base_url.format(subreddit=quote(subreddit))
                    logger.info(f"Fetching Reddit data from {url}")
                    res = await fetch_url_async(url, session)
                    if not res:
                        logger.warning(f"No response received from {url}")
                        continue

                    soup = BeautifulSoup(res.content, "lxml")
                    post_links = soup.find_all("a", {"data-click-id": "body"}) or \
                                 soup.find_all("article")

                    for link in post_links:
                        try:
                            title_tag = link.find("h3")
                            title = title_tag.text.strip() if title_tag else "No title"
                            href = link.get("href", "")
                            if href and href.startswith("/r/"):
                                post_url = f"https://www.reddit.com{href.split('?')[0]}"
                                urls.add(post_url)
                                reddit_urls.add(post_url)
                                yield {"type": "url", "data": post_url}
                                logger.debug(f"Found Reddit URL: {post_url}")

                                post_res = await fetch_url_async(post_url, session)
                                if not post_res:
                                    logger.warning(f"No response received for post {post_url}")
                                    continue
                                post_soup = BeautifulSoup(post_res.content, "lxml")
                                paragraphs = post_soup.find_all("p")
                                content = "\n".join([para.get_text() for para in paragraphs[:3]])

                                author_tag = post_soup.find("a", {"data-click-id": "user"})
                                author = author_tag.text.strip() if author_tag else "Unknown Author"

                                image_tag = post_soup.find("meta", property="og:image")
                                image_url = image_tag["content"] if image_tag and "content" in image_tag.attrs else None

                                content_lower = content.lower()
                                relevant_hashtags = [f"#{htag}" for htag in hashtags if htag.lower() in content_lower]
                                tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #Reddit"

                                is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)

                                message = (
                                    PRIORITY_HACKER_MESSAGE.format(
                                        title=title,
                                        description=content,
                                        link=post_url,
                                        author=author,
                                        tags=tags
                                    ) if is_priority else HACKER_MESSAGE.format(
                                        title=title,
                                        description=content,
                                        link=post_url,
                                        author=author,
                                        tags=tags
                                    )
                                )
                                message = translate_message(message, LANGUAGE)

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
                                reddit_posts.append(post)
                                yield {"type": "post", "data": post}
                                logger.debug(f"Found Reddit post: {title} ({post_url})")

                        except Exception as e:
                            logger.error(f"Error parsing Reddit post: {e}")
                            continue

                    logger.info(f"Fetched {len(urls)} Reddit URLs for subreddit {subreddit}")
                except Exception as e:
                    logger.error(f"Error fetching Reddit data from {url}: {e}\n{traceback.format_exc()}")
                    continue

# Function to get URLs from X (Twitter)
async def scrape_hashtag(scraper, hashtag, instance):
    urls = set()
    try:
        logger.info(f"🔫 Blasting #{hashtag} with Nitter ({instance})...")
        tweets_data = await asyncio.get_event_loop().run_in_executor(
            None, partial(scraper.get_tweets, hashtag, mode='hashtag', number=5)
        )
        for tweet in tweets_data['tweets'][:5]:
            urls.add(tweet['link'])
            logger.debug(f"🎯 Sniped tweet: {tweet['link']}")
    except Exception as e:
        logger.error(f"[🔥 ERROR] Failed to scrape #{hashtag} on {instance}: {e}\n{traceback.format_exc()}")
    return urls

async def get_twitter_urls_async(max_concurrent=5):
    global twitter_urls
    nitter_instances = [
        "https://nitter.net",
        "https://nitter.snopyta.org",
        "https://nitter.1d4.us",
        "https://nitter.cz",
        "https://nitter.nl"
    ]

    scraper = None
    for instance in random.sample(nitter_instances, len(nitter_instances)):
        try:
            scraper = Nitter(log_level=1, skip_instance_check=False)
            scraper.set_instance(instance)
            logger.info(f"⚡ Locked onto Nitter instance: {instance}")
            with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                tasks = [scrape_hashtag(scraper, hashtag, instance) for hashtag in hashtags]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in scrape_hashtag: {result}")
                    else:
                        twitter_urls.update(result)
                logger.info(f"🏆 Mission stats: Scraped {len(twitter_urls)} tweets from {len(hashtags)} hashtags")
                break
        except Exception as e:
            logger.error(f"[💥 ERROR] Nitter instance {instance} failed: {e}\n{traceback.format_exc()}")
            continue
        finally:
            if scraper:
                scraper.close()
                logger.info("🧹 Cleaned up Nitter resources")

# Async generator for all URLs and posts
async def get_urls_from_all_sources_async():
    logger.info("Starting to fetch URLs from all sources")
    async for item in get_medium_urls_and_posts_async():
        yield item
    async for item in get_reddit_urls_and_posts_async():
        yield item
    await get_twitter_urls_async()
    logger.info("Finished fetching URLs from all sources")

# Function to extract content from a URL
async def extract_content_from_url_async(url, session):
    logger.info(f"Extracting content from {url}")
    try:
        res = await fetch_url_async(url, session)
        if not res:
            logger.warning(f"No content available for {url}")
            return "No content available."
        soup = BeautifulSoup(res.content, "lxml")
        paragraphs = soup.find_all("p")
        content = "\n".join([para.get_text() for para in paragraphs[:3]])
        return content
    except Exception as e:
        logger.error(f"Failed to extract content from {url}: {e}")
        return "No content available."

# Function to extract the image from a URL
async def extract_image_from_url_async(url, session):
    logger.info(f"Extracting image from {url}")
    try:
        res = await fetch_url_async(url, session)
        if not res:
            logger.warning(f"No image available for {url}")
            return None
        soup = BeautifulSoup(res.content, "lxml")
        image_tag = soup.find("meta", property="og:image")
        if image_tag and 'content' in image_tag.attrs:
            return image_tag['content']
        author_img = soup.find("img", {"class": "avatar"})
        return author_img["src"] if author_img and "src" in author_img.attrs else None
    except Exception as e:
        logger.error(f"Failed to extract image from {url}: {e}")
        return None

# Send message to Discord
def send_discord_message(webhook_url, message, title=None, image_url=None, is_priority=False):
    logger.info("Sending message to Discord...")
    try:
        timestamp = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %Z")
        description = f"{truncate_message(message)}\n\nPosted at: {timestamp}"
        data = {
            "embeds": [{
                "title": title or ("🚨 High-Priority Alert" if is_priority else "New Post"),
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

# Send message to Telegram
async def send_telegram_message(message, image_url=None, is_priority=False):
    logger.info("Sending message to Telegram...")
    try:
        bot = Bot(token=TELEGRAM_TOKEN)
        final_message = truncate_message(f"🚨 *High-Priority Alert* 🚨\n{message}" if is_priority else message)
        final_message = translate_message(final_message, LANGUAGE)
        if image_url:
            await bot.send_photo(
                chat_id=TELEGRAM_CHAT_ID,
                photo=image_url,
                caption=final_message,
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=final_message,
                parse_mode=ParseMode.MARKDOWN
            )
        logger.info("Successfully sent message to Telegram")
    except Exception as e:
        logger.error(f"Error sending message to Telegram: {e}")

# Send error report to Telegram
async def send_error_report(error_message):
    logger.info("Sending error report to Telegram...")
    try:
        bot = Bot(token=TELEGRAM_TOKEN)
        error_message = translate_message(f"⚠️ *Error Report* ⚠️\n{error_message}", LANGUAGE)
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=truncate_message(error_message),
            parse_mode=ParseMode.MARKDOWN
        )
        logger.info("Successfully sent error report to Telegram")
    except Exception as e:
        logger.error(f"Failed to send error report to Telegram: {e}")

# Load previously stored URLs, posts, and cache
def load_stored_urls_and_posts():
    global twitter_urls, medium_urls, reddit_urls, stored_urls, medium_posts, reddit_posts
    twitter_urls = set()
    medium_urls = set()
    reddit_urls = set()
    stored_urls = set()
    medium_posts = []
    reddit_posts = []
    
    for file_path in ['twitter_urls.json', 'medium_urls.json', 'reddit_urls.json', 'stored_urls.json', 'medium_posts.json', 'reddit_posts.json']:
        initialize_json_file(file_path)
        for attempt in range(LOCK_RETRIES):
            try:
                with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            data = orjson.loads(f.read())
                            if file_path == 'twitter_urls.json':
                                twitter_urls = set(data)
                            elif file_path == 'medium_urls.json':
                                medium_urls = set(data)
                            elif file_path == 'reddit_urls.json':
                                reddit_urls = set(data)
                            elif file_path == 'stored_urls.json':
                                stored_urls = set(data)
                            elif file_path == 'medium_posts.json':
                                medium_posts = data
                            elif file_path == 'reddit_posts.json':
                                reddit_posts = data
                    else:
                        logger.info(f"{file_path} does not exist, initializing empty file")
                        with open(file_path, 'wb') as f:
                            f.write(orjson.dumps([]))
                    break
            except filelock.Timeout:
                jitter = random.uniform(0, 0.5)
                logger.warning(f"Failed to acquire lock for {file_path} (attempt {attempt + 1}/{LOCK_RETRIES})")
                if attempt == LOCK_RETRIES - 1:
                    logger.error(f"Failed to acquire lock for {file_path} after {LOCK_RETRIES} attempts")
                    raise
                time.sleep(1 + jitter)
            except orjson.JSONDecodeError as e:
                logger.error(f"Failed to load {file_path}: {e}. Initializing empty data.")
                if file_path in ['medium_posts.json', 'reddit_posts.json']:
                    globals()[file_path.split('.')[0]] = []
                else:
                    globals()[file_path.split('.')[0]] = set()
                with open(file_path, 'wb') as f:
                    f.write(orjson.dumps([]))
    
    load_cache()
    logger.info(f"Loaded {len(twitter_urls)} Twitter URLs, {len(medium_urls)} Medium URLs, {len(reddit_urls)} Reddit URLs, {len(stored_urls)} stored URLs, {len(medium_posts)} Medium posts, {len(reddit_posts)} Reddit posts")
    return stored_urls

# Save URLs, posts, and cache
def save_stored_urls_and_posts():
    logger.info(f"Before saving: twitter_urls={len(twitter_urls)}, medium_urls={len(medium_urls)}, reddit_urls={len(reddit_urls)}, stored_urls={len(stored_urls)}, medium_posts={len(medium_posts)}, reddit_posts={len(reddit_posts)}")
    for file_path, data in [
        ('twitter_urls.json', list(twitter_urls)),
        ('medium_urls.json', list(medium_urls)),
        ('reddit_urls.json', list(reddit_urls)),
        ('stored_urls.json', list(stored_urls)),
        ('medium_posts.json', medium_posts),
        ('reddit_posts.json', reddit_posts)
    ]:
        for attempt in range(LOCK_RETRIES):
            try:
                with filelock.FileLock(f"{file_path}.lock", timeout=LOCK_TIMEOUT):
                    if os.path.exists(file_path):
                        shutil.copy(file_path, f"{file_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                    with open(file_path, 'wb') as f:
                        f.write(orjson.dumps(data))
                    logger.info(f"Saved {file_path} with {len(data)} entries")
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
    global twitter_urls, medium_urls, reddit_urls, stored_urls, medium_posts, reddit_posts
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
                            tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #Twitter"
                            is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)
                            message = PRIORITY_HACKER_MESSAGE.format(
                                title="New Tweet",
                                description=content,
                                link=url,
                                author="Unknown",
                                tags=tags
                            ) if is_priority else HACKER_MESSAGE.format(
                                title="New Tweet",
                                description=content,
                                link=url,
                                author="Unknown",
                                tags=tags
                            )
                            message = translate_message(message, LANGUAGE)
                            title = "New Tweet"
                            image_url = await extract_image_from_url_async(url, session)
                            send_discord_message(WEBHOOK_URL, message, title, image_url, is_priority)
                            await send_telegram_message(message, image_url, is_priority)
                        elif url in reddit_urls:
                            content = await extract_content_from_url_async(url, session)
                            content_lower = content.lower()
                            relevant_hashtags = [f"#{tag}" for tag in hashtags if tag.lower() in content_lower]
                            tags = " ".join(relevant_hashtags) if relevant_hashtags else "#Cybersecurity #Reddit"
                            is_priority = any(keyword.lower() in content_lower for keyword in PRIORITY_KEYWORDS)
                            message = PRIORITY_HACKER_MESSAGE.format(
                                title="New Reddit Post",
                                description=content,
                                link=url,
                                author="Unknown",
                                tags=tags
                            ) if is_priority else HACKER_MESSAGE.format(
                                title="New Reddit Post",
                                description=content,
                                link=url,
                                author="Unknown",
                                tags=tags
                            )
                            message = translate_message(message, LANGUAGE)
                            title = "New Reddit Post"
                            image_url = await extract_image_from_url_async(url, session)
                            send_discord_message(WEBHOOK_URL, message, title, image_url, is_priority)
                            await send_telegram_message(message, image_url, is_priority)
                elif item["type"] == "post":
                    post = item["data"]
                    if post["link"] not in stored_urls:
                        stored_urls.add(post["link"])
                        if post["link"] in medium_urls:
                            medium_posts.append(post)
                        elif post["link"] in reddit_urls:
                            reddit_posts.append(post)
                        send_discord_message(WEBHOOK_URL, post["message"], post["title"], post["image_url"], post["is_priority"])
                        await send_telegram_message(post["message"], post["image_url"], post["is_priority"])
            except Exception as e:
                error_msg = f"Error processing item {item}: {e}\n{traceback.format_exc()}"
                logger.error(error_msg)
                await send_error_report(error_msg)
                continue
    
    logger.info(f"Fetched {len(new_urls)} total URLs, {len(medium_posts)} Medium posts, {len(reddit_posts)} Reddit posts")
    logger.info(f"New posts count: {len(new_urls - stored_urls)}")
    save_stored_urls_and_posts()

# Schedule updates
def schedule_updates(interval_minutes=5):
    async def run_async():
        try:
            await check_for_updates_async()
        except Exception as e:
            error_msg = f"Error in check_for_updates_async: {e}\n{traceback.format_exc()}"
            logger.error(error_msg)
            await send_error_report(error_msg)
            save_stored_urls_and_posts()
    schedule.every(interval_minutes).minutes.do(lambda: asyncio.run(run_async()))

# Main bot loop with auto-restart
def main():
    global cycles
    cycles = 0
    try:
        test_message = HACKER_MESSAGE.format(
            title="Test Post",
            description="This is a test post from the digital underworld.",
            link="https://example.com",
            author="Test Author",
            tags="#Cybersecurity"
        )
        test_message = translate_message(test_message, LANGUAGE)
        send_discord_message(WEBHOOK_URL, test_message, title="Test Message")
        asyncio.run(send_telegram_message(test_message))
        stored_urls = load_stored_urls_and_posts()
        schedule_updates(interval_minutes=5)
        while True:
            schedule.run_pending()
            time.sleep(1)
            cycles += 1
            if cycles % 30 == 0:
                logger.info("Periodic save triggered")
                save_stored_urls_and_posts()
    except KeyboardInterrupt:
        logger.info("Bot interrupted, saving data.")
        save_stored_urls_and_posts()
    except Exception as e:
        error_msg = f"Unexpected error: {e}\n{traceback.format_exc()}"
        logger.error(error_msg)
        asyncio.run(send_error_report(error_msg))
        save_stored_urls_and_posts()
        logger.info("Restarting bot in 60 seconds...")
        time.sleep(60)
        main()

if __name__ == '__main__':
    main()
