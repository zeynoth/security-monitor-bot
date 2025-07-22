import requests
import logging
import schedule
import time
import random
import os
import json
from bs4 import BeautifulSoup
from telegram import Bot, ParseMode, InputMediaPhoto
from datetime import datetime
import pytz
from tqdm import tqdm
import colorlog
import tweepy
import praw

# Configure logging with colorlog
log_format = '%(log_color)s%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
logger = logging.getLogger()

# Set up colorlog for different log levels
log_handler = colorlog.StreamHandler()
log_handler.setFormatter(colorlog.ColoredFormatter(log_format))
logger.addHandler(log_handler)

# Set your Telegram bot token and chat ID
TELEGRAM_TOKEN = ''  # Your Telegram Bot Token
TELEGRAM_CHAT_ID = ''  # Your Telegram Chat ID

# Set your Discord webhook URL
WEBHOOK_URL = ''  # Your Discord Webhook URL

# Twitter API credentials (X)
TWITTER_API_KEY = ''  # Your Twitter API key
TWITTER_API_SECRET_KEY = ''  # Your Twitter API secret key
TWITTER_ACCESS_TOKEN = ''  # Your Twitter Access Token
TWITTER_ACCESS_TOKEN_SECRET = ''  # Your Twitter Access Token Secret

# Reddit API credentials
REDDIT_CLIENT_ID = ''  # Your Reddit Client ID
REDDIT_SECRET = ''  # Your Reddit Secret
REDDIT_USER_AGENT = ''  # Your Reddit User Agent
REDDIT_USERNAME = ''  # Your Reddit Username
REDDIT_PASSWORD = ''  # Your Reddit Password

# Hashtags for Medium, X (Twitter), and Reddit scraping
hashtags = [
    "owasp", "penetration-testing", "bug-hunting", "web-vulnerabilities", "xss", "sql-injection", 
    "appsec", "bug-bounty", "hacking", "cybersecurity"
]

# ASCII Art Options
ascii_art_options = [
    '''
    _________
    /        \\
   |  BOOM!  |
    \________/
    ''',
    '''
     _______
    /       \\
   |  ALERT |
    \\_______/
    ''',
    '''
     _______
    |       |
    |  🚨   |
    |       |
    \\_______/
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
def fetch_url(url, retries=MAX_RETRIES):
    for i in range(retries):
        try:
            res = requests.get(url, timeout=10)
            res.raise_for_status()
            return res
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            wait_time = BACKOFF_TIME * (2 ** i)  # Exponential backoff
            logger.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    return None

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
    auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET_KEY)
    auth.set_access_token(TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_TOKEN_SECRET)
    api = tweepy.API(auth)
    
    urls = set()
    for hashtag in hashtags:
        tweets = api.search(q=f"#{hashtag}", lang="en", result_type="recent", count=5)
        for tweet in tweets:
            urls.add(f"https://twitter.com/{tweet.user.screen_name}/status/{tweet.id}")
    return urls

# Function to get Reddit posts
def get_reddit_urls():
    reddit = praw.Reddit(client_id=REDDIT_CLIENT_ID, client_secret=REDDIT_SECRET, 
                         user_agent=REDDIT_USER_AGENT, username=REDDIT_USERNAME, password=REDDIT_PASSWORD)
    
    urls = set()
    for subreddit in ['netsec', 'bugbounty', 'OWASP']:
        for submission in reddit.subreddit(subreddit).new(limit=5):
            urls.add(submission.url)
    return urls

# Function to get all URLs from all platforms
def get_urls_from_all_sources():
    medium_urls = get_medium_urls("https://medium.com/tag/owasp/latest")
    twitter_urls = get_twitter_urls()
    reddit_urls = get_reddit_urls()
    
    all_urls = medium_urls.union(twitter_urls).union(reddit_urls)
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
    stored_urls = load_stored_urls()  # Load stored URLs from file on start
    schedule_updates(interval_minutes=20)  # Adjust this interval as needed
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Bot interrupted, saving stored URLs.")
        save_stored_urls()  # Save URLs when stopping the bot
