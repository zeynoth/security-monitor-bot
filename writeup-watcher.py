import requests
from bs4 import BeautifulSoup
import schedule
import time

# Discord bot details
TOKEN = ''
GUILD_ID = ''
CHANNEL_ID = ''
WEBHOOK_URL = ''

# Hashtags
owasp_hashtags = ["owasp", "owasp-top-10", "owasp-web-security-testing-guide", "owasp-zap", "owasp-asvs", "owasp-esapi", "owasp-juice-shop", "owasp-mstg", "owasp-threat-dragon"]
penetration_testing_hashtags = ["penetration-testing", "penetration-testing-tools", "penetration-testing-methodology", "web-penetration-testing", "network-penetration-testing", "mobile-penetration-testing"]
bug_hunting_hashtags = ["bug-hunting", "bug-bounty-hunting", "web-security", "appsec", "bug-bounty-programs", "bug-bounty-tips"]
web_vulnerabilities_hashtags = ["web-vulnerabilities", "web-application-security", "web-security-threats", "sql-injection", "xss", "csrf", "clickjacking", "code-injection", "file-inclusion", "path-traversal", "server-side-request-forgery"]
hashtags = owasp_hashtags + penetration_testing_hashtags + bug_hunting_hashtags + web_vulnerabilities_hashtags

# Get all the Medium URLs related to the hashtags
def get_all_urls(url):
    res = requests.get(url)
    soup = BeautifulSoup(res.content, "html.parser")
    links = soup.find_all("a", href=True)
    urls = set()
    for link in links:
        href = link["href"]
        if href.startswith("https://medium.com/"):
            urls.add(href)
    return urls

def get_urls_by_hashtags(hashtags):
    urls = set()
    for hashtag in hashtags:
        url = f"https://medium.com/tag/{hashtag}/latest"
        urls.update(get_all_urls(url))
    return urls

urls = get_urls_by_hashtags(hashtags)

# Send message to Discord channel
def send_discord_message(webhook_url, message):
    data = {"content": message}
    requests.post(webhook_url, json=data)

def check_for_updates():
    global urls
    new_urls = get_urls_by_hashtags(hashtags)
    if new_urls != urls:
        urls = new_urls
        for url in urls:
            message = f"New Medium post found: {url}"
            send_discord_message(WEBHOOK_URL, message)

# Check for updates
schedule.every(20).minutes.do(check_for_updates)

# Run the bot
if __name__ == '__main__':
    while True:
        schedule.run_pending()
        time.sleep(1)
