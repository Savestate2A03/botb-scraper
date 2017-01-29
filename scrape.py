import urllib.request
import getpass

# Get session cookies which allows for downloading BotB content
print('Please provide your BotB session cookies!')
botb_cookies = {}
botb_cookie_types = ['PHPSESSID', 'botbr_id', 'serial', 'user_id']
for botb_cookie_type in botb_cookie_types:
    print(botb_cookie_type)
    botb_cookies[botb_cookie_type] = getpass.getpass(" --> ")
print(botb_cookies)

# http://battleofthebits.org/arena/Entry/botb-scraper/X/
# where X is the entry ID

# if it contains ...
# <a href="/barracks/Signup/" title="register">
# you are currently not logged in (cookies failed!)

signup_text = '<a href="/barracks/Signup/" title="register">'
with urllib.request.urlopen('http://battleofthebits.org/arena/Entry/botb-scraper/1') as response:
    html = str(response.read())
    if signup_text in html:
        print('Invalid Cookies (not signed in)')
    else:
        print('Valid Cookies (signed in)')
