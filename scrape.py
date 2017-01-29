import http.client
import getpass

def default_headers(client):
    client.putheader('Accept', 'text/html')
    client.putheader('Accept-Language', 'en-US')
    client.putheader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36')

base_url = 'battleofthebits.org'
base_dir = '/arena/Entry/botb-scraper/'
base_login = '/barracks/Login/'
req_boundary = '----BotBScraperBoundary'

# Get session cookies which allows for downloading BotB content
print('Please sign into BotB')
botb_user = input(' emailadd: ')
botb_pass = getpass.getpass(' password: ')

# Get PHP SessionID
client = http.client.HTTPConnection(base_url)
client.connect()
client.putrequest("GET", base_dir)
default_headers(client)
client.endheaders()
response = client.getresponse()
# Get cookie through black magic
php_session = [header[1] for header in response.getheaders() if header[0] == 'Set-Cookie'][0]
client.close()

# Sign into BotB using the provided credidentials
client.putrequest("POST", base_login)
default_headers(client)
client.putheader('Content-Type', 'multipart/form-data; boundary=' + req_boundary)
client.putheader('Cookie', php_session)

# Build the request payload
payload = '--' + req_boundary + '\n'
payload += 'Content-Disposition: form-data; name="email"\n'
payload += '\n'
payload += botb_user + '\n'
payload += '--' + req_boundary + '\n'
payload += 'Content-Disposition: form-data; name="password"\n'
payload += '\n'
payload += botb_pass + '\n'
payload += '--' + req_boundary + '\n'
payload += 'Content-Disposition: form-data; name="submitok"\n'
payload += '\n'
payload += 'LOGIN\n'
payload += '--' + req_boundary
client.putheader('Content-Length', len(payload))
client.endheaders()

# Send the payload
client.send(payload.encode())
response = client.getresponse()

