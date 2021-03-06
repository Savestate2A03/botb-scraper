import http.client
import getpass
import re
import urllib

import base64
import os
import sys

from pathlib import Path
import errno

# https://mutagen.readthedocs.io/en/latest/
# install with '$ pip install mutagen'
import mutagen
from mutagen.easyid3 import EasyID3

# https://pypi.python.org/pypi/cryptography
# install with '$ pip install cryptography'
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# botb api
import json
from io import StringIO

# sleep
import time

base_url = 'battleofthebits.org'
base_dir = '/arena/Entry/botb-scraper/'
base_donload_orig = '/player/EntryDonload/' # number/file#
base_donload_mp3  = '/player/MP3Donload/' # number/file
base_api = '/api/v1/entry/load/'
base_login = '/barracks/Login/'
req_boundary = '----BotBScraperBoundary'

# Given a client and optional cookies
# it will add a few headers that are used
# for all connections.
def default_headers(client, cookies = None):
    client.putheader('Accept', 'text/html')
    client.putheader('Accept-Language', 'utf-8')
    client.putheader('Accept-Charset', 'utf-8')
    client.putheader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36')
    if cookies is not None:
        client.putheader('Cookie', '; '.join(cookies))

# Returns the 1st group in a matched
# regular expression and adds it to
# a dictionary.
def regex_extract(expression, source, key, dictionary):
    regex = re.compile(expression)
    match = regex.search(source)
    dictionary[key] = match.group(1)

# Returns the 1st group in a matched
# regular expression and adds it to
# a dictionary.
def regex_extract_simple(expression, source):
    regex = re.compile(expression)
    match = regex.search(source)
    return match.group(1)

# Signs into BotB
# Returns the session cookies
def botb_signin():
    # Get session cookies which allows for downloading BotB content
    print('Please sign into BotB')
    botb_user = input(' email: ')
    botb_pass = getpass.getpass(' password: ')

    # Get PHP SessionID
    client = http.client.HTTPConnection(base_url)
    client.connect()
    client.putrequest("GET", '/')
    default_headers(client)
    client.endheaders()
    response = client.getresponse()
    # Get cookie through black magic
    php_session = [header[1] for header in response.getheaders() if header[0] == 'Set-Cookie'][0]
    php_session = php_session[:php_session.index(";")]
    client.close()

    # Sign into BotB using the provided credidentials
    client = http.client.HTTPConnection(base_url)
    client.connect()
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
    client.send(payload.encode())

    response = client.getresponse()

    # In addition to our php session, we now have 3 more cookies that are used...
    # user_id, serial, and botbr_id. These 3 plus the session id allow for using
    # BotB to it's fullest extent!
    botb_cookies = []
    botb_cookies.append(php_session)
    for header in response.getheaders():
        if header[0] == 'Set-Cookie':
            botb_cookies.append(header[1][:header[1].index(';')])
    client.close()

    print("Logged in!")

    # Save these cookies for future use!
    cookies_pass = getpass.getpass(' cookies password (saving encrypted cookies to disk)\n --> ')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(cookies_pass.encode()))
    fnet = Fernet(key)
    token = fnet.encrypt('; '.join(botb_cookies).encode())
    print('Saving encrypted cookies & salt to disk...')
    file = open('salt', 'wb')
    file.write(salt)
    file.close()
    file = open('cookies', 'wb')
    file.write(token)
    file.close()
    print('...saved! "./salt" and "./cookies".')
    return botb_cookies

def botb_load_init_info(botb_cookies):
    # Load up the BotB homepage, allowing us to get the user and their points etc
    # Havin some fun here w/ the scraper.
    client = http.client.HTTPConnection(base_url)
    client.connect()
    client.putrequest("GET", '/')
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    webpage = response.read().decode('utf-8', 'ignore')
    client.close()

    # RegEx / BotBr info building
    botbr_info = {}
    regex_extract('<b><a href="http://battleofthebits.org/barracks/Profile/.{1,64}/">(.{1,64})</a></b>',
                  webpage, 'username', botbr_info)
    regex_extract('<sub>b</sub>([0-9\.]+)\W+</span>',
                  webpage, 'b00ns', botbr_info)
    regex_extract('\W+L([0-9]{,2})\W+.{,64}\W+&nbsp;',
                  webpage, 'level', botbr_info)
    regex_extract('\W+L[0-9]{,2}\W+(\w{,64})\W+&nbsp;',
                  webpage, 'class', botbr_info)
    regex_extract('<div class="levelProgress" title="([0-9]+) points to next level">',
                  webpage, 'levelup_progress', botbr_info)

    return botbr_info

def botb_load_cookies():
    path_cookies = Path('cookies')
    path_salt    = Path('salt')
    if path_cookies.is_file() and path_salt.is_file():
        cookies_pass = getpass.getpass('Previous session found! Password to decrypt cookies\n --> ')
        file_salt = path_salt.open('rb')
        salt = file_salt.read()
        file_salt.close()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(cookies_pass.encode()))
        fnet = Fernet(key)
        file_cookies = path_cookies.open('rb')
        encrypted_cookies = file_cookies.read()
        file_cookies.close()
        return fnet.decrypt(encrypted_cookies).decode().split('; ')
    else:
        return botb_signin()

# http://stackoverflow.com/questions/273192/
# how-to-check-if-a-directory-exists-and-create-it-if-necessary
def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

# create scraping directories
def create_default_directories(input_subfolder):
    try:
        make_sure_path_exists('files/'+ input_subfolder)
        make_sure_path_exists('files/' + input_subfolder + '/mp3')
        make_sure_path_exists('files/' + input_subfolder + '/orig')
    except OSError as exception:
        print('Error creating directories!!')
        sys.exit(-1)

def tag_mp3(filename, entry_number, botb_cookies, input_subfolder):
    client = http.client.HTTPConnection(base_url)
    client.putrequest("GET", base_api + str(entry_number))
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    entry_json = response.read().decode()
    json_io = StringIO(entry_json)
    botb_json_object = json.load(json_io)
    mp3_filepath = "files/" + input_subfolder + "/mp3/" + filename
    if 'sample' in botb_json_object['format']['token']:
        print('sample! not saving mp3 render...')
        os.remove(mp3_filepath)
        return
    try:
        audio = EasyID3(mp3_filepath)
    except mutagen.id3.ID3NoHeaderError:
        try:
            audio = mutagen.File(mp3_filepath, easy=True)
            audio.add_tags()
        except mutagen.mp3.HeaderNotFoundError:
            print('botbr uploaded the wrong filetype, discarding mp3!')
            os.remove(mp3_filepath)
            return
    audio['title']  = botb_json_object['title']
    audio['album']  = botb_json_object['battle']['title']
    audio['artist'] = botb_json_object['botbr']['name']
    audio['date']   = botb_json_object['battle']['end_date']
    audio['albumartist'] = 'battleofthebits.org'
    audio['genre'] = botb_json_object['format']['token']
    audio['tracknumber'] = ''
    audio['discnumber'] = ''
    audio['copyright'] = 'CC BY-NC-SA 3.0'
    audio.save()

def get_entry_filename(botb_cookies, entry_number, ismp3 = False):
    client = http.client.HTTPConnection(base_url)
    client.connect()
    client.putrequest("GET", base_dir + str(entry_number) + '/')
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    fixed_url = "butts"
    if not ismp3:
        raw_url = regex_extract_simple('/player/EntryDonload/[0-9]+/(.*)" class="inner boxLink"', response.read().decode('utf-8', 'ignore'))
        fixed_url = urllib.parse.unquote(urllib.parse.unquote(raw_url))
    else:
        raw_url = regex_extract_simple('/player/MP3Donload/[0-9]+/(.*)" class="inner boxLink"', response.read().decode('utf-8', 'ignore'))
        fixed_url = raw_url
    client.close()
    return fixed_url

# check if a visual entry
def is_visual(botb_cookies, entry_number):
    client = http.client.HTTPConnection(base_url)
    client.connect()
    client.putrequest("GET", base_dir + str(entry_number) + '/')
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    if 'title="view entry"><div class="botb-icon icons-eye' in response.read().decode('utf-8', 'ignore'):
        client.close()
        return True
    client.close()
    return False
    
# donload the files given an entry number
def download_entry(botb_cookies, entry_number, input_subfolder):
    client = http.client.HTTPConnection(base_url)
    # original file --------------------
    print(" - original file...")
    client.connect()
    client.putrequest("GET", base_donload_orig + str(entry_number) + '/file')
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    try:
        filename = get_entry_filename(botb_cookies, entry_number)
    except:
        print('no entry found!! 0:')
        return
    original_file = response.read()
    # filename cleanup, longtitleislong
    if len(filename) > 70:
        filename_r = re.compile(r'^(.{1,70}).*\.(\S+)')
        filename_m = filename_r.match(filename)
        print(filename.encode(sys.stdout.encoding, errors='replace').decode('utf-8'))
        print(' ! - has been shortened to - ! ')
        filename = filename_m.group(1) + '.' + filename_m.group(2)
        print(filename.encode(sys.stdout.encoding, errors='replace').decode('utf-8'))
    f = open('files/' + input_subfolder + '/orig/' + filename, 'wb')
    f.write(original_file)
    f.close()
    client.close()
    # mp3 --------------------
    print(" - mp3...")
    client.connect()
    client.putrequest("GET", base_donload_mp3 + str(entry_number) + '/file')
    default_headers(client, botb_cookies)
    client.endheaders()
    response = client.getresponse()
    if not response.getheader('Content-Length') or is_visual(botb_cookies, entry_number):
        print ('   > No mp3 render!')
        return
    if not filename.lower().endswith('.mp3'):
        filename = filename + ".mp3"
    original_file = response.read()
    f = open('files/' + input_subfolder + '/mp3/' + filename, 'wb')
    f.write(original_file)
    f.close()
    tag_mp3(filename, entry_number, botb_cookies, input_subfolder)
    client.close()    

# ==================== #
# #### Main Logic #### #
# ==================== #

input_subfolder = input("subfolder name: ")

botb_cookies = botb_load_cookies()
botbr_info = botb_load_init_info(botb_cookies)
create_default_directories(input_subfolder)

print('helo there ' + botbr_info['username'] + '!~ (-:')
print('stats panel [[ lvl. ' + botbr_info['level'] + ' ' + botbr_info['class'].lower())
print('            [[ ' + botbr_info['levelup_progress'] + ' pts till lvl. ' + str(int(botbr_info['level'])+1))
print('            [[ ' + botbr_info['b00ns'] + ' b00ns')
print('_______________________________________')

input_from = input("entry from: ")
input_to = input("entry to: ")

for num in range(int(input_from), int(input_to)+1):
    print(" Donloadin' " + str(num) + "...")
    download_entry(botb_cookies, num, input_subfolder)
    time.sleep(2)
