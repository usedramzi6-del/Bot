import requests
import secrets
import random
import uuid
import time
import os
import binascii
import re
from urllib.parse import urlencode
import SignerPy
from MedoSigner import Argus, Gorgon, md5, Ladon
import string
import telebot
from datetime import datetime, timedelta
import pycountry
import codecs
import logging

# Optional: configure basic logging for this module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ouss")

# ---------------- Hostnames: BASE + EU merged in a single BASE_HOSTS (no duplicates) ----------------
# Original large BASE list plus EU hosts merged together
BASE_HOSTS = [
    # original base hosts
    "api16-normal-c-alisg.tiktokv.com", "api.tiktokv.com", "api-h2.tiktokv.com",
    "api-va.tiktokv.com", "api16.tiktokv.com", "api16-va.tiktokv.com",
    "api19.tiktokv.com", "api19-va.tiktokv.com", "api21.tiktokv.com",
    "api15-h2.tiktokv.com", "api21-h2.tiktokv.com", "api21-va.tiktokv.com",
    "api22.tiktokv.com", "api22-va.tiktokv.com", "api-t.tiktok.com",
    "api16-normal-baseline.tiktokv.com", "api23-normal-zr.tiktokv.com",
    "api21-normal.tiktokv.com", "api22-normal-zr.tiktokv.com", "api33-normal.tiktokv.com",
    "api22-normal.tiktokv.com", "api31-normal.tiktokv.com", "api15-normal.tiktokv.com",
    "api31-normal-cost-sg.tiktokv.com", "api3-normal.tiktokv.com", "api31-normal-zr.tiktokv.com",
    "api9-normal.tiktokv.com", "api16-normal.tiktokv.com", "api16-normal.ttapis.com",
    "api19-normal-zr.tiktokv.com", "api16-normal-zr.tiktokv.com", "api16-normal-apix.tiktokv.com",
    "api74-normal.tiktokv.com", "api32-normal-zr.tiktokv.com", "api23-normal.tiktokv.com",
    "api32-normal.tiktokv.com", "api16-normal-quic.tiktokv.com", "api-normal.tiktokv.com",
    "api16-normal-apix-quic.tiktokv.com", "api19-normal-tiktokv.com", "api19-normal.tiktokv.com",
    "api31-normal-cost-mys.tiktokv.com", "im-va.tiktokv.com", "imapi-16.tiktokv.com",
    "imapi-16.musical.ly", "imapi-mu.isnssdk.com", "api.tiktok.com", "api.ttapis.com",
    "api.tiktokv.us", "api.tiktokv.eu", "api.tiktokw.us", "api.tiktokw.eu",
    "webcast-ws16-normal-useast5.tiktokv.us", "webcast-ws16-normal-useast8.tiktokv.us",
    "webcast16-normal-useast5.tiktokv.us", "webcast16-normal-useast8.tiktokv.us",
    "webcast19-normal-useast5.tiktokv.us", "webcast19-normal-useast8.tiktokv.us",
    "api16-core-useast5.tiktokv.us", "api16-core-useast8.tiktokv.us",
    "api16-normal-useast5.tiktokv.us", "api16-normal-useast8.tiktokv.us",
    "api19-core-useast5.tiktokv.us", "api19-core-useast8.tiktokv.us",
    "api19-normal-useast5.tiktokv.us", "api19-normal-useast8.tiktokv.us",
    "ad.tiktokv.us", "tiktokv.us", "tiktokw.us",
    # EU hosts (merged)
    "api16-normal-eu-ams.tiktokv.com",
    "api16-normal-eu-fra.tiktokv.com",
    "api16-normal-eu-lon.tiktokv.com",
    "api16-normal-eu-par.tiktokv.com",
    "api16-normal-eu-mad.tiktokv.com",
    "api16-normal-eu-zrh.tiktokv.com",
    "api16-normal-eu-arn.tiktokv.com",
    "api16-normal-eu-waw.tiktokv.com",
    "api16-normal-eu-mil.tiktokv.com",
    "webcast16-normal-eu.tiktokv.com",
    "api16-core-eu.tiktokv.com",
    "api16-normal-eu-quic.tiktokv.com",
    "api-eu.tiktokv.com",
    "api16-normal-eu-ams.snssdk.com",
    # additional common EU webcast/core endpoints (examples that may be useful)
    "webcast16-normal-no1a.tiktokv.eu",
    "webcast16-normal-no1.tiktokv.eu",
    "api16-core-eu-ams.tiktokv.com",
    "api16-core-eu-fra.tiktokv.com",
]

def _dedupe_preserve_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

# Build Hostnames by deduping while preserving the order (BASE first, then EU entries already appended above)
Hostnames = _dedupe_preserve_order(BASE_HOSTS)
logger.info("Hostnames built: %d hosts", len(Hostnames))
# -------------------------------------------------------------------------

def get_available_ways(host, token, params, cookies, proxies=None):
    try:
        params_step2 = params.copy()
        params_step2['not_login_ticket'] = token
        params_step2['ts'] = str(int(time.time()))
        params_step2['_rticket'] = str(int(time.time() * 1000))

        url_step2 = f"https://{host}/passport/auth/available_ways/?" + urlencode(params_step2)

        signature_step2 = SignerPy.sign(params=url_step2, payload=None, version=4404)
        
        headers_step2 = {
            'User-Agent': "com.zhiliaoapp.musically.go/410203 (Linux; U; Android 14; ar; RMX3834; Build/UP1A.231005.007;tt-ok/3.12.13.44.lite-ul)",
            'x-ss-req-ticket': signature_step2.get('x-ss-req-ticket', ''),
            'x-ss-stub': signature_step2.get('x-ss-stub', ''),
            'x-gorgon': signature_step2.get("x-gorgon", ""),
            'x-khronos': signature_step2.get("x-khronos", ""),
            'x-tt-passport-csrf-token': cookies.get('passport_csrf_token', ''),
            'passport_csrf_token': cookies.get('passport_csrf_token', ''),
            'content-type': "application/x-www-form-urlencoded",
            'x-ss-dp': "1340",
            'sdk-version': "2",
            'x-tt-ultra-lite': "1",
        }

        res_step2 = requests.post(
            url_step2,
            headers=headers_step2,
            cookies=cookies,
            timeout=15,
        )
        
        response_json_step2 = res_step2.json()
  
        if 'success' in response_json_step2.get("message", ""):
            data_step2 = response_json_step2.get('data', {})
            
            return {
                'data': {
                    'has_email': data_step2.get('has_email', False),
                    'has_mobile': data_step2.get('has_mobile', False),
                    'has_oauth': data_step2.get('has_oauth', False),
                    'has_passkey': data_step2.get('has_passkey', False),
                    'oauth_platforms': data_step2.get('oauth_platforms', [])
                },
                'message': 'success',
                'host': host
            }
          
    except Exception:
        logger.debug("get_available_ways failed for host %s", host, exc_info=True)
    return None


def find_account_end_point(username, proxies=None):
    for host in Hostnames:
        try:
            secret = secrets.token_hex(16)
            cookies = {
                "passport_csrf_token": secret,
                "passport_csrf_token_default": secret
            }

            params = {
                'request_tag_from': "h5",
                'manifest_version_code': "410203",
                '_rticket': str(int(time.time() * 1000)),
                'app_language': "ar",
                'app_type': "normal",
                'iid': str(random.randint(1, 10**19)),
                'app_package': "com.zhiliaoapp.musically.go",
                'channel': "googleplay",
                'device_type': "RMX3834",
                'language': "ar",
                'host_abi': "arm64-v8a",
                'locale': "ar",
                'resolution': "720*1454",
                'openudid': "b57299cf6a5bb211",
                'update_version_code': "410203",
                'ac2': "lte",
                'cdid': str(uuid.uuid4()),
                'sys_region': "EG",
                'os_api': "34",
                'timezone_name': "Asia/Baghdad",
                'dpi': "272",
                'carrier_region': "IQ",
                'ac': "4g",
                'device_id': str(random.randint(1, 10**19)),
                'os': "android",
                'os_version': "14",
                'timezone_offset': "10800",
                'version_code': "410203",
                'app_name': "musically_go",
                'ab_version': "41.2.3",
                'version_name': "41.2.3",
                'device_brand': "realme",
                'op_region': "IQ",
                'ssmix': "a",
                'device_platform': "android",
                'build_number': "41.2.3",
                'region': "EG",
                'aid': "1340",
                'ts': str(int(time.time())),
                'okhttp_version': "4.1.103.107-ul",
                'use_store_region_cookie': "1"
            }

            url = f"https://{host}/passport/find_account/tiktok_username/?" + urlencode(params)

            payload = {
                'mix_mode': "1",
                'username': username,
            }

            signature = SignerPy.sign(params=url, payload=payload, version=4404)

            headers = {
                'User-Agent': "com.zhiliaoapp.musically.go/410203 (Linux; U; Android 14; ar; RMX3834; Build/UP1A.231005.007;tt-ok/3.12.13.44.lite-ul)",
                'x-ss-req-ticket': signature.get('x-ss-req-ticket', ''),
                'x-ss-stub': signature.get('x-ss-stub', ''),
                'x-gorgon': signature.get("x-gorgon", ""),
                'x-khronos': signature.get("x-khronos", ""),
                'x-tt-passport-csrf-token': cookies.get('passport_csrf_token', ''),
                'passport_csrf_token': cookies.get('passport_csrf_token', ''),
                'content-type': "application/x-www-form-urlencoded",
                'x-ss-dp': "1340",
                'sdk-version': "2",
                'x-tt-ultra-lite': "1",
                'x-vc-bdturing-sdk-version': "2.3.15.i18n",
                'ttzip-tlb': "1",
            }

            response = requests.post(
                url,
                data=payload,
                headers=headers,
                cookies=cookies,
                timeout=15
            )
            try:
                data = response.json()
                if data.get('message') == 'success':
                    token = data["data"]["token"]
                    return get_available_ways(host, token, params, cookies, proxies)
            except Exception:
                logger.debug("find_account_end_point: failed to parse response json for host %s", host, exc_info=True)
        except Exception:
            logger.debug("find_account_end_point: exception for host %s", host, exc_info=True)
    return None


def info(username):
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Android 10; Pixel 3 Build/QKQ1.200308.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6394.70 Mobile Safari/537.36 trill_350402 JsSdk/1.0 NetType/MOBILE Channel/googleplay AppName/trill app_version/35.3.1 ByteLocale/en ByteFullLocale/en Region/IN AppId/1180 Spark/1.5.9.1 AppVersion/35.3.1 BytedanceWebview/d8a21c6",
    }
    try:
        tikinfo = requests.get(f'https://www.tiktok.com/@{username}', headers=headers).text
        getting = str(tikinfo.split('webapp.user-detail"')[1]).split('"RecommendUserList"')[0]
        user_id = str(getting.split('id":"')[1]).split('",')[0]
        try:
            binary = "{0:b}".format(int(user_id))
            i = 0
            bits = ""
            while i < 31:
                bits += binary[i]
                i += 1
                timestamp = int(bits, 2)
                cdt = datetime.fromtimestamp(timestamp)
        except:
            cdt = ""
        try:
            username_modifytime_timestamp = str(getting.split('uniqueIdModifyTime":')[1]).split(',')[0]
            username_modifytime = datetime.fromtimestamp(int(username_modifytime_timestamp))
            swap_time = username_modifytime + timedelta(days=30)
        except:
            username_modifytime = ""
            swap_time = ""
        try:
            name = str(getting.split('nickname":"')[1]).split('",')[0]
        except:
            name = ""
        try:
            bio = str(getting.split('signature":"')[1]).split('",')[0]
        except:
            bio = ""
        try:
            country = str(getting.split('region":"')[1]).split('",')[0]
        except:
            country = "" 
        try:
            countryn = str(pycountry.countries.get(alpha_2=country)).split("name='")[1].split("'")[0]
        except:
            countryn = ""
        try:
            countryf = str(pycountry.countries.get(alpha_2=country)).split("flag='")[1].split("'")[0]    
        except:
            countryf = ""    
        try:
            private = str(getting.split('privateAccount":')[1]).split(',')[0]
        except:
            private = ""
        try:
            followers = str(getting.split('followerCount":')[1]).split(',')[0]
        except:
            followers = "" 
        try:
            following = str(getting.split('followingCount":')[1]).split(',')[0]
        except:
            following = ""
        try:
            like = str(getting.split('heart":')[1]).split(',')[0]
        except:
            like = ""
        try:
            video = str(getting.split('videoCount":')[1]).split(',')[0]
        except:
            video = ""
        try:
            avatar = str(getting.split('avatarThumb":"')[1]).split('",')[0]
        except:
            avatar = ""
        if avatar:
            avatar = codecs.decode(avatar, 'unicode_escape')

        return {
            'user_id': user_id,
            'cdt': cdt,
            'username_modifytime': username_modifytime,
            'countryn': countryn,
            'countryf': countryf,
            'name': name,
            'bio': bio,
            'country': country,
            'private': private,
            'followers': followers,
            'following': following,
            'like': like,
            'video': video,
            'avatar': avatar
        }
    except Exception:
        logger.debug("info() failed for username %s", username, exc_info=True)
        return None


def sign_level(params, payload: str = None, sec_device_id: str = "", cookie: str or None = None, aid: int = 1233, license_id: int = 1611921764, sdk_version_str: str = "2.3.1.i18n", sdk_version: int = 2, platform: int = 19, unix: int = None):
    x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload != None else None
    if not unix:
        unix = int(time.time())
    return Gorgon(params, unix, payload, cookie).get_value() | {
        "x-ladon": Ladon.encrypt(unix, license_id, aid),
        "x-argus": Argus.get_sign(params, x_ss_stub, unix, platform=platform, aid=aid, license_id=license_id, sec_device_id=sec_device_id, sdk_version=sdk_version_str, sdk_version_int=sdk_version)
    }


def get_level(username):
    user_info = info(username)
    user_id = user_info['user_id'] if user_info else None
    if not user_id:
        return None

    # Use a EU webcast endpoint by default to try to get EU-levels.
    url = "https://webcast16-normal-no1a.tiktokv.eu/webcast/user/?request_from=profile_card_v2&request_from_scene=1&target_uid=" + \
        str(user_id)+"&iid="+str(random.randint(1, 10**19))+"&device_id="+str(random.randint(1, 10**19))+"&ac=wifi&channel=googleplay&aid=1233&app_name=musical_ly&version_code=300102&version_name=30.1.2&device_platform=android&os=android&ab_version=30.1.2&ssmix=a&device_type=RMX3511&device_brand=realme&language=ar&os_api=33&os_version=13&openudid="+str(binascii.hexlify(os.urandom(8)).decode())+"&manifest_version_code=2023001020&resolution=1080*2236&dpi=360&update_version_code=2023001020&_rticket="+str(round(random.uniform(
            1.2, 1.6) * 100000000) * -1) + "4632"+"&current_region=IQ&app_type=normal&sys_region=IQ&mcc_mnc=41805&timezone_name=Asia%2FBaghdad&carrier_region_v2=418&residence=IQ&app_language=ar&carrier_region=IQ&ac2=wifi&uoo=0&op_region=IQ&timezone_offset=10800&build_number=30.1.2&host_abi=arm64-v8a&locale=ar&region=IQ&content_language=gu%2C&ts="+str(round(random.uniform(1.2, 1.6) * 100000000) * -1)+"&cdid="+str(uuid.uuid4())+"&webcast_sdk_version=2920&webcast_language=ar&webcast_locale=ar_IQ"
    headers = {
        'User-Agent': "com.zhiliaoapp.musically/2023001020 (Linux; U; Android 13; ar; RMX3511; Build/TP1A.220624.014; Cronet/TTNetVersion:06d6a583 2023-04-17 QuicVersion:d298137e 2023-02-13)"}
    headers.update(sign_level(url.split('?')[1], '', "AadCFwpTyztA5j9L" + ''.join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(9)), None, 1233))

    try:
        response = requests.get(url, headers=headers)
        match = re.search(r'"default_pattern":"(.*?)"', response.text)
        if match:
            return match.group(1)
    except Exception:
        logger.debug("get_level() failed for username %s", username, exc_info=True)
    return None



if __name__ == "__main__":
    BOT_TOKEN = input("Enter bot token: ")
    bot = telebot.TeleBot(BOT_TOKEN)

    @bot.message_handler(commands=['start'])
    def start(message):
        bot.reply_to(message, "Send me a TikTok username to check account info")

    @bot.message_handler(func=lambda message: True)
    def check_username(message):
        username = message.text.strip()
        user_info = info(username)
        if not user_info:
            bot.reply_to(message, "User not found or invalid username.")
            return
        
        result = find_account_end_point(username)
        caption = f"Username: @{username}\n"
        if user_info['name']:
            caption += f"Name: {user_info['name']}\n"
        if user_info['bio']:
            caption += f"Bio: {user_info['bio']}\n"
        if user_info['country']:
            caption += f"Country: {user_info['country']}"
            if user_info['countryn']:
                caption += f" ({user_info['countryn']})"
            if user_info['countryf']:
                caption += f" {user_info['countryf']}"
            caption += "\n"
        if user_info['cdt']:
            caption += f"Created: {user_info['cdt'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        if user_info['username_modifytime']:
            caption += f"Username Modified: {user_info['username_modifytime'].strftime('%Y-%m-%d %H:%M:%S')}\n"
       
        if user_info['private']:
            caption += f"Private: {'Yes' if user_info['private'] == 'true' else 'No'}\n"
        if user_info['followers']:
            caption += f"Followers: {user_info['followers']}\n"
        if user_info['following']:
            caption += f"Following: {user_info['following']}\n"
        if user_info['like']:
            caption += f"Likes: {user_info['like']}\n"
        if user_info['video']:
            caption += f"Videos: {user_info['video']}\n"
        
        if result:
            data = result['data']
            email_status = "✅" if data.get('has_email') else "❌"
            phone_status = "✅" if data.get('has_mobile') else "❌"
            oauth_status = "✅" if data.get('has_oauth') else "❌"
            passkey_status = "✅" if data.get('has_passkey') else "❌"
            
            caption += f"Email : {email_status}\nPhone : {phone_status}\nOAuth : {oauth_status}\nPasskey : {passkey_status}"
            
            platforms = data.get('oauth_platforms', [])
            if platforms:
                caption += f"\nPlatforms : {', '.join(platforms)}"
        else:
            caption += "فشلت في فحص الروابط الخارجيه\n"
        
        level = get_level(username)
        if level:
            caption += f"\nLevel : {level}"
        else:
            caption += "\nLevel : Unknown"
        
        if user_info['avatar']:
            try:
                bot.send_photo(message.chat.id, user_info['avatar'], caption=caption)
            except:
                bot.reply_to(message, caption)
        else:
            bot.reply_to(message, caption)

    bot.polling()