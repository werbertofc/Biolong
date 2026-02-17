from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import base64
import json
import jwt
import time
from datetime import datetime, timedelta, timezone
import my_pb2
import output_pb2
import proto_long_bio_pb2

app = Flask(__name__)

JWT_LIFETIME_HOURS = 7
jwt_token_cache = {}

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    8: "Google",
    10: "AppleId",
    11: "X (Twitter)"
}

def convert_timestamp_to_human_readable(timestamp_seconds: int) -> dict:
    try:
        utc_time = datetime.fromtimestamp(timestamp_seconds, tz=timezone.utc)
        ist_offset = timedelta(hours=5, minutes=30)
        ist_time = utc_time + ist_offset
        current_time = int(time.time())
        time_remaining = timestamp_seconds - current_time
        days = time_remaining // (24 * 3600)
        hours = (time_remaining % (24 * 3600)) // 3600
        minutes = (time_remaining % 3600) // 60
        seconds = time_remaining % 60
        is_expired = time_remaining <= 0
        return {
            "timestamp": timestamp_seconds,
            "utc_time": utc_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "ist_time": ist_time.strftime("%Y-%m-%d %H:%M:%S IST"),
            "time_remaining_seconds": time_remaining,
            "time_remaining_human": f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds" if time_remaining > 0 else "Expired",
            "is_expired": is_expired
        }
    except Exception as e:
        return {
            "timestamp": timestamp_seconds,
            "utc_time": "Invalid timestamp",
            "ist_time": "Invalid timestamp",
            "time_remaining_seconds": 0,
            "time_remaining_human": "Invalid timestamp",
            "is_expired": True,
            "error": str(e)
        }

def encrypt_message(plaintext, key_bytes, iv_bytes):
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def get_oauth_token(uid, password):
    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10)
        if oauth_response.status_code == 200:
            oauth_data = oauth_response.json()
            if 'access_token' in oauth_data and 'open_id' in oauth_data:
                return oauth_data
    except requests.RequestException:
        pass
    return None

def get_token_inspect_data(access_token):
    try:
        resp = requests.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=15,
            verify=False
        )
        data = resp.json()
        if 'open_id' in data and 'platform' in data and 'uid' in data:
            if 'expiry_time' in data:
                expiry_info = convert_timestamp_to_human_readable(data['expiry_time'])
                data['expiry_info'] = expiry_info
            elif 'expires_in' in data:
                expires_at = int(time.time()) + data['expires_in']
                expiry_info = convert_timestamp_to_human_readable(expires_at)
                data['expiry_info'] = expiry_info
            return data
    except Exception as e:
        print(f"Error inspecting token: {e}")
    return None

def major_login(access_token, open_id, platform_type=4):
    key_bytes = b'Yg&tc%DEuh6%Zc^8'[:16]
    iv_bytes = b'6oyZDr22E3ychjM%'[:16]
    try:
        game_data = my_pb2.GameData()
        game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.120.1"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data, key_bytes, iv_bytes)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51"
        }
        edata = bytes.fromhex(hex_encrypted_data)

        response = requests.post(url, data=edata, headers=headers, timeout=10)

        if response.status_code == 200:
            data_dict = None
            try:
                example_msg = output_pb2.Garena_420()
                example_msg.ParseFromString(response.content)
                data_dict = {field.name: getattr(example_msg, field.name)
                             for field in example_msg.DESCRIPTOR.fields
                             if field.name not in ["binary", "binary_data", "Garena420"]}
            except Exception:
                try:
                    data_dict = response.json()
                except ValueError:
                    return None

            if data_dict and "token" in data_dict:
                token_value = data_dict["token"]
                try:
                    jwt.decode(token_value, options={"verify_signature": False})
                    return token_value
                except Exception:
                    return None
    except requests.RequestException:
        pass
    return None

def generate_jwt_token(uid, password):
    for attempt in range(5):
        oauth_data = get_oauth_token(uid, password)
        if oauth_data:
            access_token = oauth_data['access_token']
            open_id = oauth_data['open_id']
            token = major_login(access_token, open_id)
            if token:
                return token
        time.sleep(2)
    return None

def generate_jwt_from_access_token(access_token):
    for attempt in range(5):
        token_data = get_token_inspect_data(access_token)
        if token_data:
            open_id = token_data['open_id']
            platform_type = token_data['platform']
            token = major_login(access_token, open_id, platform_type)
            if token:
                return token
        time.sleep(2)
    return None

def get_jwt_token(uid, password):
    cache_key = f"{uid}_{password}"
    token_data = jwt_token_cache.get(cache_key)
    if token_data and token_data['expiry'] > datetime.utcnow():
        return token_data['token']
    token = generate_jwt_token(uid, password)
    if token:
        expiry_time = datetime.utcnow() + timedelta(hours=JWT_LIFETIME_HOURS)
        jwt_token_cache[cache_key] = {'token': token, 'expiry': expiry_time}
        return token
    return None

def get_jwt_from_access_token(access_token):
    cache_key = f"access_{access_token}"
    token_data = jwt_token_cache.get(cache_key)
    if token_data and token_data['expiry'] > datetime.utcnow():
        return token_data['token']
    token = generate_jwt_from_access_token(access_token)
    if token:
        expiry_time = datetime.utcnow() + timedelta(hours=JWT_LIFETIME_HOURS)
        jwt_token_cache[cache_key] = {'token': token, 'expiry': expiry_time}
        return token
    return None

def encrypt_bio_data(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64.encode())
        return json.loads(decoded.decode())
    except Exception:
        return {}

def get_region_endpoint(jwt_token):
    try:
        decoded = decode_jwt(jwt_token)
        region = decoded.get("lock_region") or decoded.get("noti_region", "").upper()
        if region == "IND":
            return "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"
        elif region in ["BR", "US", "NA", "SAC"]:
            return "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"
        else:
            return "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"
    except Exception:
        return "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"

def update_bio_with_token(bio_text, jwt_token):
    try:
        data_msg = proto_long_bio_pb2.Data()
        data_msg.field_2 = 17
        data_msg.field_8 = bio_text
        data_msg.field_9 = 1
        data_msg.field_5.SetInParent()
        data_msg.field_6.SetInParent()
        data_msg.field_11.SetInParent()
        data_msg.field_12.SetInParent()

        encrypted_data_hex = encrypt_bio_data(data_msg.SerializeToString())
        data_bytes_send = binascii.unhexlify(encrypted_data_hex)

        primary_endpoint = get_region_endpoint(jwt_token)
        endpoints = [
            primary_endpoint,
            "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
            "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
            "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"
        ]

        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        decoded = decode_jwt(jwt_token)
        region = decoded.get("lock_region") or decoded.get("noti_region", "Unknown")

        last_error = None
        for url in endpoints:
            try:
                headers["Host"] = url.split("//")[1].split("/")[0]
                response = requests.post(url, headers=headers, data=data_bytes_send, timeout=10)
                if response.status_code == 200:
                    return {
                        "success": True,
                        "message": "Bio updated successfully",
                        "name": decoded.get("nickname", "Unknown"),
                        "uid": decoded.get("account_id", "Unknown"),
                        "region": region,
                        "credits": {
                            "developer": "t.me/danger_ff_like",
                            "main channel": "t.me/freefirelikesdanger",
                            "free apis channel": "t.me/dangerfreeapis"
                        }
                    }
                else:
                    last_error = f"Status: {response.status_code}, Response: {response.text}"
            except Exception as e:
                last_error = f"Error: {str(e)}"
                continue

        return {
            "success": False,
            "message": "Failed to update bio on all endpoints",
            "error": last_error,
            "region": region
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

@app.route('/')
def home():
    return jsonify({
        "message": "Free Fire Bio Updater API",
        "endpoints": {
            "/update_bio": "update bio and one of: token, uid+password, access_token"
        },
        "credit": "t.me/danger_ff_like"
    })

@app.route('/update_bio', methods=['POST', 'GET'])
def update_bio():
    try:
        data = request.get_json(silent=True) or {}
        bio = data.get('bio') or request.args.get('bio') or request.form.get('bio')
        token = data.get('token') or request.args.get('token') or request.form.get('token')
        uid = data.get('uid') or request.args.get('uid') or request.form.get('uid')
        password = data.get('password') or request.args.get('password') or request.form.get('password')
        access_token = data.get('access_token') or request.args.get('access_token') or request.form.get('access_token')

        if not bio:
            return jsonify({"success": False, "error": "Bio is required", "credit": "t.me/danger_ff_like"}), 400
        if len(bio) > 250:
            return jsonify({"success": False, "error": "Bio must be 250 characters or less", "credit": "t.me/danger_ff_like"}), 400
        lines = [line for line in bio.split('\n') if line.strip()]
        if len(lines) > 3:
            return jsonify({"success": False, "error": "Bio must have maximum 3 lines", "credit": "t.me/danger_ff_like"}), 400

        jwt_token = None
        if token:
            jwt_token = token
        elif uid and password:
            jwt_token = get_jwt_token(uid, password)
            if not jwt_token:
                return jsonify({"success": False, "error": "Failed to generate JWT token. Please check your UID and password.", "credit": "t.me/danger_ff_like"}), 400
        elif access_token:
            jwt_token = get_jwt_from_access_token(access_token)
            if not jwt_token:
                return jsonify({"success": False, "error": "Failed to generate JWT token from access token. Please check your access token.", "credit": "t.me/danger_ff_like"}), 400
        else:
            return jsonify({"success": False, "error": "Authentication method is required (token, uid+password, or access_token)", "credit": "t.me/danger_ff_like"}), 400

        result = update_bio_with_token(bio, jwt_token)
        if result["success"]:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Server error: {str(e)}", "credit": "t.me/danger_ff_like"}), 500

@app.route('/api/update_bio', methods=['POST', 'GET'])
def api_update_bio():
    return update_bio()

if __name__ == '__main__':
    port = 5050
    app.run(host='0.0.0.0', port=port, debug=False)