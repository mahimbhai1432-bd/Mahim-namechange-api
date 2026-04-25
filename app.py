from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import FreeFire_pb2
import data_pb2
import jwt
from datetime import datetime
import time
import logging
import os
import urllib3
import base64

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== CONSTANTS ==========
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

MAX_RETRIES = 3
RETRY_DELAY = 1
SECRET_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"
# OAuth endpoints
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"

# ========== AES ENCRYPTION ==========
def encrypt_message(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def encrypt_api(plain_text: str) -> str:
    try:
        plain_bytes = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_bytes, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        logger.error(f"API encryption failed: {str(e)}")
        return ""

# ========== OAUTH TOKEN RETRIEVAL ==========
def get_token_with_retry(uid: str, password: str) -> dict | None:
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

    for attempt in range(MAX_RETRIES):
        try:
            oauth_response = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=10, verify=False)
            if oauth_response.status_code == 200:
                oauth_data = oauth_response.json()
                if 'access_token' in oauth_data and 'open_id' in oauth_data:
                    logger.info(f"Successfully got token for UID: {uid}")
                    return oauth_data
        except requests.RequestException as e:
            logger.warning(f"Request exception for UID {uid}: {str(e)}")

        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

# ========== MAJOR LOGIN (JWT GENERATION) ==========
def major_login_with_retry(access_token: str, open_id: str, platform_type: int = 4) -> str | None:
    for attempt in range(MAX_RETRIES):
        try:
            login_req = FreeFire_pb2.LoginReq()
            login_req.open_id = open_id
            login_req.open_id_type = str(platform_type)
            login_req.login_token = access_token
            login_req.client_version = "1.123.1"
            login_req.origin_platform_type = str(platform_type)
            login_req.release_channel = "DANGER_ALWAYS_ON_TOP"

            proto_bytes = login_req.SerializeToString()
            encrypted_data = encrypt_message(proto_bytes)

            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975F Build/PI)",
                "Content-Type": "application/octet-stream",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53"
            }

            response = requests.post(MAJOR_LOGIN_URL, data=encrypted_data,
                                     headers=headers, verify=False, timeout=10)

            if response.status_code == 200:
                login_res = FreeFire_pb2.LoginRes()
                login_res.ParseFromString(response.content)
                token = login_res.token
                if token:
                    return token
        except Exception as e:
            logger.warning(f"MajorLogin exception (attempt {attempt+1}): {e}")

        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

# ========== EAT TO ACCESS TOKEN CONVERSION ==========
def get_access_token_from_eat(eat_token: str) -> dict:
    try:
        url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        response = requests.get(url, allow_redirects=True, timeout=30, verify=False)

        if 'help.garena.com' in response.url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(response.url)
            params = parse_qs(parsed.query)

            if 'access_token' in params:
                access_token = params['access_token'][0]
                inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
                inspect_resp = requests.get(inspect_url, timeout=15, verify=False)

                if inspect_resp.status_code == 200:
                    token_data = inspect_resp.json()
                    if 'open_id' in token_data and 'platform' in token_data:
                        return {
                            'success': True,
                            'access_token': access_token,
                            'open_id': token_data['open_id'],
                            'platform_type': token_data.get('platform', 4),
                            'uid': token_data.get('uid'),
                            'region': params.get('region', [None])[0]
                        }
        return {'success': False, 'error': 'Invalid EAT token'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ========== JWT FROM ACCESS TOKEN ==========
def get_jwt_from_access_token(access_token: str) -> dict:
    try:
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        inspect_resp = requests.get(inspect_url, timeout=15, verify=False)

        if inspect_resp.status_code == 200:
            token_data = inspect_resp.json()
            if 'open_id' in token_data:
                platform_type = token_data.get('platform', 4)
                open_id = token_data['open_id']
                jwt_token = major_login_with_retry(access_token, open_id, platform_type)
                if jwt_token:
                    return {
                        'success': True,
                        'jwt_token': jwt_token,
                        'platform_type': platform_type,
                        'open_id': open_id,
                        'uid': token_data.get('uid')
                    }
        return {'success': False, 'error': 'Invalid Access Token'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ========== JWT FROM UID + PASSWORD ==========
def get_jwt_from_uid_password(uid: str, password: str) -> str | None:
    oauth_data = get_token_with_retry(uid, password)
    if not oauth_data:
        return None
    access_token = oauth_data['access_token']
    open_id = oauth_data['open_id']
    return major_login_with_retry(access_token, open_id, 4)

# ========== GENERIC JWT RETRIEVAL ==========
def get_jwt_token(params: dict) -> str | None:
    token = params.get('token')
    eat_token = params.get('eat_token')
    access_token = params.get('access_token')
    uid = params.get('uid')
    password = params.get('password')

    if token:
        return token
    if eat_token:
        eat_result = get_access_token_from_eat(eat_token)
        if eat_result.get('success'):
            jwt_token = major_login_with_retry(
                eat_result['access_token'],
                eat_result['open_id'],
                eat_result['platform_type']
            )
            if jwt_token:
                return jwt_token
    if access_token:
        access_result = get_jwt_from_access_token(access_token)
        if access_result.get('success'):
            return access_result['jwt_token']
    if uid and password:
        return get_jwt_from_uid_password(uid, password)
    return None

def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ SECRET_KEY[i % len(SECRET_KEY)])
        return dec.decode('utf-8', errors='replace')
    except Exception as e:
        logger.warning(f"Nickname decode failed: {e}")
        return encoded

def decode_jwt(token: str):
    try:
        if token.startswith('Bearer '):
            token = token[7:]
        decoded = jwt.decode(token, options={"verify_signature": False})
        uid = decoded.get('account_id', 'N/A')
        raw_nickname = decoded.get('nickname', 'N/A')
        if isinstance(raw_nickname, str) and raw_nickname != 'N/A':
            nickname = decode_nickname(raw_nickname)
        else:
            nickname = raw_nickname
        region = decoded.get('lock_region', 'N/A')
        return uid, nickname, region, True
    except Exception as e:
        logger.error(f"JWT decode error: {e}")
        return "N/A", "Invalid JWT", "N/A", False

# ========== NICKNAME CHANGE REQUEST ==========
def change_nickname_request(token: str, nickname: str) -> dict:
    url = "https://loginbp.ggpolarbear.com/MajorModifyNickname"
    freefire_version = "OB53"

    msg = data_pb2.Message()
    msg.data = nickname.encode('utf-8')
    msg.timestamp = int(time.time() * 1000)

    payload = msg.SerializeToString()
    encrypted_payload_hex = encrypt_api(payload.hex())
    encrypted_payload = bytes.fromhex(encrypted_payload_hex)

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Connection": "Keep-Alive",
    }

    try:
        response = requests.post(url, data=encrypted_payload, headers=headers,
                                 verify=False, timeout=10)
        return {"status": response.status_code, "response": response.text}
    except Exception as e:
        return {"status": 500, "response": str(e)}

# ========================
# API ENDPOINTS (No HTML)
# ========================

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Free Fire Nickname Changer API",
        "version": "2.1",
        "authentication_methods": ["guest_login", "jwt_token", "eat_token", "access_token"],
        "credit": "t.me/mahim_offcial_143"
    }), 200

@app.route('/get-info', methods=['GET'])
def get_info():
    token = request.args.get('token')
    if not token:
        return jsonify({"success": False, "message": "Token required"}), 400

    uid, nickname, region, valid = decode_jwt(token)
    if not valid:
        return jsonify({"success": False, "message": "Invalid token"}), 401

    return jsonify({
        "success": True,
        "uid": uid,
        "nickname": nickname,
        "region": region,
        "nickname_length": len(nickname),
        "credit": "t.me/mahim_offcial_143"
    })

@app.route('/change-name', methods=['GET'])
def change_name():
    token = request.args.get('token')
    eat_token = request.args.get('eat_token')
    access_token = request.args.get('access_token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    nickname = request.args.get('nickname')

    # Validate authentication
    if not (token or eat_token or access_token or (uid and password)):
        return jsonify({
            "success": False,
            "message": "Authentication required: provide token, eat_token, access_token, or uid+password"
        }), 400

    if not nickname:
        return jsonify({"success": False, "message": "Nickname required"}), 400

    if len(nickname) < 3 or len(nickname) > 12:
        return jsonify({
            "success": False,
            "message": "Nickname must be 3-12 characters",
            "error": "BR_ACCOUNT_INVALID_NAME_LEN"
        }), 400

    # Get JWT token
    params = {
        'token': token,
        'eat_token': eat_token,
        'access_token': access_token,
        'uid': uid,
        'password': password
    }
    jwt_token = get_jwt_token(params)
    if not jwt_token:
        return jsonify({
            "success": False,
            "message": "Failed to obtain JWT token – invalid credentials"
        }), 401

    # Decode JWT for user info
    user_uid, current_nickname, region, valid = decode_jwt(jwt_token)
    if not valid:
        return jsonify({"success": False, "message": "Invalid JWT token"}), 401

    # Perform nickname change
    result = change_nickname_request(jwt_token, nickname)

    response = {
        "success": result["status"] == 200,
        "status": result["status"],
        "uid": user_uid,
        "current_nickname": current_nickname,
        "new_nickname": nickname,
        "new_nickname_length": len(nickname),
        "region": region,
        "server_response": result["response"],
        "credit": "t.me/mahim_offcial_143"
    }

    # Specific error handling
    resp_text = result["response"]
    if "BR_ACCOUNT_DUPLICATE_NICKNAME" in resp_text:
        response["error"] = "Duplicate nickname – already exists"
    elif "BR_INVENTORY_NOT_ENOUGH_ITEMS" in resp_text:
        response["error"] = "No name change card in inventory"
    elif "BR_ACCOUNT_INVALID_NAME_LEN" in resp_text:
        response["error"] = "Invalid nickname length (3-12 characters)"
    elif "BR_ACCOUNT_DIRTY_NAME" in resp_text:
        response["error"] = "Invalid nickname – forbidden characters"
    elif "signature is invalid" in resp_text:
        response["error"] = "Invalid token signature"
    elif "BR_GOP_TOKEN_AUTH_FAILED" in resp_text:
        response["error"] = "Authentication failed – invalid token"

    return jsonify(response)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 1080))
    app.run(host='0.0.0.0', port=port, debug=False)