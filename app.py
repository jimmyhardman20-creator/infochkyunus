import asyncio
import time
import json
import os
import sys
import traceback
from datetime import datetime, timedelta

import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from google.protobuf import json_format

# ============= Proto files (same folder) =============
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROTO_ERROR = None
try:
    import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    import GetOutfit_pb2  # noqa: F401
except Exception as e:  # don't sys.exit on Vercel - it kills the function
    PROTO_ERROR = f"{type(e).__name__}: {e}"
    print(f"❌ Proto import error: {PROTO_ERROR}")

# =============================================
# CONFIG  (env var diye change kora jabe, redeploy chara)
# =============================================
RELEASEVERSION = os.environ.get("FF_RELEASE_VERSION", "OB55")
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"
# OB55 real client theke (capture): client 1.132.13, Unity 2018.4.12f1
CLIENT_VERSION = os.environ.get("FF_CLIENT_VERSION", "1.132.13")
UNITY_VERSION = os.environ.get("FF_UNITY_VERSION", "2018.4.12f1")
GAME_UA = f"UnityPlayer/{UNITY_VERSION} (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

JWT_API_BASE = os.environ.get("JWT_API_BASE", "https://infoboka.vercel.app/token")  # JWT API BY JAHID X EMPIRE

# Vercel Hobby = 10s limit, Pro = 60s. Total time er niche rakhte hobe.
TOTAL_TIMEOUT = float(os.environ.get("TOTAL_TIMEOUT", "8"))
TOKEN_TTL = 6 * 3600

# Ek region e onek account dite parben -> 429 khele next account e jabe.
# NIJER guest account use korun. Public code er account sobai use kore, tai 429 dey.
# Vercel env e FF_ACCOUNTS = {"BD":[{"uid":"..","password":".."}], "IND":[...], "BR":[...]} dileo hobe.
DEFAULT_ACCOUNTS = {
    "BD": [
        {"uid": "4154906111", "password": "7BC23AA30150C95046701844CD8863512284E01994571A6AC26A516F1A8D16A8"},
    ],
    "IND": [
        {"uid": "4154906113", "password": "572D81BBA2ED8CA715844F9CEF9864392B58F2A8210F71DF27EB1D714EFD81FA"},
    ],
    "BR": [
        {"uid": "4154906112", "password": "0F1730E44AA2A1AB41900917DEE5326AA2CCC01AD8EA34C1F4272251D66C64DE"},
    ],
}
try:
    ACCOUNTS = json.loads(os.environ["FF_ACCOUNTS"]) if os.environ.get("FF_ACCOUNTS") else DEFAULT_ACCOUNTS
except Exception as e:
    print(f"❌ FF_ACCOUNTS parse error: {e}")
    ACCOUNTS = DEFAULT_ACCOUNTS

# Shared JWT API (sobai use kore) -> default OFF. "1" dile age oita try korbe.
USE_JWT_API = os.environ.get("USE_JWT_API", "0") == "1"
COOLDOWN_429 = int(os.environ.get("COOLDOWN_429", "90"))      # 429 khawa account koto sec bosha thakbe
RESULT_CACHE_TTL = int(os.environ.get("RESULT_CACHE_TTL", "300"))  # same UID result cache (sec)

REGION_CONFIG = {
    "BD": "https://clientbp.ppmainecoonghj.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
}
LOGIN_URL = "https://loginbp.ppmainecoonghj.com"
REGION_PRIORITY = ["BD", "IND", "BR"]

app = Flask(__name__)
CORS(app)

_token_cache = {}     # key: "REGION:uid"
_cooldown = {}        # key: "REGION:uid" -> until timestamp
_item_cache = {}
_result_cache = {}    # uid -> (expires, data, names)
_uid_region = {}      # uid -> region jekhane age pawa gechilo

# =============================================
# Helpers
# =============================================
def pkcs7_pad(data: bytes) -> bytes:
    n = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([n] * n)

def aes_cbc_encrypt(plaintext: bytes) -> bytes:
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(pkcs7_pad(plaintext))

def dict_to_proto(data: dict, proto_message) -> bytes:
    json_format.ParseDict(data, proto_message)
    return proto_message.SerializeToString()

def valid_url(u):
    return isinstance(u, str) and u.startswith("http")

def ff_headers(token=None, login=False):
    h = {
        'User-Agent': USERAGENT if login else GAME_UA,
        'Connection': "Keep-Alive",
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'Content-Type': "application/x-www-form-urlencoded" if not login else "application/octet-stream",
        'X-Unity-Version': UNITY_VERSION,
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }
    if token:
        h['Authorization'] = token
        h['X-GA-SV'] = str(int(time.time()))
    return h

# =============================================
# Raw protobuf encoder (MajorLogin OB55 payload e 60+ field, proto file e nai)
# =============================================
def _varint(n: int) -> bytes:
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def pb_encode(fields: dict) -> bytes:
    out = bytearray()
    for num in sorted(fields, key=int):
        v = fields[num]
        num = int(num)
        if isinstance(v, bool):
            v = int(v)
        if isinstance(v, int):
            out += _varint(num << 3) + _varint(v)
        else:
            b = pb_encode(v) if isinstance(v, dict) else (v if isinstance(v, bytes) else str(v).encode())
            out += _varint((num << 3) | 2) + _varint(len(b)) + b
    return bytes(out)

def major_login_payload(open_id: str, access_token: str) -> bytes:
    """OB55 real client er login payload (device info generic kora)."""
    import uuid
    from datetime import datetime as _dt
    return pb_encode({
        3: _dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire",
        5: 1,
        7: CLIENT_VERSION,
        8: "Android OS 14 / API-34 (UP1A.231005.007/T505NXXS4CXF1)",
        9: "Handheld",
        10: "Jio",
        11: "WIFI",
        12: 2400,
        13: 1080,
        14: "400",
        15: "ARM64 FP ASIMD AES | 2200 | 8",
        16: 7612,
        17: "Adreno (TM) 642L",
        18: "OpenGL ES 3.2 V@0502.0",
        19: f"Google|{uuid.uuid4()}",
        20: "103.120.10.10",
        21: "en",
        22: open_id,
        23: "4",
        24: "Handheld",
        25: "samsung SM-A525F",
        29: access_token,
        30: 1,
        41: "Jio",
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 114357, 61: 44031, 62: 639, 64: 44555, 65: 114357, 66: 44555, 67: 114357,
        73: 3,
        74: "/data/app/~~TkA4r3HTgUB3TyTQDnSLVg==/com.dts.freefireth-3FcQpaMtijSJxpvJy4yoWg==/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~TkA4r3HTgUB3TyTQDnSLVg==/com.dts.freefireth-3FcQpaMtijSJxpvJy4yoWg==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019121229",
        85: 3,
        86: "OpenGLES2",
        87: 3071,
        88: 4,
        92: 10843,
        93: "android",
        95: 111107,
        96: '{"cur_rate":[60,30,90,120],"support_etc2":false}',
        99: "4",
        100: "4",
    })

# =============================================
# Token
# =============================================
async def token_from_api(client, region, cred, errors):
    try:
        r = await client.get(JWT_API_BASE, params={"uid": cred["uid"], "password": cred["password"]},
                             headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, timeout=6)
        if r.status_code != 200:
            errors.append(f"{region}: JWT API HTTP {r.status_code}")
            return None
        data = r.json()
        token = data.get("token") or data.get("jwt") or data.get("access_token")
        if not token:
            errors.append(f"{region}: JWT API no token -> {str(data)[:150]}")
            return None
        if not token.startswith("Bearer "):
            token = f"Bearer {token}"
        api_region = str(data.get("region") or data.get("lockRegion") or region).upper()
        server_url = data.get("serverUrl") or data.get("server_url")
        if not valid_url(server_url):
            server_url = REGION_CONFIG.get(api_region, REGION_CONFIG.get(region))
        return {"token": token, "region": api_region, "server_url": server_url,
                "expires_at": time.time() + TOKEN_TTL}
    except Exception as e:
        errors.append(f"{region}: JWT API {type(e).__name__}: {e}")
        return None

async def token_backup(client, region, cred, errors):
    try:
        payload = (f"uid={cred['uid']}&password={cred['password']}&response_type=token&client_type=2"
                   "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067")
        r = await client.post("https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant",
                              data=payload, headers={'User-Agent': USERAGENT,
                                                     'Content-Type': "application/x-www-form-urlencoded"}, timeout=6)
        if r.status_code != 200:
            errors.append(f"{region}: guest grant HTTP {r.status_code}")
            return None
        g = r.json()
        access_token, open_id = g.get("access_token"), g.get("open_id")
        if not access_token or not open_id:
            errors.append(f"{region}: guest grant empty")
            return None

        body = major_login_payload(open_id, access_token)
        r = await client.post(f"{LOGIN_URL}/MajorLogin", content=aes_cbc_encrypt(body),
                              headers=ff_headers(login=True), timeout=6)
        if r.status_code != 200:
            errors.append(f"{region}: MajorLogin HTTP {r.status_code} {r.text[:80]!r}")
            return None
        res = FreeFire_pb2.LoginRes()
        res.ParseFromString(r.content)
        msg = json_format.MessageToDict(res)
        token = msg.get("token")
        server_url = msg.get("serverUrl")
        if not token or not valid_url(server_url):
            errors.append(f"{region}: MajorLogin invalid response")
            return None
        return {"token": f"Bearer {token}", "region": msg.get("lockRegion", region),
                "server_url": server_url, "expires_at": time.time() + TOKEN_TTL}
    except Exception as e:
        errors.append(f"{region}: backup {type(e).__name__}: {e}")
        return None

async def get_token(client, region, cred, errors, force=False):
    key = f"{region}:{cred['uid']}"
    cached = _token_cache.get(key)
    if not force and cached and cached["expires_at"] > time.time():
        return cached
    info = None
    if USE_JWT_API:
        info = await token_from_api(client, region, cred, errors)
    if not info:
        info = await token_backup(client, region, cred, errors)
    if not info and not USE_JWT_API:
        info = await token_from_api(client, region, cred, errors)  # last fallback
    if info:
        _token_cache[key] = info
    else:
        _token_cache.pop(key, None)
    return info

# =============================================
# Player info
# =============================================
RATE_LIMITED = "rate_limited"

async def fetch_player(client, uid, region, errors, deadline):
    # real OB55 client body: {1: uid, 2: 7, 4: 1, 5: 1}
    payload = aes_cbc_encrypt(pb_encode({1: uid, 2: 7, 4: 1, 5: 1}))
    accounts = ACCOUNTS.get(region, [])
    now = time.time()
    usable = [c for c in accounts if _cooldown.get(f"{region}:{c['uid']}", 0) <= now]
    if not usable:
        errors.append(f"{region}: sob account cooldown e (429)")
        return RATE_LIMITED
    # least-recently-limited first, a little rotation
    usable.sort(key=lambda c: _cooldown.get(f"{region}:{c['uid']}", 0))

    hit_429 = False
    for cred in usable:
        key = f"{region}:{cred['uid']}"
        for attempt in range(2):  # 2nd attempt = fresh token
            if time.time() > deadline:
                errors.append(f"{region}: time shesh")
                return RATE_LIMITED if hit_429 else None
            info = await get_token(client, region, cred, errors, force=(attempt == 1))
            if not info:
                break
            try:
                r = await client.post(info["server_url"] + "/GetPlayerPersonalShow", content=payload,
                                      headers=ff_headers(info["token"]), timeout=5)
            except Exception as e:
                errors.append(f"{region}/{cred['uid']}: request {type(e).__name__}: {e}")
                break

            if r.status_code == 429:
                hit_429 = True
                _cooldown[key] = time.time() + COOLDOWN_429
                errors.append(f"{region}/{cred['uid']}: 429 rate limit -> next account")
                break
            if r.status_code in (401, 403) and attempt == 0:
                _token_cache.pop(key, None)
                continue
            if r.status_code != 200 or not r.content:
                errors.append(f"{region}/{cred['uid']}: HTTP {r.status_code} {r.text[:100]!r}")
                break

            try:
                acc = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                acc.ParseFromString(r.content)
                result = json_format.MessageToDict(acc)
            except Exception as e:
                errors.append(f"{region}: proto parse {type(e).__name__}: {e}")
                return None

            if not result.get("basicInfo"):
                errors.append(f"{region}: player ei server e nai")
                return None  # onno account e try kore labh nai

            # proto te "isBanned" field nai -> ager code sob player ke UNBANNED dekhato (vul)
            result["ban_status"] = ("🔴 BANNED" if result["isBanned"] else "🟢 UNBANNED") if "isBanned" in result else "❓ N/A"
            result["region"] = info["region"]
            return result
    return RATE_LIMITED if hit_429 else None

async def get_item_names(client, ids):
    async def one(i):
        if not i or str(i) == "0":
            return i, "N/A"
        i = str(i)
        if i in _item_cache:
            return i, _item_cache[i]
        try:
            r = await client.get(f"https://api.danger.workers.dev/item/{i}", timeout=2.5)
            name = r.json().get("name", i) if r.status_code == 200 else i
        except Exception:
            name = i
        _item_cache[i] = name
        return i, name
    pairs = await asyncio.gather(*(one(i) for i in set(ids)))
    return {str(k): v for k, v in pairs}

async def lookup(uid):
    errors = []
    cached = _result_cache.get(uid)
    if cached and cached[0] > time.time():
        return cached[1], cached[2], ["cache"], False

    deadline = time.time() + TOTAL_TIMEOUT - 2.5
    order = list(REGION_PRIORITY)
    if uid in _uid_region and _uid_region[uid] in order:
        order.remove(_uid_region[uid])
        order.insert(0, _uid_region[uid])

    data, limited = None, False
    async with httpx.AsyncClient(http2=False, follow_redirects=True) as client:
        # ek ek kore (parallel na) -> Garena te 3x kom request
        for region in order:
            if time.time() > deadline:
                errors.append("timeout")
                break
            res = await fetch_player(client, uid, region, errors, deadline)
            if res == RATE_LIMITED:
                limited = True
                continue
            if res:
                data = res
                _uid_region[uid] = region
                break

        if not data:
            return None, {}, errors, limited

        basic = data.get("basicInfo", {})
        pet = data.get("petInfo", {})
        cap = data.get("captainBasicInfo", {})
        ids = [basic.get("title"), cap.get("title"), pet.get("id"), pet.get("selectedSkillId"), pet.get("skinId")]
        try:
            remaining = max(0.5, deadline + 2 - time.time())
            names = await asyncio.wait_for(get_item_names(client, ids), timeout=min(2.5, remaining))
        except Exception:
            names = {}

    if len(_result_cache) > 2000:
        _result_cache.clear()
    _result_cache[uid] = (time.time() + RESULT_CACHE_TTL, data, names)
    return data, names, errors, False

def get_rank_name(rp):
    try:
        rp = int(rp)
    except Exception:
        return "N/A"
    tiers = [(1, "Bronze I"), (100, "Bronze II"), (200, "Bronze III"), (300, "Silver I"), (400, "Silver II"),
             (500, "Silver III"), (600, "Gold I"), (700, "Gold II"), (800, "Gold III"), (900, "Platinum I"),
             (1000, "Platinum II"), (1100, "Platinum III"), (1200, "Diamond I"), (1300, "Diamond II"),
             (1400, "Diamond III"), (1500, "Heroic"), (2000, "Master")]
    for limit, name in tiers:
        if rp < limit:
            return name
    return "Grandmaster"

def ts_to_bst(ts):
    try:
        ts = int(ts)
        if ts <= 0:
            return "N/A"
        dt = datetime.utcfromtimestamp(ts) + timedelta(hours=6)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except Exception:
        return "N/A"

# =============================================
# Routes
# =============================================
@app.route('/info')
def get_full_info():
    if PROTO_ERROR:
        return jsonify({"error": "Proto files load hoyni", "detail": PROTO_ERROR}), 500

    uid = request.args.get('uid', '').strip()
    if not uid:
        return jsonify({"error": "UID required"}), 400
    if not uid.isdigit():
        return jsonify({"error": "Invalid UID"}), 400

    try:
        data, names, errors, limited = asyncio.run(lookup(int(uid)))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal error", "detail": f"{type(e).__name__}: {e}"}), 500

    if not data:
        print("Lookup failed:", errors)
        if limited:
            return jsonify({"error": "Rate limited (429). Kichukkhon pore try korun ba aro account add korun.",
                            "debug": errors}), 429
        return jsonify({"error": "Player not found", "debug": errors}), 404

    n = lambda i: names.get(str(i), "N/A") if i and str(i) != "0" else "N/A"
    basic = data.get("basicInfo", {})
    clan = data.get("clanBasicInfo", {})
    social = data.get("socialInfo", {})
    pet = data.get("petInfo", {})
    cap = data.get("captainBasicInfo", {})
    credit = data.get("creditScoreInfo", {})

    prime = basic.get("primeLevel")
    prime_level = prime.get("level", "N/A") if isinstance(prime, dict) else (str(prime) if prime is not None else "N/A")

    return jsonify({
        "status": "success",
        "server_used": data.get("region", "Unknown"),
        "BanStatus": data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "CsRank": basic.get("csRank", "N/A"),
            "CsPoints": basic.get("csRankingPoints", 0),
            "Title": n(basic.get("title")),
            "Signature": social.get("signature", "N/A"),
        },
        "ActivityInformation": {
            "MostRecentOB": basic.get("releaseVersion", "N/A"),
            "BooyahPass": "Yes" if basic.get("hasElitePass") else "No",
            "CurrentBpBadges": basic.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(basic.get("rankingPoints", 0)),
            "BRPoints": basic.get("rankingPoints", 0),
            "ShowBRRank": str(bool(basic.get("showBrRank"))),
            "ShowCSRank": str(bool(basic.get("showCsRank"))),
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0)),
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A"),
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("isSelected") else "No",
            "PetNick": pet.get("name", "N/A"),
            "PetType": n(pet.get("id")),
            "PetSkill": n(pet.get("selectedSkillId")),
            "PetSkin": n(pet.get("skinId")),
            "PetExp": pet.get("exp", "N/A"),
            "PetLevel": pet.get("level", "N/A"),
        },
        "LeaderInformation": {
            "Name": cap.get("nickname", "N/A"),
            "UID": cap.get("accountId", "N/A"),
            "Level": cap.get("level", "N/A"),
            "Region": cap.get("region", "N/A"),
            "BooyahPass": "Yes" if cap.get("hasElitePass") else "No",
            "CreatedAt": ts_to_bst(cap.get("createAt", 0)),
            "LastLogin": ts_to_bst(cap.get("lastLoginAt", 0)),
            "MostRecentOB": cap.get("releaseVersion", "N/A"),
            "Title": n(cap.get("title")),
            "BpBadges": cap.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(cap.get("rankingPoints", 0)),
            "BRPoints": cap.get("rankingPoints", 0),
        },
    })

@app.route('/')
def home():
    return jsonify({
        "status": "running" if not PROTO_ERROR else "proto_error",
        "proto_error": PROTO_ERROR,
        "version": RELEASEVERSION,
        "endpoint": "/info?uid=UID",
        "example": "/info?uid=2084018498",
        "priority": "BD → IND → BR",
        "credit": "@Itz_Jahid_X",
    })

@app.route('/status')
def token_status():
    now = time.time()
    return jsonify({
        "use_jwt_api": USE_JWT_API,
        "accounts": {r: len(a) for r, a in ACCOUNTS.items()},
        "tokens": {k: f"{(i['expires_at'] - now) / 3600:.1f}h" for k, i in _token_cache.items()},
        "cooldown": {k: f"{int(t - now)}s" for k, t in _cooldown.items() if t > now},
        "cached_results": len(_result_cache),
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
