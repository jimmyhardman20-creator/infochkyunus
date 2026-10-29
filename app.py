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
MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

JWT_API_BASE = os.environ.get("JWT_API_BASE", "https://infoboka.vercel.app/token")  # JWT API BY JAHID X EMPIRE

# Vercel Hobby = 10s limit, Pro = 60s. Total time er niche rakhte hobe.
TOTAL_TIMEOUT = float(os.environ.get("TOTAL_TIMEOUT", "8"))
TOKEN_TTL = 6 * 3600

ACCOUNT_CREDENTIALS = {
    "BD": {"uid": "4154906111", "password": "7BC23AA30150C95046701844CD8863512284E01994571A6AC26A516F1A8D16A8"},
    "IND": {"uid": "4154906113", "password": "572D81BBA2ED8CA715844F9CEF9864392B58F2A8210F71DF27EB1D714EFD81FA"},
    "BR": {"uid": "4154906112", "password": "0F1730E44AA2A1AB41900917DEE5326AA2CCC01AD8EA34C1F4272251D66C64DE"},
}

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

_token_cache = {}
_item_cache = {}

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

def ff_headers(token=None):
    h = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION,
    }
    if token:
        h['Authorization'] = token
    return h

# =============================================
# Token
# =============================================
async def token_from_api(client, region, errors):
    cred = ACCOUNT_CREDENTIALS[region]
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

async def token_backup(client, region, errors):
    cred = ACCOUNT_CREDENTIALS[region]
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

        body = dict_to_proto({"open_id": open_id, "open_id_type": "4", "login_token": access_token,
                              "orign_platform_type": "4"}, FreeFire_pb2.LoginReq())
        r = await client.post(f"{LOGIN_URL}/MajorLogin", content=aes_cbc_encrypt(body),
                              headers=ff_headers(), timeout=6)
        if r.status_code != 200:
            errors.append(f"{region}: MajorLogin HTTP {r.status_code} (OB version thik ache?)")
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

async def get_token(client, region, errors, force=False):
    cached = _token_cache.get(region)
    if not force and cached and cached["expires_at"] > time.time():
        return cached
    info = await token_from_api(client, region, errors) or await token_backup(client, region, errors)
    if info:
        _token_cache[region] = info
    else:
        _token_cache.pop(region, None)
    return info

# =============================================
# Player info
# =============================================
async def fetch_player(client, uid, region, errors):
    payload = aes_cbc_encrypt(dict_to_proto({'a': uid, 'b': '7'}, main_pb2.GetPlayerPersonalShow()))

    for attempt in range(2):  # 2nd attempt = fresh token (expired token fix)
        info = await get_token(client, region, errors, force=(attempt == 1))
        if not info:
            return None
        try:
            r = await client.post(info["server_url"] + "/GetPlayerPersonalShow", content=payload,
                                  headers=ff_headers(info["token"]), timeout=6)
        except Exception as e:
            errors.append(f"{region}: request {type(e).__name__}: {e}")
            return None

        if r.status_code in (401, 403) and attempt == 0:
            _token_cache.pop(region, None)
            continue
        if r.status_code != 200 or not r.content:
            errors.append(f"{region}: GetPlayerPersonalShow HTTP {r.status_code} {r.text[:100]!r}")
            return None

        try:
            acc = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            acc.ParseFromString(r.content)
            result = json_format.MessageToDict(acc)
        except Exception as e:
            errors.append(f"{region}: proto parse {type(e).__name__}: {e}")
            return None

        if not result.get("basicInfo"):
            errors.append(f"{region}: empty basicInfo (player ei server e nai)")
            return None

        result["ban_status"] = "🔴 BANNED" if result.get("isBanned") else "🟢 UNBANNED"
        result["region"] = info["region"]
        return result
    return None

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
    async with httpx.AsyncClient(http2=False, follow_redirects=True) as client:
        tasks = [asyncio.create_task(fetch_player(client, uid, rg, errors)) for rg in REGION_PRIORITY]
        data = None
        try:
            for fut in asyncio.as_completed(tasks, timeout=TOTAL_TIMEOUT - 2):
                res = await fut
                if res:
                    data = res
                    break
        except asyncio.TimeoutError:
            errors.append("timeout: kono server time er moddhe reply dey nai")
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if not data:
            return None, {}, errors

        basic = data.get("basicInfo", {})
        pet = data.get("petInfo", {})
        cap = data.get("captainBasicInfo", {})
        ids = [basic.get("title"), cap.get("title"), pet.get("id"), pet.get("selectedSkillId"), pet.get("skinId")]
        try:
            names = await asyncio.wait_for(get_item_names(client, ids), timeout=2.5)
        except Exception:
            names = {}
        return data, names, errors

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
        data, names, errors = asyncio.run(lookup(int(uid)))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal error", "detail": f"{type(e).__name__}: {e}"}), 500

    if not data:
        print("Lookup failed:", errors)
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
            "CelebrityStatus": "Yes" if basic.get("showBrRank") else "No",
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
    return jsonify({
        "total_tokens": len(_token_cache),
        "tokens": {r: {"server_url": i["server_url"],
                       "expires_in": f"{(i['expires_at'] - time.time()) / 3600:.1f} hours"}
                   for r, i in _token_cache.items()},
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
