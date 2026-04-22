import os
import time
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, jsonify, request, send_file
import requests
import urllib3
from dotenv import load_dotenv
from cachetools import TTLCache
import io

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("traffic_monitor.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==========================================
# تنظیمات فورتی‌گیت اصلی (fg‑site2)
# ==========================================
FGT_IP = os.getenv("FGT_IP", "fg-site2.partcorp.ir")
API_TOKEN = os.getenv("FGT_API_TOKEN", "sz7sQpwwGx1Hj9qk1xd666gQm6wGz3")
VDOM = os.getenv("FGT_VDOM", "Internal")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# ==========================================
# تنظیمات فایروال دوم (fg‑part)
# ==========================================
FGT_PART_IP = os.getenv("FGT_PART_IP", "fg-part.partcorp.ir")
FGT_PART_TOKEN = os.getenv("FGT_PART_TOKEN", "9NQkw8Hdcd6009hqfmkq1GqwQ8hfqm")
FGT_PART_VDOM = os.getenv("FGT_PART_VDOM", "root")
MASHHAD_PART_POLICIES = list(range(1145, 1191))

# ==========================================
# تنظیمات LLM
# ==========================================
LLM_API_URL = os.getenv("LLM_API_URL", "https://llm-net.partcorp.ir/v1/chat/completions")
LLM_API_KEY = os.getenv("LLM_API_KEY", "sk-c5cbHOjQmpDvGi15Zn2hdw")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-oss-120b")

# ==========================================
# فایل سیاست‌ها
# ==========================================
POLICIES_FILE = "policies.json"

def fetch_policy_names_from_fgpart():
    """دریافت نام واقعی Policyهای فایروال دوم"""
    url = f"https://{FGT_PART_IP}/api/v2/cmdb/firewall/policy"
    params = {"vdom": FGT_PART_VDOM, "access_token": FGT_PART_TOKEN}
    names = {}
    try:
        response = requests.get(url, params=params, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        data = response.json()
        results = data.get('results', [])
        for policy in results:
            pid = policy.get('policyid')
            if pid in MASHHAD_PART_POLICIES:
                name = policy.get('name')
                if name:
                    names[pid] = name
        logger.info(f"Fetched {len(names)} policy names from fg‑part")
    except Exception as e:
        logger.error(f"Failed to fetch policy names from fg‑part: {e}")
    return names

def update_policy_names():
    """به‌روزرسانی نام Policyها در policies_config"""
    names = fetch_policy_names_from_fgpart()
    if not names:
        return
    group = policies_config['groups'].get('کاربران مشهد به تفکیک تیم', [])
    for p in group:
        pid = p['id']
        if pid in names:
            p['name'] = names[pid]
    save_policies(policies_config)

def load_policies():
    if not os.path.exists(POLICIES_FILE):
        names = fetch_policy_names_from_fgpart()
        default = {
            "groups": {
                "سرویس‌های تجاری": [
                    {"id": 1631, "name": "vira"},
                    {"id": 1728, "name": "gateway hpc"},
                    {"id": 1719, "name": "Repo-INF"},
                    {"id": 1834, "name": "npmrepo-7 to NPMJS"},
                    {"id": 1829, "name": "Datagathering-API-2"},
                    {"id": 1809, "name": "hpc backup"}
                ],
                "سرویس‌های داخلی (LocalService)": [
                    {"id": 202, "name": "دسترسی ماشین سرویس های عمومی توسعه و تست به هویتا"},
                    {"id": 199, "name": "پروکسی"},
                    {"id": 1002, "name": "localservices-vpn-5"}
                ],
                "کاربران تهران": [
                    {"id": 1790, "name": "کاربران تهران"}
                ],
                "کاربران مشهد": [
                    {"id": 1777, "name": "کاربران مشهد"}
                ],
                "کاربران مشهد به تفکیک تیم": [
                    {"id": pid, "name": names.get(pid, f"Policy {pid}")} for pid in MASHHAD_PART_POLICIES
                ]
            }
        }
        with open(POLICIES_FILE, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default
    with open(POLICIES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_policies(data):
    with open(POLICIES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

policies_config = load_policies()
threading.Thread(target=update_policy_names, daemon=True).start()

# ==========================================
# کش و سرویس پس‌زمینه
# ==========================================
cache = TTLCache(maxsize=1, ttl=2)
background_data = {}
background_lock = threading.Lock()
stop_background = threading.Event()

def fetch_raw_policy_data(fgt_ip, api_token, vdom):
    url = f"https://{fgt_ip}/api/v2/monitor/firewall/policy"
    params = {"vdom": vdom, "access_token": api_token}
    try:
        response = requests.get(url, params=params, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status()
        return response.json().get('results', [])
    except Exception as e:
        logger.error(f"Failed to fetch from {fgt_ip}: {e}")
        return []

def calculate_speed_from_samples(samples):
    if len(samples) < 2:
        return {}
    recent = samples[-5:]
    total_bytes_diff = {}
    total_time = 0.0
    for i in range(1, len(recent)):
        t_prev, bytes_prev = recent[i-1]
        t_curr, bytes_curr = recent[i]
        dt = t_curr - t_prev
        if dt <= 0:
            continue
        total_time += dt
        for pid, curr_bytes in bytes_curr.items():
            prev_bytes = bytes_prev.get(pid, curr_bytes)
            diff = curr_bytes - prev_bytes
            if diff < 0:
                diff = 0
            total_bytes_diff[pid] = total_bytes_diff.get(pid, 0) + diff
    if total_time == 0:
        return {}
    return {pid: (total_bytes * 8) / total_time for pid, total_bytes in total_bytes_diff.items()}

def background_worker():
    samples = []
    while not stop_background.is_set():
        try:
            t_start = time.perf_counter()
            data_main = fetch_raw_policy_data(FGT_IP, API_TOKEN, VDOM)
            data_part = fetch_raw_policy_data(FGT_PART_IP, FGT_PART_TOKEN, FGT_PART_VDOM)
            combined_data = data_main.copy()
            for item in data_part:
                pid = item.get('policyid')
                if pid in MASHHAD_PART_POLICIES:
                    existing = next((x for x in combined_data if x.get('policyid') == pid), None)
                    if existing:
                        existing.update(item)
                    else:
                        combined_data.append(item)

            bytes_map = {item.get('policyid'): item.get('bytes', 0) for item in combined_data}
            samples.append((t_start, bytes_map))
            if len(samples) > 100:
                samples.pop(0)
            speed_map = calculate_speed_from_samples(samples)

            policy_data = {}
            for item in combined_data:
                pid = item.get('policyid')
                if not pid:
                    continue
                sessions = item.get('active_sessions', 0)
                week_data = item.get('1_week_ipv4', {})
                bytes_array = week_data.get('bytes', [])
                if bytes_array:
                    today_bytes = bytes_array[-1]
                    week_bytes = sum(bytes_array)
                    daily_bytes = bytes_array
                else:
                    today_bytes = item.get('bytes', 0)
                    week_bytes = today_bytes
                    daily_bytes = [today_bytes] * 8
                policy_data[pid] = {
                    "volume_bytes": today_bytes,
                    "week_bytes": week_bytes,
                    "speed_bps": speed_map.get(pid, 0),
                    "sessions": sessions,
                    "daily_bytes": daily_bytes
                }
            with background_lock:
                global background_data
                background_data = policy_data
                cache['traffic'] = policy_data
            logger.info(f"Background poll OK. {len(policy_data)} policies.")
        except Exception as e:
            logger.error(f"Background error: {e}")
        time.sleep(1)

worker_thread = threading.Thread(target=background_worker, daemon=True)
worker_thread.start()

# ==========================================
# دریافت اطلاعات Source Address
# ==========================================
policy_sources = {}
sources_lock = threading.Lock()

def fetch_policy_sources():
    temp_dict = {}
    url = f"https://{FGT_IP}/api/v2/cmdb/firewall/policy"
    params = {"vdom": VDOM, "access_token": API_TOKEN}
    try:
        response = requests.get(url, params=params, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        data = response.json()
        results = data.get('results', [])
        for policy in results:
            pid = policy.get('policyid')
            if pid:
                srcaddr_objs = policy.get('srcaddr', [])
                src_names = [addr.get('name') for addr in srcaddr_objs if addr.get('name')]
                temp_dict[pid] = src_names if src_names else ["(any)"]
    except Exception as e:
        logger.error(f"Error fetching policy sources from main: {e}")

    url2 = f"https://{FGT_PART_IP}/api/v2/cmdb/firewall/policy"
    params2 = {"vdom": FGT_PART_VDOM, "access_token": FGT_PART_TOKEN}
    try:
        response2 = requests.get(url2, params=params2, verify=VERIFY_SSL, timeout=15)
        response2.raise_for_status()
        data2 = response2.json()
        results2 = data2.get('results', [])
        for policy in results2:
            pid = policy.get('policyid')
            if pid in MASHHAD_PART_POLICIES:
                srcaddr_objs = policy.get('srcaddr', [])
                src_names = [addr.get('name') for addr in srcaddr_objs if addr.get('name')]
                temp_dict[pid] = src_names if src_names else ["(any)"]
    except Exception as e:
        logger.error(f"Error fetching policy sources from part: {e}")

    with sources_lock:
        global policy_sources
        policy_sources = temp_dict
    logger.info(f"Fetched source addresses for {len(temp_dict)} policies.")

def sources_updater():
    while not stop_background.is_set():
        fetch_policy_sources()
        time.sleep(300)

sources_thread = threading.Thread(target=sources_updater, daemon=True)
sources_thread.start()
fetch_policy_sources()

# ==========================================
# دریافت آبجکت‌های آدرس
# ==========================================
address_objects = {}
address_lock = threading.Lock()

def fetch_address_objects():
    url = f"https://{FGT_IP}/api/v2/cmdb/firewall/address"
    params = {"vdom": VDOM, "access_token": API_TOKEN}
    try:
        response = requests.get(url, params=params, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        data = response.json()
        results = data.get('results', [])
        temp_dict = {}
        for addr in results:
            name = addr.get('name')
            if not name:
                continue
            ip_list = []
            if addr.get('type') == 'ipmask' and addr.get('subnet'):
                subnet_str = addr['subnet']
                parts = subnet_str.split()
                if len(parts) == 2:
                    ip, mask = parts
                    try:
                        import ipaddress
                        if '.' in mask:
                            cidr = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False).prefixlen
                        else:
                            cidr = mask
                        ip_list.append(f"{ip}/{cidr}")
                    except:
                        ip_list.append(ip)
                else:
                    ip_list.append(subnet_str)
            elif addr.get('type') == 'iprange' and addr.get('start-ip') and addr.get('end-ip'):
                ip_list.append(f"{addr['start-ip']}-{addr['end-ip']}")
            elif addr.get('type') == 'fqdn' and addr.get('fqdn'):
                ip_list.append(f"FQDN: {addr['fqdn']}")
            elif addr.get('type') == 'geography' and addr.get('country'):
                ip_list.append(f"Country: {addr['country']}")
            else:
                ip_list.append(f"({addr.get('type', 'unknown')})")
            temp_dict[name] = ip_list if ip_list else ["(no IP)"]
        with address_lock:
            global address_objects
            address_objects = temp_dict
        logger.info(f"Fetched {len(temp_dict)} address objects.")
    except Exception as e:
        logger.error(f"Error fetching address objects: {e}")

def address_updater():
    while not stop_background.is_set():
        fetch_address_objects()
        time.sleep(300)

address_thread = threading.Thread(target=address_updater, daemon=True)
address_thread.start()
fetch_address_objects()

# ==========================================
# APIها
# ==========================================
@app.route('/api/policy_source_ips')
def get_policy_source_ips():
    with address_lock:
        addr_map = address_objects.copy()
    with sources_lock:
        src_map = policy_sources.copy()
    result = {}
    for pid, src_names in src_map.items():
        ips = []
        for name in src_names:
            if name in addr_map:
                ips.extend(addr_map[name])
            else:
                ips.append(f"(unknown: {name})")
        result[pid] = list(set(ips))
    return jsonify(result)

def get_top_destinations(policy_id, limit=10):
    if policy_id in MASHHAD_PART_POLICIES:
        fgt_ip = FGT_PART_IP
        api_token = FGT_PART_TOKEN
        vdom = FGT_PART_VDOM
    else:
        fgt_ip = FGT_IP
        api_token = API_TOKEN
        vdom = VDOM

    url = f"https://{fgt_ip}/api/v2/monitor/fortiview/statistics"
    filter_obj = {"policyid": str(policy_id), "policytype": "policy"}
    params = {
        "type": "destination",
        "vdom": vdom,
        "count": limit,
        "device": "disk",
        "filter": json.dumps(filter_obj),
        "ip_version": "ipboth",
        "realtime": "true",
        "report_by": "destination",
        "sort_by": "bytes"
    }
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, params=params, headers=headers, verify=VERIFY_SSL, timeout=15)
        if response.status_code == 200:
            data = response.json()
            results_dict = data.get('results', {})
            details = results_dict.get('details', [])
            destinations = []
            for item in details:
                apps = item.get('apps', [])
                app_name = apps[0].get('name', 'N/A') if apps else 'N/A'
                country = item.get('country', '')
                flag_map = {
                    "United States": "🇺🇸", "Iran": "🇮🇷", "United Kingdom": "🇬🇧",
                    "Germany": "🇩🇪", "France": "🇫🇷", "Netherlands": "🇳🇱",
                    "Sweden": "🇸🇪", "Canada": "🇨🇦", "Australia": "🇦🇺",
                    "Reserved": "🌐"
                }
                flag = flag_map.get(country, "🌐")
                destinations.append({
                    "dst_ip": item.get('dstaddr'),
                    "dst_name": item.get('resolved', item.get('dstaddr')),
                    "bytes_sent": item.get('sentbyte', 0),
                    "bytes_rcvd": item.get('rcvdbyte', 0),
                    "sessions": item.get('sessions', 0),
                    "tx_bandwidth": item.get('tx_bandwidth', 0),
                    "rx_bandwidth": item.get('rx_bandwidth', 0),
                    "app_name": app_name,
                    "country": country,
                    "flag": flag
                })
            return destinations
        else:
            logger.error(f"API error {response.status_code}: {response.text[:200]}")
            return []
    except Exception as e:
        logger.error(f"Error in get_top_destinations: {e}")
        return []

def get_destination_info(dest_ip):
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    info = {"owner": "N/A", "location": "N/A", "latitude": None, "longitude": None, "running_services": []}
    try:
        url1 = f"https://{FGT_IP}/api/v2/monitor/network/reverse-ip-lookup"
        params1 = {"ip": dest_ip, "vdom": VDOM}
        resp1 = requests.get(url1, params=params1, headers=headers, verify=VERIFY_SSL, timeout=5)
        if resp1.status_code == 200:
            data1 = resp1.json()
            info['owner'] = data1.get('owner', 'N/A')
            info['location'] = data1.get('country', 'N/A')
            info['latitude'] = data1.get('latitude')
            info['longitude'] = data1.get('longitude')
    except Exception as e:
        logger.debug(f"reverse-ip-lookup failed for {dest_ip}: {e}")
    try:
        url2 = f"https://{FGT_IP}/api/v2/monitor/firewall/internet-service-match"
        params2 = {"ip": dest_ip, "ipv4_mask": "255.255.255.255", "vdom": VDOM}
        resp2 = requests.get(url2, params=params2, headers=headers, verify=VERIFY_SSL, timeout=5)
        if resp2.status_code == 200:
            data2 = resp2.json()
            services = []
            for item in data2.get('results', []):
                services.append(item.get('name'))
            info['running_services'] = services[:5]
    except Exception as e:
        logger.debug(f"internet-service-match failed for {dest_ip}: {e}")
    return info

@app.route('/api/destination_info/<string:dest_ip>')
def api_destination_info(dest_ip):
    info = get_destination_info(dest_ip)
    return jsonify(info)

def get_sessions_for_destination(policy_id, destination_ip, limit=100):
    if policy_id in MASHHAD_PART_POLICIES:
        fgt_ip = FGT_PART_IP
        api_token = FGT_PART_TOKEN
        vdom = FGT_PART_VDOM
    else:
        fgt_ip = FGT_IP
        api_token = API_TOKEN
        vdom = VDOM

    url = f"https://{fgt_ip}/api/v2/monitor/firewall/session"
    params = {
        "vdom": vdom,
        "policyid": policy_id,
        "destination": destination_ip,
        "count": limit,
        "filter-csf": "false",
        "ip_version": "ipboth",
        "start": 0,
        "summary": "true"
    }
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, params=params, headers=headers, verify=VERIFY_SSL, timeout=15)
        if response.status_code == 200:
            data = response.json()
            sessions = data.get('results', {}).get('details', [])
            session_list = []
            for sess in sessions:
                session_list.append({
                    "src_ip": sess.get('saddr'),
                    "dst_ip": sess.get('daddr'),
                    "bytes": sess.get('sentbyte', 0) + sess.get('rcvdbyte', 0),
                    "packets": sess.get('tx_packets', 0) + sess.get('rx_packets', 0),
                    "duration": sess.get('duration', 0),
                    "owner": sess.get('owner', 'N/A'),
                    "application": sess.get('apps', [{}])[0].get('name', 'N/A') if sess.get('apps') else 'N/A',
                    "protocol": sess.get('proto', 'N/A')
                })
            return session_list
        else:
            logger.error(f"Session API error for policy {policy_id}, destination {destination_ip}: {response.status_code}")
            return []
    except Exception as e:
        logger.error(f"Error in get_sessions_for_destination: {e}")
        return []

@app.route('/api/top_destinations/<int:policy_id>')
def api_top_destinations(policy_id):
    destinations = get_top_destinations(policy_id)
    return jsonify(destinations)

@app.route('/api/session_details/<int:policy_id>/<string:destination_ip>')
def api_session_details(policy_id, destination_ip):
    sessions = get_sessions_for_destination(policy_id, destination_ip)
    return jsonify(sessions)

@app.route('/api/comparison_data')
def api_comparison_data():
    with background_lock:
        raw = background_data.copy()
    result = {}
    for group_name, policies in policies_config['groups'].items():
        group_today = 0.0
        group_yesterday = 0.0
        group_last_week = 0.0
        for p in policies:
            pid = p['id']
            if pid in raw:
                vol_gb = raw[pid]["volume_bytes"] / (1024**3)
                group_today += vol_gb
                daily = raw[pid].get("daily_bytes", [])
                if len(daily) >= 2:
                    group_yesterday += daily[-2] / (1024**3)
                if len(daily) >= 8:
                    group_last_week += daily[-8] / (1024**3)
        result[group_name] = {
            "today": round(group_today, 2),
            "yesterday": round(group_yesterday, 2),
            "last_week": round(group_last_week, 2)
        }
    return jsonify(result)

def call_llm(prompt, temperature=0.3, max_tokens=1000):
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": "شما یک تحلیلگر ارشد شبکه هستید. پاسخ‌های شما دقیق، فنی و به زبان فارسی است."},
            {"role": "user", "content": prompt}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    try:
        resp = requests.post(LLM_API_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return None

# ==========================================
# گزارش مدیریتی پیشرفته
# ==========================================
@app.route('/api/generate_static_report')
def generate_static_report():
    with background_lock:
        raw = background_data.copy()

    SECONDS_IN_DAY = 86400
    now_str = time.strftime('%Y-%m-%d %H:%M:%S')

    # ===== جمع‌آوری داده‌های جامع =====
    all_groups_data = {}
    all_services_flat = []

    for group_name, policies in policies_config['groups'].items():
        g = {
            "policies": [],
            "total_today_gb": 0.0, "total_yesterday_gb": 0.0,
            "total_week_gb": 0.0, "total_sessions": 0, "total_speed_mbps": 0.0
        }
        for p in policies:
            pid = p['id']
            svc = {
                "id": pid, "name": p['name'],
                "volume_gb": 0.0, "yesterday_gb": 0.0, "week_total_gb": 0.0,
                "speed_mbps": 0.0, "avg_bw_mbps": 0.0,
                "sessions": 0, "daily_trend": [], "change_pct": 0.0
            }
            if pid in raw:
                vol_bytes = raw[pid]["volume_bytes"]
                vol_gb = vol_bytes / (1024 ** 3)
                week_gb = raw[pid]["week_bytes"] / (1024 ** 3)
                speed_mbps = raw[pid]["speed_bps"] / 1e6
                sessions = raw[pid]["sessions"]
                daily = raw[pid].get("daily_bytes", [])
                yesterday_gb = daily[-2] / (1024 ** 3) if len(daily) >= 2 else 0
                avg_bw = (vol_bytes * 8) / SECONDS_IN_DAY / 1e6 if vol_bytes > 0 else 0
                change_pct = round(((vol_gb - yesterday_gb) / yesterday_gb * 100) if yesterday_gb > 0 else 0, 1)
                daily_trend = [round(b / (1024 ** 3), 2) for b in daily[-7:]] if daily else []
                svc = {
                    "id": pid, "name": p['name'],
                    "volume_gb": round(vol_gb, 2), "yesterday_gb": round(yesterday_gb, 2),
                    "week_total_gb": round(week_gb, 2), "speed_mbps": round(speed_mbps, 2),
                    "avg_bw_mbps": round(avg_bw, 2), "sessions": sessions,
                    "daily_trend": daily_trend, "change_pct": change_pct
                }
                g["total_today_gb"] += vol_gb
                g["total_yesterday_gb"] += yesterday_gb
                g["total_week_gb"] += week_gb
                g["total_sessions"] += sessions
                g["total_speed_mbps"] += speed_mbps
            g["policies"].append(svc)
            all_services_flat.append({**svc, "group": group_name})

        g["total_today_gb"] = round(g["total_today_gb"], 2)
        g["total_yesterday_gb"] = round(g["total_yesterday_gb"], 2)
        g["total_week_gb"] = round(g["total_week_gb"], 2)
        g["change_pct"] = round(
            (g["total_today_gb"] - g["total_yesterday_gb"]) / g["total_yesterday_gb"] * 100
            if g["total_yesterday_gb"] > 0 else 0, 1
        )
        all_groups_data[group_name] = g

    # ===== Top Destinations برای سرویس‌های برتر =====
    pid_list = []
    for gname, gdata in all_groups_data.items():
        for svc in sorted(gdata["policies"], key=lambda x: x["volume_gb"], reverse=True)[:2]:
            if svc["volume_gb"] > 0:
                pid_list.append((gname, svc["id"], svc["name"]))
    pid_list = pid_list[:10]

    top_dests_map = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(get_top_destinations, pid, 5): (gname, pid, pname)
            for gname, pid, pname in pid_list
        }
        for f in as_completed(futures):
            gname, pid, pname = futures[f]
            try:
                top_dests_map[pid] = {"name": pname, "group": gname, "dests": f.result()}
            except Exception as e:
                logger.error(f"Top dest failed for {pid}: {e}")
                top_dests_map[pid] = {"name": pname, "group": gname, "dests": []}

    # ===== KPIهای کلی =====
    total_today_gb = round(sum(g["total_today_gb"] for g in all_groups_data.values()), 2)
    total_yesterday_gb = round(sum(g["total_yesterday_gb"] for g in all_groups_data.values()), 2)
    total_sessions = sum(g["total_sessions"] for g in all_groups_data.values())
    total_speed_mbps = round(sum(g["total_speed_mbps"] for g in all_groups_data.values()), 2)
    overall_change = round(
        (total_today_gb - total_yesterday_gb) / total_yesterday_gb * 100
        if total_yesterday_gb > 0 else 0, 1
    )
    top_svc = max(all_services_flat, key=lambda x: x["volume_gb"],
                  default={"name": "N/A", "volume_gb": 0, "group": ""})

    # ===== LLM Analysis =====
    llm_input = {
        "date": now_str,
        "kpis": {
            "total_today_gb": total_today_gb,
            "total_yesterday_gb": total_yesterday_gb,
            "change_pct": overall_change,
            "total_sessions": total_sessions,
            "total_speed_mbps": total_speed_mbps,
        },
        "groups": {
            gname: {
                "today_gb": gdata["total_today_gb"],
                "yesterday_gb": gdata["total_yesterday_gb"],
                "change_pct": gdata["change_pct"],
                "sessions": gdata["total_sessions"],
                "top_services": sorted(
                    gdata["policies"], key=lambda x: x["volume_gb"], reverse=True
                )[:4]
            }
            for gname, gdata in all_groups_data.items()
        }
    }

    prompt = f"""تاریخ گزارش: {now_str}

داده‌های جامع ترافیک شبکه سازمانی:
{json.dumps(llm_input, ensure_ascii=False, indent=2)}

به عنوان متخصص ارشد شبکه و امنیت سایبری، گزارش مدیریتی دقیقاً با این قالب تهیه کن:

[خلاصه اجرایی]
۲ تا ۳ جمله کلیدی برای مدیر ارشد. شامل مهم‌ترین آمار و وضعیت کلی.

[تحلیل روند]
تحلیل تغییرات هر گروه نسبت به دیروز. الگوهای غیرعادی، پیک‌های مصرف، و نکات مهم با ذکر اعداد.

[نقاط بحرانی]
موارد نیاز به توجه فوری با ذکر سرویس یا گروه مربوطه. اگر همه چیز طبیعی بود بنویس: وضعیت پایدار - موارد بحرانی گزارش نشده.

[پیشنهادات عملی]
- پیشنهاد اول با اولویت بالا
- پیشنهاد دوم
- پیشنهاد سوم
- پیشنهاد چهارم (اختیاری)

[ارزیابی ریسک]
سطح: کم/متوسط/بالا/بحرانی — توضیح کوتاه یک جمله‌ای."""

    llm_response = call_llm(prompt, max_tokens=1800)

    # پارس کردن پاسخ LLM
    parsed = {
        "executive_summary": "",
        "trend_analysis": "",
        "critical_points": "",
        "suggestions": [],
        "risk_assessment": ""
    }
    section_map = {
        "[خلاصه اجرایی]": "executive_summary",
        "[تحلیل روند]": "trend_analysis",
        "[نقاط بحرانی]": "critical_points",
        "[پیشنهادات عملی]": "suggestions",
        "[ارزیابی ریسک]": "risk_assessment"
    }
    if llm_response:
        current = None
        for line in llm_response.splitlines():
            s = line.strip()
            matched = False
            for marker, key in section_map.items():
                if marker in s:
                    current = key
                    matched = True
                    break
            if not matched and current:
                if current == "suggestions":
                    if s and s[0] in '-•*۱۲۳۴۵1234':
                        parsed[current].append(s.lstrip('-•*۱۲۳۴۵1234. ').strip())
                else:
                    parsed[current] += line + "\n"
        for k in parsed:
            if isinstance(parsed[k], str):
                parsed[k] = parsed[k].strip()

    if not parsed["executive_summary"]:
        parsed["executive_summary"] = "تحلیل هوشمند در این لحظه در دسترس نیست. لطفاً چند دقیقه بعد تلاش کنید."
    if not parsed["suggestions"]:
        parsed["suggestions"] = [
            "بررسی و مانیتورینگ سرویس‌های با مصرف بالا",
            "بازبینی قوانین فایروال و پالیسی‌های ترافیکی",
            "بررسی لاگ‌های امنیتی"
        ]

    # تعیین رنگ ریسک
    rt = parsed["risk_assessment"]
    if "بحرانی" in rt:
        risk_bg, risk_label, risk_icon = "#dc2626", "بحرانی", "🔴"
    elif "بالا" in rt:
        risk_bg, risk_label, risk_icon = "#d97706", "بالا", "🟠"
    elif "متوسط" in rt:
        risk_bg, risk_label, risk_icon = "#ca8a04", "متوسط", "🟡"
    else:
        risk_bg, risk_label, risk_icon = "#059669", "کم", "🟢"

    # ===== داده‌های چارت برای Frontend =====
    group_labels = list(all_groups_data.keys())
    chart_data = {
        "groups": {
            "labels": group_labels,
            "today": [all_groups_data[g]["total_today_gb"] for g in group_labels],
            "yesterday": [all_groups_data[g]["total_yesterday_gb"] for g in group_labels]
        },
        "dist": {
            "labels": [g for g in group_labels if all_groups_data[g]["total_today_gb"] > 0],
            "data": [all_groups_data[g]["total_today_gb"] for g in group_labels
                     if all_groups_data[g]["total_today_gb"] > 0]
        },
        "topsvcs": {
            "labels": [s["name"] for s in
                       sorted(all_services_flat, key=lambda x: x["volume_gb"], reverse=True)[:10]],
            "data": [s["volume_gb"] for s in
                     sorted(all_services_flat, key=lambda x: x["volume_gb"], reverse=True)[:10]]
        }
    }

    # ===== تولید HTML گزارش =====
    PALETTE = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']

    def arrow_span(pct):
        if pct > 5:
            return f'<span style="color:#dc2626;font-size:0.77rem;font-weight:600;">▲ {abs(pct)}%</span>'
        elif pct < -5:
            return f'<span style="color:#059669;font-size:0.77rem;font-weight:600;">▼ {abs(pct)}%</span>'
        return f'<span style="color:#94a3b8;font-size:0.77rem;">→ {abs(pct)}%</span>'

    overall_arrow = "▲" if overall_change > 0 else ("▼" if overall_change < 0 else "→")
    overall_col = "#dc2626" if overall_change > 5 else ("#059669" if overall_change < -5 else "#64748b")
    sugg_html = "".join(f'<li style="margin-bottom:10px;line-height:1.7;">{s}</li>'
                        for s in parsed["suggestions"])

    html = f"""<div id="rpt-wrap" style="font-family:Vazirmatn,Tahoma,sans-serif;direction:rtl;background:#eef2f7;color:#1e293b;line-height:1.6;min-width:860px;">

<!-- ===== HEADER ===== -->
<div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 55%,#1d4ed8 100%);padding:36px 40px;color:white;position:relative;overflow:hidden;">
  <div style="position:absolute;top:-50px;left:-50px;width:250px;height:250px;background:rgba(255,255,255,0.04);border-radius:50%;pointer-events:none;"></div>
  <div style="position:absolute;bottom:-70px;right:60px;width:300px;height:300px;background:rgba(255,255,255,0.03);border-radius:50%;pointer-events:none;"></div>
  <div style="position:relative;display:flex;justify-content:space-between;align-items:flex-start;gap:20px;">
    <div>
      <div style="font-size:0.72rem;color:#93c5fd;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px;">Network Traffic Management Report</div>
      <h1 style="font-size:1.75rem;font-weight:700;margin:0 0 8px;color:white;">گزارش مدیریتی ترافیک شبکه</h1>
      <div style="display:flex;gap:20px;flex-wrap:wrap;margin-top:10px;font-size:0.82rem;color:#cbd5e1;">
        <span>📅 تاریخ تولید: {now_str}</span>
        <span>📊 {len(all_services_flat)} سرویس پایش‌شده</span>
        <span>🔥 {total_speed_mbps:.1f} Mbps ترافیک لحظه‌ای</span>
      </div>
    </div>
    <div style="text-align:center;flex-shrink:0;">
      <div style="background:{risk_bg};color:white;padding:10px 20px;border-radius:10px;font-size:0.95rem;font-weight:700;white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,0.3);">
        {risk_icon} سطح ریسک: {risk_label}
      </div>
    </div>
  </div>
</div>

<!-- ===== KPI CARDS ===== -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:20px 28px 14px;">
  <div style="background:white;border-radius:12px;padding:18px 16px;box-shadow:0 1px 3px rgba(0,0,0,0.07);border-top:3px solid #3b82f6;">
    <div style="font-size:0.7rem;color:#94a3b8;margin-bottom:5px;text-transform:uppercase;letter-spacing:1px;">مجموع ترافیک امروز</div>
    <div style="font-size:1.9rem;font-weight:700;direction:ltr;color:#1e293b;">{total_today_gb} <span style="font-size:0.85rem;font-weight:400;color:#94a3b8;">GB</span></div>
    <div style="font-size:0.72rem;color:#94a3b8;margin-top:5px;">دیروز: {total_yesterday_gb} GB</div>
  </div>
  <div style="background:white;border-radius:12px;padding:18px 16px;box-shadow:0 1px 3px rgba(0,0,0,0.07);border-top:3px solid {overall_col};">
    <div style="font-size:0.7rem;color:#94a3b8;margin-bottom:5px;text-transform:uppercase;letter-spacing:1px;">تغییر نسبت به دیروز</div>
    <div style="font-size:1.9rem;font-weight:700;direction:ltr;color:{overall_col};">{overall_arrow} {abs(overall_change)}%</div>
    <div style="font-size:0.72rem;color:#94a3b8;margin-top:5px;">مقایسه ۲۴ ساعته</div>
  </div>
  <div style="background:white;border-radius:12px;padding:18px 16px;box-shadow:0 1px 3px rgba(0,0,0,0.07);border-top:3px solid #10b981;">
    <div style="font-size:0.7rem;color:#94a3b8;margin-bottom:5px;text-transform:uppercase;letter-spacing:1px;">نشست‌های فعال</div>
    <div style="font-size:1.9rem;font-weight:700;direction:ltr;color:#1e293b;">{total_sessions:,}</div>
    <div style="font-size:0.72rem;color:#94a3b8;margin-top:5px;">در تمام گروه‌ها</div>
  </div>
  <div style="background:white;border-radius:12px;padding:18px 16px;box-shadow:0 1px 3px rgba(0,0,0,0.07);border-top:3px solid #f59e0b;">
    <div style="font-size:0.7rem;color:#94a3b8;margin-bottom:5px;text-transform:uppercase;letter-spacing:1px;">پرمصرف‌ترین سرویس</div>
    <div style="font-size:1.05rem;font-weight:700;color:#1e293b;line-height:1.3;margin-top:3px;">{top_svc['name']}</div>
    <div style="font-size:0.72rem;color:#94a3b8;margin-top:5px;">{top_svc['volume_gb']} GB — {top_svc.get('group','')}</div>
  </div>
</div>

<!-- ===== CHARTS ROW ===== -->
<div style="display:grid;grid-template-columns:3fr 2fr;gap:14px;padding:0 28px 14px;">
  <div style="background:white;border-radius:12px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
    <div style="font-size:0.88rem;font-weight:600;margin-bottom:12px;border-right:3px solid #3b82f6;padding-right:10px;color:#1e293b;">مقایسه ترافیک گروه‌ها — امروز در برابر دیروز (GB)</div>
    <div style="height:210px;"><canvas id="rpt-chart-groups"></canvas></div>
  </div>
  <div style="background:white;border-radius:12px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
    <div style="font-size:0.88rem;font-weight:600;margin-bottom:12px;border-right:3px solid #10b981;padding-right:10px;color:#1e293b;">توزیع ترافیک امروز</div>
    <div style="height:210px;"><canvas id="rpt-chart-dist"></canvas></div>
  </div>
</div>

<!-- ===== TOP SERVICES CHART ===== -->
<div style="background:white;border-radius:12px;padding:18px;margin:0 28px 14px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
  <div style="font-size:0.88rem;font-weight:600;margin-bottom:12px;border-right:3px solid #f59e0b;padding-right:10px;color:#1e293b;">برترین سرویس‌ها براساس حجم ترافیک (GB)</div>
  <div style="height:190px;"><canvas id="rpt-chart-topsvcs"></canvas></div>
</div>
"""

    # ===== جداول per-group =====
    for ci, (group_name, gdata) in enumerate(all_groups_data.items()):
        border_col = PALETTE[ci % len(PALETTE)]
        sorted_svcs = sorted(gdata["policies"], key=lambda x: x["volume_gb"], reverse=True)
        g_arrow = "▲" if gdata["change_pct"] > 0 else ("▼" if gdata["change_pct"] < 0 else "→")
        g_col = "#dc2626" if gdata["change_pct"] > 5 else ("#059669" if gdata["change_pct"] < -5 else "#64748b")

        html += f"""
<div style="background:white;border-radius:12px;padding:18px;margin:0 28px 14px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid #f1f5f9;">
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="width:4px;height:22px;background:{border_col};border-radius:2px;"></div>
      <span style="font-weight:700;font-size:0.95rem;">{group_name}</span>
    </div>
    <div style="display:flex;gap:18px;font-size:0.78rem;color:#64748b;flex-wrap:wrap;">
      <span>امروز: <strong style="color:#1d4ed8;">{gdata['total_today_gb']:.2f} GB</strong></span>
      <span>هفته: <strong style="color:#1e293b;">{gdata['total_week_gb']:.2f} GB</strong></span>
      <span>نشست: <strong style="color:#1e293b;">{gdata['total_sessions']:,}</strong></span>
      <span style="color:{g_col};font-weight:600;">{g_arrow} {abs(gdata['change_pct'])}% vs دیروز</span>
    </div>
  </div>
  <div style="overflow-x:auto;">
  <table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
    <thead>
      <tr style="background:#f8fafc;">
        <th style="padding:8px 10px;text-align:right;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;">سرویس</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;white-space:nowrap;">امروز (GB)</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;white-space:nowrap;">دیروز (GB)</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;">تغییر</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;white-space:nowrap;">هفته (GB)</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;white-space:nowrap;">سرعت (Mbps)</th>
        <th style="padding:8px 10px;text-align:center;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0;">نشست</th>
      </tr>
    </thead>
    <tbody>
"""
        for i, svc in enumerate(sorted_svcs):
            row_bg = "#fafbfc" if i % 2 == 0 else "white"
            c = svc.get("change_pct", 0)
            c_col = "#dc2626" if c > 10 else ("#059669" if c < -10 else "#94a3b8")
            c_sym = "▲" if c > 0 else ("▼" if c < 0 else "→")
            vol_bold = "font-weight:700;color:#1d4ed8;" if svc['volume_gb'] > 0 else "color:#94a3b8;"
            html += f"""
      <tr style="background:{row_bg};border-bottom:1px solid #f1f5f9;">
        <td style="padding:8px 10px;font-weight:500;">{svc['name']}</td>
        <td style="padding:8px 10px;text-align:center;direction:ltr;{vol_bold}">{svc['volume_gb']}</td>
        <td style="padding:8px 10px;text-align:center;direction:ltr;color:#64748b;">{svc.get('yesterday_gb',0)}</td>
        <td style="padding:8px 10px;text-align:center;color:{c_col};font-size:0.77rem;font-weight:600;">{c_sym} {abs(c)}%</td>
        <td style="padding:8px 10px;text-align:center;direction:ltr;color:#64748b;">{svc.get('week_total_gb',0)}</td>
        <td style="padding:8px 10px;text-align:center;direction:ltr;">{svc['speed_mbps']}</td>
        <td style="padding:8px 10px;text-align:center;">{svc['sessions']:,}</td>
      </tr>
"""
        html += "    </tbody>\n  </table>\n  </div>\n</div>\n"

    # ===== Top Destinations =====
    active_dests = {pid: d for pid, d in top_dests_map.items() if d.get("dests")}
    if active_dests:
        html += """
<div style="background:white;border-radius:12px;padding:18px;margin:0 28px 14px;box-shadow:0 1px 3px rgba(0,0,0,0.07);">
  <div style="font-size:0.88rem;font-weight:600;margin-bottom:14px;border-right:3px solid #8b5cf6;padding-right:10px;color:#1e293b;">مقصدهای برتر ترافیک (Top Destinations)</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;">
"""
        for pid, dest_data in active_dests.items():
            html += f"""
    <div style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
      <div style="background:#f8fafc;padding:8px 12px;font-weight:600;font-size:0.8rem;border-bottom:1px solid #e2e8f0;">
        {dest_data['name']} <span style="color:#64748b;font-weight:400;font-size:0.75rem;">({dest_data['group']})</span>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:0.75rem;">
        <tr style="background:#f8fafc;color:#64748b;">
          <th style="padding:5px 10px;text-align:right;">مقصد</th>
          <th style="padding:5px 8px;text-align:center;">حجم</th>
          <th style="padding:5px 8px;text-align:center;">Mbps</th>
          <th style="padding:5px 8px;text-align:center;">نشست</th>
          <th style="padding:5px 8px;text-align:center;">اپ</th>
        </tr>
"""
            for d in dest_data["dests"][:5]:
                b = d.get("bytes_sent", 0)
                bstr = (f"{b / 1e9:.1f}GB" if b > 1e9 else
                        f"{b / 1e6:.1f}MB" if b > 1e6 else f"{b / 1e3:.0f}KB")
                bwstr = f"{d.get('tx_bandwidth', 0) / 1e6:.1f}"
                name = (d.get("dst_name") or d.get("dst_ip", ""))[:32]
                app = (d.get("app_name") or "—")[:12]
                html += f"""
        <tr style="border-top:1px solid #f1f5f9;">
          <td style="padding:5px 10px;">{d.get('flag', '🌐')} {name}</td>
          <td style="padding:5px 8px;text-align:center;direction:ltr;">{bstr}</td>
          <td style="padding:5px 8px;text-align:center;direction:ltr;">{bwstr}</td>
          <td style="padding:5px 8px;text-align:center;">{d.get('sessions', 0)}</td>
          <td style="padding:5px 8px;text-align:center;color:#64748b;font-size:0.7rem;">{app}</td>
        </tr>
"""
            html += "      </table>\n    </div>\n"
        html += "  </div>\n</div>\n"

    # ===== LLM Analysis =====
    html += f"""
<div style="padding:0 28px 14px;">
  <div style="font-size:0.95rem;font-weight:700;margin-bottom:12px;border-right:4px solid #6366f1;padding-right:12px;color:#1e293b;">تحلیل هوشمند شبکه</div>

  <!-- Executive Summary -->
  <div style="background:linear-gradient(135deg,#eff6ff,#f0f9ff);border-radius:12px;padding:18px;margin-bottom:12px;border-right:4px solid #3b82f6;">
    <div style="font-size:0.7rem;font-weight:700;color:#1d4ed8;margin-bottom:8px;letter-spacing:1.5px;text-transform:uppercase;">خلاصه اجرایی</div>
    <p style="margin:0;line-height:1.85;color:#1e293b;font-size:0.9rem;">{parsed['executive_summary']}</p>
  </div>

  <!-- Trend + Critical -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
    <div style="background:#f8fafc;border-radius:12px;padding:16px;border:1px solid #e2e8f0;">
      <div style="font-size:0.72rem;font-weight:700;color:#475569;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">📈 تحلیل روند</div>
      <p style="margin:0;line-height:1.8;color:#374151;font-size:0.85rem;white-space:pre-wrap;">{parsed['trend_analysis'] or "اطلاعات کافی در دسترس نیست"}</p>
    </div>
    <div style="background:#fef2f2;border-radius:12px;padding:16px;border:1px solid #fecaca;">
      <div style="font-size:0.72rem;font-weight:700;color:#b91c1c;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">⚠️ نقاط بحرانی</div>
      <p style="margin:0;line-height:1.8;color:#374151;font-size:0.85rem;white-space:pre-wrap;">{parsed['critical_points'] or "موارد بحرانی گزارش نشده"}</p>
    </div>
  </div>

  <!-- Suggestions -->
  <div style="background:#f0fdf4;border-radius:12px;padding:18px;margin-bottom:12px;border:1px solid #bbf7d0;">
    <div style="font-size:0.72rem;font-weight:700;color:#15803d;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px;">✅ پیشنهادات عملی</div>
    <ul style="margin:0;padding-right:20px;color:#1e293b;font-size:0.88rem;">{sugg_html}</ul>
  </div>

  <!-- Risk -->
  <div style="background:{risk_bg};border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:16px;">
    <div style="font-size:1.3rem;font-weight:800;color:white;white-space:nowrap;">{risk_icon} ارزیابی ریسک: {risk_label}</div>
    <div style="color:rgba(255,255,255,0.92);font-size:0.86rem;line-height:1.7;">{parsed['risk_assessment']}</div>
  </div>
</div>

<!-- FOOTER -->
<div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:12px 28px;display:flex;justify-content:space-between;font-size:0.72rem;color:#94a3b8;">
  <div>سیستم مانیتورینگ ترافیک شبکه سازمانی — FortiGate Multi-Site Integration</div>
  <div>تولید شده: {now_str}</div>
</div>

</div>"""

    return jsonify({"report": html, "chart_data": chart_data})

# ==========================================
# سیستم هشدار
# ==========================================
def analyze_with_llm(traffic_summary):
    prompt = f"""
داده‌های ترافیک:
{json.dumps(traffic_summary, ensure_ascii=False, indent=2)}

هشدارها را به صورت JSON برگردانید: [{{"message": "...", "severity": "info|warning|critical", "color": "..."}}]
"""
    llm_output = call_llm(prompt, temperature=0.1, max_tokens=500)
    if llm_output:
        try:
            clean = llm_output.strip()
            if clean.startswith("```json"): clean = clean[7:]
            if clean.endswith("```"): clean = clean[:-3]
            alerts = json.loads(clean)
            if isinstance(alerts, list): return alerts
        except: pass
    alerts = []
    for item in traffic_summary:
        bw = item['avg_bw_today']
        if bw > 100:
            alerts.append({"message": f"بحرانی: سرویس '{item['service_name']}' پهنای باند {bw:.2f} Mbps", "severity": "critical", "color": "critical"})
        elif bw > 50:
            alerts.append({"message": f"هشدار: سرویس '{item['service_name']}' پهنای باند {bw:.2f} Mbps", "severity": "warning", "color": "warning"})
    return alerts

@app.route('/api/alerts')
def get_alerts():
    with background_lock:
        raw = background_data.copy()
    traffic_summary = []
    SECONDS_IN_DAY = 86400
    for group_name, policies in policies_config['groups'].items():
        for p in policies:
            pid = p['id']
            if pid in raw:
                vol_gb = raw[pid]["volume_bytes"] / (1024**3)
                avg_bw = (raw[pid]["volume_bytes"] * 8) / SECONDS_IN_DAY / 1e6 if raw[pid]["volume_bytes"] > 0 else 0
                traffic_summary.append({
                    "service_name": p['name'],
                    "group_name": group_name,
                    "volume_gb": round(vol_gb, 2),
                    "avg_bw_today": round(avg_bw, 2),
                    "sessions": raw[pid]["sessions"]
                })
    alerts = analyze_with_llm(traffic_summary)
    return jsonify(alerts)

# ==========================================
# APIهای اصلی
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/traffic_data.json')
def traffic_data():
    with background_lock:
        raw = background_data.copy()
    result = {}
    for group_name, policies in policies_config['groups'].items():
        total_vol = 0.0
        total_speed = 0.0
        details = []
        for p in policies:
            pid = p['id']
            if pid in raw:
                vol_gb = raw[pid]["volume_bytes"] / (1024**3)
                week_gb = raw[pid]["week_bytes"] / (1024**3)
                speed_mbps = raw[pid]["speed_bps"] / (1000**2)
                sessions = raw[pid]["sessions"]
                total_vol += vol_gb
                total_speed += speed_mbps
                details.append({
                    "name": p['name'],
                    "volume_gb": vol_gb,
                    "weekly_gb": week_gb,
                    "speed_mbps": speed_mbps,
                    "sessions": sessions
                })
            else:
                details.append({"name": p['name'], "volume_gb": 0, "weekly_gb": 0, "speed_mbps": 0, "sessions": 0})
        result[group_name] = {"total_volume_gb": total_vol, "total_speed_mbps": total_speed, "details": details}
    return jsonify(result)

@app.route('/api/groups', methods=['GET'])
def get_groups():
    return jsonify(policies_config)

@app.route('/api/policies', methods=['POST'])
def add_policy():
    try:
        data = request.get_json()
        pid = int(data['id'])
        name = data['name']
        group = data['group']
        if group not in policies_config['groups']:
            policies_config['groups'][group] = []
        for g in policies_config['groups'].values():
            if any(p['id'] == pid for p in g):
                return jsonify({"error": "Policy ID already exists"}), 400
        policies_config['groups'][group].append({"id": pid, "name": name})
        save_policies(policies_config)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/policies/<int:pid>', methods=['DELETE'])
def delete_policy(pid):
    for group_name, policies in policies_config['groups'].items():
        new_list = [p for p in policies if p['id'] != pid]
        if len(new_list) != len(policies):
            policies_config['groups'][group_name] = new_list
            save_policies(policies_config)
            return jsonify({"status": "ok"})
    return jsonify({"error": "Not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)