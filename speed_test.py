import os, re, json, base64, time, subprocess, yaml, requests, socket, csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse
import geoip2.database

# --- 核心配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes.txt"]
OUTPUT_FAST = "latest_nodes.txt"
OUTPUT_CSV = "speed_history.csv"
GEOIP_DB = "GeoLite2-Country.mmdb"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

TEST_URL = "https://speed.cloudflare.com/__down?bytes=104857600"
TEST_DURATION = 8  
MIN_SPEED_THRESHOLD = 1.0  # 稍微降低阈值以抓取更多有效节点

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/5] 准备内核...", flush=True)
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
            os.chmod("mihomo", 0o755)
            print("  ✅ 内核准备就绪", flush=True)
        else:
            print(f"  ❌ 错误: 找不到 {MIHOMO_GZ}", flush=True)
            return False
    return True

def get_country(ip):
    try:
        if not os.path.exists(GEOIP_DB): return "Unknown"
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            try: ip = socket.gethostbyname(ip)
            except: pass
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            return response.country.names.get('zh-CN', response.country.name)
    except: return "Unknown"

def parse_link(link):
    """深度解析引擎：适配 Reality, TUIC, Hy2, VMess WS, Trojan"""
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        
        # 基础通用配置
        node = {
            "name": name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "udp": True,
            "skip-cert-verify": True # 对应 allowInsecure=1
        }

        # 1. VLESS (核心：Reality 支持)
        if url.scheme == 'vless':
            node.update({
                "type": "vless", "uuid": url.username, "cipher": "auto",
                "tls": query.get('security') in ['tls', 'reality'],
                "servername": query.get('sni'),
                "network": query.get('type', 'tcp'),
                "flow": query.get('flow'),
            })
            if query.get('security') == 'reality':
                node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
            if query.get('fp'): node["client-fingerprint"] = query.get('fp')
            if node["network"] == 'ws':
                node["ws-opts"] = {"path": query.get('path', '/'), "headers": {"Host": query.get('host', '')}}

        # 2. VMess (Base64 JSON 增强)
        elif url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node.update({
                "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') in ['tls', True, 'true'],
                "network": data.get('net', 'tcp'),
                "servername": data.get('sni') or data.get('host')
            })
            if data.get('net') == 'ws':
                node["ws-opts"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}

        # 3. Hysteria2 (含 Obfs 混淆)
        elif url.scheme in ['hy2', 'hysteria2']:
            node.update({
                "type": "hysteria2", "password": url.username,
                "sni": query.get('sni'), "obfs": query.get('obfs'),
                "obfs-password": query.get('obfs-password')
            })

        # 4. TUIC v5
        elif url.scheme == 'tuic':
            node.update({
                "type": "tuic", "uuid": url.username, "password": url.password,
                "alpn": [query.get('alpn', 'h3')], 
                "congestion-controller": query.get('congestion_control', 'bbr'),
                "sni": query.get('sni'), "udp-relay-mode": query.get('udp_relay_mode', 'native')
            })

        # 5. Trojan
        elif url.scheme == 'trojan':
            node.update({
                "type": "trojan", "password": url.username,
                "sni": query.get('sni', url.hostname), "tls": True
            })

        # 6. Shadowsocks
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                method, password = user_info.split(':', 1)
                node.update({"type": "ss", "cipher": method, "password": password})

        return (name, node, link) if node.get("type") else (None, None, None)
    except: return None, None, None

def run_speed_test():
    if not setup_mihomo(): return
    now = datetime.now(SHANGHAI_TZ)
    proxies, name_to_link, seen = [], {}, set()

    print("[2/5] 正在解析节点源...", flush=True)
    if os.path.exists(INPUT_NODES[0]):
        with open(INPUT_NODES[0], 'r', encoding='utf-8') as f:
            for line in f:
                name, config, raw = parse_link(line)
                if config and raw not in seen:
                    u_name = f"N_{len(proxies):03d}_{config['type']}"
                    config['name'] = u_name
                    proxies.append(config)
                    name_to_link[u_name] = raw
                    seen.add(raw)

    if not proxies:
        print("  ❌ 未找到有效节点配置", flush=True)
        return

    # 生成临时配置
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({
            "mixed-port": 7890,
            "external-controller": "127.0.0.1:9090",
            "mode": "global",
            "log-level": "silent",
            "proxies": proxies,
            "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}]
        }, f)
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL)
    time.sleep(5) # 等待内核完全启动

    valid_results = []
    total = len(proxies)
    print(f"[3/5] 开始测速 (共 {total} 个节点)...", flush=True)

    try:
        for idx, p in enumerate(proxies, 1):
            name = p['name']
            print(f"  [{idx}/{total}] 测试 {p['type'].upper()}: {p['server']} ...", end=" ", flush=True)
            
            try:
                # 切换节点
                requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name}, timeout=5)
                
                start_time = time.time()
                dl_bytes = 0
                # 开始下载测速
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=(5, 12)) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=512*1024):
                        dl_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION: break
                
                duration = time.time() - start_time
                speed = (dl_bytes * 8) / (duration * 1024 * 1024)
                
                if speed >= MIN_SPEED_THRESHOLD:
                    country = get_country(p['server'])
                    res = {"date": now.strftime('%Y-%m-%d'), "speed": round(speed, 2), "country": country, "server": p['server'], "raw_link": name_to_link[name]}
                    valid_results.append(res)
                    print(f"✅ {res['speed']} Mbps ({country})", flush=True)
                else:
                    print(f"🐌 {round(speed, 2)} Mbps", flush=True)
            except Exception as e:
                print(f"💀 失败 ({type(e).__name__})", flush=True)
                
    finally:
        proc.terminate()
        proc.wait()

    # --- 结果持久化 ---
    if not valid_results:
        print("[4/5] ⚠️ 没有符合要求的节点。", flush=True)
        return

    valid_results.sort(key=lambda x: x['speed'], reverse=True)
    
    # 保存 txt
    final_links = []
    csv_rows = []
    for item in valid_results:
        # 重命名 fragment
        url = urlparse(item['raw_link'])
        new_name = f"[{item['country']}][{item['speed']}M]_{item['server'][:8]}"
        new_link = urlunparse(url._replace(fragment=new_name))
        final_links.append(new_link)
        csv_rows.append([item['date'], item['country'], item['speed'], item['server']])

    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    file_exists = os.path.isfile(OUTPUT_CSV)
    with open(OUTPUT_CSV, 'a', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        if not file_exists: writer.writerow(['日期', '国家', '速度(Mbps)', '服务器地址'])
        writer.writerows(csv_rows)

    print(f"[5/5] 任务完成，筛选出 {len(final_links)} 个优质节点。", flush=True)

if __name__ == "__main__":
    run_speed_test()
