import os
import re
import json
import base64
import time
import subprocess
import yaml
import requests
import socket
import csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse
import geoip2.database

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes.txt"]
OUTPUT_FAST = "latest_nodes.txt"
OUTPUT_CSV = "speed_history.csv"
GEOIP_DB = "GeoLite2-Country.mmdb"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

TEST_URL = "https://speed.cloudflare.com/__down?bytes=104857600"
TEST_DURATION = 10
MIN_SPEED_THRESHOLD = 2.0

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/5] 准备内核...")
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
            os.chmod("mihomo", 0o755)
            print("  ✅ 内核已解压并赋权")
        else:
            print(f"  ❌ 错误: 找不到 {MIHOMO_GZ}，请确认文件是否存在于根目录")
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
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}"
        node_config = None
        
        # --- 协议解析 (保持原样) ---
        if url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node_config = {
                "name": name, "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') == "tls", "network": data.get('net'),
                "ws-opts": {"path": data.get('path'), "headers": {"Host": data.get('host', '')}} if data.get('net') == 'ws' else None
            }
        elif url.scheme == 'vless':
            query = parse_qs(url.query)
            node_config = {
                "name": name, "type": "vless", "server": url.hostname, "port": url.port,
                "uuid": url.username, "cipher": "auto", "tls": True, "udp": True,
                "servername": query.get('sni', [''])[0]
            }
        elif url.scheme == 'hysteria2':
            node_config = {
                "name": name, "type": "hysteria2", "server": url.hostname, "port": url.port,
                "password": url.username, "skip-cert-verify": True
            }
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                method, password = user_info.split(':', 1)
                node_config = {"name": name, "type": "ss", "server": url.hostname, "port": url.port, "cipher": method, "password": password}

        if node_config: return name, node_config, link
    except: pass
    return None, None, None

def run_speed_test():
    if not setup_mihomo(): return
    now = datetime.now(SHANGHAI_TZ)
    name_to_link = {}
    proxies = []
    seen_links = set()

    print("[2/5] 扫描节点源...")
    for file_path in INPUT_NODES:
        if not os.path.exists(file_path): 
            print(f"  ⚠️ 找不到输入文件: {file_path}")
            continue
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line in seen_links: continue
                name, config, raw_link = parse_link(line)
                if config:
                    u_name = f"node_{len(proxies)}"
                    config['name'] = u_name
                    proxies.append(config)
                    name_to_link[u_name] = raw_link
                    seen_links.add(line)

    if not proxies: 
        print("  ❌ 未发现有效节点，请检查 nodes.txt 格式")
        return

    # 生成配置文件
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({
            "mixed-port": 7890,
            "external-controller": "127.0.0.1:9090",
            "mode": "rule",
            "log-level": "info",
            "proxies": proxies,
            "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}]
        }, f)
    
    # 启动内核 (取消静默模式以便调试)
    print("  🚀 启动 Mihomo 内核...")
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"])
    
    # 关键：检查 API 是否准备就绪
    api_ready = False
    for i in range(15):
        try:
            requests.get("http://127.0.0.1:9090", timeout=1)
            api_ready = True
            print("  ✅ Mihomo API 已就绪")
            break
        except:
            time.sleep(1)
    
    if not api_ready:
        print("  ❌ 错误: Mihomo 启动超时，API 无法访问")
        proc.terminate()
        return

    valid_results = []
    print(f"[3/5] 开始测速 (目标: {len(proxies)} 个节点)...")

    try:
        for p in proxies:
            name = p['name']
            # 切换节点
            try:
                requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name}, timeout=5)
            except Exception as e:
                print(f"  ❌ 切换节点失败 {name}: {e}")
                continue
            
            start_time = time.time()
            total_bytes = 0
            try:
                # 测速请求 (增加 stream 超时判断)
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=(5, 15)) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=1024*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION: break
                
                duration = time.time() - start_time
                speed = (total_bytes * 8) / (duration * 1024 * 1024)
                
                if speed >= MIN_SPEED_THRESHOLD:
                    country = get_country(p['server'])
                    res = {
                        "date": now.strftime('%Y-%m-%d'),
                        "speed": round(speed, 2),
                        "country": country,
                        "server": p['server'],
                        "raw_link": name_to_link[name]
                    }
                    valid_results.append(res)
                    print(f"  ✨ [PASS] {country} | {res['speed']} Mbps")
                else:
                    print(f"  🐌 [SLOW] {round(speed, 2)} Mbps")
            except Exception as e:
                # 这里会打印节点为何失败
                print(f"  💀 [FAIL] {p['server']} | 原因: {type(e).__name__}")
    finally:
        print("  🛑 停止 Mihomo 内核")
        proc.terminate()
        proc.wait()


    if not valid_results:
        print("[4/5] ⚠️ 测速完成，但没有节点达到速度阈值。")
        return

    valid_results.sort(key=lambda x: x['speed'], reverse=True)
    final_links = []
    country_counter = {}
    csv_data = []

    for item in valid_results:
        c = item['country']
        country_counter[c] = country_counter.get(c, 0) + 1
        url = urlparse(item['raw_link'])
        new_name = f"[{c}][{item['speed']}M] {country_counter[c]}"
        new_link = urlunparse(url._replace(fragment=new_name))
        final_links.append(new_link)
        csv_data.append([item['date'], item['country'], item['speed'], item['server']])

    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    file_exists = os.path.isfile(OUTPUT_CSV)
    with open(OUTPUT_CSV, 'a', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '国家', '速度(Mbps)', '服务器地址'])
        writer.writerows(csv_data)

    print(f"[5/5] 完成。筛选出 {len(final_links)} 个优质节点。")

if __name__ == "__main__":
    run_speed_test()
