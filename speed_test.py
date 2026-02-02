import os
import re
import json
import base64
import time
import subprocess
import yaml
import requests
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = "nodes_list.txt"     
OUTPUT_FAST = "nodes_list_fast.txt" 
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
TEST_DURATION = 5  

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/4] 准备内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def update_link_name(raw_link, speed_str):
    """修改原始链接的 # 后面部分，加上速度"""
    try:
        url = urlparse(raw_link)
        old_name = unquote(url.fragment) if url.fragment else "Node"
        # 新名称格式：[速度] 原名称
        new_name = f"[{speed_str}] {old_name}"
        # 重新构建链接
        url = url._replace(fragment=new_name)
        return urlunparse(url)
    except:
        return raw_link

def parse_link(link):
    try:
        link = link.strip()
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}"
        node_config = None
        
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

        if node_config:
            return name, node_config, link
    except: pass
    return None, None, None

def run_speed_test():
    setup_mihomo()
    now = datetime.now(SHANGHAI_TZ)
    
    name_to_link = {}
    proxies = []
    with open(INPUT_NODES, 'r', encoding='utf-8') as f:
        for line in f:
            name, config, raw_link = parse_link(line)
            if name and config:
                unique_name = f"{name}_{len(proxies)}"
                config['name'] = unique_name
                proxies.append(config)
                name_to_link[unique_name] = raw_link

    if not proxies: return

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "proxies": proxies, 
                   "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}]}, f)
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)

    valid_results = []
    try:
        resp = requests.get("http://127.0.0.1:9090/proxies", timeout=5).json()
        all_names = [p['name'] for p in proxies][:50]
        
        for name in all_names:
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            start_time = time.time()
            total_bytes = 0
            try:
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890"}, timeout=10) as r:
                    for chunk in r.iter_content(chunk_size=256*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION: break
                
                speed = (total_bytes * 8) / ((time.time() - start_time) * 1024 * 1024)
                if speed > 1.0: 
                    speed_label = f"{round(speed, 1)}Mbps"
                    # 修改原始链接名
                    new_link = update_link_name(name_to_link[name], speed_label)
                    valid_results.append((speed, new_link))
                    print(f"✅ {speed_label} | {name}")
            except: pass
    finally:
        proc.terminate()

    valid_results.sort(key=lambda x: x[0], reverse=True)
    final_links = [item[1] for item in valid_results]

    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    # 备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, f"fast_{now.strftime('%d_%H%M%S')}.txt"), 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

if __name__ == "__main__":
    run_speed_test()
