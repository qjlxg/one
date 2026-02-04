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
import geoip2.database

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes_list.txt", "latest_nodes.txt"]
OUTPUT_FAST = "nodes_list_fast.txt"
GEOIP_DB = "GeoLite2-Country.mmdb"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
TEST_DURATION = 10

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/5] 准备内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def get_country(ip):
    """根据IP获取国家名称"""
    try:
        if not os.path.exists(GEOIP_DB):
            return "Unknown"
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            # 返回中文名，如果没有则返回英文名
            return response.country.names.get('zh-CN', response.country.name)
    except:
        return "Unknown"

def update_link_full(raw_link, country, speed_str, index):
    """重构链接名称: [国家][速度] 编号"""
    try:
        url = urlparse(raw_link)
        new_name = f"[{country}][{speed_str}] {index}"
        url = url._replace(fragment=new_name)
        return urlunparse(url)
    except:
        return raw_link

def parse_link(link):
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}"
        node_config = None
        
        # 提取核心配置用于测速
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

def update_readme(links):
    """更新 README.md，将节点放在代码块中方便复制"""
    now_str = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
    content = [
        "# Speed Test Results\n",
        f"最后更新时间: `{now_str} (CST)`\n",
        "## 快速复制节点\n",
        "```text\n"
    ]
    content.extend([l + "\n" for l in links])
    content.append("```\n")
    
    with open("README.md", "w", encoding="utf-8") as f:
        f.writelines(content)

def run_speed_test():
    setup_mihomo()
    now = datetime.now(SHANGHAI_TZ)
    name_to_link = {}
    proxies = []
    seen_links = set()

    print("[2/5] 读取节点并准备测速...")
    for file_path in INPUT_NODES:
        if not os.path.exists(file_path): continue
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line in seen_links: continue
                name, config, raw_link = parse_link(line)
                if name and config:
                    unique_name = f"node_{len(proxies)}"
                    config['name'] = unique_name
                    proxies.append(config)
                    name_to_link[unique_name] = raw_link
                    seen_links.add(line)

    if not proxies: return

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({
            "mixed-port": 7890, 
            "external-controller": "127.0.0.1:9090", 
            "proxies": proxies, 
            "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}]
        }, f)
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)

    valid_results = []
    country_counter = {} # 用于国家重名计数

    try:
        # 测速逻辑
        all_names = [p['name'] for p in proxies][:500]
        for name in all_names:
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            start_time = time.time()
            total_bytes = 0
            try:
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890"}, timeout=7) as r:
                    for chunk in r.iter_content(chunk_size=512*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION: break
                
                speed = (total_bytes * 8) / ((time.time() - start_time) * 1024 * 1024)
                if speed > 0.8:
                    # 关键修改：获取地理位置
                    server_ip = next((p['server'] for p in proxies if p['name'] == name), "")
                    # 如果是域名，尝试解析IP（简单处理，如果GeoIP不支持域名）
                    country = get_country(server_ip)
                    
                    speed_label = f"{round(speed, 1)}Mbps"
                    valid_results.append({
                        "speed": speed,
                        "country": country,
                        "label": speed_label,
                        "raw_link": name_to_link[name]
                    })
                    print(f"   ✅ [{country}] {speed_label}")
            except: pass
    finally:
        proc.terminate()

    # 排序并重命名
    valid_results.sort(key=lambda x: x['speed'], reverse=True)
    
    final_links = []
    for item in valid_results:
        c = item['country']
        country_counter[c] = country_counter.get(c, 0) + 1
        new_link = update_link_full(item['raw_link'], c, item['label'], country_counter[c])
        final_links.append(new_link)

    # 保存结果
    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    # 更新 README
    update_readme(final_links)

    # 备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, f"fast_{now.strftime('%d_%H%M%S')}.txt"), 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

if __name__ == "__main__":
    run_speed_test()
