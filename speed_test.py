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
from urllib.parse import urlparse, unquote, parse_qs

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = "nodes_list.txt"     # 原始输入文件
OUTPUT_FAST = "nodes_list_fast.txt" # 测速后的精选文件
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
TEST_DURATION = 5  # 每个节点测速5秒

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/4] 准备内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def parse_link(link):
    """
    全协议解析逻辑：将链接转为 Mihomo 配置，并保留原始链接
    支持: vmess, vless, hysteria2, trojan, ss
    """
    try:
        link = link.strip()
        url = urlparse(link)
        # 生成唯一名称，防止重复
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}_{hash(link)%1000}"
        node_config = None
        
        # 1. VMess
        if url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            # 补齐 base64 填充
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node_config = {
                "name": name, "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') == "tls", "network": data.get('net'),
                "ws-opts": {"path": data.get('path'), "headers": {"Host": data.get('host', '')}} if data.get('net') == 'ws' else None,
                "grpc-opts": {"grpc-service-name": data.get('path')} if data.get('net') == 'grpc' else None
            }

        # 2. VLESS
        elif url.scheme == 'vless':
            query = parse_qs(url.query)
            node_config = {
                "name": name, "type": "vless", "server": url.hostname, "port": url.port,
                "uuid": url.username, "cipher": "auto", "udp": True,
                "tls": query.get('security', [''])[0] in ['tls', 'reality'],
                "network": query.get('type', ['tcp'])[0],
                "servername": query.get('sni', [''])[0],
                "reality-opts": {"public-key": query.get('pbk', [''])[0], "short-id": query.get('sid', [''])[0]} if query.get('security', [''])[0] == 'reality' else None
            }

        # 3. Hysteria2
        elif url.scheme == 'hysteria2':
            query = parse_qs(url.query)
            node_config = {
                "name": name, "type": "hysteria2", "server": url.hostname, "port": url.port,
                "password": url.username, "sni": query.get('sni', [''])[0],
                "skip-cert-verify": True, "obfs": query.get('obfs', [None])[0],
                "obfs-password": query.get('obfs-password', [None])[0]
            }

        # 4. Trojan
        elif url.scheme == 'trojan':
            query = parse_qs(url.query)
            node_config = {
                "name": name, "type": "trojan", "server": url.hostname, "port": url.port,
                "password": url.username, "sni": query.get('sni', [''])[0], "udp": True
            }

        # 5. Shadowsocks
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
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    
    # 1. 解析
    print("[2/4] 解析节点...")
    name_to_link = {}
    proxies = []
    with open(INPUT_NODES, 'r', encoding='utf-8') as f:
        for line in f:
            name, config, raw_link = parse_link(line)
            if name and config:
                # 防止重名冲突
                unique_name = f"{name}_{len(proxies)}"
                config['name'] = unique_name
                proxies.append(config)
                name_to_link[unique_name] = raw_link

    if not proxies:
        print("未识别到任何有效协议节点！")
        return

    # 生成配置
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({
            "mixed-port": 7890, 
            "external-controller": "127.0.0.1:9090", 
            "proxies": proxies, 
            "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}]
        }, f, allow_unicode=True)
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10) # 节点多，给足加载时间

    # 2. 测速
    print(f"[3/4] 正在对 {len(proxies)} 个节点进行测速筛选...")
    valid_results = []
    try:
        # 增加重试机制连接 API
        for _ in range(3):
            try:
                resp = requests.get("http://127.0.0.1:9090/proxies", timeout=5).json()
                break
            except: time.sleep(2)
        
        # 只测前 50 个
        all_names = [p['name'] for p in proxies][:50]
        
        for name in all_names:
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            start_time = time.time()
            total_bytes = 0
            try:
                # 实际下载 5 秒
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=10) as r:
                    for chunk in r.iter_content(chunk_size=256*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION: break
                
                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1024 * 1024)
                if speed_mbps > 0.5: # 过滤掉极慢节点
                    valid_results.append((speed_mbps, name_to_link[name]))
                    print(f"✅ {round(speed_mbps, 2)} Mbps | {name[:20]}")
            except: pass
    finally:
        proc.terminate()

    # 3. 保存结果
    print("[4/4] 正在保存精选列表...")
    valid_results.sort(key=lambda x: x[0], reverse=True) # 速度从高到低
    final_links = [item[1] for item in valid_results]

    # 保存到 nodes_list_fast.txt
    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    # 更新 README.md
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 测速精选列表\n\n最后更新时间: `{date_str}` (北京时间)\n\n")
        rm.write(f"从 {len(proxies)} 个原始节点中筛选出可用节点: **{len(final_links)}** 个\n\n")
        rm.write(f"测速文件: `{TEST_URL}`\n\n")
        rm.write(f"### 精选节点 (按下载速度排序)\n```text\n" + '\n'.join(final_links) + "\n```\n")

    # 按年月归档备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    backup_path = os.path.join(dir_path, f"fast_nodes_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    print(f"测试结束！精选节点已保存至 {OUTPUT_FAST}")

if __name__ == "__main__":
    run_speed_test()
