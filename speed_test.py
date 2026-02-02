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
NODES_FILE = "nodes_list.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
TEST_DURATION = 5 

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/4] 正在准备 Mihomo 内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def parse_vmess(link):
    try:
        data = json.loads(base64.b64decode(link[8:]).decode('utf-8'))
        return {
            "name": data.get('ps', 'vmess_node'),
            "type": "vmess",
            "server": data.get('add'),
            "port": int(data.get('port')),
            "uuid": data.get('id'),
            "alterId": int(data.get('aid', 0)),
            "cipher": "auto",
            "udp": True,
            "tls": data.get('tls') == "tls",
            "network": data.get('net'),
            "ws-opts": {"path": data.get('path'), "headers": {"Host": data.get('host', '')}} if data.get('net') == 'ws' else None
        }
    except: return None

def generate_local_config(nodes_file):
    """本地解析节点并生成 Clash 配置"""
    proxies = []
    with open(nodes_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('vmess://'):
                p = parse_vmess(line)
                if p: proxies.append(p)
            # 这里可以扩展 vless/ss 的解析，为了稳定，我们优先处理 vmess
    
    config = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "allow-lan": True,
        "mode": "rule",
        "log-level": "silent",
        "proxies": proxies,
        "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}],
        "rules": ["MATCH,GLOBAL"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)
    return len(proxies)

def run_speed_test():
    setup_mihomo()
    now = datetime.now(SHANGHAI_TZ)
    report_name = f"speed_test_{now.strftime('%Y%m%d_%H%M%S')}.txt"

    print("[2/4] 正在本地转换节点配置...")
    count = generate_local_config(NODES_FILE)
    if count == 0:
        print("未识别到有效节点，请检查 nodes_list.txt 格式")
        return

    print(f"成功加载 {count} 个节点，正在启动内核...")
    log_file = open("mihomo_log.txt", "w")
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=log_file, stderr=log_file)
    
    time.sleep(5) 

    results = []
    try:
        # 获取节点列表
        resp = requests.get("http://127.0.0.1:9090/proxies", timeout=5)
        proxies_data = resp.json()['proxies']
        target_nodes = [k for k, v in proxies_data.items() if v['type'] == 'vmess'][:20]
        
        for name in target_nodes:
            print(f"正在测试: {name}")
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            
            start_time = time.time()
            total_bytes = 0
            try:
                # 显式指定代理
                proxies = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
                with requests.get(TEST_URL, stream=True, proxies=proxies, timeout=10) as r:
                    for chunk in r.iter_content(chunk_size=1024*128):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION:
                            break
                
                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1024 * 1024)
                results.append(f"✅ {round(speed_mbps, 2)} Mbps | {name}")
            except:
                results.append(f"❌ 失败 | {name}")

    finally:
        proc.terminate()
        log_file.close()

    with open(report_name, "w", encoding="utf-8") as f:
        f.write(f"测试报告 - {now.strftime('%Y-%m-%d %H:%M:%S')}\n" + "="*40 + "\n")
        f.write("\n".join(results))
    print(f"报告已生成: {report_name}")

if __name__ == "__main__":
    run_speed_test()
