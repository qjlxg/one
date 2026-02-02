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
TEST_DURATION = 5  # 每个节点测试5秒

def setup_mihomo():
    if not os.path.exists("mihomo"):
        print("[1/4] 正在准备 Mihomo 内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def parse_link(link):
    """通用解析逻辑，支持多种协议"""
    try:
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        
        # 1. VMess
        if url.scheme == 'vmess':
            data = json.loads(base64.base64decode(link[8:]).decode('utf-8'))
            return {
                "name": data.get('ps', name),
                "type": "vmess",
                "server": data.get('add'),
                "port": int(data.get('port')),
                "uuid": data.get('id'),
                "alterId": int(data.get('aid', 0)),
                "cipher": "auto",
                "tls": data.get('tls') == "tls",
                "network": data.get('net'),
                "ws-opts": {"path": data.get('path'), "headers": {"Host": data.get('host', '')}} if data.get('net') == 'ws' else None,
                "grpc-opts": {"grpc-service-name": data.get('path')} if data.get('net') == 'grpc' else None
            }

        # 2. VLESS
        elif url.scheme == 'vless':
            query = parse_qs(url.query)
            return {
                "name": name,
                "type": "vless",
                "server": url.hostname,
                "port": url.port,
                "uuid": url.username,
                "cipher": "auto",
                "tls": query.get('security', [''])[0] == 'tls',
                "udp": True,
                "network": query.get('type', ['tcp'])[0],
                "servername": query.get('sni', [''])[0],
                "reality-opts": {"public-key": query.get('pbk', [''])[0], "short-id": query.get('sid', [''])[0]} if query.get('security', [''])[0] == 'reality' else None
            }

        # 3. Hysteria2
        elif url.scheme == 'hysteria2':
            query = parse_qs(url.query)
            return {
                "name": name,
                "type": "hysteria2",
                "server": url.hostname,
                "port": url.port,
                "password": url.username,
                "sni": query.get('sni', [''])[0],
                "skip-cert-verify": query.get('insecure', ['0'])[0] == '1',
                "obfs": query.get('obfs', [None])[0],
                "obfs-password": query.get('obfs-password', [None])[0]
            }

        # 4. Shadowsocks (SS)
        elif url.scheme == 'ss':
            # 处理 ss://base64(method:password)@host:port
            if '@' in url.netloc:
                user_info = unquote(url.username + ':' + url.password) if url.password else base64.b64decode(url.username).decode()
                method, password = user_info.split(':', 1)
                return {"name": name, "type": "ss", "server": url.hostname, "port": url.port, "cipher": method, "password": password}
    except Exception:
        pass
    return None

def generate_local_config(nodes_file):
    proxies = []
    with open(nodes_file, 'r', encoding='utf-8') as f:
        for line in f:
            p = parse_link(line.strip())
            if p: proxies.append(p)
    
    if not proxies: return 0

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

    print("[2/4] 正在本地解析全协议配置...")
    count = generate_local_config(NODES_FILE)
    if count == 0:
        print("未识别到任何有效节点！")
        return

    print(f"成功加载 {count} 个节点，正在启动内核...")
    log_file = open("mihomo_log.txt", "w")
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=log_file, stderr=log_file)
    
    time.sleep(7) # 节点多时，给内核更多解析时间

    results = []
    try:
        # 连接 API
        resp = requests.get("http://127.0.0.1:9090/proxies", timeout=5)
        proxies_data = resp.json()['proxies']
        # 排除系统保留名
        target_nodes = [k for k, v in proxies_data.items() if v['type'] not in ['Selector', 'URLTest', 'Direct', 'Reject']]
        
        # 为了不让 Actions 超时，默认测速前 30 个
        print(f"开始测速 (计划测试前 {min(len(target_nodes), 30)} 个节点)...")
        for name in target_nodes[:30]:
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            
            start_time = time.time()
            total_bytes = 0
            try:
                proxies = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
                # 使用 stream=True 进行块下载测速
                with requests.get(TEST_URL, stream=True, proxies=proxies, timeout=8) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=256*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION:
                            break
                
                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1024 * 1024)
                res_str = f"✅ {round(speed_mbps, 2)} Mbps | {name}"
                print(res_str)
                results.append(res_str)
            except:
                print(f"❌ 失败 | {name}")
                results.append(f"❌ 失败 | {name}")

    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        proc.terminate()
        log_file.close()

    with open(report_name, "w", encoding="utf-8") as f:
        f.write(f"测试报告 - {now.strftime('%Y-%m-%d %H:%M:%S')}\n" + "="*50 + "\n")
        f.write("\n".join(results))
    print(f"测试完成！报告: {report_name}")

if __name__ == "__main__":
    run_speed_test()
