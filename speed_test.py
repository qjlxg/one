import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes.txt"]
OUTPUT_LATEST = "latest_nodes.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 测速目标改为 Google 204，这通常不会被防火墙报 403 错误
LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5  # 超过 5 秒认为超时不可用

def parse_link(link):
    """全协议解析逻辑 (保持原有高性能解析)"""
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        node = {"name": name, "server": url.hostname, "port": int(url.port or 443), "udp": True, "skip-cert-verify": True}

        if url.scheme == 'vless':
            node.update({"type": "vless", "uuid": url.username, "cipher": "auto", "tls": query.get('security') in ['tls', 'reality'], "servername": query.get('sni'), "network": query.get('type', 'tcp'), "flow": query.get('flow')})
            if query.get('security') == 'reality': node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
        elif url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node.update({"type": "vmess", "server": data.get('add'), "port": int(data.get('port')), "uuid": data.get('id'), "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'), "servername": data.get('sni') or data.get('host')})
        elif url.scheme in ['hy2', 'hysteria2']:
            node.update({"type": "hysteria2", "password": url.username, "sni": query.get('sni'), "obfs": query.get('obfs'), "obfs-password": query.get('obfs-password')})
        elif url.scheme == 'tuic':
            node.update({"type": "tuic", "uuid": url.username, "password": url.password, "alpn": [query.get('alpn', 'h3')], "congestion-controller": query.get('congestion_control', 'bbr'), "sni": query.get('sni')})
        elif url.scheme == 'trojan':
            node.update({"type": "trojan", "password": url.username, "sni": query.get('sni', url.hostname), "tls": True})
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                method, password = user_info.split(':', 1)
                node.update({"type": "ss", "cipher": method, "password": password})
        return name, node, link if node.get("type") else (None, None, None)
    except: return None, None, None

def run_test():
    # 1. 准备内核
    if not os.path.exists("mihomo"):
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
    
    # 2. 解析节点
    proxies, name_to_link, seen = [], {}, set()
    print(f"[{datetime.now(SHANGHAI_TZ).strftime('%H:%M:%S')}] 🔍 正在加载节点...", flush=True)
    with open(INPUT_NODES[0], 'r', encoding='utf-8') as f:
        for line in f:
            name, config, raw = parse_link(line)
            if config and raw not in seen:
                u_name = f"N_{len(proxies):03d}_{config['type']}"
                config['name'] = u_name
                proxies.append(config)
                name_to_link[u_name] = raw
                seen.add(raw)

    # 3. 生成配置
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "log-level": "silent", "proxies": proxies}, f)

    # 4. 启动内核
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL)
    time.sleep(4)

    valid_nodes = []
    print(f"🚀 开始联通性测试 (共 {len(proxies)} 节点)", flush=True)

    # 5. 测试循环
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    for p in proxies:
        name = p['name']
        print(f"  [{p['type'].upper()}] {p['server']} ...", end=" ", flush=True)
        try:
            # 切换节点
            requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name}, timeout=3)
            
            # 测试延迟
            start_t = time.time()
            r = requests.get(LATENCY_URL, 
                             proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, 
                             headers=headers, 
                             timeout=TIMEOUT)
            
            if r.status_code == 204 or r.status_code == 200:
                ms = int((time.time() - start_t) * 1000)
                print(f"✅ {ms}ms", flush=True)
                # 重新组合链接，带上延迟标记
                valid_nodes.append(f"{name_to_link[name]}#({ms}ms)")
            else:
                print(f"💀 状态异常 ({r.status_code})", flush=True)
        except Exception as e:
            print(f"💀 超时/断开", flush=True)

    proc.terminate()
    
    # 6. 保存结果
    with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))
    
    print(f"\n✨ 测试结束！有效节点: {len(valid_nodes)} / {len(proxies)}")

if __name__ == "__main__":
    run_test()
