import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes.txt"]
OUTPUT_LATEST = "latest_nodes.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 测速目标：Google 204 是最稳的连通性测试点
LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5  

def parse_link(link):
    """全协议解析逻辑"""
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        # 初始名称提取
        raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        node = {"name": raw_name, "server": url.hostname, "port": int(url.port or 443), "udp": True, "skip-cert-verify": True}

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
        return raw_name, node, link if node.get("type") else (None, None, None)
    except: return None, None, None

def run_test():
    if not os.path.exists("mihomo"):
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
    
    proxies, name_to_link, seen = [], {}, set()
    print(f"[{datetime.now(SHANGHAI_TZ).strftime('%H:%M:%S')}] 🔍 正在加载节点源...", flush=True)
    
    with open(INPUT_NODES[0], 'r', encoding='utf-8') as f:
        for line in f:
            raw_name, config, raw_link = parse_link(line)
            if config and raw_link not in seen:
                # 统一内核内部使用的索引名，防止特殊字符导致内核启动失败
                u_name = f"N_{len(proxies):03d}"
                config['name'] = u_name
                proxies.append(config)
                # 存储原始名字和链接
                name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
                seen.add(raw_link)

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "log-level": "silent", "proxies": proxies}, f)

    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL)
    time.sleep(4)

    valid_results = []
    print(f"🚀 开始极速联通性筛选 (共 {len(proxies)} 节点)", flush=True)

    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    for p in proxies:
        idx_name = p['name']
        print(f"  [{p['type'].upper()}] {p['server']} ...", end=" ", flush=True)
        try:
            requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=3)
            start_t = time.time()
            r = requests.get(LATENCY_URL, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, headers=headers, timeout=TIMEOUT)
            
            if r.status_code in [200, 204]:
                ms = int((time.time() - start_t) * 1000)
                print(f"✅ {ms}ms", flush=True)
                valid_results.append({
                    "link": name_to_link[idx_name]['link'],
                    "raw_name": name_to_link[idx_name]['raw_name'],
                    "ms": ms
                })
            else: print(f"💀 状态异常 ({r.status_code})", flush=True)
        except: print(f"💀 超时", flush=True)

    proc.terminate()
    
    # --- 排序并保存 ---
    if valid_results:
        # 按延迟从低到高排序
        valid_results.sort(key=lambda x: x['ms'])
        
        final_output = []
        for item in valid_results:
            
            base_url = item['link'].split('#')[0]
          
            new_name = f"{item['raw_name']} ✅ {item['ms']}ms"
            final_output.append(f"{base_url}#{new_name}")

        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_output))
        
        print(f"\n✨ 筛选完成！最优节点: {valid_results[0]['ms']}ms，已存入 {OUTPUT_LATEST}")
    else:
        print("\n⚠️ 未发现可用节点。")

if __name__ == "__main__":
    run_test()
