import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "https://github.com/qjlxg/aggregator/raw/refs/heads/main/data/v2ray.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"

# 更换为对 Actions 极度友好的测速地址
LATENCY_URL = "http://cp.cloudflare.com/generate_204"
BACKUP_URL = "http://connectivitycheck.gstatic.com/generate_204"

# 核心参数：在保持质量的同时提高通过率
TIMEOUT = 8             # 给免费节点更多一点响应时间
MAX_WORKERS = 25        # 进一步降低并发，防止 Actions 网络拥塞导致误判
MAX_LATENCY = 1800      # 1.8秒，兼顾可用性与稳定性
RETRY_COUNT = 2         # 2次采样足够排除偶然断连
# ==========================================

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def safe_base64_decode(s):
    try:
        s = s.strip().replace('-', '+').replace('_', '/')
        missing_padding = len(s) % 4
        if missing_padding: s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def parse_link(link):
    try:
        link = link.strip()
        if not link or len(link) < 10: return None, None, None
        parts = link.split('#', 1)
        base_link = parts[0]
        raw_name = unquote(parts[1]) if len(parts) > 1 else "Node"
        url = urlparse(base_link)
        scheme = url.scheme.lower()
        
        # 统一允许跳过证书验证，以适应免费源
        node = {"name": "", "server": url.hostname or "", "port": int(url.port or 443), "udp": True, "skip-cert-verify": True}

        if scheme == 'ss':
            if '@' in url.netloc:
                user_info = url.username if ':' in url.username else safe_base64_decode(url.username)
                if ':' in user_info:
                    m, p = user_info.split(':', 1)
                    node.update({"type": "ss", "cipher": m, "password": p})
                else: return None, None, None
            else:
                decoded = safe_base64_decode(base_link[5:])
                if '@' in decoded: return parse_link(f"ss://{decoded}#{raw_name}")
                return None, None, None
        elif scheme == 'vmess':
            data = json.loads(safe_base64_decode(base_link[8:]))
            node.update({"type": "vmess", "server": data.get('add'), "port": int(data.get('port', 443)), "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto", "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp')})
        elif scheme == 'vless':
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            node.update({"type": "vless", "uuid": url.username, "cipher": "auto", "tls": query.get('security') in ['tls', 'reality'], "servername": query.get('sni'), "network": query.get('type', 'tcp')})
        elif scheme == 'trojan':
            node.update({"type": "trojan", "password": url.username, "sni": url.hostname, "tls": True})
        else: return None, None, None

        return raw_name, node, link
    except: return None, None, None

def test_single_node(p, name_to_link):
    idx_name = p['name']
    proxies_config = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
    
    try:
        # 1. 切换节点
        requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=3)
        
        # 2. 延迟与连通性测试
        latencies = []
        for _ in range(RETRY_COUNT):
            start_t = time.time()
            # 【关键修改】：verify=False，不再强求证书合法性，匹配 skip-cert-verify: True
            res = requests.get(LATENCY_URL, proxies=proxies_config, timeout=TIMEOUT, verify=False)
            if res.status_code == 204 or res.status_code == 200:
                latencies.append(int((time.time() - start_t) * 1000))
            time.sleep(0.5)

        if not latencies: return None
        
        avg_ms = sum(latencies) // len(latencies)
        if avg_ms > MAX_LATENCY: return None

        # 3. 流量模拟：确保能读到数据
        with requests.get(BACKUP_URL, proxies=proxies_config, timeout=TIMEOUT, stream=True, verify=False) as r:
            if r.status_code == 200:
                chunk = r.raw.read(512) # 读取 512 字节确认链路通畅
                if not chunk: return None
            else:
                return None

        log(f"✅ [{p['type'].upper()}] {p['server']} | {avg_ms}ms")
        return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": avg_ms}
    except:
        return None

def run_test():
    log("🛠️ 环境初始化...")
    
    # 抑制 SSL 警告（因为我们开启了 verify=False）
    requests.packages.urllib3.disable_warnings()
    
    all_links = []
    for source in NODE_SOURCES:
        try:
            r = requests.get(source, timeout=15)
            content = r.text if r.status_code == 200 else ""
            if "://" not in content[:50] and len(content) > 20: content = safe_base64_decode(content)
            links = [l.strip() for l in content.splitlines() if '://' in l]
            log(f"🌐 源 {source}: 发现 {len(links)} 条链接")
            all_links.extend(links)
        except: pass

    proxies, name_to_link, seen = [], {}, set()
    for line in all_links:
        raw_name, config, raw_link = parse_link(line)
        if not config: continue
        server_key = f"{config['server']}:{config['port']}"
        if server_key not in seen:
            u_name = f"N_{len(proxies):04d}"
            config['name'] = u_name
            proxies.append(config)
            name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
            seen.add(server_key)

    log(f"📊 待测独立服务器总数: {len(proxies)}")
    if not proxies: return

    config_dict = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "mode": "global",
        "ipv6": False,
        "log-level": "silent",
        "proxies": proxies
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config_dict, f)

    if os.path.exists(MIHOMO_GZ):
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for _ in range(15):
        try:
            requests.get("http://127.0.0.1:9090/version", timeout=1)
            log("🚀 内核启动成功，执行筛选...")
            break
        except: time.sleep(1)
    else:
        log("❌ 内核启动失败"); proc.terminate(); return

    valid_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_single_node, p, name_to_link) for p in proxies]
        for f in futures:
            res = f.result()
            if res: valid_results.append(res)

    proc.terminate()

    if valid_results:
        valid_results.sort(key=lambda x: x['ms'])
        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            lines = [f"{item['link'].split('#')[0]}#{item['raw_name']}" for item in valid_results]
            f.write('\n'.join(lines))
        log(f"✨ 筛选完成！保留了 {len(valid_results)} 个可用节点")
    else:
        log("⚠️ 依旧没有节点通过测试，请检查源链接或 Actions 网络状况")

if __name__ == "__main__":
    run_test()
