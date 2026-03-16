import os, json, base64, time, subprocess, yaml, requests
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
# 聚合多个高频更新的订阅源，提高基数
NODE_SOURCES = [
    "nodes.txt"，
    "nodes_list.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"
CHECK_URL = "http://httpbin.org/ip"
LATENCY_URL = "http://cp.cloudflare.com/generate_204"

# 核心参数
TIMEOUT = 7             # 给响应慢但稳定的节点一点机会
MAX_WORKERS = 20        # 降低并发，确保节点切换指令被 mihomo 准确执行
MAX_LATENCY = 1500      # 超过 1.5s 的节点本地基本无法使用
# ==========================================

ORIGINAL_IP = ""

def log(msg):
    """带时间戳的强制刷新日志"""
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
        time.sleep(0.5) 
        
        # 2. IP 验证
        start_t = time.time()
        ip_res = requests.get(f"{CHECK_URL}?cache={idx_name}", proxies=proxies_config, timeout=TIMEOUT)
        current_ip = ip_res.json().get('origin', '')
        
        if not current_ip or current_ip == ORIGINAL_IP:
            return None

        # 3. 延迟与质量二测
        lat_res = requests.get(LATENCY_URL, proxies=proxies_config, timeout=TIMEOUT)
        if lat_res.status_code not in [200, 204]: return None
        
        ms = int((time.time() - start_t) * 1000)
        if ms > MAX_LATENCY: return None

        log(f"✅ [{p['type'].upper()}] {p['server']} | IP: {current_ip} | {ms}ms")
        return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": ms}
    except:
        return None

def run_test():
    global ORIGINAL_IP
    log("🛠️ 环境初始化...")
    
    try:
        ORIGINAL_IP = requests.get(CHECK_URL, timeout=10).json().get('origin', '')
        log(f"🏠 本地原始 IP: {ORIGINAL_IP}")
    except Exception as e:
        log(f"❌ 无法连接测速接口: {e}"); return

    all_links = []
    for source in NODE_SOURCES:
        try:
            if source.startswith("http"):
                r = requests.get(source, timeout=15)
                content = r.text
            elif os.path.exists(source):
                with open(source, 'r', encoding='utf-8') as f: content = f.read()
            else: continue

            if "://" not in content[:50] and len(content) > 20: content = safe_base64_decode(content)
            links = [l.strip() for l in content.splitlines() if '://' in l]
            log(f"🌐 源 {source}: 发现 {len(links)} 条")
            all_links.extend(links)
        except: pass

    proxies, name_to_link, seen_servers = [], {}, set()
    for line in all_links:
        raw_name, config, raw_link = parse_link(line)
        if config:
            server_key = f"{config['server']}:{config['port']}"
            if server_key not in seen_servers:
                u_name = f"N_{len(proxies):04d}"
                config['name'] = u_name
                proxies.append(config)
                name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
                seen_servers.add(server_key)

    log(f"📊 去重后待测总数: {len(proxies)}")
    if not proxies: return

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "ipv6": False, "proxies": proxies}, f)

    if os.path.exists(MIHOMO_GZ):
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
    
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    for _ in range(15):
        try:
            requests.get("http://127.0.0.1:9090/version", timeout=1)
            log("🚀 内核已就绪，开始测速...")
            break
        except: time.sleep(1)
    else:
        log("❌ 内核 API 响应超时"); proc.terminate(); return

    valid_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_single_node, p, name_to_link) for p in proxies]
        for f in futures:
            res = f.result()
            if res: valid_results.append(res)

    proc.terminate()

    # 🟢 注意：这部分现在正确地位于 run_test 函数内部
    if valid_results:
        valid_results.sort(key=lambda x: x['ms'])
        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join([f"{item['link'].split('#')[0]}#{item['raw_name']}" for item in valid_results]))
        log(f"✨ 成功！筛选出 {len(valid_results)} 个真实可用节点，已保存至 {OUTPUT_LATEST}")
    else:
        log("⚠️ 未发现高质量节点")

if __name__ == "__main__":
    run_test()
