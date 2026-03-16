import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "nodes.txt",
    "nodes_list.txt",
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/tg_collector.txt",
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"
# 验证地址：使用能返回 IP 的 API 来确保代理生效
CHECK_URL = "http://httpbin.org/ip" 
LATENCY_URL = "https://www.google.com/generate_204"

TIMEOUT = 4       
MAX_RETRIES = 0   # 既然是洗节点，不需要重试，快速过
MAX_WORKERS = 40  # 适中的并发，防止请求太快导致内核崩溃
# ==========================================

# 全局变量记录原始 IP
ORIGINAL_IP = ""

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
        raw_name = unquote(parts[1]) if len(parts) > 1 else ""
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
            if data.get('net') == 'ws': node["ws-opts"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}
        elif scheme == 'vless':
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            node.update({"type": "vless", "uuid": url.username, "cipher": "auto", "tls": query.get('security') in ['tls', 'reality'], "servername": query.get('sni'), "network": query.get('type', 'tcp')})
            if query.get('security') == 'reality': node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
        elif scheme == 'trojan':
            node.update({"type": "trojan", "password": url.username, "sni": url.hostname, "tls": True})
        elif scheme in ['hy2', 'hysteria2']:
            node.update({"type": "hysteria2", "password": url.username, "sni": parse_qs(url.query).get('sni', [None])[0]})
        elif scheme == 'tuic':
            node.update({"type": "tuic", "uuid": url.username, "password": url.password})
        else: return None, None, None

        return (raw_name if raw_name else f"{node['type']}_{node['server']}"), node, link
    except: return None, None, None

def fetch_nodes():
    all_links = []
    for source in NODE_SOURCES:
        try:
            if source.startswith("http"):
                print(f"🌐 抓取远程: {source}")
                r = requests.get(source, timeout=10)
                content = r.text if r.status_code == 200 else ""
            else:
                if os.path.exists(source):
                    print(f"📂 读取文件: {source}")
                    with open(source, 'r', encoding='utf-8') as f: content = f.read()
                else: continue
            
            if "://" not in content[:50] and len(content) > 20: content = safe_base64_decode(content)
            links = [l.strip() for l in content.splitlines() if '://' in l]
            print(f"  ✅ 发现 {len(links)} 条链接")
            all_links.extend(links)
        except Exception as e: print(f"  ⚠️ 源 {source} 出错: {e}")
    return all_links

def test_single_node(p, name_to_link):
    idx_name = p['name']
    proxies_config = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}
    
    try:
        # 1. 强制切换节点并验证 API 响应
        ctrl_res = requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=2)
        if ctrl_res.status_code != 204:
            return None

        # 2. 验证出口 IP 是否变化 (防假阳性关键)
        start_t = time.time()
        ip_res = requests.get(CHECK_URL, proxies=proxies_config, timeout=TIMEOUT)
        current_ip = ip_res.json().get('origin', '')
        
        if not current_ip or current_ip == ORIGINAL_IP:
            # 如果 IP 没变，说明走的还是虚拟机原生网络
            return None

        # 3. 测速
        requests.get(LATENCY_URL, proxies=proxies_config, timeout=TIMEOUT)
        ms = int((time.time() - start_t) * 1000)
        print(f"  ✅ [{p['type'].upper()}] 出口: {current_ip} | {ms}ms")
        return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": ms}
    except:
        return None

def run_test():
    global ORIGINAL_IP
    # 获取原始 IP 用于对比
    try:
        ORIGINAL_IP = requests.get(CHECK_URL, timeout=5).json().get('origin', '')
        print(f"🏠 本地原始出口 IP: {ORIGINAL_IP}")
    except:
        print("❌ 无法获取原始 IP，请检查网络连接")
        return

    if not os.path.exists("mihomo"):
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
        else: print("❌ 缺失内核"); return

    all_links = fetch_nodes()
    proxies, name_to_link, seen = [], {}, set()
    for line in all_links:
        raw_name, config, raw_link = parse_link(line)
        if config and raw_link not in seen:
            u_name = f"N_{len(proxies):04d}"
            config['name'] = u_name
            proxies.append(config)
            name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
            seen.add(raw_link)

    print(f"📊 解析出 {len(proxies)} 个代理。")
    if not proxies: return

    # 生成临时配置
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "proxies": proxies}, f)

    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 等待 API 就绪
    for i in range(10):
        try:
            requests.get("http://127.0.0.1:9090/version")
            break
        except: time.sleep(1)

    print(f"🚀 开始真机测速 (并发: {MAX_WORKERS})...")
    valid_results = []
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_single_node, p, name_to_link) for p in proxies]
            for f in futures:
                res = f.result()
                if res: valid_results.append(res)
    finally:
        proc.terminate()

    if valid_results:
        valid_results.sort(key=lambda x: x['ms'])
        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join([f"{item['link'].split('#')[0]}#{item['raw_name']} ✅ {item['ms']}ms" for item in valid_results]))
        print(f"✨ 成功洗出 {len(valid_results)} 个真实可用节点")
    else:
        print("⚠️ 未发现可用节点。")

if __name__ == "__main__":
    run_test()
