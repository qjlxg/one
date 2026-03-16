import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"
LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5       
MAX_RETRIES = 2   
MAX_WORKERS = 20  
# ==========================================

def safe_base64_decode(s):
    """通用 Base64 解码器：处理填充、URL安全字符及编码错误"""
    try:
        s = s.strip().replace('-', '+').replace('_', '/')
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_link(link):
    """全协议深度解析引擎 (SS/VMess/VLESS/Trojan/Hy2/TUIC)"""
    try:
        link = link.strip()
        if not link or len(link) < 10: return None, None, None
        
        parts = link.split('#', 1)
        base_link = parts[0]
        raw_name = unquote(parts[1]) if len(parts) > 1 else ""
        
        url = urlparse(base_link)
        scheme = url.scheme.lower()
        
        node = {
            "name": "", 
            "server": url.hostname or "",
            "port": int(url.port or 443),
            "udp": True,
            "skip-cert-verify": True
        }

        # 1. Shadowsocks (SS)
        if scheme == 'ss':
            if '@' in url.netloc:
                user_info_raw = url.username
                if ':' not in user_info_raw:
                    user_info = safe_base64_decode(user_info_raw)
                else:
                    user_info = user_info_raw
                
                if ':' in user_info:
                    method, password = user_info.split(':', 1)
                    node.update({"type": "ss", "cipher": method, "password": password})
                else: return None, None, None
            else:
                decoded = safe_base64_decode(base_link[5:])
                if '@' in decoded: return parse_link(f"ss://{decoded}#{raw_name}")
                return None, None, None

        # 2. VMess
        elif scheme == 'vmess':
            json_str = safe_base64_decode(base_link[8:])
            if not json_str: return None, None, None
            data = json.loads(json_str)
            node.update({
                "type": "vmess", "server": data.get('add'), "port": int(data.get('port', 443)),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'),
                "servername": data.get('sni') or data.get('host', '')
            })
            if data.get('net') == 'ws':
                node["ws-opts"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}

        # 3. VLESS
        elif scheme == 'vless':
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            node.update({
                "type": "vless", "uuid": url.username, "cipher": "auto",
                "tls": query.get('security') in ['tls', 'reality'],
                "servername": query.get('sni'), "network": query.get('type', 'tcp'),
                "flow": query.get('flow', '')
            })
            if query.get('security') == 'reality':
                node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}

        # 4. 其他协议
        elif scheme == 'trojan':
            node.update({"type": "trojan", "password": url.username, "sni": url.hostname, "tls": True})
        elif scheme in ['hy2', 'hysteria2']:
            node.update({"type": "hysteria2", "password": url.username, "sni": parse_qs(url.query).get('sni', [None])[0]})
        elif scheme == 'tuic':
            node.update({"type": "tuic", "uuid": url.username, "password": url.password})
        else: return None, None, None

        final_name = raw_name if raw_name else f"{node['type']}_{node['server']}_{node['port']}"
        return final_name, node, link
    except: return None, None, None

def test_single_node(p, name_to_link):
    idx_name = p['name']
    node_type = p.get('type', 'UNKNOWN').upper()
    node_server = p.get('server', 'NULL')
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=3)
            start_t = time.time()
            r = requests.get(LATENCY_URL, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=TIMEOUT)
            if r.status_code in [200, 204]:
                ms = int((time.time() - start_t) * 1000)
                print(f"  ✅ [{node_type}] {node_server} | {ms}ms")
                return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": ms}
        except:
            if attempt < MAX_RETRIES: time.sleep(0.5)
    print(f"  💀 [{node_type}] {node_server} | Failed")
    return None

def fetch_nodes():
    all_links = []
    for source in NODE_SOURCES:
        try:
            print(f"🌐 正在抓取源: {source}")
            r = requests.get(source, timeout=15)
            if r.status_code == 200:
                content = r.text
                if "://" not in content[:50] and len(content) > 20:
                    content = safe_base64_decode(content)
                lines = content.splitlines()
                all_links.extend([l for l in lines if '://' in l])
        except Exception as e:
            print(f"⚠️ 抓取失败: {e}")
    return all_links

def run_test():
    if not os.path.exists("mihomo"):
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
        else:
            print("❌ 错误: 未找到内核文件。")
            return

    all_links = fetch_nodes()
    print(f"🔍 原始数据: 抓取到 {len(all_links)} 行")
    
    proxies, name_to_link, seen = [], {}, set()
    for line in all_links:
        raw_name, config, raw_link = parse_link(line)
        if config and raw_link not in seen:
            u_name = f"N_{len(proxies):04d}"
            config['name'] = u_name
            proxies.append(config)
            name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
            seen.add(raw_link)

    print(f"📊 解析结果: {len(proxies)} 个有效代理配置")
    if not proxies:
        print("❌ 错误: 没有任何代理被解析。")
        return

    config_data = {"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "log-level": "silent", "proxies": proxies}
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config_data, f)

    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5) 

    print(f"🚀 开始并发测速 | 线程数: {MAX_WORKERS} | 节点总数: {len(proxies)}")
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
        final_lines = [f"{item['link'].split('#')[0]}#{item['raw_name']} ✅ {item['ms']}ms" for item in valid_results]
        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines))
        print(f"✨ 成功保存 {len(final_lines)} 个节点到 {OUTPUT_LATEST}")
    else:
        print("⚠️ 未发现有效节点。")

if __name__ == "__main__":
    run_test()
