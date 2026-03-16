import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
# 自动合并本地与远程节点源
NODE_SOURCES = [
    #"nodes.txt",
    #"nodes_list.txt",
    #"https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/tg_collector.txt",
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5       # 单次连接超时
MAX_RETRIES = 2   
MAX_WORKERS = 20  # 提高并发到 20，加速处理大量节点
# ==========================================

def parse_link(link):
    """全协议深度解析引擎 (保持原逻辑不变)"""
    try:
        link = link.strip()
        if not link or len(link) < 5: return None, None, None
        url = urlparse(link)
        raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        
        node = {
            "name": "", 
            "server": url.hostname,
            "port": int(url.port or 443),
            "udp": True,
            "skip-cert-verify": True
        }

        if url.scheme == 'vless':
            node.update({
                "type": "vless", "uuid": url.username, "cipher": "auto",
                "tls": query.get('security') in ['tls', 'reality'],
                "servername": query.get('sni'), "network": query.get('type', 'tcp'),
                "flow": query.get('flow', '')
            })
            if query.get('security') == 'reality':
                node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
            if query.get('type') in ['ws', 'grpc']:
                node["network"] = query.get('type')
                if query.get('type') == 'ws':
                    node["ws-opts"] = {"path": query.get('path', '/'), "headers": {"Host": query.get('host', '')}}
                if query.get('type') == 'grpc':
                    node["grpc-opts"] = {"grpc-service-name": query.get('serviceName', '')}
        elif url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node.update({
                "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'),
                "servername": data.get('sni') or data.get('host', '')
            })
        elif url.scheme in ['hy2', 'hysteria2']:
            node.update({"type": "hysteria2", "password": url.username, "sni": query.get('sni'), "obfs": query.get('obfs'), "obfs-password": query.get('obfs-password')})
        elif url.scheme == 'tuic':
            node.update({"type": "tuic", "uuid": url.username, "password": url.password, "alpn": [query.get('alpn', 'h3')], "congestion-controller": query.get('congestion_control', 'bbr'), "sni": query.get('sni')})
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                method, password = user_info.split(':', 1)
                node.update({"type": "ss", "cipher": method, "password": password})
        elif url.scheme == 'trojan':
            node.update({ "type": "trojan", "password": url.username, "sni": query.get('sni', url.hostname), "tls": True})

        return raw_name, node, link if node.get("type") else (None, None, None)
    except:
        return None, None, None

def test_single_node(p, name_to_link):
    """并行测试核心逻辑 - 修复 KeyError 并增强安全性"""
    idx_name = p['name']
    # 使用 .get 安全获取字段，防止格式错误的节点导致崩溃
    node_type = p.get('type', 'UNKNOWN').upper()
    node_server = p.get('server', 'NULL')

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # 切换内核当前节点
            requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=2)
            
            start_t = time.time()
            r = requests.get(LATENCY_URL, 
                             proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, 
                             timeout=TIMEOUT)
            if r.status_code in [200, 204]:
                ms = int((time.time() - start_t) * 1000)
                print(f"  ✅ [{node_type}] {node_server} | {ms}ms", flush=True)
                return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": ms}
        except:
            if attempt < MAX_RETRIES: 
                time.sleep(0.5)
            continue
    
    print(f"  💀 [{node_type}] {node_server} | Failed", flush=True)
    return None

def fetch_nodes():
    """获取本地和远程节点数据"""
    all_links = []
    for source in NODE_SOURCES:
        try:
            if source.startswith("http"):
                print(f"🌐 获取远程源: {source}", flush=True)
                r = requests.get(source, timeout=10)
                if r.status_code == 200:
                    lines = r.text.splitlines()
                    all_links.extend(lines)
                    print(f"   - 找到 {len(lines)} 条链接", flush=True)
            elif os.path.exists(source):
                print(f"📂 读取本地源: {source}", flush=True)
                with open(source, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    all_links.extend(lines)
                    print(f"   - 找到 {len(lines)} 条链接", flush=True)
        except Exception as e:
            print(f"⚠️ 无法加载源 {source}: {e}", flush=True)
    return all_links

def run_test():
    # 1. 环境准备
    if not os.path.exists("mihomo"):
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
        else:
            print("❌ 错误: 未找到内核文件。", flush=True)
            return

    # 2. 节点预处理
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

    if not proxies:
        print("⚠️ 没有解析到有效节点，任务结束。", flush=True)
        return

    # 3. 启动 Mihomo 内核
    config_data = {
        "mixed-port": 7890, 
        "external-controller": "127.0.0.1:9090", 
        "mode": "global", 
        "log-level": "silent", 
        "proxies": proxies
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config_data, f)

    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"⚙️  内核启动中 (PID: {proc.pid})...", flush=True)
    time.sleep(5) 

    # 4. 执行并发测试
    print(f"🚀 开始并行测速 | 线程数: {MAX_WORKERS} | 节点总数: {len(proxies)}", flush=True)
    valid_results = []
    
    # 捕获异常防止主程序崩溃
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_single_node, p, name_to_link) for p in proxies]
            for f in futures:
                res = f.result()
                if res:
                    valid_results.append(res)
    except Exception as e:
        print(f"❌ 运行过程中出现错误: {e}", flush=True)
    finally:
        # 5. 清理与保存
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except:
            proc.kill()

    print(f"\n📊 测试完成，正在排序结果...", flush=True)

    if valid_results:
        valid_results.sort(key=lambda x: x['ms'])
        final_lines = [f"{item['link'].split('#')[0]}#{item['raw_name']} ✅ {item['ms']}ms" for item in valid_results]
        
        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines))
        
        print(f"✨ 任务成功！保存 {len(final_lines)} 个有效节点到 {OUTPUT_LATEST}", flush=True)
        print(f"🥇 最优节点: {valid_results[0]['ms']}ms ({valid_results[0]['raw_name']})", flush=True)
    else:
        print("⚠️ 本次测试未发现任何联通节点。", flush=True)

if __name__ == "__main__":
    run_test()
