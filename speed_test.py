import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
import pytz
from urllib.parse import urlparse, unquote, parse_qs, urlunparse

# ================= 配置区 =================
# 确保你的仓库中有这个解压后的内核或对应的 .gz 文件
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = ["nodes.txt"]
OUTPUT_LATEST = "latest_nodes.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 测速目标：使用 Google 204，最稳且不返回多余数据
LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5       # 单次连接超时时间（秒）
MAX_RETRIES = 2   # 每个节点最多测2次（1次正式测试 + 1次失败重试）
# ==========================================

def parse_link(link):
    """全协议深度解析引擎"""
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urlparse(link)
        raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        
        # 基础节点信息
        node = {
            "name": raw_name,
            "server": url.hostname,
            "port": int(url.port or 443),
            "udp": True,
            "skip-cert-verify": True
        }

        # 1. VLESS 解析
        if url.scheme == 'vless':
            node.update({
                "type": "vless",
                "uuid": url.username,
                "cipher": "auto",
                "tls": query.get('security') in ['tls', 'reality'],
                "servername": query.get('sni'),
                "network": query.get('type', 'tcp'),
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

        # 2. VMess 解析
        elif url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            # 补全 base64 填充
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node.update({
                "type": "vmess",
                "server": data.get('add'),
                "port": int(data.get('port')),
                "uuid": data.get('id'),
                "alterId": int(data.get('aid', 0)),
                "cipher": "auto",
                "tls": data.get('tls') in ['tls', True, 'true'],
                "network": data.get('net', 'tcp'),
                "servername": data.get('sni') or data.get('host', '')
            })

        # 3. Hysteria2 解析
        elif url.scheme in ['hy2', 'hysteria2']:
            node.update({
                "type": "hysteria2",
                "password": url.username,
                "sni": query.get('sni'),
                "obfs": query.get('obfs'),
                "obfs-password": query.get('obfs-password')
            })

        # 4. TUIC 解析
        elif url.scheme == 'tuic':
            node.update({
                "type": "tuic",
                "uuid": url.username,
                "password": url.password,
                "alpn": [query.get('alpn', 'h3')],
                "congestion-controller": query.get('congestion_control', 'bbr'),
                "sni": query.get('sni')
            })

        # 5. Shadowsocks 解析
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                # 处理 ss://method:password@host:port 格式
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                method, password = user_info.split(':', 1)
                node.update({"type": "ss", "cipher": method, "password": password})

        # 6. Trojan 解析
        elif url.scheme == 'trojan':
            node.update({
                "type": "trojan",
                "password": url.username,
                "sni": query.get('sni', url.hostname),
                "tls": True
            })

        return raw_name, node, link if node.get("type") else (None, None, None)
    except:
        return None, None, None

def test_single_node(idx_name):
    """带自动重试的联通性测试核心逻辑"""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    # 切换当前节点为全局代理
    try:
        requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": idx_name}, timeout=3)
    except:
        return None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            start_t = time.time()
            r = requests.get(LATENCY_URL, 
                             proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, 
                             headers=headers, 
                             timeout=TIMEOUT)
            if r.status_code in [200, 204]:
                return int((time.time() - start_t) * 1000)
        except:
            if attempt < MAX_RETRIES:
                time.sleep(0.8) # 失败重试前停顿，避开瞬时网络抖动
                continue
    return None

def run_test():
    # 1. 准备 Mihomo 内核
    if not os.path.exists("mihomo"):
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
        else:
            print("❌ 错误: 未找到内核文件。")
            return

    # 2. 解析节点源
    proxies, name_to_link, seen = [], {}, set()
    print(f"[{datetime.now(SHANGHAI_TZ).strftime('%H:%M:%S')}] 🔍 正在加载节点...", flush=True)
    
    if not os.path.exists(INPUT_NODES[0]):
        print(f"❌ 错误: 找不到输入文件 {INPUT_NODES[0]}")
        return

    with open(INPUT_NODES[0], 'r', encoding='utf-8') as f:
        for line in f:
            raw_name, config, raw_link = parse_link(line)
            if config and raw_link not in seen:
                # 使用内部索引名 N_xxx，避免原始名称中的特殊字符导致 Mihomo 配置解析失败
                u_name = f"N_{len(proxies):03d}"
                config['name'] = u_name
                proxies.append(config)
                name_to_link[u_name] = {"raw_name": raw_name, "link": raw_link}
                seen.add(raw_link)

    # 3. 生成临时配置文件
    config_data = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "mode": "global",
        "log-level": "silent",
        "proxies": proxies
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config_data, f)

    # 4. 启动内核
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5) # 等待内核完全就绪

    valid_results = []
    print(f"🚀 开始极速联通性筛选 (自动重试模式, 共 {len(proxies)} 节点)", flush=True)

    # 5. 循环测试
    for p in proxies:
        idx_name = p['name']
        print(f"  [{p['type'].upper()}] {p['server']} ...", end=" ", flush=True)
        
        ms = test_single_node(idx_name)
        
        if ms is not None:
            print(f"✅ {ms}ms", flush=True)
            valid_results.append({
                "link": name_to_link[idx_name]['link'],
                "raw_name": name_to_link[idx_name]['raw_name'],
                "ms": ms
            })
        else:
            print(f"💀 失败", flush=True)

    # 6. 关闭内核
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except:
        proc.kill()

    # 7. 排序、格式化并保存结果
    if valid_results:
        # 按延迟从小到大排序
        valid_results.sort(key=lambda x: x['ms'])
        
        final_lines = []
        for item in valid_results:
            # 去掉链接原有的名字部分重新拼接
            base_url = item['link'].split('#')[0]
            # 格式：[原始名] ✅ 123ms
            optimized_name = f"{item['raw_name']} ✅ {item['ms']}ms"
            final_lines.append(f"{base_url}#{optimized_name}")

        with open(OUTPUT_LATEST, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_lines))
        
        print(f"\n✨ 任务完成！已保存 {len(final_lines)} 个有效节点到 {OUTPUT_LATEST}")
        print(f"🥇 最快节点: {valid_results[0]['ms']}ms")
    else:
        print("\n⚠️ 未发现可用节点，请检查节点源或网络环境。")

if __name__ == "__main__":
    run_test()
