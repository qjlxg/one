import os
import re
import json
import base64
import time
import subprocess
import yaml
import requests
import urllib.parse
from datetime import datetime
import pytz

# --- 配置参数 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
INPUT_NODES = "nodes_list.txt"      # 原始输入文件
OUTPUT_FAST = "nodes_list_fast.txt"  # 测速后的精选文件
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
TEST_DURATION = 5  # 每个节点下行测试5秒
SPEED_THRESHOLD = 1.0  # 过滤掉低于 1Mbps 的节点
FAKE_SPEED_LIMIT = 2500.0  # 过滤掉高于 2500Mbps 的虚假节点（机房回环）

def setup_mihomo():
    """准备 Mihomo 内核"""
    if not os.path.exists("mihomo"):
        print("[1/4] 正在准备 Mihomo 内核...")
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        else:
            # 如果不存在gz包则尝试直接寻找内核文件
            print("找不到内核压缩包，请确保 mihomo-linux-amd64...gz 在根目录")
        os.chmod("mihomo", 0o755)

def update_link_name(raw_link, speed_str):
    """
    修改原始链接的名称（别名），注入测试速度
    确保 VMess 内部 JSON 规范和通用协议的 URL 转义
    """
    try:
        if raw_link.startswith("vmess://"):
            b64_part = raw_link[8:].split('#')[0]
            b64_part += "=" * (-len(b64_part) % 4)
            data = json.loads(base64.b64decode(b64_part).decode('utf-8'))
            old_ps = data.get('ps', 'Node')
            data['ps'] = f"[{speed_str}] {old_ps}"
            new_json = json.dumps(data).encode('utf-8')
            return "vmess://" + base64.b64encode(new_json).decode('utf-8')
        else:
            url = urllib.parse.urlparse(raw_link)
            old_name = urllib.parse.unquote(url.fragment) if url.fragment else "Node"
            new_name = f"[{speed_str}] {old_name}"
            # 使用 quote 确保名称中的空格、特殊字符不会导致导入失败
            return url._replace(fragment=urllib.parse.quote(new_name)).geturl()
    except:
        return raw_link

def parse_link(link):
    """
    解析分享链接为 Mihomo 配置字典
    支持: vmess, vless, hysteria2, ss, trojan
    """
    try:
        link = link.strip()
        if not link: return None, None, None
        url = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{hash(link)%100}"
        node_config = None
        
        # 1. VMess
        if url.scheme == 'vmess':
            b64_data = link[8:].split('#')[0]
            b64_data += "=" * (-len(b64_data) % 4)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            node_config = {
                "name": name, "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') == "tls", "network": data.get('net'),
                "ws-opts": {"path": data.get('path'), "headers": {"Host": data.get('host', '')}} if data.get('net') == 'ws' else None
            }
        # 2. VLESS
        elif url.scheme == 'vless':
            query = urllib.parse.parse_qs(url.query)
            node_config = {
                "name": name, "type": "vless", "server": url.hostname, "port": url.port,
                "uuid": url.username, "cipher": "auto", "tls": True, "udp": True,
                "servername": query.get('sni', [''])[0],
                "network": query.get('type', ['tcp'])[0]
            }
        # 3. Hysteria2
        elif url.scheme == 'hysteria2':
            query = urllib.parse.parse_qs(url.query)
            node_config = {
                "name": name, "type": "hysteria2", "server": url.hostname, "port": url.port,
                "password": url.username, "auth": url.username, "skip-cert-verify": True,
                "sni": query.get('sni', [''])[0]
            }
        # 4. Shadowsocks
        elif url.scheme == 'ss':
            if '@' in url.netloc:
                user_info = base64.b64decode(url.username).decode() if ':' not in url.username else urllib.parse.unquote(url.username)
                method, password = user_info.split(':', 1)
                node_config = {"name": name, "type": "ss", "server": url.hostname, "port": url.port, "cipher": method, "password": password}

        if node_config:
            return name, node_config, link
    except:
        pass
    return None, None, None

def run_speed_test():
    setup_mihomo()
    now = datetime.now(SHANGHAI_TZ)
    
    # --- [2/4] 解析节点 ---
    print(f"[2/4] 正在从 {INPUT_NODES} 解析全协议节点...")
    name_to_link = {}
    proxies = []
    if not os.path.exists(INPUT_NODES):
        print(f"错误: 找不到输入文件 {INPUT_NODES}")
        return

    with open(INPUT_NODES, 'r', encoding='utf-8') as f:
        for line in f:
            name, config, raw = parse_link(line)
            if config:
                unique_name = f"{name}_{len(proxies)}"
                config['name'] = unique_name
                proxies.append(config)
                name_to_link[unique_name] = raw

    if not proxies:
        print("未发现有效节点链接。")
        return

    # 生成临时 Clash 配置
    clash_config = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "mode": "rule",
        "log-level": "silent",
        "proxies": proxies,
        "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [p['name'] for p in proxies]}],
        "rules": ["MATCH,GLOBAL"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)
    
    # 启动内核
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"内核已启动，加载了 {len(proxies)} 个节点，等待初始化...")
    time.sleep(12) 

    # --- [3/4] 全量测速 ---
    print(f"[3/4] 开始对 {len(proxies)} 个节点进行全量下载测速...")
    valid_results = []
    try:
        # 通过 API 获取节点列表（确保内核识别成功）
        resp = requests.get("http://127.0.0.1:9090/proxies", timeout=5).json()
        target_names = [k for k, v in resp['proxies'].items() if v['type'] not in ['Selector', 'Direct', 'Reject']]
        
        for idx, name in enumerate(target_names):
            # 切换节点
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            
            start_time = time.time()
            total_bytes = 0
            try:
                # 尝试下载
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=10) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=256*1024):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION:
                            break
                
                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1024 * 1024)
                
                # 筛选逻辑
                if speed_mbps >= FAKE_SPEED_LIMIT:
                    print(f"  [{idx+1}/{len(target_names)}] ⏩ 跳过虚假极速: {name[:20]} ({round(speed_mbps,1)}Mbps)")
                elif speed_mbps > SPEED_THRESHOLD:
                    speed_label = f"{round(speed_mbps, 1)}Mbps"
                    new_link = update_link_name(name_to_link[name], speed_label)
                    valid_results.append((speed_mbps, new_link))
                    print(f"  [{idx+1}/{len(target_names)}] ✅ {speed_label} | {name[:25]}")
                else:
                    print(f"  [{idx+1}/{len(target_names)}] ❌ 速度过低 | {name[:25]}")
            except:
                # 测速失败不打印，保持日志干净
                pass

    finally:
        proc.terminate()

    # --- [4/4] 结果归档 ---
    print(f"[4/4] 测速完成，正在生成精选列表...")
    valid_results.sort(key=lambda x: x[0], reverse=True)
    final_links = [item[1] for item in valid_results]

    # 1. 保存到 nodes_list_fast.txt
    with open(OUTPUT_FAST, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    # 2. 更新 README.md 展示
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 节点测速精选\n\n")
        rm.write(f"更新时间: `{now.strftime('%Y-%m-%d %H:%M:%S')}` (北京时间)\n\n")
        rm.write(f"本次测试原始节点: **{len(proxies)}**，筛选出可用节点: **{len(final_links)}**\n\n")
        rm.write(f"### 节点列表 (按速度排序)\n```text\n" + '\n'.join(final_links) + "\n```\n")

    # 3. 按日期备份归档
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    backup_path = os.path.join(dir_path, f"fast_{now.strftime('%d_%H%M%S')}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_links))

    print(f"流程结束。精选节点已保存至 {OUTPUT_FAST}。")

if __name__ == "__main__":
    run_speed_test()
