import os
import re
import requests
import html
import csv
import json
import base64
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# --- 配置区 ---
CHANNELS = [
    "oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys",
    "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def get_node_fingerprint(node_url):
    """
    提取节点的核心指纹，用于物理去重。
    指纹包含：协议、地址、端口、用户ID、路径/SNI（不含名称和广告）
    """
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        
        # 1. 处理 VMess (解包 JSON 提取核心参数)
        if scheme == 'vmess':
            v2_raw = base64.b64decode(parsed.netloc).decode('utf-8')
            v = json.loads(v2_raw)
            # 核心指纹：地址 + 端口 + id + 路径
            fingerprint = f"vmess|{v.get('add')}|{v.get('port')}|{v.get('id')}|{v.get('path')}|{v.get('host')}"
            return fingerprint, node_url # 返回指纹和原始链接用于重组

        # 2. 处理 VLESS / Trojan / SS / Hysteria
        # 提取核心：协议 + 用户信息(uuid) + 地址 + 端口 + 关键路径参数
        params = parse_qs(parsed.query)
        # 排除无意义参数，保留核心转发参数
        core_query = {k: v for k, v in params.items() if k in ['path', 'sni', 'serviceName', 'pid']}
        
        # 构造指纹字符串
        fingerprint = f"{scheme}|{parsed.netloc}|{parsed.path}|{urlencode(core_query, doseq=True)}"
        return fingerprint, node_url
    except:
        return node_url, node_url # 出错则按原样处理

def rebuild_clean_node(node_url):
    """
    基于指纹逻辑重新构建一个绝对纯净的链接
    """
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()

        if scheme == 'vmess':
            v = json.loads(base64.b64decode(parsed.netloc).decode('utf-8'))
            clean_v = {
                "v": "2", "ps": "", "add": v.get('add'), "port": v.get('port'),
                "id": v.get('id'), "aid": v.get('aid', "0"), "net": v.get('net'),
                "type": v.get('type'), "host": v.get('host'), "path": v.get('path'),
                "tls": v.get('tls'), "sni": v.get('sni'), "alpn": v.get('alpn')
            }
            new_netloc = base64.b64encode(json.dumps(clean_v).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_netloc}"

        # 通用处理：抹除 fragment (#之后的内容)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
    except:
        return node_url

def fetch_single_channel(channel_id):
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0...'}
        response = requests.get(url, headers=headers, timeout=15)
        raw_text = html.unescape(response.text)
        pattern = r'(?:ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        return channel_id, [n.rstrip('.,;)]') for n in nodes]
    except:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_raw_nodes = []

    # 1. 抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for _, nodes in results:
        all_raw_nodes.extend(nodes)

    # 2. 【核心改进】基于指纹的物理去重
    fingerprint_map = {} # 用于存放 {指纹: 节点链接}
    
    for raw_url in all_raw_nodes:
        fp, _ = get_node_fingerprint(raw_url)
        # 如果指纹没出现过，或者当前的链接比已有的更完整（可选），则保留
        if fp not in fingerprint_map:
            # 存入前进行最后的链接清洗（去名）
            fingerprint_map[fp] = rebuild_clean_node(raw_url)

    final_nodes = sorted(list(fingerprint_map.values()))
    
    print(f"[*] 原始: {len(all_raw_nodes)} -> 物理去重后: {len(final_nodes)}")

    # 3. 写入文件 (保持原有逻辑)
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 物理级去重节点库\n最后更新: `{date_str}`\n有效节点: **{len(final_nodes)}**\n\n```text\n")
        rm.write('\n'.join(final_nodes))
        rm.write("\n```\n")

if __name__ == "__main__":
    main()
