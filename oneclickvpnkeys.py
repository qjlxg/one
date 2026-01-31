import os
import re
import requests
import html
import csv
import json
import base64
import urllib.parse
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# --- 配置区 ---
CHANNELS = [
    "oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys",
    "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 核心逻辑：基于唯一特征标识符的规范化方法 ---

def normalize_config(config):
    """
    规范化代理配置字符串，提取核心唯一标识符 (dedupe_key) 进行去重。
    """
    try:
        # 去掉末尾备注名称
        if '#' in config:
            config_body, _ = config.rsplit('#', 1)
        else:
            config_body = config

        protocol = config_body.split('://')[0].lower()
        config_content = config_body.split('://')[1]

        # 1. VLESS, Trojan, Hysteria2, Hysteria, Tuic
        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            parsed = urllib.parse.urlparse(config_body)
            # 提取核心标识符 (UUID/Password)
            # 匹配路径或地址中的 UUID 格式
            id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 
                                parsed.path + parsed.netloc + parsed.query)
            uuid = id_match.group(1) if id_match else ""
            
            query_params = urllib.parse.parse_qs(parsed.query)
            security = query_params.get('security', [''])[0].lower()
            
            if security == 'reality':
                pbk = query_params.get('pbk', [''])[0]
                # 指纹：协议 + UUID + Reality公钥
                normalized_key = f"protocol={protocol}&uuid={uuid}&pbk={pbk}"
            else:
                # 其他协议使用协议类型 + UUID + 服务器端口作为去重依据
                normalized_key = f"protocol={protocol}&uuid={uuid}&netloc={parsed.netloc.lower()}"

            # 保持原始体部，但抹除 # 备注
            return normalized_key, config_body

        # 2. VMess
        elif protocol == 'vmess':
            # 处理可能的 base64 填充问题
            padding = len(config_content) % 4
            if padding:
                config_content += "=" * (4 - padding)
            
            decoded = base64.b64decode(config_content).decode('utf-8')
            json_data = json.loads(decoded)
            
            # 使用 VMess ID 作为唯一标识
            dedupe_key = f"vmess://{json_data.get('id', '')}@{json_data.get('add','')}:{json_data.get('port','')}"
            
            # 抹除 ps (别名) 和 add (显示地址可能变动)
            normalized_data = {k: v for k, v in json_data.items() if k not in ['ps', 'add']}
            normalized_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
            normalized_config = f"{protocol}://{base64.b64encode(normalized_json.encode('utf-8')).decode('utf-8')}"
            
            return dedupe_key, normalized_config

        # 3. Shadowsocks (SS)
        elif protocol == 'ss':
            if '@' in config_content:
                auth, _ = config_content.split('@', 1)
                dedupe_key = f"ss://{auth}"
            else:
                padding = len(config_content) % 4
                if padding: config_content += "=" * (4 - padding)
                decoded = base64.b64decode(config_content).decode('utf-8')
                dedupe_key = f"ss://{decoded.split('@')[0].strip().lower()}"
            return dedupe_key, config_body

        else:
            # 不认识的协议直接返回体部
            return config_body, config_body

    except Exception as e:
        # print(f"规范化配置时出错: {e}")
        return config, config

def fetch_single_channel(channel_id):
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        raw_text = html.unescape(response.text)
        # 匹配协议链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s<"\'#]+(?:#[^\s<"\'#]*)?'
        nodes = re.findall(pattern, raw_text)
        return channel_id, [n.rstrip('.,;)]') for n in nodes]
    except:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_raw_nodes = []

    print(f"[*] 任务开始: {date_str}")

    # 1. 并发抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for _, nodes in results:
        all_raw_nodes.extend(nodes)

    # 2. 使用您提供的方法进行规范化去重
    unique_map = {} # {dedupe_key: normalized_config}
    
    for raw_url in all_raw_nodes:
        dedupe_key, clean_config = normalize_config(raw_url)
        if dedupe_key not in unique_map:
            unique_map[dedupe_key] = clean_config

    final_nodes = sorted(list(unique_map.values()))
    
    print(f"[*] 原始发现: {len(all_raw_nodes)} -> 唯一标识符去重后: {len(final_nodes)}")

    # 3. 写入文件
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    # 4. 更新 README.md
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 物理级去重节点库\n\n")
        rm.write(f"最后更新时间: `{date_str}` (上海时间)\n")
        rm.write(f"有效节点数量: **{len(final_nodes)}**\n\n")
        rm.write(f"### 节点内容\n")
        rm.write(f"```text\n")
        rm.write('\n'.join(final_nodes))
        rm.write(f"\n```\n")

if __name__ == "__main__":
    main()
