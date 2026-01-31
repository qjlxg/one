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
from urllib.parse import urlparse, urlunparse

# --- 配置区 ---
CHANNELS = [
    "oneclickvpnkeys", 
    "v2ray_free_conf",
    "ip_cf_config",
    "vlesskeys",
    "VlessVpnFree",
    "vpnfail_vless",
    "v2Line",
    "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 核心逻辑：节点清洗与去重 ---

def clean_node(node_url):
    """
    清洗节点：去掉别名（ps/fragment），只保留官方必须的核心参数
    """
    try:
        node_url = node_url.strip()
        if not node_url:
            return None
            
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()

        # 1. 处理 vmess (Base64 编码的 JSON)
        if scheme == 'vmess':
            try:
                # vmess:// 后面通常是 base64
                v2_raw = base64.b64decode(parsed.netloc).decode('utf-8')
                v2_json = json.loads(v2_raw)
                # 抹除别名 ps (备注)
                if 'ps' in v2_json:
                    v2_json['ps'] = "" 
                # 重新编码成纯净的 vmess 链接
                new_netloc = base64.b64encode(json.dumps(v2_json).encode('utf-8')).decode('utf-8')
                return f"vmess://{new_netloc}"
            except Exception:
                return node_url

        # 2. 处理 vless / trojan / ss / hysteria2 / tuic 等
        # 这些协议的名称/备注通常在 URL 的 # (fragment) 部分
        if scheme in ['vless', 'trojan', 'ss', 'hysteria', 'hysteria2', 'tuic']:
            # 重新构建 URL，通过将 fragment 设置为空字符串来剔除名称
            clean_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # 抹除 # 后的内容
            ))
            return clean_url

        return node_url
    except Exception:
        return node_url

def fetch_single_channel(channel_id):
    """抓取并统计频道内所有节点"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 解码 HTML 实体
        raw_text = html.unescape(response.text)
        
        # 匹配所有常见协议
        pattern = r'(?:ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        
        # 初步清理末尾标点
        return channel_id, [n.rstrip('.,;)]') for n in nodes]
    except Exception:
        return channel_id, []

# --- 主程序 ---

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_raw_nodes = []
    stats_log = []

    print(f"[*] 任务开始: {date_str}")

    # 1. 并发抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for channel_id, nodes in results:
        count = len(nodes)
        all_raw_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, count])
        print(f"[+ {str(count).rjust(3)} 原始] {channel_id}")

    # 2. 深度清洗并去重
    # 使用 set 存储清洗后的 URL，自动完成去重
    cleaned_nodes_set = set()
    for raw_n in all_raw_nodes:
        cleaned = clean_node(raw_n)
        if cleaned:
            cleaned_nodes_set.add(cleaned)
    
    final_nodes = sorted(list(cleaned_nodes_set)) # 排序使列表整齐
    total_raw = len(all_raw_nodes)
    total_final = len(final_nodes)
    
    print("-" * 30)
    print(f"[*] 统计: 原始节点 {total_raw} -> 清洗去重后 {total_final} (压缩率: {((total_raw-total_final)/total_raw*100):.1f}%)")

    if not final_nodes:
        print("[!] 未抓取到有效节点。")
        return

    # 3. 写入抓取统计 CSV
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 4. 更新 README.md
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 自动更新节点列表\n\n")
        rm.write(f"最后更新时间: `{date_str}` (上海时间)\n\n")
        rm.write(f"本次去重后有效节点: **{total_final}** 个 (原始总数: {total_raw})\n\n")
        rm.write(f"### 节点内容 (纯净无名版)\n")
        rm.write(f"```text\n")
        rm.write('\n'.join(final_nodes))
        rm.write(f"\n```\n")

    # 5. 更新根目录 nodes_list.txt
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 6. 按年月归档备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"nodes_list_{timestamp}.txt")
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] README.md 已更新")
    print(f"[OK] 归档文件: {backup_path}")

if __name__ == "__main__":
    main()
