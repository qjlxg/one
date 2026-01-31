import os
import re
import requests
import html
import csv
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# 配置
CHANNELS = [
    "v2ray_configs_pool", "oneclickvpnkeys", "free_v2ray_full_speed", 
    "v2ray_free_conf", "v2ray_vless_trojan_ss", "v2ray_vless_hysteria",
    "ShadowSocksShare", "SS_V2ray_Trojan", "v2ray_footprint", "V2list"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
MIN_NODE_THRESHOLD = 5 

# [此处插入上面的 is_valid_proxy 函数]

def fetch_single_channel(channel_id):
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 1. 解码 HTML 实体（解决 &amp; 等问题）
        raw_text = html.unescape(response.text)
        
        # 2. 匹配协议链接（宽泛匹配，交给下一步深度过滤）
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'#]+'
        found = re.findall(pattern, raw_text)
        
        # 3. 深度清洗
        valid_nodes = []
        for n in found:
            # 去掉末尾可能存在的 HTML 标签残留
            clean_node = n.split('<')[0].split('"')[0].split("'")[0]
            if is_valid_proxy(clean_node):
                valid_nodes.append(clean_node)
        
        return channel_id, valid_nodes
    except Exception:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 开始分析频道数据... {date_str}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for channel_id, nodes in results:
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, len(nodes)])
        print(f"[+] {channel_id.ljust(22)} | 有效节点: {len(nodes)}")

    # 保存统计（你的 CSV 格式）
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists: writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 去重并保存
    final_nodes = list(dict.fromkeys(all_nodes))
    if len(final_nodes) >= MIN_NODE_THRESHOLD:
        with open("nodes_list.txt", 'w', encoding='utf-8') as f:
            f.writelines('\n'.join(final_nodes))
        print(f"\n[OK] 任务成功。总唯一节点: {len(final_nodes)}")
    else:
        print(f"\n[!] 抓取数 {len(final_nodes)} 过低，触发保护，未写入文件。")

if __name__ == "__main__":
    main()
