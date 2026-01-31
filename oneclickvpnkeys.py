import os
import re
import requests
import html
import csv
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# 配置：只保留产出稳定的频道
CHANNELS = [
    "oneclickvpnkeys",      # 你的稳定源
    "v2ray_free_conf",      # 你的稳定源
    "v2ray_configs_pool",   # 观察是否能恢复
    "v2ray_footprint",      # 备选
    "V2list"                # 备选
]

SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    """最简抓取：只要是代理链接就计数"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # 增加超时和简单的重试逻辑
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # 彻底解码 HTML，防止 &amp; 截断链接
        raw_text = html.unescape(response.text)
        
        # 匹配协议链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        
        return channel_id, nodes
    except Exception:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 正在统计频道节点产量... {date_str}")

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for channel_id, nodes in results:
        count = len(nodes)
        all_nodes.extend(nodes)
        # 只记录每个频道的产出总量
        stats_log.append([date_str, channel_id, count])
        print(f"[+ {str(count).rjust(3)} 节点] {channel_id}")

    # 写入 CSV (你的股票数据风格)
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 去重保存
    final_nodes = list(dict.fromkeys(all_nodes))
    if final_nodes:
        with open("nodes_list.txt", 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_nodes))
        print(f"统计完成，唯一节点总数: {len(final_nodes)}")

if __name__ == "__main__":
    main()
