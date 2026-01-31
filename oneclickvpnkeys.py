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
    "oneclickvpnkeys", 
    "v2ray_free_conf"   
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    """最简抓取：统计频道内所有节点链接数量"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 彻底解码 HTML 实体
        raw_text = html.unescape(response.text)
        
        # 匹配协议链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        
        # 简单清洗末尾残留
        clean_nodes = [n.rstrip('.,;)]') for n in nodes]
        
        return channel_id, clean_nodes
    except Exception:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 任务开始: {date_str}")

    # 1. 执行并发抓取
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for channel_id, nodes in results:
        count = len(nodes)
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, count])
        print(f"[+ {str(count).rjust(3)} 节点] {channel_id}")

    # 2. 写入 CSV 统计表
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 3. 去重
    final_nodes = list(dict.fromkeys(all_nodes))

    if not final_nodes:
        print("[!] 未发现有效节点，跳过文件写入。")
        return

    # 4. 更新根目录主文件
    base_name = "nodes_list"
    with open(f"{base_name}.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 5. 【恢复】备份归档逻辑
    # 创建 2026/01 这种格式的目录
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    
    # 备份文件名：nodes_list_20260131_115146.txt
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"{base_name}_{timestamp}.txt")
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print("-" * 30)
    print(f"[OK] 根目录文件已更新")
    print(f"[OK] 备份文件存至: {backup_path}")
    print(f"[OK] 统计数据已计入 grab_stats.csv")

if __name__ == "__main__":
    main()
