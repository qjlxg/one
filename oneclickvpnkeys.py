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
    "v2ray_free_conf",
    "ip_cf_config",
    "vlesskeys",
    "VlessVpnFree",
    "vpnfail_vless",
    "v2Line",
    "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    """抓取并统计频道内所有节点"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 解码 HTML 实体，解决 &amp; 问题
        raw_text = html.unescape(response.text)
        
        # 匹配协议链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        
        return channel_id, [n.rstrip('.,;)]') for n in nodes]
    except Exception:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 任务开始: {date_str}")

    # 1. 并发抓取
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
        print("[!] 未抓取到任何节点。")
        return

    # 4. 更新 README.md (提供可复制的内容)
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 自动更新节点列表\n\n")
        rm.write(f"最后更新时间: `{date_str}` (上海时间)\n\n")
        rm.write(f"本次共抓取有效节点: **{len(final_nodes)}** 个\n\n")
        rm.write(f"### 节点内容 (可直接复制)\n")
        rm.write(f"```text\n")
        rm.write('\n'.join(final_nodes))
        rm.write(f"\n```\n")

    # 5. 更新根目录 nodes_list.txt
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 6. 原版备份逻辑：按年月归档
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"nodes_list_{timestamp}.txt")
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print("-" * 30)
    print(f"[OK] README.md 已生成 (含可复制节点)")
    print(f"[OK] 备份文件: {backup_path}")

if __name__ == "__main__":
    main()
