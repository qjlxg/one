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
    "ShadowSocksShare", "SS_V2ray_Trojan", "v2ray_footprint", "V2list",
    "v2free66", "clash_node_share", "proxies_sharing"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    """抓取并统计频道内所有节点"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # 增加流式传输和超时，提高稳定性
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # --- 关键步骤：先反转义 HTML，还原所有被转义的 & 和参数 ---
        raw_text = html.unescape(response.text)
        
        # --- 正则匹配：匹配主流协议，直到遇到 HTML 标签或空白符 ---
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'\\]+'
        nodes = re.findall(pattern, raw_text)
        
        # 过滤掉明显的非节点（如只有协议头或太短的误报）
        clean_nodes = [n.strip().split('<')[0] for n in nodes if len(n) > 15]
        
        return channel_id, clean_nodes
    except Exception:
        # 抓取失败返回空列表，确保统计时该频道标记为 0 而不是崩溃
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 任务启动: {date_str}")

    # 并行抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        # 使用 list 确保所有线程执行完毕
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    # 遍历结果，确保每个频道只被记录一次
    for channel_id, nodes in results:
        count = len(nodes)
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, count])
        # 控制台实时反馈，方便你检查
        print(f"[+ {str(count).rjust(3)} 节点] {channel_id}")

    # --- 写入 CSV ---
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # --- 去重并保存 txt ---
    final_nodes = list(dict.fromkeys(all_nodes))
    if final_nodes:
        with open("nodes_list.txt", 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_nodes))
        print("-" * 30)
        print(f"[OK] 抓取完成！总唯一节点: {len(final_nodes)}")
    else:
        print("\n[!] 警告：本次未能抓取到任何有效节点。")

if __name__ == "__main__":
    main()
