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
MIN_NODE_THRESHOLD = 10  # 空数据保护阈值：少于10个节点不执行覆盖保存

def is_valid_proxy(node_url):
    """
    自动检测是否为真实的代理链接
    1. 排除掉包含 Telegram 内部跳转的链接
    2. 简单校验 vmess 等协议后的 Base64 或参数特征
    """
    # 排除掉常见的电报群组、机器人跳转链接及广告
    blacklist = ['t.me/', 'joinchat', '?', 'http://', 'https://']
    if any(item in node_url.lower() for item in blacklist):
        return False
    
    # 针对 vmess 做进一步校验（必须是 vmess:// 加 Base64 格式）
    if node_url.startswith('vmess://'):
        payload = node_url.split('://')[1]
        if len(payload) < 20: return False # 长度太短大概率是死链
        
    return True

def fetch_single_channel(channel_id):
    """抓取频道并过滤节点"""
    url = f"https://t.me/s/{channel_id}"
    channel_nodes = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        raw_text = html.unescape(response.text)
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic)://[^\s<"\'#]+'
        found = re.findall(pattern, raw_text)
        
        # 应用过滤函数
        channel_nodes = [n for n in found if is_valid_proxy(n)]
        return channel_id, channel_nodes
    except Exception as e:
        print(f"[-] 抓取 {channel_id} 失败: {e}")
        return channel_id, []

def save_stats_csv(stats_data):
    """
    CSV 统计功能
    格式: 日期, 频道ID, 抓取数量
    """
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_data)

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 启动任务: {date_str}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for channel_id, nodes in results:
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, len(nodes)])

    # 记录统计数据
    save_stats_csv(stats_log)

    # 去重
    final_nodes = list(dict.fromkeys(all_nodes))
    total_count = len(final_nodes)

    # --- 空数据保护逻辑 ---
    if total_count < MIN_NODE_THRESHOLD:
        print(f"[!] 警告：本次抓取仅获得 {total_count} 个节点，低于阈值 {MIN_NODE_THRESHOLD}。")
        print("[!] 为了防止覆盖现有可用列表，本次不执行写入操作。")
        return

    # 保存主文件
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 备份归档
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"nodes_{timestamp}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[+] 抓取成功：共 {total_count} 个唯一合法节点。统计已写入 grab_stats.csv。")

if __name__ == "__main__":
    main()
