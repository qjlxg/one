import os
import re
import requests
import html
import csv
import base64
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
CHANNELS = [
    "v2ray_configs_pool", "oneclickvpnkeys", "free_v2ray_full_speed", 
    "v2ray_free_conf", "v2ray_vless_trojan_ss", "v2ray_vless_hysteria",
    "ShadowSocksShare", "SS_V2ray_Trojan", "v2ray_footprint", "V2list",
    "v2free66", "clash_node_share", "proxies_sharing"
]

SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
MIN_NODE_THRESHOLD = 5  # 如果总数少于 5 个，不覆盖原文件，保护数据安全
# ==========================================

def is_valid_proxy(node_url):
    """
    节点合法性校验：
    1. 必须以主流代理协议开头
    2. 长度需大于 15 个字符
    3. 排除 Telegram 自身的频道加入链接
    """
    protocols = ('vmess://', 'vless://', 'ss://', 'trojan://', 'hysteria://', 'tuic://', 'hysteria2://', 'socks5://')
    
    if not node_url.startswith(protocols):
        return False
    if len(node_url) < 15:
        return False
    # 排除广告和频道链接
    if any(ad in node_url for ad in ["t.me/joinchat", "t.me/+", "bit.ly"]):
        return False
    return True

def fetch_single_channel(channel_id):
    """执行抓取并返回 (频道ID, 节点列表)"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # 增加超时控制
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 核心修复：解码 HTML 实体
        raw_text = html.unescape(response.text)
        
        # 正则优化：允许更多特殊字符，直到遇到 HTML 标签边界或引号
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'#]+'
        found = re.findall(pattern, raw_text)
        
        # 过滤
        valid_nodes = [n for n in found if is_valid_proxy(n)]
        return channel_id, valid_nodes
    except Exception as e:
        print(f"[-] 抓取 {channel_id} 异常: {e}")
        return channel_id, []

def save_stats_csv(stats_data):
    """保存抓取统计到 CSV (仿股票数据格式)"""
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

    print(f"[*] 任务启动时间: {date_str}")

    # 并发抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for channel_id, nodes in results:
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, len(nodes)])
        print(f"[+] 频道 {channel_id.ljust(20)} | 抓取数: {len(nodes)}")

    # 记录统计
    save_stats_csv(stats_log)

    # 去重
    final_nodes = list(dict.fromkeys(all_nodes))
    total_count = len(final_nodes)

    # --- 空数据保护 ---
    if total_count < MIN_NODE_THRESHOLD:
        print(f"\n[!] 触发保护机制：本次仅获得 {total_count} 个节点，不执行覆盖保存。")
        return

    # --- 保存明文列表 ---
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # --- 保存 Base64 订阅格式 (可选，方便直接导入客户端) ---
    b64_content = base64.b64encode('\n'.join(final_nodes).encode('utf-8')).decode('utf-8')
    with open("subscribe_base64.txt", 'w', encoding='utf-8') as f:
        f.write(b64_content)

    # --- 备份归档 ---
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"nodes_{timestamp}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print("-" * 50)
    print(f"[OK] 任务完成！")
    print(f"[OK] 唯一有效节点数: {total_count}")
    print(f"[OK] 统计已更新至: grab_stats.csv")
    print(f"[OK] Base64 订阅已生成: subscribe_base64.txt")

if __name__ == "__main__":
    main()
