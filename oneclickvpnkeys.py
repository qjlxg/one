import os
import re
import requests
import html
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# 配置
CHANNELS = ["oneclickvpnkeys"，“v2ray_configs_pool”] 
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    """抓取频道并修复转义问题"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # --- 关键修复：将 &amp; 还原为 & ---
        raw_text = html.unescape(response.text)
        
        # 只提取主流代理协议
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic)://[^\s<"\'#]+'
        nodes = re.findall(pattern, raw_text)
        
        return nodes
    except Exception as e:
        print(f"抓取 {channel_id} 失败: {e}")
        return []

def main():
    now = datetime.now(SHANGHAI_TZ)
    all_nodes = []

    # 并行抓取
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for nodes in results:
        all_nodes.extend(nodes)

    # 去重
    final_nodes = list(dict.fromkeys(all_nodes))

    if not final_nodes:
        print("未发现有效节点。")
        return

    # 保存重命名后的文件
    base_name = "nodes_list"
    
    # 1. 根目录文件 (修复后的纯净列表)
    with open(f"{base_name}.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 2. 备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"{base_name}_{timestamp}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"已修复节点格式并保存。共 {len(final_nodes)} 个节点。")

if __name__ == "__main__":
    main()
