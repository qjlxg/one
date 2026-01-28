import os
import re
import requests
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# 配置
CHANNELS = ["oneclickvpnkeys"] 
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def fetch_single_channel(channel_id):
    url = f"https://t.me/s/{channel_id}"
    try:
        # 增加 headers 模拟浏览器，防止被屏蔽
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        # 匹配各种协议节点
        pattern = r'(vmess|ss|ssr|trojan|vless)://[^\s<"\'#]+'
        return re.findall(pattern, response.text)
    except Exception as e:
        print(f"抓取 {channel_id} 出错: {e}")
        return []

def main():
    now = datetime.now(SHANGHAI_TZ)
    all_nodes = []

    # --- 脚本并行运行 ---
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for nodes in results:
        all_nodes.extend(nodes)

    # 全局去重
    final_nodes = list(dict.fromkeys(all_nodes))

    if not final_nodes:
        print("未获取到任何节点。")
        return

    content = '\n'.join(final_nodes)
    script_base_name = os.path.basename(__file__).split('.')[0]

    # 1. 在根目录生成/更新文件 (不带时间戳，始终保持最新)
    root_file_path = f"{script_base_name}.txt"
    with open(root_file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"根目录文件已更新: {root_file_path}")

    # 2. 在年月目录生成备份文件 (带时间戳)
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_file_name = f"{script_base_name}_{timestamp}.txt"
    backup_full_path = os.path.join(dir_path, backup_file_name)
    
    with open(backup_full_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"备份完成，已保存至: {backup_full_path}")

if __name__ == "__main__":
    main()
