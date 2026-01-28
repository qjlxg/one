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
    """抓取频道 Web 预览页的所有节点链接"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 通用匹配：寻找所有包含 :// 的链接（排除 http/https）
        # 这种写法可以一次性抓取 vmess, vless, ss, ssr, trojan, hysteria, tuic 等所有类型
        pattern = r'(?!(?:http|https))([a-zA-Z0-9.\-_]+://[^\s<"\'#]+)'
        nodes = re.findall(pattern, response.text)
        
        return nodes
    except Exception as e:
        print(f"抓取 {channel_id} 失败: {e}")
        return []

def main():
    now = datetime.now(SHANGHAI_TZ)
    all_nodes = []

    # 脚本内部并行执行 (方便后续增加更多频道)
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for nodes in results:
        all_nodes.extend(nodes)

    # 全局去重：利用 dict.fromkeys 保持节点出现的先后顺序
    final_nodes = list(dict.fromkeys(all_nodes))

    if not final_nodes:
        print("未发现任何节点链接。")
        return

    content = '\n'.join(final_nodes)
    script_name = "oneclickvpnkeys"

    # --- 1. 保存到根目录 (始终保持最新) ---
    root_file = f"{script_name}.txt"
    with open(root_file, 'w', encoding='utf-8') as f:
        f.write(content)

    # --- 2. 保存到年月目录 (备份存档) ---
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(dir_path, f"{script_name}_{timestamp}.txt")
    
    with open(backup_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"成功抓取 {len(final_nodes)} 个节点。")
    print(f"最新文件: ./{root_file}")
    print(f"备份文件: ./{backup_file}")

if __name__ == "__main__":
    main()
