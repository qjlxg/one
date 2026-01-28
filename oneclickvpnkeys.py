import os
import re
import requests
from datetime import datetime
import pytz

def fetch_and_save():
    # 1. 设置上海时区
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(shanghai_tz)
    
    # 2. 爬取
    channel_id = "oneclickvpnkeys"
    url = f"https://t.me/s/{channel_id}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"抓取失败: {e}")
        return

    # 3. 提取与去重 (匹配 vmess, ss, vless, trojan 等)
    pattern = r'(vmess|ss|ssr|trojan|vless)://[^\s<"\'#]+'
    nodes = re.findall(pattern, response.text)
    unique_nodes = list(dict.fromkeys(nodes))
    
    if not unique_nodes:
        print("未发现有效节点。")
        return

    # 4. 创建年月目录 (例如: 2026/01)
    dir_path = now.strftime('%Y/%m')
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    
    # 5. 文件命名: 脚本名_时间戳.txt
    file_name = f"{channel_id}_{now.strftime('%Y%m%d_%H%M%S')}.txt"
    full_path = os.path.join(dir_path, file_name)
    
    with open(full_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_nodes))
    
    print(f"任务完成：保存 {len(unique_nodes)} 个节点至 {full_path}")

if __name__ == "__main__":
    fetch_and_save()
