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
    """抓取频道并只提取代理协议节点"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 核心修改：只匹配指定的代理协议头
        # 排除掉你结果中出现的 https://, tg://, http:// 等非节点链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic)://[^\s<"\'#]+'
        nodes = re.findall(pattern, response.text)
        
        return nodes
    except Exception as e:
        print(f"抓取 {channel_id} 失败: {e}")
        return []

def main():
    now = datetime.now(SHANGHAI_TZ)
    all_nodes = []

    # 脚本内部并行执行
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_channel, CHANNELS)
    
    for nodes in results:
        all_nodes.extend(nodes)

    # 全局去重
    final_nodes = list(dict.fromkeys(all_nodes))

    if not final_nodes:
        print("未发现纯净代理节点。")
        return

    content = '\n'.join(final_nodes)
    script_name = "oneclickvpnkeys"

    # --- 保存逻辑 ---
    # 1. 根目录文件 (纯净节点列表)
    with open(f"{script_name}.txt", 'w', encoding='utf-8') as f:
        f.write(content)

    # 2. 年月目录备份 (带时间戳)
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"{script_name}_{timestamp}.txt")
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"提取完成！过滤了图片和网页链接，共获得 {len(final_nodes)} 个纯净节点。")

if __name__ == "__main__":
    main()
