import os
import json
import base64
import re
import socket
import maxminddb
import urllib.parse
from collections import defaultdict

# --- 硬性指标配置 ---
DB_PATH = 'GeoLite2-Country.mmdb'
RESULT_JSON = 'out.json'         
FINAL_FILE = 'nodes_list.txt'    
MIN_SPEED_MB = 2.0               # 门槛设为 2MB/s，保证 1080P/4K 电影流畅

def get_country(address):
    try:
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address):
            ip = socket.gethostbyname(address)
        else: ip = address
        with maxminddb.open_database(DB_PATH) as reader:
            data = reader.get(ip)
            return data['country']['names'].get('zh-CN', 'Unknown')
    except: return "Unknown"

def rename_node(raw_url, new_name):
    try:
        if raw_url.startswith('vmess://'):
            v_data = json.loads(base64.b64decode(raw_url.split('://')[1]).decode('utf-8'))
            v_data['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(v_data).encode()).decode()}"
        else:
            u = list(urllib.parse.urlparse(raw_url))
            u[5] = urllib.parse.quote(new_name)
            return urllib.parse.urlunparse(u)
    except: return None

def main():
    if not os.path.exists(RESULT_JSON):
        print("未生成 out.json，可能所有节点都超时了")
        return

    with open(RESULT_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 兼容处理：新版结果可能直接是列表或在 "nodes" 下
    nodes_data = data if isinstance(data, list) else data.get('nodes', [])
    
    # 按平均速度降序排列，最快的排第一
    nodes_data.sort(key=lambda x: x.get('speed', 0), reverse=True)

    valid_nodes = []
    name_tracker = defaultdict(int)

    for n in nodes_data:
        raw_speed = n.get('speed', 0)
        speed_mb = raw_speed / (1024 * 1024)
        
        # 核心过滤：速度不达标直接跳过
        if speed_mb < MIN_SPEED_MB:
            continue

        link = n.get('link')
        address = n.get('address')
        
        # 兜底：如果 JSON 里没给 address，从链接里解析
        if not address and link:
            try:
                if 'vmess://' in link:
                    v_tmp = json.loads(base64.b64decode(link.split('://')[1]).decode('utf-8'))
                    address = v_tmp.get('add')
                else:
                    address = urllib.parse.urlparse(link).hostname
            except: pass

        country = get_country(address) if address else "Unknown"
        count = name_tracker[country]
        display_name = country if count == 0 else f"{country} {count}"
        name_tracker[country] += 1
        
        # 改名格式：国家 序号 [带宽]
        new_name = f"{display_name} [{speed_mb:.1f}MB/s]"
        
        new_node = rename_node(link, new_name)
        if new_node:
            valid_nodes.append(new_node)

    with open(FINAL_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))
    
    print(f"筛选完成！从原有节点中选出 {len(valid_nodes)} 个高速节点。")

if __name__ == "__main__":
    main()
