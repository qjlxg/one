import os
import json
import base64
import re
import socket
import maxminddb
import urllib.parse
from collections import defaultdict

# --- 配置 ---
DB_PATH = 'GeoLite2-Country.mmdb'
RESULT_JSON = 'out.json'         # 二进制工具生成的测速报告
FINAL_FILE = 'nodes_list.txt'    # 最终输出
MIN_SPEED_MB = 1.0               # 门槛：下载速度低于 1MB/s 的节点全部扔掉

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
            data = json.loads(base64.b64decode(raw_url.split('://')[1]).decode('utf-8'))
            data['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(data).encode()).decode()}"
        else:
            u = list(urllib.parse.urlparse(raw_url))
            u[5] = urllib.parse.quote(new_name) # 修改 # 后面的备注
            return urllib.parse.urlunparse(u)
    except: return None

def main():
    if not os.path.exists(RESULT_JSON):
        print("错误：未找到测速结果 out.json")
        return

    with open(RESULT_JSON, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except:
            print("错误：out.json 格式异常")
            return

    # lite-speedtest 输出的节点通常在 "nodes" 列表中
    raw_nodes = data.get('nodes', [])
    valid_nodes = []
    name_tracker = defaultdict(int)

    # 过滤与排序
    # 先按速度从大到小排序，保证电影最流畅的排在前面
    raw_nodes.sort(key=lambda x: x.get('avg_speed', 0), reverse=True)

    for n in raw_nodes:
        # avg_speed 单位通常是 Byte/s
        avg_speed = n.get('avg_speed', 0)
        speed_mb = avg_speed / (1024 * 1024)
        
        if speed_mb < MIN_SPEED_MB:
            continue

        raw_url = n.get('link')
        address = n.get('address')
        
        # 定位命名
        country = get_country(address)
        count = name_tracker[country]
        display_name = country if count == 0 else f"{country} {count}"
        name_tracker[country] += 1
        
        # 加上速度后缀方便在客户端识别，例如 "香港 1 [1.5MB/s]"
        final_name = f"{display_name} [{speed_mb:.1f}MB/s]"
        
        new_link = rename_node(raw_url, final_name)
        if new_link:
            valid_nodes.append(new_link)

    with open(FINAL_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))
    
    print(f"筛选完成！保留了 {len(valid_nodes)} 个速度 > {MIN_SPEED_MB}MB/s 的节点。")

if __name__ == "__main__":
    main()
