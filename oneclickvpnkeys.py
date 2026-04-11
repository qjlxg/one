import os
import re
import json
import base64
import asyncio
import aiohttp
import csv
import socket
import maxminddb
import urllib.parse
import pytz
from datetime import datetime
from collections import defaultdict
from bs4 import BeautifulSoup

# --- 1. 配置区 ---
CHANNELS = ["oneclickvpnkeys", "v2ray_free_conf"]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
DB_PATH = 'GeoLite2-Country.mmdb'  
TIMEOUT = 3      # 端口检测超时时间
MAX_PAGES = 80000    # 每个频道回溯抓取的页数

# 协议验证参数
REQUIRED_PARAMS = {
    'ss': ['server', 'port', 'cipher', 'password'],
    'vmess': ['server', 'port', 'uuid'],
    'vless': ['server', 'port', 'uuid'],
    'trojan': ['server', 'port', 'password'],
    'hysteria2': ['server', 'port', 'password'],
    'hysteria': ['server', 'port', 'auth'],
    'tuic': ['server', 'port', 'uuid', 'password'],
}

# --- 2. 工具函数 ---

def is_valid_uuid(uuid_str):
    return bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', str(uuid_str)))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except: return False

def parse_to_standard_dict(raw_url):
    """将各种协议链接统一解析为标准字典"""
    try:
        parsed = urllib.parse.urlparse(raw_url)
        proto = parsed.scheme.lower()
        if proto == 'vmess':
            content = raw_url.split('://')[1]
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            data = json.loads(base64.b64decode(content).decode('utf-8'))
            return {
                'type': 'vmess', 'server': data.get('add'), 'port': data.get('port'),
                'uuid': data.get('id'), 'cipher': data.get('type', 'auto'),
                'raw': raw_url, 'meta': data
            }
        elif proto in REQUIRED_PARAMS:
            user_info = urllib.parse.unquote(parsed.netloc.split('@')[0]) if '@' in parsed.netloc else ""
            server_port = parsed.netloc.split('@')[-1] if '@' in parsed.netloc else parsed.netloc
            server = server_port.split(':')[0]
            port = server_port.split(':')[1] if ':' in server_port else (443 if proto != 'ss' else 80)
            
            res = {'type': proto, 'server': server, 'port': port, 'raw': raw_url}
            if proto == 'ss':
                if ':' in user_info:
                    res['cipher'], res['password'] = user_info.split(':', 1)
            else:
                res['uuid'] = user_info
                res['password'] = user_info
                res['auth'] = user_info
            return res
    except: return None

def apply_new_name(node_dict, new_name):
    """修改节点名称并还原为链接"""
    proto = node_dict['type']
    raw = node_dict['raw']
    try:
        if proto == 'vmess':
            data = node_dict['meta']
            data['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(data).encode()).decode()}"
        else:
            base_url = raw.split('#')[0]
            return f"{base_url}#{urllib.parse.quote(new_name)}"
    except: return raw

# --- 3. 核心异步逻辑 ---

async def test_node_smart(node_dict, loop, geo_reader):
    """测试节点可用性及获取地理位置"""
    result = {'ip': None, 'country': "Unknown", 'alive': False}
    address = node_dict.get('server')
    port = int(node_dict.get('port', 0))
    
    if not address or not port: return result
    
    try:
        # DNS 解析
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address):
            try:
                ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(address))
            except: return result
        else: ip = address
        result['ip'] = ip

        # 地理位置查询
        if geo_reader:
            try:
                data = geo_reader.get(ip)
                if data and 'country' in data:
                    names = data['country'].get('names', {})
                    result['country'] = names.get('zh-CN', names.get('en', 'Unknown'))
            except: pass

        # 存活测试
        if any(p in node_dict['type'] for p in ['hysteria', 'tuic']):
            result['alive'] = True # UDP 协议默认标记，深层测试需额外工具
        else:
            try:
                conn = asyncio.open_connection(ip, port)
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                result['alive'] = True
                writer.close()
                await writer.wait_closed()
            except: result['alive'] = False
    except: pass
    return result

async def fetch_channel(session, channel_id):
    """抓取 Telegram 频道公开页面的订阅链接"""
    configs = []
    base_url = f"https://t.me/s/{channel_id}"
    current_url = base_url
    page_count = 0
    print(f"[>] 正在抓取频道: {channel_id}")
    
    while current_url and page_count < MAX_PAGES:
        try:
            async with session.get(current_url, timeout=15) as resp:
                if resp.status != 200: break
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#\t]+'
                for m in msgs:
                    configs.extend(re.findall(pattern, m.get_text(separator='\n', strip=True)))
                
                # 获取“查看更多”按钮的偏移量
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    current_url = f"{base_url}?before={msgs_divs[0].get('data-post').split('/')[-1]}"
                    page_count += 1
                    await asyncio.sleep(0.1)
                    continue
                break
        except: break
    return configs

# --- 4. 主程序 ---

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.get_event_loop()
    
    # 初始化 GeoDB
    geo_reader = None
    if os.path.exists(DB_PATH):
        geo_reader = maxminddb.open_database(DB_PATH)

    # 1. 抓取
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}) as session:
        tasks = [fetch_channel(session, cid) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    # 2. 深度去重与格式校验
    seen_keys = set()
    valid_nodes = []
    total_raw = 0
    stats_log = []

    for i, configs in enumerate(results):
        total_raw += len(configs)
        stats_log.append([date_str, CHANNELS[i], len(configs)]) # 记录各频道抓取数
        
        for c in configs:
            d = parse_to_standard_dict(c)
            if not d or not is_valid_port(d['port']): continue
            
            # 生成唯一指纹 (协议+服务器+端口+核心认证信息)
            core_auth = d.get('uuid') or d.get('password') or d.get('cipher', '')
            unique_key = (d['type'], d['server'], d['port'], core_auth)
            
            if unique_key not in seen_keys:
                seen_keys.add(unique_key)
                valid_nodes.append(d)

    print(f"\n[+] 原始抓取: {total_raw} | 深度去重后: {len(valid_nodes)}")

    # 3. 并发可用性测试
    test_tasks = [test_node_smart(n, loop, geo_reader) for n in valid_nodes]
    test_results = await asyncio.gather(*test_tasks)
    if geo_reader: geo_reader.close()

    # 4. 命名与结果筛选
    name_tracker = defaultdict(int)
    final_nodes = []
    for node_dict, res in zip(valid_nodes, test_results):
        if res['alive']:
            country = res['country']
            idx = name_tracker[country]
            display_name = f"{country} {idx if idx > 0 else ''}".strip()
            name_tracker[country] += 1
            final_nodes.append(apply_new_name(node_dict, display_name))

    total_final = len(final_nodes)

    # 5. 写入统计 CSV
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists: 
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 6. 更新 README.md
   # with open("README.md", "w", encoding="utf-8") as rm:
   #     rm.write(f"# 订阅列表\n\n最后更新时间: `{date_str}` (北京时间)\n\n")
   #     rm.write(f"本次筛选后可用节点数: **{total_final}** 个 (去重前总数: {total_raw})\n\n")
    #    rm.write(f"### 节点明文内容\n```text\n" + '\n'.join(final_nodes) + "\n```\n")

    # 7. 更新 nodes_list.txt
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 8. 按年月归档备份
   # dir_path = now.strftime('%Y/%m')
   # os.makedirs(dir_path, exist_ok=True)
   # backup_path = os.path.join(dir_path, f"nodes_list_{now.strftime('%Y%m%d_%H%M%S')}.txt")
   # with open(backup_path, 'w', encoding='utf-8') as f:
   #     f.write('\n'.join(final_nodes))
    
    print(f"[OK] 处理完成！可用节点: {total_final}")

if __name__ == "__main__":
    asyncio.run(main())
