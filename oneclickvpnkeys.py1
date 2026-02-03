import os
import re
import json
import base64
import asyncio
import aiohttp
import hashlib
import urllib.parse
import csv
import socket
import maxminddb
from datetime import datetime
from collections import defaultdict
import pytz
from bs4 import BeautifulSoup

# --- 配置区 ---
CHANNELS = ["oneclickvpnkeys", "v2ray_free_conf"]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
DB_PATH = 'GeoLite2-Country.mmdb'
TIMEOUT = 2      
MAX_PAGES = 8    


REQUIRED_PARAMS = {
    'ss': ['server', 'port', 'cipher', 'password'],
    'vmess': ['server', 'port', 'uuid'],
    'vless': ['server', 'port', 'uuid'],
    'trojan': ['server', 'port', 'password'],
    'hysteria2': ['server', 'port', 'password'],
    'hysteria': ['server', 'port', 'auth'],
    'tuic': ['server', 'port', 'uuid', 'password'],
}

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
            elif proto in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
                res['uuid'] = user_info
                res['password'] = user_info
                res['auth'] = user_info
            return res
    except: return None

# --- 2. 核心测试与网络工具 ---

async def test_node_smart(node_dict, loop, geo_reader):
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

        # 地理位置
        if geo_reader:
            data = geo_reader.get(ip)
            if data and 'country' in data:
                names = data['country'].get('names', {})
                result['country'] = names.get('zh-CN', names.get('en', 'Unknown'))

        # 可用性测试 (UDP 默认放行, TCP 尝试握手)
        if any(p in node_dict['type'] for p in ['hysteria', 'tuic']):
            result['alive'] = True
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

# --- 3. 抓取与主逻辑 ---

async def fetch_channel(session, channel_id):
    configs = []
    base_url = f"https://t.me/s/{channel_id}"
    current_url = base_url
    page_count = 0
    print(f"[>] 抓取频道: {channel_id}")
    while current_url and page_count < MAX_PAGES:
        try:
            async with session.get(current_url, timeout=15) as resp:
                if resp.status != 200: break
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#\t]+'
                for m in msgs:
                    configs.extend(re.findall(pattern, m.get_text(separator='\n', strip=True)))
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    current_url = f"{base_url}?before={msgs_divs[0].get('data-post').split('/')[-1]}"
                    page_count += 1
                    await asyncio.sleep(0.05)
                    continue
                break
        except: break
    return configs

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
            # 处理 URL 锚点部分 (# 后面的名称)
            base_url = raw.split('#')[0]
            return f"{base_url}#{urllib.parse.quote(new_name)}"
    except: return raw

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.get_event_loop()
    geo_reader = maxminddb.open_database(DB_PATH) if os.path.exists(DB_PATH) else None

    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0...'}) as session:
        tasks = [fetch_channel(session, cid) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    # --- 深度去重与验证 ---
    seen_keys = set()
    valid_nodes = []
    total_raw = 0

    for configs in results:
        total_raw += len(configs)
        for c in configs:
            d = parse_to_standard_dict(c)
            if not d: continue
            
            p_type = d['type']
            # 1. 验证端口和核心参数
            if not is_valid_port(d['port']): continue
            if 'uuid' in d and not is_valid_uuid(d['uuid']): continue
            
            # 2. 生成唯一指纹 (协议+IP+端口+核心认证)
            # 这样即便名字变了，只要服务器和账号一样，就会被去重
            core_auth = d.get('uuid') or d.get('password') or d.get('cipher','')
            unique_key = (p_type, d['server'], d['port'], core_auth)
            
            if unique_key not in seen_keys:
                seen_keys.add(unique_key)
                valid_nodes.append(d)

    print(f"\n[+] 原始: {total_raw} | 深度去重后: {len(valid_nodes)}")

    # 并发测试
    test_tasks = [test_node_smart(n, loop, geo_reader) for n in valid_nodes]
    test_results = await asyncio.gather(*test_tasks)
    if geo_reader: geo_reader.close()

    # 命名与导出
    name_tracker = defaultdict(int)
    final_strings = []
    for node_dict, res in zip(valid_nodes, test_results):
        if res['alive']:
            country = res['country']
            idx = name_tracker[country]
            display_name = f"{country} {idx if idx > 0 else ''}".strip()
            name_tracker[country] += 1
            final_strings.append(apply_new_name(node_dict, display_name))

    # 保存文件 (保持你原有的 README 和 txt 逻辑)
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_strings))
    
    print(f"[OK] 最终可用节点: {len(final_strings)}")

if __name__ == "__main__":
    asyncio.run(main())
