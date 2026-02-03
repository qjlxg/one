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

# --- 1. 严格验证工具 ---
def is_valid_uuid(uuid_str):
    return bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', str(uuid_str)))

def is_valid_server(server):
    return bool(re.match(r'^[a-zA-Z0-9.-]+$', str(server)))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except: return False

# --- 2. 深度解析与去重逻辑 ---
def get_node_fingerprint(node):
    """
    生成全特征唯一指纹
    考虑：协议、地址、端口、认证信息、传输层路径/SNI
    """
    try:
        p_type = node.get('type', '').lower()
        server = str(node.get('server', '')).lower().strip()
        port = str(node.get('port', ''))
        
        # 提取核心凭证 (UUID/Password/Auth)
        auth = str(node.get('uuid') or node.get('password') or node.get('auth') or '').strip()
        
        # 提取传输层特征 (Path/SNI/Host)
        # 很多节点物理 IP 一样，但通过不同的 Path 分流，这不算重复
        path = str(node.get('path') or node.get('sni') or node.get('host') or '').strip()

        # 组装指纹元组
        return (p_type, server, port, auth, path)
    except:
        return None

def parse_to_dict(raw_url):
    """将原始链接解析为标准化字典，便于特征提取"""
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
                'uuid': data.get('id'), 'path': data.get('path'), 'host': data.get('host'),
                'raw': raw_url, 'meta': data
            }
        
        # 处理其他通用协议
        user_info = urllib.parse.unquote(parsed.netloc.split('@')[0]) if '@' in parsed.netloc else ""
        server_port = parsed.netloc.split('@')[-1] if '@' in parsed.netloc else parsed.netloc
        server = server_port.split(':')[0]
        port = server_port.split(':')[1] if ':' in server_port else (443 if proto != 'ss' else 80)
        
        query = urllib.parse.parse_qs(parsed.query)
        res = {
            'type': proto, 'server': server, 'port': port, 'raw': raw_url,
            'sni': query.get('sni', [''])[0], 'path': query.get('path', [''])[0]
        }
        
        if proto == 'ss':
            if ':' in user_info: res['cipher'], res['password'] = user_info.split(':', 1)
        else:
            res['uuid'] = user_info # vless/trojan 等
        return res
    except:
        return None

# --- 3. 核心抓取与测试逻辑 ---

async def test_node(node_dict, loop, geo_reader):
    """智能连通性测试 + 地理位置"""
    result = {'ip': None, 'country': "Unknown", 'alive': False}
    addr = node_dict.get('server')
    port = int(node_dict.get('port', 0))

    try:
        # 1. 解析 IP (用于去重增强和归属地查询)
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", addr):
            try:
                ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(addr))
            except: return result
        else: ip = addr
        result['ip'] = ip

        # 2. 地理归属
        if geo_reader:
            data = geo_reader.get(ip)
            if data and 'country' in data:
                names = data['country'].get('names', {})
                result['country'] = names.get('zh-CN', names.get('en', 'Unknown'))

        # 3. 连通性 (UDP协议如 hy2/tuic 默认过)
        if any(p in node_dict['type'] for p in ['hysteria', 'tuic']):
            result['alive'] = True
        else:
            try:
                conn = asyncio.open_connection(ip, port)
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                result['alive'] = True
                writer.close()
                await writer.wait_closed()
            except: pass
    except: pass
    return result

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.get_event_loop()
    geo_reader = maxminddb.open_database(DB_PATH) if os.path.exists(DB_PATH) else None

    # 抓取数据
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0...'}) as session:
        tasks = [fetch_channel(session, cid) for cid in CHANNELS] # 使用之前的 fetch_channel 函数
        results = await asyncio.gather(*tasks)

    # 第一轮：解析与初步验证
    raw_list = []
    for configs in results:
        for c in configs:
            node = parse_to_dict(c)
            if node and is_valid_server(node['server']) and is_valid_port(node['port']):
                raw_list.append(node)

    # 第二轮：深度特征去重
    seen_keys = set()
    unique_nodes = []
    for node in raw_list:
        fp = get_node_fingerprint(node)
        if fp and fp not in seen_keys:
            seen_keys.add(fp)
            unique_nodes.append(node)

    print(f"\n[+] 原始抓取: {sum(len(r) for r in results)} | 深度去重后: {len(unique_nodes)}")

    # 第三轮：连通性测试
    test_tasks = [test_node(n, loop, geo_reader) for n in unique_nodes]
    test_results = await asyncio.gather(*test_tasks)
    if geo_reader: geo_reader.close()

    # 第四轮：重命名与输出
    name_tracker = defaultdict(int)
    final_output = []
    for node, res in zip(unique_nodes, test_results):
        if res['alive']:
            country = res['country']
            count = name_tracker[country]
            new_name = f"{country} {count if count > 0 else ''}".strip()
            name_tracker[country] += 1
            
            # 还原为链接字符串
            link = apply_new_name(node, new_name) # 使用之前的 apply_new_name 函数
            final_output.append(link)

    # 写入文件
    with open("nodes_list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_output))
    
    print(f"[OK] 流程结束，保留可用节点: {len(final_output)}")

# (fetch_channel 和 apply_new_name 函数保持之前版本不变...)
