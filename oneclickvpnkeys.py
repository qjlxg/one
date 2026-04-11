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
import random
from datetime import datetime
from collections import defaultdict
from bs4 import BeautifulSoup

# --- 1. 配置区 ---
CHANNELS = ["oneclickvpnkeys", "v2ray_free_conf"]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
DB_PATH = 'GeoLite2-Country.mmdb'  
TIMEOUT = 3          # 端口检测超时时间
MAX_PAGES = 80000    # 每个频道回溯抓取的页数
CRAWL_DELAY = 1.5    # 每次翻页基础延迟 (秒)
STATE_FILE = 'crawl_state.json' # 记录抓取进度的文件

# 代理配置 (如不需要请设为 None)
# 示例: "http://127.0.0.1:7890"
PROXY_URL = None 

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

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=4)

def is_valid_uuid(uuid_str):
    return bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', str(uuid_str)))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except: return False

def parse_to_standard_dict(raw_url):
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
    result = {'ip': None, 'country': "Unknown", 'alive': False}
    address = node_dict.get('server')
    port = int(node_dict.get('port', 0))
    if not address or not port: return result
    
    try:
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address):
            try:
                ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(address))
            except: return result
        else: ip = address
        result['ip'] = ip

        if geo_reader:
            try:
                data = geo_reader.get(ip)
                if data and 'country' in data:
                    names = data['country'].get('names', {})
                    result['country'] = names.get('zh-CN', names.get('en', 'Unknown'))
            except: pass

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

async def fetch_channel(session, channel_id, last_min_id=None):
    """
    抓取 Telegram 频道。
    last_min_id: 上次抓取到的最旧消息 ID。如果提供，则从该 ID 继续往前回溯。
    """
    configs = []
    base_url = f"https://t.me/s/{channel_id}"
    # 如果有断点记录，从断点开始，否则从头开始
    current_url = f"{base_url}?before={last_min_id}" if last_min_id else base_url
    page_count = 0
    new_min_id = last_min_id

    print(f"[>] 正在{'继续' if last_min_id else '开始'}抓取频道: {channel_id} (起始ID: {last_min_id or '最新'})")
    
    while page_count < MAX_PAGES:
        try:
            async with session.get(current_url, timeout=20, proxy=PROXY_URL) as resp:
                if resp.status == 429:
                    wait_time = int(resp.headers.get("Retry-After", 120))
                    print(f"[!] 触发频率限制，需等待 {wait_time} 秒...")
                    await asyncio.sleep(wait_time)
                    continue
                
                if resp.status != 200:
                    print(f"[!] 响应异常: {resp.status}")
                    break

                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # 提取配置
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                if not msgs:
                    # 如果页面没内容，可能是到底了或者结构变了
                    print(f"[*] 频道 {channel_id} 似乎没有更多消息了。")
                    break

                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#\t]+'
                for m in msgs:
                    configs.extend(re.findall(pattern, m.get_text(separator='\n', strip=True)))
                
                # 寻找更旧的消息 ID (before=...)
                # Telegram Web S版 消息由新到旧排列，找到当前页最上面（最早）的一条
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    # 获取本页最旧的一条 ID
                    try:
                        first_post_id = int(msgs_divs[0].get('data-post').split('/')[-1])
                        # 更新当前 URL 指向更旧的内容
                        current_url = f"{base_url}?before={first_post_id}"
                        new_min_id = first_post_id
                        page_count += 1
                        
                        if page_count % 10 == 0:
                            print(f"--- 已抓取 {page_count} 页，当前消息 ID 偏移至: {new_min_id}")
                        
                        await asyncio.sleep(CRAWL_DELAY + random.random())
                    except Exception as e:
                        print(f"[!] 解析消息ID失败: {e}")
                        break
                else:
                    break
        except Exception as e:
            print(f"[!] 抓取网络异常: {e}")
            await asyncio.sleep(5)
            break

    return configs, new_min_id

# --- 4. 主程序 ---

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.get_event_loop()
    
    # 加载进度
    crawl_state = load_state()
    
    # 初始化 GeoDB
    geo_reader = None
    if os.path.exists(DB_PATH):
        geo_reader = maxminddb.open_database(DB_PATH)

    all_configs = []
    stats_log = []
    total_raw = 0

    # 1. 抓取 (逐个频道抓取以便维护状态)
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}) as session:
        for cid in CHANNELS:
            last_id = crawl_state.get(cid)
            configs, min_id = await fetch_channel(session, cid, last_id)
            
            # 更新状态
            crawl_state[cid] = min_id
            save_state(crawl_state)
            
            all_configs.append(configs)
            stats_log.append([date_str, cid, len(configs)])
            total_raw += len(configs)

    # 2. 深度去重与格式校验
    seen_keys = set()
    valid_nodes = []

    for configs in all_configs:
        for c in configs:
            d = parse_to_standard_dict(c)
            if not d or not is_valid_port(d['port']): continue
            
            core_auth = d.get('uuid') or d.get('password') or d.get('cipher', '')
            unique_key = (d['type'], d['server'], d['port'], core_auth)
            
            if unique_key not in seen_keys:
                seen_keys.add(unique_key)
                valid_nodes.append(d)

    print(f"\n[+] 原始抓取总数: {total_raw} | 深度去重后: {len(valid_nodes)}")

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

    # 6. 更新 nodes_list.txt
    # 注意：这里会覆盖之前的文件。如果想累加，请改为 'a' 模式
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] 处理完成！本次发现可用节点: {total_final}")
    print(f"[*] 抓取进度已保存至 {STATE_FILE}，下次运行将继续往回抓取。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 用户中断退出")
