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
CHANNELS = ["oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys", "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns","farahvpn", "bored_vpn", "empirevpn7", "V2raythekyo", "hpv2ray_official", "vmess_ir", "configfree_1", "PrivateVPNs", "Outline_Vpn", "directvpn", "m_vipv2ray", "outline_ir", "v2rayngconfings", "DigiV2ray23", "proxy_mtproto_vpns_free", "v2rayfree", "v2rayngseven", "nofiltering2", "v2_fast", "v2logy", "proxy48", "v2aryng_vpn", "siigmavpn", "disvpn", "igrsdet", "iran_access", "vpn_room", "v2rayPort", "configpluse", "customvpnserver", "v2rayng954", "Free_Internet_Iran", "mftizi", "NIM_VPN_ir", "berice_v2", "v2rayip1", "v2raytg", "V2RAY_VMESS_free", "WomanLifeFreedomVPN", "bluevpn_v2ray", "v2rayy_vpn13", "vpn_kanfik", "FalconPolV2rayNG", "ghalagyann", "iranbaxvpn", "vipvpn_v2ray", "vpncostumer", "pruoxyi", "v2ngfast", "arv2ra", "renetvpn", "v2rayngvpn_1", "v2rplus", "vpncostume", "lightning6", "hopev2ray", "arv2ray", "tehranargo", "v2raxx", "v2ryng01", "drakvpn", "sobyv2ray", "V2pedia", "v2pedia", "jiedianf", "nofilter_v2rayng", "v2rayland02", "mt_team_iran", "proxy_n1", "x4azadi", "toxicvid", "MTProto_666", "castom_v2ray", "club_vpn9", "mrvpn1403", "skivpn", "gozargah_azadi", "fastvpnorummobile", "Easy_Free_VPN", "clubvpn443", "khalaa_vpn", "servernett", "turboo_server", "virav2ray", "MsV2ray", "amirinventor2010", "black8rose", "bolbolvpn", "iranmedicalvpn", "v2rayng_81", "fhkllvjkll", "http_injector99", "SVNTEAM", "armod_iran", "artemisvpn1", "digigard_vpn", "iranvpnnet", "maxshare", "moft_vpn", "payam_nsi", "seven_ping", "svnteam", "vmess_iran", "vpn4ir_1", "yuproxytelegram", "inikotesla"]
MAX_PAGES = 3
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
DB_PATH = 'GeoLite2-Country.mmdb'
TIMEOUT = 5  # TCP连接超时时间

# --- 核心工具 ---

async def test_node_smart(protocol, address, port, loop):
    """
    并发测试核心：
    1. 解析域名 + 归属地查询
    2. TCP协议执行连接测试
    3. UDP协议(Hysteria/TUIC)跳过测试直接返回可用
    """
    result = {'ip': None, 'country': "Unknown", 'alive': False}
    try:
        # 1. 域名解析
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address):
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(address))
        else:
            ip = address
        result['ip'] = ip

        # 2. 地理位置查询
        with maxminddb.open_database(DB_PATH) as reader:
            data = reader.get(ip)
            if data and 'country' in data:
                names = data['country'].get('names', {})
                result['country'] = names.get('zh-CN', names.get('en', 'Unknown'))

        # 3. 智能可用性测试
        # 判断是否属于 UDP 核心协议
        is_udp_protocol = any(p in protocol.lower() for p in ['hysteria', 'tuic'])
        
        if is_udp_protocol:
            result['alive'] = True  # 对 UDP 协议宽容处理，默认认为存活
        else:
            # 对 TCP 协议进行连接测试
            conn = asyncio.open_connection(ip, port)
            try:
                _, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                result['alive'] = True
                writer.close()
                await writer.wait_closed()
            except:
                result['alive'] = False
    except:
        pass
    return result

def get_dedupe_fingerprint(config):
    """提取指纹及节点元数据"""
    try:
        raw_config = config.split('#')[0].split('\t')[0].strip()
        parsed = urllib.parse.urlparse(raw_config)
        protocol = parsed.scheme.lower()
        
        if protocol == 'vmess':
            content = raw_config.split('://')[1]
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            data = json.loads(base64.b64decode(content).decode('utf-8'))
            fingerprint = f"vmess|{data.get('id')}|{data.get('port')}|{data.get('path')}|{data.get('host')}"
            return fingerprint, {'type': 'vmess', 'data': data, 'addr': data.get('add'), 'port': int(data.get('port')), 'proto': 'vmess'}
        
        elif protocol in ['vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'hysteria', 'tuic']:
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            query = urllib.parse.parse_qs(parsed.query)
            sni = query.get('sni', [''])[0]
            pbk = query.get('pbk', [''])[0]
            fingerprint = f"{protocol}|{user_info}|{parsed.port}|{sni}|{pbk}"
            return fingerprint, {'type': 'url', 'url': raw_config, 'addr': parsed.hostname, 'port': parsed.port, 'proto': protocol}
        return hashlib.md5(raw_config.encode()).hexdigest(), None
    except:
        return hashlib.md5(config.encode()).hexdigest(), None

def apply_new_name(node_info, new_name):
    """重命名逻辑"""
    try:
        if node_info['type'] == 'vmess':
            data = node_info['data']
            data['ps'] = new_name
            return f"vmess://{base64.b64encode(json.dumps(data).encode()).decode()}"
        else:
            url_parts = list(urllib.parse.urlparse(node_info['url']))
            url_parts[5] = urllib.parse.quote(new_name)
            return urllib.parse.urlunparse(url_parts)
    except:
        return ""

async def fetch_channel(session, channel_id):
    configs = []
    base_url = f"https://t.me/s/{channel_id}"
    current_url = base_url
    page_count = 0
    while current_url and page_count < MAX_PAGES:
        try:
            async with session.get(current_url, timeout=15) as resp:
                if resp.status != 200: break
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                if not msgs: break
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#\t]+(?:#[^\s<"\'#\t]*)?'
                for m in msgs:
                    configs.extend(re.findall(pattern, m.get_text(separator='\n', strip=True)))
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    current_url = f"{base_url}?before={msgs_divs[0].get('data-post').split('/')[-1]}"
                    page_count += 1
                    await asyncio.sleep(0.1)
                    continue
                break
        except: break
    return channel_id, configs

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.get_event_loop()
    
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0...'}) as session:
        tasks = [fetch_channel(session, cid) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    unique_nodes_info = {}
    stats_log = []
    total_raw = 0

    for cid, configs in results:
        raw_count = len(configs)
        total_raw += raw_count
        stats_log.append([date_str.split()[0], cid, raw_count])
        for c in configs:
            fingerprint, info = get_dedupe_fingerprint(c)
            if info and fingerprint not in unique_nodes_info:
                unique_nodes_info[fingerprint] = info

    # 并发测试
    print(f"正在对 {len(unique_nodes_info)} 个节点进行筛选定位(Hysteria/TUIC已跳过连接测试)...")
    node_items = list(unique_nodes_info.values())
    test_tasks = [test_node_smart(item['proto'], item['addr'], item['port'], loop) for item in node_items]
    test_results = await asyncio.gather(*test_tasks)

    # 处理命名逻辑
    name_tracker = defaultdict(int)
    final_nodes_list = []
    
    for info, res in zip(node_items, test_results):
        if res['alive'] and res['ip']:
            country = res['country']
            count = name_tracker[country]
            display_name = country if count == 0 else f"{country} {count}"
            name_tracker[country] += 1
            final_nodes_list.append(apply_new_name(info, display_name))

    final_nodes = sorted(list(filter(None, final_nodes_list)))
    total_final = len(final_nodes)

   
    # 3. 写入抓取统计 CSV
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists: writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 4. 更新 README.md
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 自动更新节点列表\n\n最后更新时间: `{date_str}` (北京时间)\n\n")
        rm.write(f"本次筛选后可用节点数: **{total_final}** 个 (原始总数: {total_raw})\n\n")
        rm.write(f"### 节点内容 (地理位置重命名 & 可用性筛选版)\n```text\n" + '\n'.join(final_nodes) + "\n```\n")

    # 5. 更新根目录 nodes_list.txt
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 6. 按年月归档备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    backup_path = os.path.join(dir_path, f"nodes_list_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] 原始抓取: {total_raw} -> 最终保留: {total_final}")

if __name__ == "__main__":
    asyncio.run(main())
