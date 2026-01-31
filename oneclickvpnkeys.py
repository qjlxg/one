import os
import re
import json
import base64
import asyncio
import aiohttp
import hashlib
import urllib.parse
import csv
from datetime import datetime
import pytz
from bs4 import BeautifulSoup

# --- 配置区 ---
CHANNELS = ["oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys", "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"]
MAX_PAGES = 2
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def get_dedupe_fingerprint(config):
    """
    去重：通过提取核心身份指纹，彻底忽略 IP/域名变动。
    """
    try:
        # 1. 基础清理
        config = config.split('#')[0].split('\t')[0].strip()
        parsed = urllib.parse.urlparse(config)
        protocol = parsed.scheme.lower()

        # 2. 针对 Vless / Trojan / Hysteria2 / Tuic
        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            query = urllib.parse.parse_qs(parsed.query)
            
            # 核心指纹：协议 + 用户ID + 端口 + SNI + PBK
            # 故意不包含 hostname，这样同 ID 的不同 IP 节点会被强行归为同一个
            sni = query.get('sni', [''])[0]
            pbk = query.get('pbk', [''])[0]
            
            fingerprint = f"{protocol}|{user_info}|{parsed.port}|{sni}|{pbk}"
            return fingerprint, config

        # 3. 针对 VMess (深度解包去重)
        elif protocol == 'vmess':
            content = config.split('://')[1]
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            data = json.loads(base64.b64decode(content).decode('utf-8'))
            
            # 指纹：用户ID + 端口 + 路径 + 主机
            fingerprint = f"vmess|{data.get('id')}|{data.get('port')}|{data.get('path')}|{data.get('host')}"
            
            # 重构：抹除所有可能导致重复的备注(ps)和地址(add)
            clean_data = {k: v for k, v in data.items() if k not in ['ps', 'add']}
            new_conf = f"vmess://{base64.b64encode(json.dumps(clean_data).encode()).decode()}"
            return fingerprint, new_conf

        # 4. 针对 Shadowsocks
        elif protocol == 'ss':
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            fingerprint = f"ss|{user_info}|{parsed.port}"
            return fingerprint, config

        return hashlib.md5(config.encode()).hexdigest(), config
    except:
        return hashlib.md5(config.encode()).hexdigest(), config

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
                    await asyncio.sleep(0.2)
                    continue
                break
        except: break
    return channel_id, configs

async def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0...'}) as session:
        tasks = [fetch_channel(session, cid) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    unique_nodes = {}
    stats_log = []
    total_raw = 0

    for cid, configs in results:
        raw_count = len(configs)
        total_raw += raw_count
        stats_log.append([date_str.split()[0], cid, raw_count])
        for c in configs:
            fingerprint, clean_url = get_dedupe_fingerprint(c)
            # 只有当此物理指纹从未出现过时，才保留抓到的第一个链接
            if fingerprint not in unique_nodes:
                unique_nodes[fingerprint] = clean_url

    final_nodes = sorted(list(unique_nodes.values()))
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
        rm.write(f"本次去重后节点数: **{total_final}** 个 (原始总数: {total_raw})\n\n")
        rm.write(f"### 节点内容 (重复较少版)\n```text\n" + '\n'.join(final_nodes) + "\n```\n")

    # 5. 更新根目录 nodes_list.txt 
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 6. 按年月归档备份 
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    backup_path = os.path.join(dir_path, f"nodes_list_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] 原始: {total_raw} -> 去重后: {total_final}")

if __name__ == "__main__":
    asyncio.run(main())
