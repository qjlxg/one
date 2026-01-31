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
MAX_PAGES = 20
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 核心优化：物理参数指纹提取 ---

def get_dedupe_fingerprint(config):
    """
    通过提取核心指纹实现物理去重。
    逻辑：如果 ID、端口和关键加密混淆参数一致，即便服务器 IP 不同也视为同一个节点。
    """
    try:
        # 预处理：去掉备注名和多余空格
        config = config.split('#')[0].split('\t')[0].strip()
        parsed = urllib.parse.urlparse(config)
        protocol = parsed.scheme.lower()

        # 1. 针对 Hysteria2 / Vless / Trojan / Tuic 的深度去重
        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            query = urllib.parse.parse_qs(parsed.query)
            
            # 关键：指纹不包含 hostname (服务器地址)，实现同账号多IP强制去重
            sni = query.get('sni', [''])[0]
            pbk = query.get('pbk', [''])[0]
            path = query.get('path', [''])[0]
            
            fingerprint = f"{protocol}|{user_info}|{parsed.port}|{sni}|{pbk}|{path}"
            return fingerprint, config

        # 2. 针对 VMess 的 JSON 深度去重
        elif protocol == 'vmess':
            try:
                content = config.split('://')[1]
                padding = len(content) % 4
                if padding: content += "=" * (4 - padding)
                data = json.loads(base64.b64decode(content).decode('utf-8'))
                
                # 指纹不包含 'add' 字段
                fingerprint = f"vmess|{data.get('id')}|{data.get('port')}|{data.get('path')}|{data.get('host')}"
                
                # 清洗数据：抹除备注和地址，让 NekoBox 识别更纯净
                clean_data = {k: v for k, v in data.items() if k not in ['ps', 'add']}
                new_conf = f"vmess://{base64.b64encode(json.dumps(clean_data).encode()).decode()}"
                return fingerprint, new_conf
            except: pass

        # 3. 针对 Shadowsocks (ss)
        elif protocol == 'ss':
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            fingerprint = f"ss|{user_info}|{parsed.port}"
            return fingerprint, config

        return hashlib.md5(config.encode()).hexdigest(), config
    except:
        return hashlib.md5(config.encode()).hexdigest(), config

# --- 抓取、统计与归档逻辑 ---

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
        raw_len = len(configs)
        total_raw += raw_len
        stats_log.append([date_str.split()[0], cid, raw_len])
        for c in configs:
            fingerprint, clean_url = get_dedupe_fingerprint(c)
            # 只有当物理指纹（ID+端口等）未出现过时才保留
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
        rm.write(f"# 自动更新节点列表\n\n最后更新时间: `{date_str}` (上海时间)\n\n")
        rm.write(f"本次去重后有效节点: **{total_final}** 个 (原始总数: {total_raw})\n\n")
        rm.write(f"### 节点内容 (纯净无名版)\n```text\n" + '\n'.join(final_nodes) + "\n```\n")

    # 5. 更新根目录 nodes_list.txt
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # 6. 按年月归档备份
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    backup_path = os.path.join(dir_path, f"nodes_list_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] 原始: {total_raw} -> 物理去重后: {total_final}")

if __name__ == "__main__":
    asyncio.run(main())
