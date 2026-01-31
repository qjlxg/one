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
CHANNELS = [
    "oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys",
    "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"
]
MAX_PAGES = 20
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 1. 核心去重算法 (针对 NekoBox 优化) ---

def normalize_and_clean_config_header(config):
    """清理协议头杂质"""
    if not config: return ""
    protocols = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria2://', 'hysteria://', 'tuic://']
    start_index = -1
    for proto in protocols:
        if proto in config:
            start_index = config.find(proto)
            break
    if start_index == -1: return config
    clean_config = config[start_index:]
    clean_config = re.split(r'[\s<>"\'\)]', clean_config)[0]
    return clean_config.strip()

def get_dedupe_fingerprint(config):
    """
    极致物理去重：通过协议核心参数生成指纹。
    忽略服务器地址，只识别核心服务 ID。
    """
    try:
        config = normalize_and_clean_config_header(config)
        # 移除备注名
        config_body = config.split('#')[0] if '#' in config else config
        parsed = urllib.parse.urlparse(config_body)
        protocol = parsed.scheme.lower()

        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            # 指纹：协议 + 用户ID + 端口 + 关键加密参数(pbk)
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            query = urllib.parse.parse_qs(parsed.query)
            pbk = query.get('pbk', [''])[0]
            # 注意：这里故意不放 parsed.hostname，实现同账号多IP去重
            fingerprint = f"{protocol}|{user_info}|{parsed.port}|{pbk}"
            return fingerprint, config_body

        elif protocol == 'vmess':
            content = config_body.split('://')[1]
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            data = json.loads(base64.b64decode(content).decode('utf-8'))
            # 指纹：ID + 端口 + 伪装路径/主机
            fingerprint = f"vmess|{data.get('id')}|{data.get('port')}|{data.get('path')}|{data.get('host')}"
            # 抹除 ps 和 add 重新封包，保证节点在 NekoBox 显示纯净
            clean_data = {k: v for k, v in data.items() if k not in ['ps', 'add']}
            new_conf = base64.b64encode(json.dumps(clean_data).encode()).decode()
            return fingerprint, f"vmess://{new_conf}"

        elif protocol == 'ss':
            user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
            fingerprint = f"ss|{user_info}|{parsed.port}"
            return fingerprint, config_body

        return hashlib.md5(config_body.encode()).hexdigest(), config_body
    except:
        return hashlib.md5(config.encode()).hexdigest(), config

# --- 2. 爬取逻辑 ---

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
                
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#]+(?:#[^\s<"\'#]*)?'
                page_found = []
                for m in msgs:
                    found = re.findall(pattern, m.get_text(separator='\n', strip=True))
                    page_found.extend(found)
                
                configs.extend(page_found)
                
                # 分页
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    first_id = msgs_divs[0].get('data-post').split('/')[-1]
                    current_url = f"{base_url}?before={first_id}"
                    page_count += 1
                    await asyncio.sleep(0.3)
                    continue
                break
        except: break
    return channel_id, configs

# --- 3. 执行、去重与保存 ---

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
            if fingerprint not in unique_nodes:
                unique_nodes[fingerprint] = clean_url

    final_nodes = sorted(list(unique_nodes.values()))
    total_final = len(final_nodes)

    # --- 3. 写入抓取统计 CSV ---
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # --- 4. 更新 README.md ---
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 自动更新节点列表\n\n")
        rm.write(f"最后更新时间: `{date_str}` (上海时间)\n\n")
        rm.write(f"本次去重后有效节点: **{total_final}** 个 (原始总数: {total_raw})\n\n")
        rm.write(f"### 节点内容 (纯净无名版)\n")
        rm.write(f"```text\n")
        rm.write('\n'.join(final_nodes))
        rm.write(f"\n```\n")

    # --- 5. 更新根目录 nodes_list.txt ---
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))

    # --- 6. 按年月归档备份 ---
    dir_path = now.strftime('%Y/%m')
    os.makedirs(dir_path, exist_ok=True)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(dir_path, f"nodes_list_{timestamp}.txt")
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes))
    
    print(f"[OK] 原始: {total_raw} -> 去重后: {total_final}")
    print(f"[OK] README.md 已更新")
    print(f"[OK] 归档文件: {backup_path}")

if __name__ == "__main__":
    asyncio.run(main())
