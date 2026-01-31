import os
import re
import json
import base64
import asyncio
import aiohttp
import hashlib
import urllib.parse
from datetime import datetime
import pytz
from bs4 import BeautifulSoup

# --- 配置区 ---
CHANNELS = [
    "oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys",
    "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 1. 核心去重与清洗逻辑 ---

def normalize_and_clean_config_header(config):
    """强制修正协议开头，剔除抓取时混入的杂质文字"""
    if not config: return ""
    protocols = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria2://', 'hysteria://', 'tuic://']
    start_index = -1
    for proto in protocols:
        if proto in config:
            start_index = config.find(proto)
            break
    if start_index == -1: return config
    clean_config = config[start_index:]
    # 截断空白、引号、尖括号等非法结束符
    clean_config = re.split(r'[\s<>"\'\)]', clean_config)[0]
    return clean_config.strip()

def normalize_config(config):
    """提取物理指纹进行去重 (核心逻辑)"""
    try:
        config = normalize_and_clean_config_header(config)
        # 分离配置体和备注
        config_body = config.split('#')[0] if '#' in config else config
        protocol = config_body.split('://')[0].lower()
        content = config_body.split('://')[1]

        # VLESS, Trojan, Hysteria2, Tuic 等 UUID 类协议
        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            parsed = urllib.parse.urlparse(config_body)
            # 提取 UUID/密码 (指纹的核心)
            id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', config_body)
            uuid = id_match.group(1) if id_match else "no-uuid"
            # 物理唯一键：协议 + UUID + 服务器地址端口
            dedupe_key = f"{protocol}|{uuid}|{parsed.netloc.lower()}"
            return dedupe_key, config_body

        # VMess 协议 (Base64 编码)
        elif protocol == 'vmess':
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            decoded = json.loads(base64.b64decode(content).decode('utf-8'))
            # VMess 物理键：地址 + 端口 + 用户ID
            dedupe_key = f"vmess|{decoded.get('add')}|{decoded.get('port')}|{decoded.get('id')}"
            # 抹除 ps (别名) 后重组，确保链接纯净
            normalized_data = {k: v for k, v in decoded.items() if k not in ['ps', 'add']}
            normalized_json = json.dumps(normalized_data, sort_keys=True, ensure_ascii=False)
            normalized_config = f"vmess://{base64.b64encode(normalized_json.encode('utf-8')).decode('utf-8')}"
            return dedupe_key, normalized_config

        # Shadowsocks 协议
        elif protocol == 'ss':
            dedupe_key = f"ss|{content.lower()}"
            return dedupe_key, config_body

        return hashlib.md5(config_body.encode()).hexdigest(), config_body
    except:
        return hashlib.md5(config.encode()).hexdigest(), config

# --- 2. 异步分页抓取逻辑 ---

async def get_v2ray_links(session, channel_id, max_pages=3):
    """从单个频道分页抓取链接"""
    v2ray_configs = []
    base_url = f"https://t.me/s/{channel_id}"
    current_url = base_url
    page_count = 0
    
    while current_url and page_count < max_pages:
        try:
            async with session.get(current_url, timeout=15) as response:
                if response.status != 200: break
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # 寻找所有可能包含链接的标签
                tags = soup.find_all(['div', 'pre', 'code'], class_=lambda x: x != 'tgme_widget_message_author')
                
                page_configs = []
                # 强化的正则匹配
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#]+(?:#[^\s<"\'#]*)?'
                
                for tag in tags:
                    text = tag.get_text(separator='\n', strip=True)
                    matches = re.findall(pattern, text)
                    for m in matches:
                        clean_m = normalize_and_clean_config_header(m)
                        if len(clean_m) > 20:
                            page_configs.append(clean_m)
                
                v2ray_configs.extend(page_configs)
                
                # 分页：寻找更早的消息
                msgs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs:
                    # data-post 格式通常是 "channel/123"
                    first_msg_id = msgs[0].get('data-post').split('/')[-1]
                    if first_msg_id.isdigit():
                        current_url = f"{base_url}?before={first_msg_id}"
                        page_count += 1
                        continue
                break
        except: break
    return v2ray_configs

# --- 3. 主程序入口 ---

async def main():
    print(f"[*] 启动抓取任务: {datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')}")
    
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}) as session:
        tasks = [get_v2ray_links(session, cid) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    # 物理去重存储 {指纹: 唯一配置}
    unique_nodes = {}
    raw_count = 0
    
    for channel_configs in results:
        for c in channel_configs:
            raw_count += 1
            dedupe_key, clean_config = normalize_config(c)
            # 如果指纹没出现过，则存入
            if dedupe_key not in unique_nodes:
                unique_nodes[dedupe_key] = clean_config

    final_nodes = sorted(list(unique_nodes.values()))
    
    # 写入文件
    os.makedirs("sub", exist_ok=True)
    update_time = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
    
    with open("sub/merged_configs.txt", "w", encoding="utf-8") as f:
        f.write(f"# 物理去重订阅 | 更新: {update_time}\n")
        f.write("\n".join(final_nodes))

    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 自动更新节点库\n\n")
        rm.write(f"- 最后更新: `{update_time}` (上海时间)\n")
        rm.write(f"- 频道来源: `{len(CHANNELS)}` 个\n")
        rm.write(f"- 原始发现: `{raw_count}` 个\n")
        rm.write(f"- 物理去重后: **{len(final_nodes)}** 个\n\n")
        rm.write(f"### 订阅链接 (可直接复制)\n")
        rm.write(f"```text\n")
        rm.write("\n".join(final_nodes))
        rm.write(f"\n```\n")

    print(f"[*] 抓取结束。原始节点: {raw_count} | 物理去重后: {len(final_nodes)}")

if __name__ == "__main__":
    asyncio.run(main())
