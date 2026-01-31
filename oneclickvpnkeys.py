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
MAX_PAGES_PER_CHANNEL = 20  # 每个频道读取的页数，调高以获取更多历史节点
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# --- 1. 物理级去重与重组逻辑 ---

def normalize_and_clean_config_header(config):
    """强制修正协议开头，剔除文字杂质"""
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

        # VLESS, Trojan, Hysteria2 等 UUID 类协议
        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            parsed = urllib.parse.urlparse(config_body)
            # 提取核心标识：UUID
            id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', config_body)
            uuid = id_match.group(1) if id_match else "no-uuid"
            # 物理唯一键：协议 + UUID + 服务器地址端口
            # 即使备注或某些次要参数变了，只要核心服务器和账号一致，就视为重复
            dedupe_key = f"{protocol}|{uuid}|{parsed.netloc.lower()}"
            return dedupe_key, config_body

        # VMess 协议 (解码 JSON 后去重)
        elif protocol == 'vmess':
            padding = len(content) % 4
            if padding: content += "=" * (4 - padding)
            decoded = json.loads(base64.b64decode(content).decode('utf-8'))
            dedupe_key = f"vmess|{decoded.get('add')}|{decoded.get('port')}|{decoded.get('id')}"
            # 抹除 ps (别名) 和多余字段，保持链接纯净
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

# --- 2. 深度异步分页抓取逻辑 ---

async def get_v2ray_links(session, channel_id, max_pages):
    """从单个频道深度翻页抓取"""
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
                
                # 寻找消息文本
                messages = soup.find_all('div', class_='tgme_widget_message_text')
                if not messages: break # 没消息了就退出
                
                page_configs = []
                pattern = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|tuic)://[^\s<"\'#]+(?:#[^\s<"\'#]*)?'
                
                for msg in messages:
                    text = msg.get_text(separator='\n', strip=True)
                    matches = re.findall(pattern, text)
                    for m in matches:
                        clean_m = normalize_and_clean_config_header(m)
                        if len(clean_m) > 20:
                            page_configs.append(clean_m)
                
                v2ray_configs.extend(page_configs)
                print(f"  [+] {channel_id} 第 {page_count+1} 页: 抓取到 {len(page_configs)} 个")
                
                # 分页核心：查找页面中最早的消息 ID，拼装 before 参数
                msgs_divs = soup.find_all('div', class_='tgme_widget_message', attrs={'data-post': True})
                if msgs_divs:
                    first_msg_id = msgs_divs[0].get('data-post').split('/')[-1]
                    if first_msg_id.isdigit():
                        current_url = f"{base_url}?before={first_msg_id}"
                        page_count += 1
                        # 稍微延迟防止被 TG 屏蔽
                        await asyncio.sleep(0.5) 
                        continue
                break
        except Exception as e:
            print(f"  [!] {channel_id} 错误: {e}")
            break
    return v2ray_configs

# --- 3. 执行与汇总 ---

async def main():
    start_time = datetime.now(SHANGHAI_TZ)
    print(f"[*] 深度抓取任务启动: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 模拟浏览器请求
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [get_v2ray_links(session, cid, MAX_PAGES_PER_CHANNEL) for cid in CHANNELS]
        results = await asyncio.gather(*tasks)

    # 物理指纹去重
    unique_nodes = {}
    raw_total = 0
    
    for channel_results in results:
        for raw_url in channel_results:
            raw_total += 1
            fingerprint, clean_url = normalize_config(raw_url)
            # 只有指纹唯一的节点才会被记录
            if fingerprint not in unique_nodes:
                unique_nodes[fingerprint] = clean_url

    final_list = sorted(list(unique_nodes.values()))
    
    # 保存结果
    os.makedirs("sub", exist_ok=True)
    update_time = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
    
    # 导出 txt 订阅
    with open("sub/merged_configs.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))

    # 更新 README
    with open("README.md", "w", encoding="utf-8") as rm:
        rm.write(f"# 深度物理去重节点库\n\n")
        rm.write(f"- **更新时间**: `{update_time}` (上海时间)\n")
        rm.write(f"- **爬取深度**: 每频道 `{MAX_PAGES_PER_CHANNEL}` 页\n")
        rm.write(f"- **原始链接总数**: `{raw_total}`\n")
        rm.write(f"- **物理指纹去重后**: **{len(final_list)}** (已抹除别名与广告)\n\n")
        rm.write(f"### 纯净节点列表\n")
        rm.write(f"```text\n")
        rm.write("\n".join(final_list))
        rm.write(f"\n```\n")

    end_time = datetime.now(SHANGHAI_TZ)
    duration = (end_time - start_time).seconds
    print(f"[*] 任务完成！耗时: {duration}秒")
    print(f"[*] 发现原始节点: {raw_total} -> 最终保留唯一节点: {len(final_list)}")

if __name__ == "__main__":
    asyncio.run(main())
