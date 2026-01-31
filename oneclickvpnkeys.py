import os
import re
import requests
import html
import csv
import base64
import json
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# 配置
CHANNELS = [
    "v2ray_configs_pool", "oneclickvpnkeys", "free_v2ray_full_speed", 
    "v2ray_free_conf", "v2ray_vless_trojan_ss", "v2ray_vless_hysteria",
    "ShadowSocksShare", "SS_V2ray_Trojan", "v2ray_footprint", "V2list"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
MIN_NODE_THRESHOLD = 5 

def is_valid_proxy(node_url):
    """
    深度检测是否为真实代理链接
    """
    try:
        # 1. 基础检查
        if not node_url or len(node_url) < 20: return False
        
        # 排除电报内部跳转和广告域名
        blacklist = ('t.me/', 'tg://', 'bit.ly', 'shorturl', 'google.com', 'github.com')
        if any(item in node_url.lower() for item in blacklist): return False

        # 2. 协议分发检测
        if node_url.startswith('vmess://'):
            # 校验 vmess 是否为合法的 Base64 JSON
            payload = node_url.split("://")[1]
            # 自动补全 Base64 填充符
            payload += "=" * ((4 - len(payload) % 4) % 4)
            try:
                decoded = base64.b64decode(payload).decode('utf-8')
                data = json.loads(decoded)
                return 'add' in data and 'port' in data # 核心字段存在即视为有效
            except:
                return False
        
        # 3. 其他协议 (vless/ss/trojan/hysteria) 必须包含 @ 符号或特定的结构
        # 排除掉只有协议头没有内容的垃圾数据
        if '://' in node_url:
            body = node_url.split("://")[1]
            if len(body) > 10: return True
            
        return False
    except:
        return False

def fetch_single_channel(channel_id):
    """改进的抓取函数：解决内容为 0 的问题"""
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'zh-CN,zh;q=0.9'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # --- 修复关键点 1：必须先反转义 HTML ---
        raw_content = html.unescape(response.text)
        
        # --- 修复关键点 2：更具包容性的正则 ---
        # 匹配协议开头，直到遇到引号、尖括号、空格或反斜杠
        pattern = r'(?:ss|vmess|vless|trojan|hysteria|tuic|socks5)://[^\s<"\'\\]+'
        found = re.findall(pattern, raw_content)
        
        valid_nodes = []
        for n in found:
            # 清洗节点末尾可能存在的干扰符
            clean_node = n.strip().split('#')[0] # 暂时去掉备注以防干扰检测，或保留
            if is_valid_proxy(n): 
                valid_nodes.append(n)
        
        return channel_id, valid_nodes
    except Exception as e:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    all_nodes = []
    stats_log = []

    print(f"[*] 正在扫描 {len(CHANNELS)} 个渠道...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    for channel_id, nodes in results:
        all_nodes.extend(nodes)
        stats_log.append([date_str, channel_id, len(nodes)])
        print(f"[+ {len(nodes):3} 节点] <- {channel_id}")

    # 保存统计数据 (CSV)
    file_exists = os.path.isfile('grab_stats.csv')
    with open('grab_stats.csv', 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['日期', '频道ID', '抓取数量'])
        writer.writerows(stats_log)

    # 去重处理
    final_nodes = list(dict.fromkeys(all_nodes))

    # --- 空数据保护 ---
    if len(final_nodes) < MIN_NODE_THRESHOLD:
        print(f"\n[!] 警告：有效节点总数 ({len(final_nodes)}) 过低，未更新 nodes_list.txt")
        return

    # 保存结果
    with open("nodes_list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_nodes))

    print(f"\n[OK] 任务结束。抓取总数: {len(all_nodes)} | 唯一有效数: {len(final_nodes)}")
    print(f"[OK] 数据已记录至 grab_stats.csv")

if __name__ == "__main__":
    main()
