import os
import re
import requests
import html
import csv
import json
import base64
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

# --- 配置区 ---
CHANNELS = [
    "oneclickvpnkeys", "v2ray_free_conf", "ip_cf_config", "vlesskeys",
    "VlessVpnFree", "vpnfail_vless", "v2Line", "vless_vpns"
]
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

def normalize_node(node_url):
    """
    终极清洗：将节点彻底拆解并按标准字典排序重建，强制物理去重
    """
    try:
        node_url = node_url.strip()
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        
        # 1. 核心数据容器
        core_data = {"scheme": scheme}

        # 2. 针对不同协议的暴力提取
        if scheme == 'vmess':
            try:
                # 兼容处理：有些 vmess 后面可能带 # 备注，先去掉
                netloc = parsed.netloc.split('#')[0]
                v = json.loads(base64.b64decode(netloc).decode('utf-8'))
                # 只保留决定连接的核心键，且全部转为字符串并剔除空格
                for key in ['add', 'port', 'id', 'net', 'type', 'host', 'path', 'tls', 'sni']:
                    core_data[key] = str(v.get(key, '')).strip().lower()
            except: return None
            
        elif scheme in ['vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic']:
            # 提取 用户信息@地址:端口 (忽略大小写和空格)
            core_data['netloc'] = parsed.netloc.strip().lower()
            core_data['path'] = parsed.path.strip().lower()
            
            # 提取关键 Query 参数并排序（去除随机生成的干扰项）
            params = parse_qs(parsed.query.lower())
            # 只保留对连接有意义的参数白名单
            whitelist = ['sni', 'path', 'serviceoriginal', 'servicename', 'mode', 'type', 'security', 'alpn', 'fp', 'pbk', 'sid', 'flow']
            clean_params = {k: sorted([v.strip() for v in vals])[0] for k, vals in params.items() if k in whitelist}
            core_data['params'] = clean_params
        else:
            return None

        # 3. 生成唯一指纹（序列化字典，确保顺序一致）
        fingerprint = json.dumps(core_data, sort_keys=True)
        
        # 4. 根据核心数据重建“无名”节点链接
        if scheme == 'vmess':
            # 这里的 ps 为空，确保软件导入时没有名字
            v_rebuilt = {**core_data, "v": "2", "ps": ""}
            del v_rebuilt['scheme'] # 移除内部使用的标记
            new_v = base64.b64encode(json.dumps(v_rebuilt).encode('utf-8')).decode('utf-8')
            return fingerprint, f"vmess://{new_v}"
        else:
            # 重组 query 字符串
            from urllib.parse import urlencode
            q_str = urlencode(core_data.get('params', {}))
            new_url = f"{scheme}://{core_data['netloc']}{core_data['path']}?{q_str}"
            return fingerprint, new_url

    except Exception:
        return None

def fetch_single_channel(channel_id):
    url = f"https://t.me/s/{channel_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        raw_text = html.unescape(response.text)
        # 修正正则，确保能抓到带特殊字符的完整链接
        pattern = r'(?:ss|vmess|vless|trojan|hysteria2|hysteria|tuic)://[^\s<"\'#]+(?:#[^\s<"\'#]+)?'
        nodes = re.findall(pattern, raw_text)
        return channel_id, nodes
    except:
        return channel_id, []

def main():
    now = datetime.now(SHANGHAI_TZ)
    date_str = now.strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"[*] 任务开始: {date_str}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_single_channel, CHANNELS))
    
    # 使用字典指纹去重
    unique_nodes = {} # {fingerprint: final_url}
    raw_count = 0

    for _, nodes in results:
        for n in nodes:
            raw_count += 1
            result = normalize_node(n)
            if result:
                fp, clean_url = result
                # 如果指纹重复，后面的会覆盖前面的，达到去重效果
                unique_nodes[fp] = clean_url

    final_list = sorted(list(unique_nodes.values()))
    
    # 写入文件
    with open("nodes_list.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_list))
        
    print(f"[*] 原始节点: {raw_count} | 物理去重后: {len(final_list)}")
    print(f"[OK] 已经剔除所有名称和广告参数，仅保留连接核心。")

if __name__ == "__main__":
    main()
