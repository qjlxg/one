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

# =========================
# 1. 核心去重算法 (优化版)
# =========================

def _safe_strip(s: str) -> str:
    """安全 strip，并去除常见不可见字符。"""
    if not isinstance(s, str):
        return ""
    # 去除零宽空格、\u200b 等常见隐形字符
    s = re.sub(r'[\u200b\u200c\u200d\uFEFF]', '', s)
    return s.strip()

def normalize_and_clean_config_header(config: str) -> str:
    """清理协议头杂质，只保留从协议头开始的纯净部分。"""
    if not config:
        return ""

    config = _safe_strip(config)

    protocols = [
        'vless://', 'vmess://', 'trojan://',
        'ss://', 'ssr://', 'hysteria2://', 'hysteria://', 'tuic://'
    ]
    lower_conf = config.lower()
    start_index = -1
    for proto in protocols:
        idx = lower_conf.find(proto)
        if idx != -1:
            start_index = idx
            break
    if start_index == -1:
        # 不是节点链接，原样返回（稍后会走 md5 指纹）
        return config

    clean_config = config[start_index:]
    # 只截取到遇到空白符或常见 HTML/Markdown 分隔符为止
    clean_config = re.split(r'[\s<>"\'\)\]]', clean_config)[0]
    return _safe_strip(clean_config)

def _normalize_query_string(query: str) -> str:
    """对 URL query 做稳定排序、去空，从而在指纹里更稳定。"""
    if not query:
        return ""
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    # 排序 key，并过滤空值
    items = []
    for k in sorted(q.keys()):
        vs = [v for v in q[k] if v is not None]
        for v in vs:
            items.append((k, v))
    return urllib.parse.urlencode(items, doseq=True)

def _safe_b64_decode(s: str) -> bytes:
    """宽容 base64 解码：自动补齐 padding。"""
    s = s.strip()
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.b64decode(s)

def _fingerprint_vless_like(parsed: urllib.parse.ParseResult, protocol: str):
    """
    针对 vless / trojan / hysteria / hysteria2 / tuic 的指纹逻辑：
    - 忽略 hostname，实现同账号多 IP 去重
    - 关键字段：协议 + 用户ID(含密码) + 端口 + pbk(如有) + sni(如有) + alpn(如有)
    """
    # netloc 结构：userinfo@host:port
    user_info = parsed.netloc.split('@')[0] if '@' in parsed.netloc else ""
    user_info = _safe_strip(user_info)

    # 稳定化 query 字段，保证同配置不同参数顺序也视为同一节点
    query = urllib.parse.parse_qs(parsed.query)

    pbk = _safe_strip(query.get('pbk', [''])[0])
    sni = _safe_strip(query.get('sni', [''])[0])
    alpn = ','.join(sorted([_safe_strip(a) for a in query.get('alpn', []) if a]))

    port = parsed.port or ''

    fingerprint = f"{protocol}|{user_info}|{port}|{pbk}|{sni}|{alpn}"

    # 生成一个“规整版”的 URL（不改 hostname，以免破坏可用性）
    # 只对 query 做排序和去空
    norm_query = _normalize_query_string(parsed.query)
    norm_parsed = parsed._replace(query=norm_query)
    clean_url = urllib.parse.urlunparse(norm_parsed)

    return fingerprint, clean_url

def _fingerprint_vmess(config_body: str):
    """
    vmess:// 的指纹逻辑：
    - 内容是 base64(JSON)
    - 指纹字段：id + port + path + host
    - ps、add 被抹除，用于生成“纯净版”配置
    """
    try:
        content = config_body.split('://', 1)[1]
    except Exception:
        # 格式异常，退回 md5
        return hashlib.md5(config_body.encode()).hexdigest(), config_body

    try:
        raw = _safe_b64_decode(content)
        data = json.loads(raw.decode('utf-8'))
    except Exception:
        # 解码失败，退回 md5
        return hashlib.md5(config_body.encode()).hexdigest(), config_body

    # Key fields for physical dedupe
    id_ = data.get('id', '')
    port = str(data.get('port', ''))
    path = data.get('path', '') or ''
    host = data.get('host', '') or ''
    fingerprint = f"vmess|{id_}|{port}|{path}|{host}"

    # 生成“纯净版” vmess：去除 ps 和 add，以便 NekoBox 显示更干净
    clean_data = {k: v for k, v in data.items() if k not in ['ps', 'add']}
    try:
        new_conf_b64 = base64.b64encode(json.dumps(clean_data, separators=(',', ':')).encode()).decode()
        clean_url = f"vmess://{new_conf_b64}"
    except Exception:
        clean_url = config_body

    return fingerprint, clean_url

def _fingerprint_ss(parsed: urllib.parse.ParseResult, config_body: str):
    """
    Shadowsocks 指纹逻辑（兼容常见两类写法）：
    1) ss://base64(method:password)@host:port
    2) ss://method:password@host:port
    指纹字段：method + password + port
    """
    try:
        body = config_body.split('://', 1)[1]
    except Exception:
        return hashlib.md5(config_body.encode()).hexdigest(), config_body

    # 有的 ss 链接可能带 #remark
    body = body.split('#', 1)[0]
    body = _safe_strip(body)

    # 先尝试再 URL 级别解析
    # 注意：urlparse 的 scheme 在 config_body 中已经是 ss
    # 这里的 parsed 已经是完整 URL
    netloc = parsed.netloc

    # userinfo@host:port
    # 但还有另一种写法：整个 base64 放在“主机”部分，这里不再过度复杂化，
    # 主流机场和频道基本为“userinfo@host:port”。
    userinfo = netloc.split('@')[0] if '@' in netloc else ""
    userinfo = _safe_strip(userinfo)

    method = ""
    password = ""

    if userinfo:
        # 可能是 “method:password” 或 base64(method:password)
        if ':' in userinfo:
            method, password = userinfo.split(':', 1)
        else:
            # 尝试 base64 解码
            try:
                decoded = _safe_b64_decode(userinfo).decode('utf-8')
                if ':' in decoded:
                    method, password = decoded.split(':', 1)
            except Exception:
                pass

    method = _safe_strip(method)
    password = _safe_strip(password)
    port = parsed.port or ''

    if not (method and password and port):
        # 冗余/异常格式，退回 md5
        return hashlib.md5(config_body.encode()).hexdigest(), config_body

    fingerprint = f"ss|{method}|{password}|{port}"

    # 为了保持原有可用性，不强行重写 URL，只简单 strip
    clean_url = normalize_and_clean_config_header(config_body)
    return fingerprint, clean_url

def get_dedupe_fingerprint(config: str):
    """
    极致物理去重（针对 NekoBox 优化）：
    - 统一清洗协议头
    - 按协议提取“核心服务 ID”生成指纹
    - 尽量忽略服务器 IP/域名，实现同账号多 IP 去重
    - 若无法可靠解析，则退回 config_body 的 md5 作为指纹
    返回: (fingerprint, clean_config_for_output)
    """
    if not config:
        return "", ""

    try:
        config = normalize_and_clean_config_header(config)
        # 移除备注名(#suffix)，只保留 # 前面作为主体
        config_body = config.split('#', 1)[0] if '#' in config else config
        config_body = _safe_strip(config_body)

        parsed = urllib.parse.urlparse(config_body)
        protocol = (parsed.scheme or "").lower()

        if protocol in ['vless', 'trojan', 'hysteria2', 'hysteria', 'tuic']:
            return _fingerprint_vless_like(parsed, protocol)

        elif protocol == 'vmess':
            return _fingerprint_vmess(config_body)

        elif protocol == 'ss':
            return _fingerprint_ss(parsed, config_body)

        # 对于其他协议（如 ssr 等），没有特别逻辑，则用整体 md5
        return hashlib.md5(config_body.encode()).hexdigest(), config_body

    except Exception:
        # 任何异常，保证不影响主流程
        cfg = _safe_strip(config) or ""
        return hashlib.md5(cfg.encode()).hexdigest(), cfg


# =========================
# 2. 爬取逻辑（原样保留）
# =========================

async def fetch_channel(session, channel_id):
    configs = []
    base_url = f"https://t.me/s/{channel_id}"
    current_url = base_url
    page_count = 0
    
    while current_url and page_count < MAX_PAGES:
        try:
            async with session.get(current_url, timeout=15) as resp:
                if resp.status != 200:
                    break
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_text')
                if not msgs:
                    break
                
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
        except:
            break
    return channel_id, configs

# =========================
# 3. 执行、去重与保存（核心流程保持不变）
# =========================

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
            if not fingerprint:
                continue
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
