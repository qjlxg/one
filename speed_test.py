import os, re, json, base64, time, subprocess, yaml, requests, csv
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_LATEST = "latest_nodes.txt"
LATENCY_URL = "https://www.google.com/generate_204"
TIMEOUT = 5
MAX_RETRIES = 2
MAX_WORKERS = 20
# ==========================================

def safe_base64_decode(s):
    """通用 Base64 解码器：处理填充、URL安全字符及编码错误"""
    try:
        s = s.strip().replace('-', '+').replace('_', '/')
        # 补齐 Base64 填充位
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_link(link):
    """
    全兼容解析引擎：支持 SS(标准/老旧/插件), VMess, VLESS, Trojan, Hysteria2, TUIC
    """
    try:
        link = link.strip()
        if not link or len(link) < 10: return None, None, None
        
        # 预处理：分离链接与备注
        parts = link.split('#', 1)
        base_link = parts[0]
        raw_name = unquote(parts[1]) if len(parts) > 1 else ""
        
        url = urlparse(base_link)
        scheme = url.scheme.lower()
        
        # 基础节点模板
        node = {
            "name": "", 
            "server": url.hostname or "",
            "port": int(url.port or 443),
            "udp": True,
            "skip-cert-verify": True
        }

        # 1. Shadowsocks (SS) - 复杂度最高，变种最多
        if scheme == 'ss':
            # 情况A: ss://BASE64_ENCODED_USER_INFO@HOST:PORT
            if '@' in url.netloc:
                user_info_raw = url.username
                # 检查 user_info 是否是 Base64
                if ':' not in user_info_raw:
                    user_info = safe_base64_decode(user_info_raw)
                else:
                    user_info = user_info_raw
                
                if ':' in user_info:
                    method, password = user_info.split(':', 1)
                    node.update({"type": "ss", "cipher": method, "password": password})
                else:
                    return None, None, None
            # 情况B: ss://BASE64(method:password@host:port) - 老旧格式
            else:
                decoded = safe_base64_decode(base_link[5:])
                if '@' in decoded:
                    # 递归解析解码后的内容
                    return parse_link(f"ss://{decoded}#{raw_name}")
                return None, None, None

        # 2. VMess - 标准 JSON Base64 格式
        elif scheme == 'vmess':
            b64_data = base_link[8:]
            json_str = safe_base64_decode(b64_data)
            if not json_str: return None, None, None
            data = json.loads(json_str)
            node.update({
                "type": "vmess", "server": data.get('add'), "port": int(data.get('port', 443)),
                "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'),
                "servername": data.get('sni') or data.get('host', '')
            })
            if data.get('net') == 'ws':
                node["ws-opts"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}

        # 3. VLESS
        elif scheme == 'vless':
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            node.update({
                "type": "vless", "uuid": url.username, "cipher": "auto",
                "tls": query.get('security') in ['tls', 'reality'],
                "servername": query.get('sni'), "network": query.get('type', 'tcp'),
                "flow": query.get('flow', '')
            })
            if query.get('security') == 'reality':
                node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}

        # 4. Trojan / Hysteria2 / TUIC
        elif scheme == 'trojan':
            node.update({"type": "trojan", "password": url.username, "sni": url.hostname, "tls": True})
        elif scheme in ['hy2', 'hysteria2']:
            node.update({"type": "hysteria2", "password": url.username, "sni": parse_qs(url.query).get('sni', [None])[0]})
        elif scheme == 'tuic':
            node.update({"type": "tuic", "uuid": url.username, "password": url.password})

        else:
            return None, None, None

        # 最终校准名字
        final_name = raw_name if raw_name else f"{node['type']}_{node['server']}_{node['port']}"
        return final_name, node, link

    except Exception as e:
        # 调试时可以开启：print(f"解析失败 [{link[:20]}...]: {e}")
        return None, None, None

def fetch_nodes():
    all_links = []
    for source in NODE_SOURCES:
        try:
            print(f"🌐 正在抓取: {source}")
            r = requests.get(source, timeout=15)
            if r.status_code == 200:
                # 兼容处理：有些源是 Base64 加密的订阅格式
                content = r.text
                if "://" not in content[:50] and len(content) > 20:
                    content = safe_base64_decode(content)
                
                lines = content.splitlines()
                all_links.extend([l for l in lines if '://' in l])
        except Exception as e:
            print(f"⚠️ 抓取失败: {e}")
    return all_links

# ... (run_test 函数逻辑同前，但增加 proxies 长度检查的打印)
