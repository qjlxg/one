import asyncio
import aiohttp
import re
import base64
import csv
import os
from datetime import datetime, timedelta
import yaml
import json
import logging
from urllib.parse import urlparse, unquote, quote, parse_qs
from collections import defaultdict

# 配置日志
logging.basicConfig(
    filename="debug.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# 定义不同协议所需的参数
required_params = {
    'ss': ['server', 'port', 'cipher', 'password'],
    'vmess': ['server', 'port', 'uuid'],
    'vless': ['server', 'port', 'uuid'],
    'trojan': ['server', 'port', 'password'],
    'hysteria2': ['server', 'port', 'password'],
}

def is_valid_server(server):
    """验证服务器地址是否有效"""
    return re.match(r'^[a-zA-Z0-9.-]+$', server)

def is_valid_port(port, proxy_type):
    """验证端口是否有效"""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_uuid(uuid):
    """验证 UUID 格式是否有效"""
    return re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', uuid)

def is_valid_cipher(cipher):
    """验证 SS 加密方式是否有效"""
    return isinstance(cipher, str) and len(cipher) > 0

def is_valid_alter_id(alterId):
    """验证 alterId 是否有效"""
    return isinstance(alterId, int) and alterId >= 0

def is_valid_password(password, proxy_type):
    """验证密码是否有效"""
    if proxy_type == 'hysteria2':
        return isinstance(password, str) and password
    return isinstance(password, str) and len(password) > 0


def load_urls_from_yaml(yaml_file):
    """从 YAML 文件加载 URL 列表，处理动态日期占位符，并避免重复抓取固定链接。"""
    try:
        with open(yaml_file, 'r', encoding='utf-8') as f:
            urls = yaml.safe_load(f)
        
        formatted_urls = []
        today = datetime.utcnow()
        yesterday = today - timedelta(days=1)
        
        seen_urls = set()

        for url in urls:
            if '%' in url:
                # 如果 URL 包含 % 符号，处理日期占位符
                today_url = today.strftime(url)
                yesterday_url = yesterday.strftime(url)
                
                if today_url not in seen_urls:
                    formatted_urls.append({"url": today_url})
                    seen_urls.add(today_url)
                
                if yesterday_url not in seen_urls:
                    formatted_urls.append({"url": yesterday_url})
                    seen_urls.add(yesterday_url)
            else:
                # 如果 URL 不包含 % 符号，只添加一次
                if url not in seen_urls:
                    formatted_urls.append({"url": url})
                    seen_urls.add(url)
                    
        return formatted_urls
    except FileNotFoundError:
        logging.error(f"Configuration file '{yaml_file}' not found.")
        return []
    except Exception as e:
        logging.error(f"Failed to load URLs from {yaml_file}: {str(e)}")
        return []

def parse_base64_links(text):
    """解析 Base64 编码的节点订阅链接"""
    nodes = []
    try:
        decoded_content = base64.b64decode(text.strip()).decode('utf-8')
        for line in decoded_content.splitlines():
            line = line.strip()
            if line and re.match(r'^(ss|trojan|vmess|vless|hysteria2):\/\/', line):
                nodes.append(line)
    except Exception:
        pass
    return nodes

def parse_direct_links(content):
    """解析纯文本中的节点链接"""
    nodes = []
    for line in content.splitlines():
        line = line.strip().strip('"').strip()
        if line and re.match(r'^(ss|trojan|vmess|vless|hysteria2):\/\/', line):
            nodes.append(line)
    return nodes

def parse_yaml_nodes(content):
    """解析 YAML 格式的节点，支持完整 Clash 配置和纯代理列表"""
    try:
        data = yaml.safe_load(content)
        
        # 如果是完整的 Clash 配置，代理列表在 'proxies' 键下
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            return data['proxies']
        
        # 如果是纯代理列表，直接返回
        if isinstance(data, list):
            return data
            
        # 如果上述情况都不匹配，尝试按行解析（兼容部分不规范文件）
        nodes = []
        for line in content.splitlines():
            try:
                node = yaml.safe_load(line)
                if isinstance(node, dict):
                    nodes.append(node)
            except yaml.YAMLError:
                pass
        return nodes

    except yaml.YAMLError:
        pass
    return []

def parse_json_nodes(content):
    """解析 JSON 格式的节点"""
    nodes = []
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    try:
        json_objects = re.findall(r'\{.*?\}', content, re.DOTALL)
        for obj_str in json_objects:
            try:
                node = json.loads(obj_str)
                nodes.append(node)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return nodes

def parse_vmess(vmess_url):
    """解析 Vmess 链接，返回 Clash 格式的字典"""
    try:
        if not vmess_url.startswith('vmess://'):
            return None
        vmess_data = vmess_url[8:]
        decoded_data = json.loads(base64.b64decode(vmess_data).decode('utf-8'))
        
        node = {
            "name": decoded_data.get('ps', ''),
            "type": "vmess",
            "server": decoded_data.get('add', ''),
            "port": int(decoded_data.get('port', 443)),
            "uuid": decoded_data.get('id', ''),
            "alterId": decoded_data.get('aid', 0),
            "cipher": decoded_data.get('scy', 'auto'),
            "network": decoded_data.get('net', 'tcp'),
            "tls": decoded_data.get('tls', '') == 'tls',
            "skip-cert-verify": False,
            "udp": True
        }
        
        if node["network"] == "ws":
            ws_path = decoded_data.get('path', '/')
            ws_headers = {"Host": decoded_data.get('host', '')}
            node["ws-opts"] = {"path": ws_path, "headers": ws_headers}
        
        if node["tls"]:
            node["servername"] = decoded_data.get('sni', node["server"])
            node["fingerprint"] = decoded_data.get('fp', '')
            
        return node
    except Exception as e:
        logging.error(f"Failed to parse vmess link {vmess_url}: {e}")
        return None

def parse_ss(ss_url):
    """解析 SS 链接，返回 Clash 格式的字典"""
    try:
        parsed_url = urlparse(ss_url)
        name = unquote(parsed_url.fragment) if parsed_url.fragment else f"SS_{parsed_url.hostname}"
        user_info = unquote(parsed_url.username)
        password = unquote(parsed_url.password)
        
        if not user_info and not password:
            credentials = base64.urlsafe_b64decode(parsed_url.netloc.split('@')[0] + '==').decode('utf-8')
            user_info, password = credentials.split(':', 1)

        node = {
            "name": name,
            "type": "ss",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "cipher": user_info,
            "password": password,
            "udp": True
        }
        return node
    except Exception as e:
        logging.error(f"Failed to parse ss link {ss_url}: {e}")
        return None

def parse_trojan(trojan_url):
    """解析 Trojan 链接，返回 Clash 格式的字典"""
    try:
        parsed_url = urlparse(trojan_url)
        name = unquote(parsed_url.fragment) if parsed_url.fragment else f"Trojan_{parsed_url.hostname}"
        
        query = parse_qs(parsed_url.query)
        sni = query.get('sni', [parsed_url.hostname])[0]
        
        node = {
            "name": name,
            "type": "trojan",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "password": unquote(parsed_url.username),
            "tls": True,
            "skip-cert-verify": False,
            "sni": sni,
            "udp": True
        }
        
        if parsed_url.scheme == 'trojan':
            if query.get('type') == ['ws']:
                node["network"] = "ws"
                node["ws-opts"] = {"path": query.get('path', ['/'])[0], "headers": {"Host": query.get('host', [sni])[0]}}
            elif query.get('type') == ['grpc']:
                node["network"] = "grpc"
                node["grpc-opts"] = {"grpc-service-name": query.get('serviceName', [''])[0]}

        return node
    except Exception as e:
        logging.error(f"Failed to parse trojan link {trojan_url}: {e}")
        return None

def parse_vless(vless_url):
    """解析 VLESS 链接，返回 Clash 格式的字典"""
    try:
        parsed_url = urlparse(vless_url)
        uuid, server_port = parsed_url.netloc.split('@')
        server, port = server_port.split(':')
        
        name = unquote(parsed_url.fragment) if parsed_url.fragment else f"VLESS_{server}"
        query = parse_qs(parsed_url.query)

        node = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": int(port),
            "uuid": uuid,
            "udp": True,
            "tls": "tls" in query or "security" in query
        }

        if "ws" in query.get('type', []):
            node["network"] = "ws"
            node["ws-opts"] = {
                "path": query.get('path', ['/'])[0],
                "headers": {"Host": query.get('host', [server])[0]}
            }
        
        if node["tls"]:
            node["servername"] = query.get('sni', [server])[0]
            node["skip-cert-verify"] = query.get('allowInsecure', ['0'])[0] == '1'
        
        return node
    except Exception as e:
        logging.error(f"Failed to parse vless link {vless_url}: {e}")
        return None
        
def parse_hysteria2(hysteria_url):
    """解析 Hysteria2 链接，返回 Clash 格式的字典"""
    try:
        parsed_url = urlparse(hysteria_url)
        password = unquote(parsed_url.username)
        server = parsed_url.hostname
        port = parsed_url.port
        
        name = unquote(parsed_url.fragment) if parsed_url.fragment else f"Hysteria2_{server}"
        query = parse_qs(parsed_url.query)
        
        node = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "tls": True,
            "skip-cert-verify": False,
            "udp": True
        }
        
        if 'sni' in query:
            node['sni'] = query.get('sni')[0]
            
        return node
    except Exception as e:
        logging.error(f"Failed to parse hysteria2 link {hysteria_url}: {e}")
        return None

def convert_node_to_clash_dict(node):
    """将节点字符串或字典转换为 Clash 格式的字典"""
    if isinstance(node, dict):
        return node
    if node.startswith('vmess://'):
        return parse_vmess(node)
    elif node.startswith('ss://'):
        return parse_ss(node)
    elif node.startswith('trojan://'):
        return parse_trojan(node)
    elif node.startswith('vless://'):
        return parse_vless(node)
    elif node.startswith('hysteria2://'):
        return parse_hysteria2(node)
    return None

async def fetch_url(session, url):
    """异步获取 URL 内容并解析节点"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    debug_logs = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as response:
                response.raise_for_status()
                content = await response.text()
                
                if not content.strip():
                    debug_logs.append(f"Received empty content from {url}")
                    return [], debug_logs

                nodes = parse_yaml_nodes(content)
                if nodes:
                    return nodes, debug_logs
                
                nodes = parse_base64_links(content)
                if nodes:
                    return nodes, debug_logs
                
                nodes = parse_direct_links(content)
                if nodes:
                    return nodes, debug_logs

                debug_logs.append(f"Failed to parse content from {url}")
                return [], debug_logs

    except aiohttp.ClientError as e:
        debug_logs.append(f"Client error fetching {url}: {str(e)}")
        return [], debug_logs
    except Exception as e:
        debug_logs.append(f"Unexpected error fetching {url}: {str(e)}")
        return [], debug_logs


def convert_clash_dict_to_link(node):
    """将 Clash 格式的字典转换回原始代理链接"""
    proxy_type = node.get('type', '').lower()
    
    # 转换为 Vmess 链接
    if proxy_type == 'vmess':
        vmess_data = {
            "v": "2",
            "ps": node.get('name', ''),
            "add": node.get('server', ''),
            "port": str(node.get('port', 443)),
            "id": node.get('uuid', ''),
            "aid": node.get('alterId', 0),
            "net": node.get('network', 'tcp'),
            "type": "none",
            "host": node.get('ws-opts', {}).get('headers', {}).get('Host', ''),
            "path": node.get('ws-opts', {}).get('path', ''),
            "tls": "tls" if node.get('tls', False) else "",
            "sni": node.get('servername', '')
        }
        json_data = json.dumps(vmess_data, ensure_ascii=False)
        encoded = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded}"

    # 转换为 SS 链接
    elif proxy_type == 'ss':
        encoded_creds = base64.urlsafe_b64encode(f"{node.get('cipher', '')}:{node.get('password', '')}".encode('utf-8')).decode('utf-8').rstrip('=')
        return f"ss://{encoded_creds}@{node.get('server', '')}:{node.get('port', '')}#{node.get('name', '')}"
    
    # 转换为 Trojan 链接
    elif proxy_type == 'trojan':
        link = f"trojan://{node.get('password', '')}@{node.get('server', '')}:{node.get('port', '')}"
        params = {}
        if 'sni' in node:
            params['sni'] = node['sni']
        if 'network' in node and node['network'] == 'ws':
            params['type'] = 'ws'
            params['path'] = node.get('ws-opts', {}).get('path', '/')
            params['host'] = node.get('ws-opts', {}).get('headers', {}).get('Host', '')
        
        if params:
            query_string = "&".join([f"{k}={v}" for k,v in params.items()])
            link += f"?{query_string}"
        
        link += f"#{quote(node.get('name', ''), safe='')}"
        return link

    # 转换为 Vless 链接
    elif proxy_type == 'vless':
        link = f"vless://{node.get('uuid', '')}@{node.get('server', '')}:{node.get('port', '')}"
        params = {}
        if node.get('tls', False):
            params['security'] = 'tls'
            if 'servername' in node:
                params['sni'] = node['servername']
            if node.get('skip-cert-verify', False):
                params['allowInsecure'] = '1'
        if node.get('network', '') == 'ws':
            params['type'] = 'ws'
            params['path'] = node.get('ws-opts', {}).get('path', '/')
            params['host'] = node.get('ws-opts', {}).get('headers', {}).get('Host', '')
            
        if params:
            query_string = "&".join([f"{k}={v}" for k,v in params.items()])
            link += f"?{query_string}"
        
        link += f"#{quote(node.get('name', ''), safe='')}"
        return link
        
    # 转换为 Hysteria2 链接
    elif proxy_type == 'hysteria2':
        password = node.get('password', '')
        server = node.get('server', '')
        port = node.get('port', '')
        name = node.get('name', '')

        link = f"hysteria2://{password}@{server}:{port}"
        
        params = {}
        if 'sni' in node:
            params['sni'] = node['sni']
            
        if params:
            query_string = "&".join([f"{k}={v}" for k, v in params.items()])
            link += f"?{query_string}"
            
        link += f"#{quote(name, safe='')}"
        return link
    
    return None

async def main():
    urls = load_urls_from_yaml("fetch-nodes.yml")
    if not urls:
        logging.info("No URLs to process. Exiting.")
        return

    all_nodes = []
    stats = []
    debug_logs = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, site["url"]) for site in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result, site in zip(results, urls):
            if isinstance(result, tuple) and len(result) == 2:
                nodes, debug = result
                all_nodes.extend(nodes)
                stats.append({"url": site["url"], "node_count": len(nodes)})
                debug_logs.extend(debug)
                logging.info(f"Fetched {len(nodes)} nodes from {site['url']}")
            else:
                debug_logs.append(f"Error fetching {site['url']}: {str(result)}")
                logging.error(f"Error fetching {site['url']}: {str(result)}")
    
    # 将所有节点转换为 Clash 字典格式，以便统一处理
    clash_proxies = []
    for node_item in all_nodes:
        clash_node = convert_node_to_clash_dict(node_item)
        if clash_node:
            clash_proxies.append(clash_node)
    
    # 核心去重和验证逻辑
    cleaned_proxies = []
    seen_keys = set()
    name_counter = defaultdict(int)
    discarded_stats = {
        'unsupported_protocol': 0,
        'missing_params': 0,
        'invalid_params': 0,
        'duplicates': 0,
    }

    for proxy in clash_proxies:
        proxy_type = proxy.get('type', '').lower()

        # 1. 检查基本参数和协议类型
        if not proxy_type or proxy_type not in required_params:
            discarded_stats['unsupported_protocol'] += 1
            continue
        
        server = proxy.get('server')
        port = proxy.get('port')

        # 2. 检查 server 和 port 是否存在
        if not server or not port:
            discarded_stats['missing_params'] += 1
            continue
        
        # 3. 对 server 和 port 进行严格的值验证
        if not is_valid_server(str(server)):
            discarded_stats['invalid_params'] += 1
            continue
        
        if not is_valid_port(port, proxy_type):
            discarded_stats['invalid_params'] += 1
            continue
        
        # 4. 根据协议检查必要的参数及其值
        is_valid = True
        for param in required_params[proxy_type]:
            value = proxy.get(param)
            if value is None:
                is_valid = False
                break
            
            # 特定参数验证
            if param == 'uuid' and not is_valid_uuid(str(value)):
                is_valid = False
                break
            if param == 'cipher' and not is_valid_cipher(str(value)):
                is_valid = False
                break
            if param == 'alterId' and not is_valid_alter_id(value):
                is_valid = False
                break
            if param == 'password' and not is_valid_password(str(value), proxy_type):
                is_valid = False
                break
        
        if not is_valid:
            discarded_stats['invalid_params'] += 1
            continue

        # 仅提取必要的参数
        cleaned_proxy_data = {}
        for param in required_params[proxy_type]:
            cleaned_proxy_data[param] = proxy[param]
        
        # 处理 Hysteria2 密码/认证兼容性
        if proxy_type in ['hy2', 'hysteria2']:
            if 'password' not in cleaned_proxy_data and 'auth' in proxy:
                cleaned_proxy_data['password'] = proxy['auth']
                
        # 5. 创建唯一键并检查重复项
        unique_key = (proxy_type, str(server), str(port))
        
        if unique_key in seen_keys:
            discarded_stats['duplicates'] += 1
        else:
            seen_keys.add(unique_key)
            
            # 6. 分配唯一的名称
            base_name = f"[{proxy_type.upper()}] {server}:{port}"
            name_counter[base_name] += 1
            if name_counter[base_name] > 1:
                cleaned_proxy_data['name'] = f"{base_name} ({name_counter[base_name]})"
            else:
                cleaned_proxy_data['name'] = base_name
            
            # 从原始 proxy 中复制所有其他键，以保留网络、tls等配置
            final_proxy = {**proxy, **cleaned_proxy_data}
            cleaned_proxies.append(final_proxy)

    total_nodes_after = len(cleaned_proxies)
    total_discarded = sum(discarded_stats.values())
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- 保存为原始的 nodes.txt 文件格式 ---
    with open("nodes.txt", "w", encoding="utf-8") as f:
        f.write(f"# Updated at {timestamp}\n")
        for node in cleaned_proxies:
            link = convert_clash_dict_to_link(node)
            if link:
                f.write(f"{link}\n")
    logging.info(f"Successfully saved {len(cleaned_proxies)} unique nodes to nodes.txt")

    # --- 保存为 YAML 格式 ---
    yaml_data = {
        'proxies': cleaned_proxies,
        'update_time': timestamp,
        'source': 'auto-fetched'
    }

    with open("nodes.yaml", "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, allow_unicode=True, sort_keys=False)
    logging.info(f"Successfully saved {len(cleaned_proxies)} unique nodes to nodes.yaml")

    # 保存统计信息
    with open("stats.csv", "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["url", "node_count"])
        writer.writeheader()
        for stat in stats:
            writer.writerow(stat)

if __name__ == "__main__":
    asyncio.run(main())
