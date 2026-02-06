import requests
import re
import os
import time
import base64
import json
import socket
import csv
import yaml
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# --- 配置区 ---
GITHUB_TOKEN = os.getenv("MY_GITHUB_TOKEN")
OUTPUT_DIR = "."
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
STATS_CSV_PATH = "source_stats.csv"
MAX_WORKERS = 180  # 提高并发数，加快检测速度

# 排除关键词
EXCLUDE_KEYWORDS = ["127.0.0.1", "localhost", "0.0.0.0", "google.com", "github.com"]
# 标准节点正则
NODE_PATTERN = r'(?:vmess|vless|ss|ssr|trojan|tuic|hysteria2|hysteria)://[a-zA-Z0-9%@\[\]\._\-\?&=\+#/:]+'

RAW_NODE_SOURCES = [
   
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml",
    "https://raw.githubusercontent.com/qjlxg/one/refs/heads/main/nodes_list.txt",
    "https://raw.githubusercontent.com/ImMyron/V2ray/main/Telegram",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge/main/configs/all.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/airport_sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/qjlxg/one/refs/heads/main/latest_nodes.txt",
    "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
    "https://raw.githubusercontent.com/Roywaller/clash_subscription/main/clash_subscription.txt",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc0.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/refs/heads/main/APIs/sc4.yaml",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/raw/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
    "https://raw.githubusercontent.com/aiboboxx/clashfree/refs/heads/main/clash.yml",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vmess.txt",
    "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/main/final.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/liMilCo/v2r/main/all_configs.txt",
    "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
    "https://raw.githubusercontent.com/maimengmeng/mysub/main/valid_content_all.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/ss.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayScrapeByCountry/refs/heads/main/output_configs/Vless.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayScrapeByCountry/refs/heads/main/output_configs/Vmess.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/10ium/V2ray-Config/refs/heads/main/Splitted-By-Protocol/tuic.txt",
    "https://raw.githubusercontent.com/217CnoC/configs-collector-v2ray/refs/heads/main/sub/all_configs.txt",
    "https://raw.githubusercontent.com/245237866/v2rayn/main/everydaynode",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/all.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/refs/heads/main/v2tel_links1.txt",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/refs/heads/main/v2tel_links2.txt",
    "https://raw.githubusercontent.com/anaer/Sub/refs/heads/main/clash.yaml",
    "https://raw.githubusercontent.com/mfbpn/tg_mfbpn_sub/main/trial.yaml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/All_Config.txt",
    "https://raw.githubusercontent.com/SoroushImanian/BlackKnight/main/sub/mix",
    "https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/seperated_by_protocol/other.txt",
    "https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/seperated_by_protocol/shadowsocks.txt",
    "https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/seperated_by_protocol/trojan.txt",
    "https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/seperated_by_protocol/vmess.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",
    "https://raw.githubusercontent.com/rango-cfs/NewCollector/refs/heads/main/v2ray_links.txt",
    "https://elena.com.co/ELiV2-RAY-Sublink.txt",
    "https://raw.githubusercontent.com/AB-84-AB/Free-Shadowsocks/refs/heads/main/Telegram-id-AB_841",
    "https://raw.githubusercontent.com/TelAB841Conf/AB_841-config-Free-X-ray/refs/heads/main/X-ray_Server-Free",
    "https://raw.githubusercontent.com/Created-By/Telegram-Eag1e_YT/main/%40Eag1e_YT",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/vpei/free-node-1/refs/heads/main/res/nod-4.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/config.yaml",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
    "https://msk.vless-balancer.ru/sub/dXNlcl82Nzg4MzMxMjQ5LDE3Njk1MzUzMTkBqGm3A1STd/"
]

# --- 工具函数 ---

def auto_decode_base64(text):
    text = text.strip()
    if "://" in text and len(text) > 60: return text
    try:
        clean_text = re.sub(r'[^a-zA-Z0-9+/=]', '', text)
        missing_padding = len(clean_text) % 4
        if missing_padding: clean_text += '=' * (4 - missing_padding)
        return base64.b64decode(clean_text).decode('utf-8', errors='ignore')
    except:
        return text

def parse_yaml_to_links(content):
    links = []
    try:
        if "proxies:" not in content: return []
        data = yaml.safe_load(content)
        if not data or 'proxies' not in data: return []
        
        for p in data['proxies']:
            try:
                t = p.get('type', '').lower()
                server = p.get('server')
                port = p.get('port')
                name = p.get('name', 'node')
                if not server or not port: continue

                if t == 'vless':
                    uuid = p.get('uuid')
                    tls = "tls" if p.get('tls') else "none"
                    sni = p.get('servername', '')
                    links.append(f"vless://{uuid}@{server}:{port}?security={tls}&sni={sni}#{name}")
                elif t == 'trojan':
                    pw = p.get('password')
                    links.append(f"trojan://{pw}@{server}:{port}#{name}")
                elif t == 'ss':
                    links.append(f"ss://{server}:{port}#{name}")
            except: continue
    except: pass
    return links

def extract_host_port(node_url):
    """优化后的 host/port 提取，支持 IPv6"""
    try:
        if node_url.startswith("vmess://"):
            v2_raw = base64.b64decode(node_url[8:]).decode('utf-8')
            v2_json = json.loads(v2_raw)
            return str(v2_json.get('add')).strip(), str(v2_json.get('port')).strip()
        
        parsed = urlparse(node_url)
        netloc = parsed.netloc
        if "@" in netloc: netloc = netloc.split("@")[-1]
        
        # 使用 rsplit 兼容 IPv6
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
            return host.strip("[] "), port.strip()
        return netloc.strip(), "0"
    except:
        return None, None

def check_alive(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.5)
            return s.connect_ex((host, int(port))) == 0
    except: return False

# --- 核心类 ---

class NodeAggregator:
    def __init__(self):
        self.raw_nodes = set()
        self.source_stats = []
        self.geo_reader = None
        if os.path.exists(GEOIP_DB_PATH):
            self.geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)

    def get_country(self, host):
        if not self.geo_reader: return "UN"
        try:
            ip = host
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                ip = socket.gethostbyname(host)
            return self.geo_reader.country(ip).country.iso_code
        except: return "UN"

    def fetch_source(self, url):
        try:
            res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
            if res.status_code == 200:
                text = res.text
                found = re.findall(NODE_PATTERN, auto_decode_base64(text), re.IGNORECASE)
                if "proxies:" in text:
                    found.extend(parse_yaml_to_links(text))
                return url, found, 200
            return url, [], res.status_code
        except Exception as e:
            return url, [], str(e)

    def run(self):
        start_time = datetime.now()
        print(f"[{start_time.strftime('%H:%M:%S')}] 🚀 启动流...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.fetch_source, url) for url in RAW_NODE_SOURCES]
            for f in as_completed(futures):
                url, nodes, status = f.result()
                self.raw_nodes.update(nodes)
                self.source_stats.append({
                    "date": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_url": url,
                    "node_count": len(nodes),
                    "status": status
                })

        self.save_stats()

        unique_pool = {}
        for node in self.raw_nodes:
            if len(node) < 15 or any(kw in node.lower() for kw in EXCLUDE_KEYWORDS):
                continue
            
            host, port = extract_host_port(node)
            if host and port:
                protocol = node.split("://")[0].lower()
                identity = f"{protocol}://{host}:{port}" 
                if identity not in unique_pool:
                    unique_pool[identity] = node.split("#")[0] if "#" in node else node

        print(f"⚡ 正在检测 {len(unique_pool)} 个独特节点...")
        results_by_country = {}
        
        def process_node(item):
            identity, url = item
            try:
                # 修复核心：使用 rsplit 处理身份标识
                protocol, address = identity.split("://", 1)
                if ":" in address:
                    host, port = address.rsplit(":", 1)
                    if check_alive(host, port):
                        country = self.get_country(host)
                        return country, f"{url}#{country}_{protocol}_{host}"
            except: pass
            return None, None

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            node_futures = [executor.submit(process_node, it) for it in unique_pool.items()]
            for f in as_completed(node_futures):
                country, labeled_node = f.result()
                if country:
                    if country not in results_by_country: results_by_country[country] = []
                    results_by_country[country].append(labeled_node)

        self.save_nodes(results_by_country)

        print(f"---")
        print(f"✅ 处理完成！")
        print(f"📦 抓取总数: {len(self.raw_nodes)}")
        print(f"🌍 存活节点: {sum(len(v) for v in results_by_country.values())}")
        print(f"⏱️  总耗时: {datetime.now() - start_time}")

    def save_stats(self):
        with open(STATS_CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=["date", "source_url", "node_count", "status"])
            writer.writeheader()
            writer.writerows(self.source_stats)
        print(f"📊 统计报表已更新: {STATS_CSV_PATH}")

    def save_nodes(self, data):
        with open(os.path.join(OUTPUT_DIR, "nodes.txt"), "w", encoding="utf-8") as f:
            for country in sorted(data.keys()):
                f.write(f"\n# --- {country} ---\n")
                f.write("\n".join(sorted(data[country])) + "\n")

if __name__ == "__main__":
    aggregator = NodeAggregator()
    aggregator.run()
