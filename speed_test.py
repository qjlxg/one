import asyncio
import httpx
import yaml
import json
import base64
import os
import subprocess
import time
from urllib.parse import urlparse, unquote, parse_qs

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_FILE = "latest_nodes.txt"
TEST_URL = "https://www.google.com/generate_204"
CONCURRENCY_LIMIT = 50  
RETRIES = 0             # 设为0可以最快速度刷完一遍，只看是否通畅
TIMEOUT = 5             
API_URL = "http://127.0.0.1:9090"
PROXY_ADDR = "http://127.0.0.1:7890"
# ==========================================

class AsyncNodeTester:
    def __init__(self):
        self.proxies = []
        self.name_map = {}
        self.seen_endpoints = set()
        self.results = []
        self.tested_count = 0

    def parse_link(self, link):
        try:
            link = link.strip()
            if not link or len(link) < 5: return None
            url = urlparse(link)
            server = url.hostname
            port = int(url.port or 443)
            endpoint_key = f"{server}:{port}"
            if endpoint_key in self.seen_endpoints: return None

            raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{server}_{port}"
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            node = {"name": "", "server": server, "port": port, "udp": True, "skip-cert-verify": True}

            if url.scheme == 'vless':
                node.update({"type": "vless", "uuid": url.username, "cipher": "auto", "tls": query.get('security') in ['tls', 'reality'], "servername": query.get('sni'), "network": query.get('type', 'tcp'), "flow": query.get('flow', '')})
                if query.get('security') == 'reality': node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
                if query.get('type') in ['ws', 'grpc']:
                    node["network"] = query.get('type')
                    if query.get('type') == 'ws': node["ws-opts"] = {"path": query.get('path', '/'), "headers": {"Host": query.get('host', '')}}
                    if query.get('type') == 'grpc': node["grpc-opts"] = {"grpc-service-name": query.get('serviceName', '')}
            elif url.scheme == 'vmess':
                b64_data = link[8:].split('#')[0]
                missing_padding = len(b64_data) % 4
                if missing_padding: b64_data += '=' * (4 - missing_padding)
                data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
                node.update({"type": "vmess", "server": data.get('add'), "port": int(data.get('port')), "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto", "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'), "servername": data.get('sni') or data.get('host', '')})
            elif url.scheme in ['hy2', 'hysteria2']:
                node.update({"type": "hysteria2", "password": url.username, "sni": query.get('sni'), "obfs": query.get('obfs'), "obfs-password": query.get('obfs-password')})
            elif url.scheme == 'tuic':
                node.update({"type": "tuic", "uuid": url.username, "password": url.password, "alpn": [query.get('alpn', 'h3')], "congestion-controller": query.get('congestion_control', 'bbr'), "sni": query.get('sni')})
            elif url.scheme == 'ss':
                if '@' in url.netloc:
                    user_info = base64.b64decode(url.username).decode() if ':' not in url.username else unquote(url.username)
                    method, password = user_info.split(':', 1)
                    node.update({"type": "ss", "cipher": method, "password": password})
            elif url.scheme == 'trojan':
                node.update({ "type": "trojan", "password": url.username, "sni": query.get('sni', url.hostname), "tls": True})

            if not node.get("type"): return None
            self.seen_endpoints.add(endpoint_key)
            return raw_name, node, link
        except: return None

    async def test_node(self, p_client, a_client, node_id):
        node_info = self.name_map[node_id]
        try:
            # 切换节点
            await a_client.put("/proxies/GLOBAL", json={"name": node_id})
            
            latencies = []
            for _ in range(RETRIES + 1):
                start_t = time.perf_counter()
                r = await p_client.get(TEST_URL, timeout=TIMEOUT)
                if r.status_code in [200, 204]:
                    latencies.append((time.perf_counter() - start_t) * 1000)
            
            self.tested_count += 1
            if latencies:
                avg_ms = int(sum(latencies) / len(latencies))
                print(f"[{self.tested_count}] ✅ {node_info['type'].upper()} | {avg_ms}ms | {node_info['raw_name'][:20]}", flush=True)
                return {**node_info, "ms": avg_ms, "jitter": int(max(latencies)-min(latencies))}
            else:
                # 每测 10 个失败的打个点，证明程序没死
                if self.tested_count % 10 == 0:
                    print(f"[{self.tested_count}...] 正在扫描中...", flush=True)
        except Exception:
            self.tested_count += 1
        return None

    async def worker(self, queue, p_client, a_client):
        while True:
            node_id = await queue.get()
            res = await self.test_node(p_client, a_client, node_id)
            if res: self.results.append(res)
            queue.task_done()

    async def run(self):
        if not os.path.exists("mihomo"):
            if os.path.exists(MIHOMO_GZ): os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
            else: return

        print("🌐 1. 正在拉取远程节点...", flush=True)
        async with httpx.AsyncClient(timeout=15) as client:
            for source in NODE_SOURCES:
                try:
                    r = await client.get(source)
                    for line in r.text.splitlines():
                        parsed = self.parse_link(line)
                        if parsed:
                            r_name, config, r_link = parsed
                            u_id = f"N_{len(self.proxies):04d}"
                            config['name'] = u_id
                            self.proxies.append(config)
                            self.name_map[u_id] = {"id": u_id, "raw_name": r_name, "raw_link": r_link, "type": config['type']}
                except: continue

        print(f"📦 2. 解析完成，共 {len(self.proxies)} 个唯一节点 (去重后)。", flush=True)
        
        config_data = {"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "log-level": "silent", "proxies": self.proxies}
        with open("config.yaml", "w", encoding="utf-8") as f: yaml.dump(config_data, f)

        proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("⚙️ 3. 内核启动中...", flush=True)
        await asyncio.sleep(10) # 缩短等待

        queue = asyncio.Queue()
        for p in self.proxies: queue.put_nowait(p['name'])

        print(f"🚀 4. 开始并发测速 (线程池: {CONCURRENCY_LIMIT})...", flush=True)
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=CONCURRENCY_LIMIT)
        async with httpx.AsyncClient(proxy=PROXY_ADDR, limits=limits) as p_client, \
                   httpx.AsyncClient(base_url=API_URL, timeout=3) as a_client:
            
            workers = [asyncio.create_task(self.worker(queue, p_client, a_client)) for _ in range(CONCURRENCY_LIMIT)]
            await queue.join()
            for w in workers: w.cancel()

        proc.terminate()
        if self.results:
            self.results.sort(key=lambda x: x['ms'])
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join([f"{i['raw_link'].split('#')[0]}#{i['raw_name']} ✅ {i['ms']}ms" for i in self.results]))
            print(f"✨ 任务完成，保存了 {len(self.results)} 个可用节点。")
        else:
            print("❌ 所有节点测试失败。")

if __name__ == "__main__":
    asyncio.run(AsyncNodeTester().run())
