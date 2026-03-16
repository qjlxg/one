import asyncio
import httpx
import yaml
import json
import base64
import os
import subprocess
import time
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime

# ================= 配置区 =================
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/x.sub/refs/heads/main/leaked_nodes.txt"
]
OUTPUT_FILE = "latest_nodes.txt"
TEST_URL = "https://www.google.com/generate_204"
CONCURRENCY_LIMIT = 30  # 异步并发数
RETRIES = 1             # 延迟抖动测试的额外请求次数
TIMEOUT = 5
# ==========================================

class AsyncNodeTester:
    def __init__(self):
        self.proxies = []
        self.name_map = {}
        self.seen_endpoints = set()
        self.results = []

    def parse_link(self, link):
        """全协议深度解析引擎 (已迁移并增强去重)"""
        try:
            link = link.strip()
            if not link or len(link) < 5: return None
            url = urlparse(link)
            
            # 基础信息
            server = url.hostname
            port = int(url.port or 443)
            # 深度去重：基于 服务器+端口
            endpoint_key = f"{server}:{port}"
            if endpoint_key in self.seen_endpoints: return None

            raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{server}_{port}"
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            
            node = {
                "name": "", 
                "server": server,
                "port": port,
                "udp": True,
                "skip-cert-verify": True
            }

            # --- 协议分支 ---
            if url.scheme == 'vless':
                node.update({
                    "type": "vless", "uuid": url.username, "cipher": "auto",
                    "tls": query.get('security') in ['tls', 'reality'],
                    "servername": query.get('sni'), "network": query.get('type', 'tcp'),
                    "flow": query.get('flow', '')
                })
                if query.get('security') == 'reality':
                    node["reality-opts"] = {"public-key": query.get('pbk'), "short-id": query.get('sid', '')}
                if query.get('type') in ['ws', 'grpc']:
                    node["network"] = query.get('type')
                    if query.get('type') == 'ws':
                        node["ws-opts"] = {"path": query.get('path', '/'), "headers": {"Host": query.get('host', '')}}
                    if query.get('type') == 'grpc':
                        node["grpc-opts"] = {"grpc-service-name": query.get('serviceName', '')}
            
            elif url.scheme == 'vmess':
                b64_data = link[8:].split('#')[0]
                missing_padding = len(b64_data) % 4
                if missing_padding: b64_data += '=' * (4 - missing_padding)
                data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
                node.update({
                    "type": "vmess", "server": data.get('add'), "port": int(data.get('port')),
                    "uuid": data.get('id'), "alterId": int(data.get('aid', 0)), "cipher": "auto",
                    "tls": data.get('tls') in ['tls', True, 'true'], "network": data.get('net', 'tcp'),
                    "servername": data.get('sni') or data.get('host', '')
                })
            
            elif url.scheme in ['hy2', 'hysteria2']:
                node.update({
                    "type": "hysteria2", "password": url.username, 
                    "sni": query.get('sni'), "obfs": query.get('obfs'), 
                    "obfs-password": query.get('obfs-password')
                })
            
            elif url.scheme == 'tuic':
                node.update({
                    "type": "tuic", "uuid": url.username, "password": url.password, 
                    "alpn": [query.get('alpn', 'h3')], 
                    "congestion-controller": query.get('congestion_control', 'bbr'), 
                    "sni": query.get('sni')
                })
            
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

        except Exception:
            return None

    async def test_node(self, client, node_id):
        """异步测试单个节点"""
        latencies = []
        node_info = self.name_map[node_id]
        
        try:
            # 切换内核当前节点
            async with httpx.AsyncClient() as c:
                await c.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": node_id}, timeout=2)

            for _ in range(RETRIES + 1):
                start_t = time.perf_counter()
                r = await client.get(TEST_URL, timeout=TIMEOUT)
                if r.status_code in [200, 204]:
                    latencies.append((time.perf_counter() - start_t) * 1000)
            
            if latencies:
                avg_ms = int(sum(latencies) / len(latencies))
                jitter = int(max(latencies) - min(latencies))
                print(f"  ✅ [{node_info['type'].upper()}] {avg_ms}ms | {node_info['raw_name'][:20]}")
                return {**node_info, "ms": avg_ms, "jitter": jitter}
        except:
            pass
        return None

    async def worker(self, queue, client):
        while True:
            node_id = await queue.get()
            res = await self.test_node(client, node_id)
            if res:
                self.results.append(res)
            queue.task_done()

    def prepare_kernel(self):
        """准备 Mihomo 内核"""
        if not os.path.exists("mihomo"):
            if os.path.exists(MIHOMO_GZ):
                os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
            else:
                raise FileNotFoundError("Mihomo core not found.")

    async def run(self):
        self.prepare_kernel()
        
        # 1. 获取并解析节点
        print("🌐 正在获取远程节点并解析...")
        async with httpx.AsyncClient(timeout=10) as client:
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
                            self.name_map[u_id] = {
                                "id": u_id, "raw_name": r_name, 
                                "raw_link": r_link, "type": config['type']
                            }
                except Exception as e:
                    print(f"⚠️ 源 {source} 加载失败: {e}")

        if not self.proxies:
            print("❌ 未发现有效节点")
            return

        # 2. 启动内核
        config_data = {
            "mixed-port": 7890,
            "external-controller": "127.0.0.1:9090",
            "mode": "global",
            "log-level": "silent",
            "proxies": self.proxies
        }
        with open("config.yaml", "w", encoding="utf-8") as f:
            yaml.dump(config_data, f)

        proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL)
        print(f"⚙️  内核已启动 (PID: {proc.pid})，开始并发测速...")
        await asyncio.sleep(4)

        # 3. 异步并发测试
        queue = asyncio.Queue()
        for p in self.proxies:
            queue.put_nowait(p['name'])

        async with httpx.AsyncClient(proxies="http://127.0.0.1:7890") as proxy_client:
            workers = [asyncio.create_task(self.worker(queue, proxy_client)) for _ in range(CONCURRENCY_LIMIT)]
            await queue.join()
            for w in workers: w.cancel()

        # 4. 清理与结果保存
        proc.terminate()
        
        if self.results:
            self.results.sort(key=lambda x: (x['ms'], x['jitter']))
            output = []
            for item in self.results:
                line = f"{item['raw_link'].split('#')[0]}#{item['raw_name']} ✅ {item['ms']}ms (±{item['jitter']}ms)"
                output.append(line)
            
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output))
            
            print(f"\n📊 测试完成！")
            print(f"✨ 有效节点: {len(self.results)} / {len(self.proxies)}")
            print(f"🥇 最优节点: {self.results[0]['raw_name']} ({self.results[0]['ms']}ms)")
        else:
            print("⚠️ 未发现可用节点。")

if __name__ == "__main__":
    tester = AsyncNodeTester()
    asyncio.run(tester.run())
