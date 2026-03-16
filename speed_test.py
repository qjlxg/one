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
MAX_RETRIES = 1   # 调试阶段建议先减小重试，加快报错反馈
MAX_WORKERS = 10  # 调试阶段降低并发，方便观察日志
# ==========================================

def parse_link(link):
    """保持原逻辑不变，仅增加基本校验"""
    try:
        link = link.strip()
        if not link or len(link) < 5: return None, None, None
        url = urlparse(link)
        raw_name = unquote(url.fragment) if url.fragment else f"{url.scheme}_{url.hostname}_{url.port}"
        
        # ... (此处省略你原有的 parse_link 逻辑，建议直接复用原脚本该函数)
        # 为了演示简洁，假设逻辑已加载
        return raw_name, {"type": "vless", "server": url.hostname}, link 
    except:
        return None, None, None

def test_single_node(p, name_to_link):
    """增强报错信息的测试函数"""
    idx_name = p['name']
    node_type = p.get('type', 'UNKNOWN').upper()
    node_server = p.get('server', 'NULL')

    try:
        # 1. 尝试切换节点
        switch_res = requests.put(
            f"http://127.0.0.1:9090/proxies/GLOBAL", 
            json={"name": idx_name}, 
            timeout=3
        )
        if switch_res.status_code != 204:
            print(f"  ❌ [API错误] 无法切换到节点 {idx_name}: {switch_res.text}")
            return None

        # 2. 执行测速
        start_t = time.time()
        r = requests.get(
            LATENCY_URL, 
            proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, 
            timeout=TIMEOUT
        )
        
        if r.status_code in [200, 204]:
            ms = int((time.time() - start_t) * 1000)
            print(f"  ✅ [{node_type}] {node_server} | {ms}ms")
            return {"link": name_to_link[idx_name]['link'], "raw_name": name_to_link[idx_name]['raw_name'], "ms": ms}
        else:
            print(f"  ⚠️ [{node_type}] {node_server} | HTTP {r.status_code}")
            
    except requests.exceptions.ProxyError:
        print(f"  💀 [{node_type}] {node_server} | 代理服务器拒绝连接 (内核可能挂了)")
    except requests.exceptions.Timeout:
        print(f"  ⏰ [{node_type}] {node_server} | 测试超时")
    except Exception as e:
        print(f"  ❌ [{node_type}] {node_server} | 未知错误: {type(e).__name__}")
    
    return None

def run_test():
    # 1. 检查内核文件
    if not os.path.exists("mihomo"):
        print("🔍 尝试解压内核文件...")
        if os.path.exists(MIHOMO_GZ):
            os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
        else:
            print(f"❌ 错误: 找不到 {MIHOMO_GZ}")
            return

    # 2. 启动内核 (开启日志输出以供调试)
    # 注意：在本地运行时，如果 7890 端口被占用，这里会启动失败
    print("⚙️ 正在启动 Mihomo 内核...")
    proc = subprocess.Popen(
        ["./mihomo", "-f", "config.yaml"], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT,
        text=True
    )

    # 3. 验证内核 API 是否就绪
    time.sleep(3)
    try:
        api_check = requests.get("http://127.0.0.1:9090/version", timeout=2)
        print(f"🚀 内核已就绪: {api_check.json().get('version')}")
    except Exception as e:
        print(f"❌ 内核启动验证失败! 请检查端口 9090 是否被占用。错误: {e}")
        # 读取内核最后几行报错
        stdout, _ = proc.communicate(timeout=1)
        print(f"内核日志输出:\n{stdout}")
        proc.kill()
        return

    # ... (后续执行 ThreadPoolExecutor)
    # 执行完后记得 proc.kill()

if __name__ == "__main__":
    # 模拟简单的配置写入测试
    test_config = {"mixed-port": 7890, "external-controller": "127.0.0.1:9090", "mode": "global", "proxies": [{"name": "test", "type": "ss", "server": "1.1.1.1", "port": 8388, "cipher": "aes-256-gcm", "password": "test"}]}
    with open("config.yaml", "w") as f: yaml.dump(test_config, f)
    run_test()
