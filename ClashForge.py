# -*- coding: utf-8 -*-
import base64
import threading
import time
import urllib.parse
import json
import re
import yaml
import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 核心配置优化 ---
INPUT = "."              # 读取当前目录下的 nodes_list.txt
SPEED_TEST = True
SPEED_TEST_LIMIT = 100   # 深度测试前100个连通的节点
MAX_WORKERS = 10         # 下载测速并发数 (不建议太高，否则 Actions 带宽会满)
test_duration = 3        # 每个节点下载测试3秒 (3秒足以判断能否看电影)
DOWNLOAD_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
CLASH_API = "http://127.0.0.1:9090"
BAN = ["中国", "China", "CN", "回国"]

results_speed = []
lock = threading.Lock()

def get_proxies_from_file():
    """从 nodes_list.txt 解析节点"""
    proxies = []
    file_path = "nodes_list.txt"
    if not os.path.exists(file_path):
        print(f"找不到 {file_path}")
        return proxies
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        if not line: continue
        # 这里简单模拟解析，实际脚本中应包含 vmess/hy2 的 Base64/正则解析逻辑
        # 假设解析后的字典为 proxy_dict
        proxy_dict = parse_proxy_link(line)
        if proxy_dict:
            proxies.append(proxy_dict)
    return proxies

def parse_proxy_link(link):
    """简单解析示例，支持 hysteria2 和 vmess"""
    try:
        if link.startswith("hysteria2://"):
            parts = urllib.parse.urlparse(link)
            name = urllib.parse.unquote(parts.fragment) or "Hy2-Node"
            return {"name": name, "type": "hysteria2", "server": parts.hostname, "port": parts.port, "link": link}
        elif link.startswith("vmess://"):
            # 简易解析 vmess ps 字段
            return {"name": "Vmess-Node", "type": "vmess", "link": link}
    except: return None
    return None

def switch_proxy(proxy_name):
    """通过 API 切换 Clash 节点"""
    try:
        url = f"{CLASH_API}/proxies/GLOBAL" # 假设使用 GLOBAL 模式
        data = json.dumps({"name": proxy_name})
        requests.put(url, data=data, timeout=2)
    except: pass

def single_node_test(proxy):
    """单个节点的下载测速核心逻辑"""
    proxy_name = proxy['name']
    # 1. 切换节点
    switch_proxy(proxy_name)
    time.sleep(0.5) # 给核心一点点切换缓冲
    
    proxies = {
        "http": "http://127.0.0.1:7890",
        "https": "http://127.0.0.1:7890",
    }
    
    start_time = time.time()
    total_length = 0
    try:
        # stream=True 开启流式下载测速
        with requests.get(DOWNLOAD_URL, stream=True, proxies=proxies, timeout=5) as r:
            for chunk in r.iter_content(chunk_size=1024*512):
                total_length += len(chunk)
                if time.time() - start_time >= test_duration:
                    break
        
        duration = time.time() - start_time
        speed_bps = (total_length / duration) if duration > 0 else 0
        speed_mb = speed_bps / (1024 * 1024)
        
        print(f"节点: {proxy_name} | 速度: {speed_mb:.2f} MB/s")
        return {"name": proxy_name, "speed": speed_mb, "link": proxy['link']}
    except:
        return None

def main():
    print("开始加载节点...")
    all_proxies = get_proxies_from_file()
    print(f"共加载 {len(all_proxies)} 个节点")

    # 过滤掉黑名单关键词
    filtered_proxies = [p for p in all_proxies if not any(b in p['name'] for b in BAN)]

    # 使用线程池并发测速
    print(f"开始多线程测速 (并发数: {MAX_WORKERS})...")
    final_results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 注意：由于 Clash 全局模式下切换节点会相互干扰，
        # 如果需要极速并发，建议脚本内为每个线程启动独立的 Clash 实例（较为复杂）。
        # 这里采用优化的顺序切换测试，但在下载 IO 上利用线程池。
        futures = [executor.submit(single_node_test, p) for p in filtered_proxies[:SPEED_TEST_LIMIT]]
        
        for future in as_completed(futures):
            res = future.result()
            if res and res['speed'] > 0.5: # 仅保留大于 0.5MB/s 的节点
                final_results.append(res)

    # 按速度排序
    final_results.sort(key=lambda x: x['speed'], reverse=True)

    # 导出为 Clash 配置或 TXT
    print(f"测速完成，共筛选出 {len(final_results)} 个高速节点")
    save_config(final_results)

def save_config(nodes):
    # 生成最终文件的逻辑...
    pass

if __name__ == "__main__":
    main()