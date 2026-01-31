# -*- coding: utf-8 -*-
import base64
import threading
import time
import urllib.parse
import json
import yaml
import requests
import os

# --- 配置 ---
CLASH_API = "http://127.0.0.1:9090"
PROXY_ADDR = "http://127.0.0.1:7890"
DOWNLOAD_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
SPEED_TEST_LIMIT = 100  # 测前100个
MIN_SPEED_MB = 0.5      # 至少 0.5MB/s 才保留
INPUT_FILE = "nodes_list.txt"
OUTPUT_FILE = "clash_config.yaml"

def parse_nodes():
    """解析明文链接"""
    proxies = []
    if not os.path.exists(INPUT_FILE):
        return proxies
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if line.startswith("hysteria2://") or line.startswith("vmess://"):
                    # 获取备注名
                    name = "Node"
                    if "#" in line:
                        name = urllib.parse.unquote(line.split("#")[1])
                    elif "ps=" in line:
                        name = "Vmess-Node" # 简单处理
                    proxies.append({"name": name, "link": line})
            except: continue
    return proxies

def switch_node(name):
    """切换 Mihomo 节点"""
    try:
        requests.put(f"{CLASH_API}/proxies/GLOBAL", json={"name": name}, timeout=5)
        time.sleep(1) # 必须等待，给内核握手时间
        return True
    except: return False

def test_speed(name):
    """测速逻辑"""
    start_time = time.time()
    total_data = 0
    try:
        # 使用本地代理进行下载
        with requests.get(DOWNLOAD_URL, stream=True, proxies={"http": PROXY_ADDR, "https": PROXY_ADDR}, timeout=5) as r:
            for chunk in r.iter_content(chunk_size=1024*256):
                total_data += len(chunk)
                if time.time() - start_time > 3: # 测试3秒
                    break
        duration = time.time() - start_time
        mb_speed = (total_data / duration) / (1024 * 1024)
        return round(mb_speed, 2)
    except:
        return 0

def main():
    nodes = parse_nodes()
    print(f"开始加载节点... 共 {len(nodes)} 个")
    
    # 为了保证准确性，这里改回顺序测速，但优化了切换等待
    # GitHub Actions 环境下，单核 Mihomo 无法支持真正的多线程节点切换
    valid_proxies = []
    
    # 准备基础 Clash 配置字典 (用于最后输出)
    final_config = {
        "proxies": [],
        "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": []}],
        "rules": ["MATCH,Proxy"]
    }

    count = 0
    for node in nodes[:SPEED_TEST_LIMIT]:
        print(f"正在测试 [{count+1}/{SPEED_TEST_LIMIT}]: {node['name']}...", end="")
        if switch_node(node['name']):
            speed = test_speed(node['name'])
            if speed >= MIN_SPEED_MB:
                print(f" 成功! 速度: {speed} MB/s")
                # 此处应调用你原有的 link 转 clash 配置的函数
                # 简化演示：直接保存
                valid_proxies.append(node)
            else:
                print(f" 失败或速度太慢 ({speed} MB/s)")
        count += 1

    # 保存文件，防止 git add 报错
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # 这里模拟输出，你需要确保你的脚本能把 link 转为真正的 clash 字典对象
        yaml.dump(final_config, f)
    
    print(f"测速完成，共筛选出 {len(valid_proxies)} 个高速节点")

if __name__ == "__main__":
    main()
