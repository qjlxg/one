import os
import re
import json
import time
import subprocess
import requests
from datetime import datetime
import pytz

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODES_FILE = "nodes_list.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
SUB_API = "http://127.0.0.1:25500/sub?target=clash&config=https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini&url="
TEST_URL = "https://cachefly.cachefly.net/10mb.test" # 测速文件
TIMEOUT = 10 # 每个节点下载限时

def setup_env():
    """准备二进制环境"""
    print("[1/4] 准备内核环境...")
    # 解压 mihomo
    os.system(f"gunzip -c {MIHOMO_GZ} > mihomo && chmod +x mihomo")
    
    # 下载并准备 subconverter (用于链接转配置)
    if not os.path.exists("subconverter"):
        print("下载 subconverter 二进制...")
        os.system("wget -q https://github.com/tindy2013/subconverter/releases/latest/download/subconverter_linux64.tar.gz")
        os.system("tar -xzf subconverter_linux64.tar.gz")
        os.chmod("subconverter/subconverter", 0o755)

def run_speed_test():
    setup_env()
    now = datetime.now(SHANGHAI_TZ)
    report_name = f"speed_test_{now.strftime('%Y%m%d_%H%M%S')}.txt"
    
    # 1. 启动 subconverter (后台)
    sub_proc = subprocess.Popen(["./subconverter/subconverter"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    # 2. 读取并转换节点
    with open(NODES_FILE, 'r') as f:
        raw_links = "|".join([line.strip() for line in f if line.strip()])
    
    try:
        print("[2/4] 转换节点格式...")
        encoded_links = requests.utils.quote(raw_links)
        r = requests.get(f"{SUB_API}{encoded_links}", timeout=30)
        with open("config.yaml", "w") as f:
            f.write(r.text)
    except Exception as e:
        print(f"转换失败: {e}")
        sub_proc.terminate()
        return

    # 3. 启动 Mihomo (后台)
    print("[3/4] 启动测试内核...")
    mihomo_proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=subprocess.DEVNULL)
    time.sleep(5) # 等待内核完全启动

    # 4. 循环测速
    print("[4/4] 开始测速...")
    try:
        # 获取所有节点名称 (通过 Mihomo API)
        proxies = requests.get("http://127.0.0.1:9090/proxies").json()['proxies']
        # 过滤出真实节点
        target_nodes = [n for n in proxies.keys() if proxies[n]['type'] not in ['Selector', 'Direct', 'Reject', 'URLTest']]
        
        results = []
        for name in target_nodes:
            # 切换节点
            requests.put(f"http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            
            # 测试下载
            start_time = time.time()
            try:
                # 使用 curl 通过代理测试，获取下载速度 (单位: byte/s)
                cmd = f"curl -m {TIMEOUT} -x http://127.0.0.1:7890 -o /dev/null -s -w '%{{speed_download}}' {TEST_URL}"
                speed_bytes = float(subprocess.check_output(cmd, shell=True).decode())
                speed_mb = round(speed_bytes / 1024 / 1024, 2)
                status = "✅ 可用" if speed_mb > 0 else "❌ 连通失败"
            except:
                speed_mb = 0
                status = "❌ 异常"

            print(f"节点: {name[:20]}... | 速度: {speed_mb} MB/s")
            results.append(f"{status} | {speed_mb} MB/s | {name}")

        # 写入文件
        with open(report_name, "w", encoding="utf-8") as f:
            f.write(f"测试时间: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"测试文件: {TEST_URL}\n")
            f.write("-" * 60 + "\n")
            f.write("\n".join(results))
            
    finally:
        mihomo_proc.terminate()
        sub_proc.terminate()
        print(f"测试完成，报告已生成: {report_name}")

if __name__ == "__main__":
    run_speed_test()
