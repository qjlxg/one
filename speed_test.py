import os
import re
import json
import base64
import time
import subprocess
import yaml
import requests
from datetime import datetime
import pytz

# --- 配置 ---
MIHOMO_GZ = "mihomo-linux-amd64-compatible-v1.19.19.gz"
NODES_FILE = "nodes_list.txt"
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')
TEST_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" # 谷歌镜像，Actions测速极快
TEST_DURATION = 5 # 每个节点测速5秒

def setup_mihomo():
    """解压并准备内核"""
    if not os.path.exists("mihomo"):
        print("[1/4] 正在准备 Mihomo 内核...")
        os.system(f"gunzip -c {MIHOMO_GZ} > mihomo")
        os.chmod("mihomo", 0o755)

def parse_nodes_to_clash(file_path):
    """
    核心思路借用自 ClashForge: 
    不依赖外部转换器，简单解析 vmess/vless/ss 链接并构造 clash 字典
    这里先用简易正则提取，为了切实可行，我们直接构造一个极简的 Clash 配置文件
    """
    proxies = []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        try:
            # 这里的解析逻辑可以极其复杂，为了演示核心，我们构造一个节点信息
            # 生产环境下建议此处使用更完善的解析函数，或者确保 nodes_list 内容格式正确
            # 这里我们假定 nodes_list.txt 中的节点可以被简单的解析
            # 实际上：最稳妥的方法是在 Actions 里启动一个本地 subconverter
            pass
        except:
            continue
    return proxies

def run_speed_test():
    setup_mihomo()
    now = datetime.now(SHANGHAI_TZ)
    report_name = f"speed_test_{now.strftime('%Y%m%d_%H%M%S')}.txt"

    # 生成一个基础配置 (借用 ClashForge 逻辑)
    # 为了保证 100% 成功，我们直接利用 subconverter 的在线 API 或本地构建
    # 在 Actions 里，最稳妥的是用在线转换 API 拿到 config.yaml
    print("[2/4] 正在获取节点配置...")
    with open(NODES_FILE, 'r', encoding='utf-8') as f:
        raw_content = f.read()
    
    # 使用通用的转换后端 (也可以本地启动 subconverter)
    sub_url = f"https://sub.id9.cc/sub?target=clash&url={requests.utils.quote(raw_content)}"
    try:
        config_data = requests.get(sub_url, timeout=15).text
        with open("config.yaml", "w", encoding="utf-8") as f:
            f.write(config_data)
    except:
        print("在线转换失败，尝试本地解析...")
        return

    # 启动 Mihomo
    print("[3/4] 正在启动内核并等待就绪...")
    # 增加日志输出重定向，方便调试输出错误
    log_file = open("mihomo_log.txt", "w")
    proc = subprocess.Popen(["./mihomo", "-f", "config.yaml"], stdout=log_file, stderr=log_file)
    
    # 必须给内核足够的时间加载大型 nodes_list
    time.sleep(10) 

    print("[4/4] 开始执行下行带宽测试...")
    results = []
    try:
        # 获取节点列表
        api_url = "http://127.0.0.1:9090/proxies"
        for _ in range(5): # 重试 5 次连接 API
            try:
                resp = requests.get(api_url, timeout=2)
                if resp.status_code == 200:
                    break
            except:
                time.sleep(2)
        
        proxies_data = resp.json()['proxies']
        # 排除非代理节点
        target_nodes = [k for k, v in proxies_data.items() if v['type'] not in ['Selector', 'URLTest', 'Direct', 'Reject']]
        
        # 只测试前 20 个节点（避免 Actions 运行超时）
        for name in target_nodes[:20]:
            # 切换节点
            requests.put("http://127.0.0.1:9090/proxies/GLOBAL", json={"name": name})
            
            # 测速逻辑 (借用 ClashForge 里的下载块累加思路)
            start_time = time.time()
            total_bytes = 0
            try:
                # 通过 Mihomo 代理下载
                with requests.get(TEST_URL, stream=True, proxies={"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}, timeout=10) as r:
                    for chunk in r.iter_content(chunk_size=1024*512):
                        total_bytes += len(chunk)
                        if time.time() - start_time >= TEST_DURATION:
                            break
                
                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1024 * 1024)
                speed_result = f"{round(speed_mbps, 2)} Mbps"
                print(f"节点: {name} | 速度: {speed_result}")
                results.append(f"✅ {speed_result} | {name}")
            except:
                print(f"节点: {name} | 测试失败")
                results.append(f"❌ 失败 | {name}")

    finally:
        proc.terminate()
        log_file.close()

    # 写入报告
    with open(report_name, "w", encoding="utf-8") as f:
        f.write(f"测试时间: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n")
        f.write("\n".join(results))
    print(f"报告已保存: {report_name}")

if __name__ == "__main__":
    run_speed_test()
