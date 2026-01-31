import os
import json
import base64
import urllib.parse

# --- 配置区 ---
RESULT_JSON = 'out.json'         
FINAL_FILE = 'nodes_list.txt'    
# 电影流畅指标：1.5MB/s。如果运行后节点太少，可以调低到 0.5 或 1.0
MIN_SPEED_MB = 1.5               

def rename_with_speed(raw_url, speed_mb):
    """保持原名，仅在末尾加上速度标识"""
    try:
        if raw_url.startswith('vmess://'):
            v_data = json.loads(base64.b64decode(raw_url.split('://')[1]).decode('utf-8'))
            old_ps = v_data.get('ps', 'Unknown')
            # 去掉旧的速度标识（如果有），重新打标
            clean_ps = old_ps.split(' [')[0]
            v_data['ps'] = f"{clean_ps} [{speed_mb:.1f}MB/s]"
            return f"vmess://{base64.b64encode(json.dumps(v_data).encode()).decode()}"
        else:
            # 处理 vless, trojan, ss 等 URL 格式
            u = list(urllib.parse.urlparse(raw_url))
            old_name = urllib.parse.unquote(u[5]) # 获取 # 后面的名字
            clean_name = old_name.split(' [')[0]
            u[5] = urllib.parse.quote(f"{clean_name} [{speed_mb:.1f}MB/s]")
            return urllib.parse.urlunparse(u)
    except:
        return raw_url

def main():
    if not os.path.exists(RESULT_JSON):
        print("错误：测速工具未生成 out.json")
        return

    with open(RESULT_JSON, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except:
            print("JSON 解析失败")
            return

    # 获取节点列表
    nodes_data = data if isinstance(data, list) else data.get('nodes', [])
    
    # 1. 核心排序：速度最快的排在文件最前面
    nodes_data.sort(key=lambda x: x.get('speed', 0), reverse=True)

    valid_nodes = []
    
    

    for n in nodes_data:
        raw_speed = n.get('speed', 0)
        speed_mb = raw_speed / (1024 * 1024)
        
        # 2. 核心过滤：低于门槛的全部扔掉
        # 这一步会直接把那 1400 多个连不上的、死掉的、卡顿的节点全部清理掉
        if speed_mb < MIN_SPEED_MB:
            continue

        link = n.get('link')
        if not link:
            continue
            
        # 3. 重新打标：在节点名字后面加上真实测出来的速度
        final_link = rename_with_speed(link, speed_mb)
        valid_nodes.append(final_link)

    # 4. 覆盖写入
    with open(FINAL_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_nodes))
    
    print(f"筛选完成：保留了 {len(valid_nodes)} 个流畅节点 (速度 > {MIN_SPEED_MB}MB/s)")

if __name__ == "__main__":
    main()
