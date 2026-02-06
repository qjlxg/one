import os

# 定义文件路径
INPUT_FILE = 'link.txt'
OUTPUT_FILE = 'trojan_links.txt'

# 定义 Trojan 节点模板
TROJAN_TEMPLATE = "trojan://bpb-trojan@www.vpslook.com:443?security=tls&sni={domain}&alpn=h3&fp=randomized&allowlnsecure=1&type=ws&host={domain}&path=%2Ftr%3Fed%3D2560#BPB-{domain}"

def generate_trojan_links():
    """
    读取 link.txt 文件中的域名，生成 Trojan 链接并写入 trojan_links.txt 文件。
    """
    if not os.path.exists(INPUT_FILE):
        print(f"错误：输入文件 {INPUT_FILE} 不存在。")
        return

    generated_links = []
    
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"读取文件 {INPUT_FILE} 失败: {e}")
        return

    if not domains:
        print("警告：link.txt 中没有可用的域名。")
        return

    # 遍历域名列表，生成链接
    for domain in domains:
        # 使用 format() 方法替换模板中的占位符
        link = TROJAN_TEMPLATE.format(domain=domain)
        generated_links.append(link)

    # 将生成的链接写入输出文件
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(generated_links))
        
        print(f"成功生成 {len(generated_links)} 个 Trojan 链接，并写入 {OUTPUT_FILE}。")
        
    except Exception as e:
        print(f"写入文件 {OUTPUT_FILE} 失败: {e}")

if __name__ == "__main__":
    generate_trojan_links()
