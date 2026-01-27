#!/usr/bin/env python3
"""
智能证书管理脚本
自动识别主域名和子域名，只申请主域名证书和泛域名证书
"""
import os
import subprocess
import sys
from collections import defaultdict

def get_env_var(key):
    """获取环境变量"""
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(f"Environment variable {key} not set")
    return value

def extract_root_domain(domain):
    """
    提取根域名
    例如: npc.mzyyun.com -> mzyyun.com
          mzyyun.com -> mzyyun.com
    """
    parts = domain.strip().split('.')
    if len(parts) >= 2:
        # 返回最后两个部分作为根域名
        return '.'.join(parts[-2:])
    return domain.strip()

def group_domains(domains):
    """
    将域名分组为主域名和子域名
    返回: {
        'root_domains': [主域名列表],
        'subdomains_by_root': {根域名: [子域名列表]}
    }
    """
    root_domains = []
    subdomains_by_root = defaultdict(list)
    
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
            
        root = extract_root_domain(domain)
        
        # 如果域名本身就是根域名（没有子域名部分）
        if domain == root or domain.count('.') == root.count('.'):
            if root not in root_domains:
                root_domains.append(root)
        else:
            # 这是子域名
            subdomains_by_root[root].append(domain)
            # 确保根域名也在列表中（用于申请泛证书）
            if root not in root_domains:
                root_domains.append(root)
    
    return {
        'root_domains': root_domains,
        'subdomains_by_root': dict(subdomains_by_root)
    }

def issue_certificate(domain, is_wildcard=False):
    """
    申请SSL证书
    domain: 域名（如 mzyyun.com）
    is_wildcard: 是否为泛域名证书
    """
    acme_sh_path = os.path.expanduser('~/.acme.sh/acme.sh')
    
    # 确定证书存储路径（使用 wildcard. 前缀来标识泛域名证书）
    if is_wildcard:
        cert_dir = f"~/certs/wildcard.{domain}"
        cert_domain = f"*.{domain}"
    else:
        cert_dir = f"~/certs/{domain}"
        cert_domain = domain
    
    # 创建证书目录
    os.makedirs(os.path.expanduser(cert_dir), exist_ok=True)
    
    key_file = os.path.expanduser(f"{cert_dir}/privkey.pem")
    fullchain_file = os.path.expanduser(f"{cert_dir}/fullchain.pem")
    
    # 检查证书是否已存在且有效
    if os.path.exists(key_file) and os.path.exists(fullchain_file):
        print(f"证书已存在: {cert_domain}")
        return True
    
    # 申请证书
    cmd = [
        acme_sh_path,
        '--issue',
        '--dns', 'dns_ali',
        '-d', cert_domain,
        '--key-file', key_file,
        '--fullchain-file', fullchain_file
    ]
    
    print(f"正在申请证书: {cert_domain}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"申请证书失败: {cert_domain}")
        print(f"错误信息: {result.stderr}")
        return False
    
    print(f"证书申请成功: {cert_domain}")
    return True

def main():
    """主函数"""
    try:
        # 获取环境变量
        domains_str = get_env_var('DOMAINS')
        domains = [d.strip() for d in domains_str.split(',') if d.strip()]
        
        if not domains:
            print("错误: 没有找到域名配置")
            sys.exit(1)
        
        print(f"输入的域名列表: {domains}")
        
        # 分组域名
        grouped = group_domains(domains)
        root_domains = grouped['root_domains']
        subdomains_by_root = grouped['subdomains_by_root']
        
        print(f"\n识别到的主域名: {root_domains}")
        for root, subs in subdomains_by_root.items():
            print(f"  {root} 的子域名: {subs}")
        
        # 申请证书
        certs_to_issue = []
        
        for root_domain in root_domains:
            # 检查主域名本身是否在域名列表中（需要主域名证书）
            needs_root_cert = root_domain in domains
            
            # 检查是否有子域名（需要泛域名证书）
            has_subdomains = root_domain in subdomains_by_root and len(subdomains_by_root[root_domain]) > 0
            
            if has_subdomains:
                # 有子域名，申请泛域名证书
                certs_to_issue.append((root_domain, True))
                print(f"\n为 {root_domain} 申请泛域名证书 (*.{root_domain})")
            
            if needs_root_cert:
                # 主域名本身需要证书
                certs_to_issue.append((root_domain, False))
                print(f"\n为 {root_domain} 申请主域名证书")
        
        # 执行证书申请
        success = True
        for domain, is_wildcard in certs_to_issue:
            if not issue_certificate(domain, is_wildcard):
                success = False
        
        if not success:
            print("\n部分证书申请失败，请检查错误信息")
            sys.exit(1)
        
        print("\n所有证书申请完成！")
        
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
