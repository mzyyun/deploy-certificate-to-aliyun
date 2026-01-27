import datetime
import os
from aliyunsdkcore.client import AcsClient
from aliyunsdkcdn.request.v20180510 import SetCdnDomainSSLCertificateRequest

def get_env_var(key):
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(f"Environment variable {key} not set")
    return value

def file_exists_and_not_empty(file_path):
    expanded_path = os.path.expanduser(file_path)
    return os.path.isfile(expanded_path) and os.path.getsize(expanded_path) > 0

def extract_root_domain(domain):
    """
    提取根域名
    例如: npc.mzyyun.com -> mzyyun.com
          mzyyun.com -> mzyyun.com
    """
    parts = domain.strip().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain.strip()

def find_certificate_path(domain, root_domains):
    """
    为CDN域名找到对应的证书路径
    返回: (cert_path, key_path) 或 None
    """
    root = extract_root_domain(domain)
    
    # 首先检查是否是主域名（直接匹配）
    if domain == root:
        cert_path = f'~/certs/{root}/fullchain.pem'
        key_path = f'~/certs/{root}/privkey.pem'
        if file_exists_and_not_empty(cert_path) and file_exists_and_not_empty(key_path):
            return (cert_path, key_path)
    
    # 检查泛域名证书（使用 wildcard. 前缀）
    wildcard_cert_path = f'~/certs/wildcard.{root}/fullchain.pem'
    wildcard_key_path = f'~/certs/wildcard.{root}/privkey.pem'
    if file_exists_and_not_empty(wildcard_cert_path) and file_exists_and_not_empty(wildcard_key_path):
        return (wildcard_cert_path, wildcard_key_path)
    
    # 如果泛证书不存在，尝试主域名证书（可能主域名证书也支持子域名）
    if root in root_domains:
        cert_path = f'~/certs/{root}/fullchain.pem'
        key_path = f'~/certs/{root}/privkey.pem'
        if file_exists_and_not_empty(cert_path) and file_exists_and_not_empty(key_path):
            return (cert_path, key_path)
    
    return None

def upload_certificate(client, domain_name, cert_path, key_path):
    expanded_cert_path = os.path.expanduser(cert_path)
    expanded_key_path = os.path.expanduser(key_path)

    if not file_exists_and_not_empty(expanded_cert_path) or not file_exists_and_not_empty(expanded_key_path):
        raise FileNotFoundError(f"Certificate or key file for domain {domain_name} is missing or empty")
    
    with open(expanded_cert_path, 'r') as f:
        cert = f.read()

    with open(expanded_key_path, 'r') as f:
        key = f.read()

    request = SetCdnDomainSSLCertificateRequest.SetCdnDomainSSLCertificateRequest()
    # CDN加速域名
    request.set_DomainName(domain_name)
    # 证书名称
    request.set_CertName(domain_name + datetime.datetime.now().strftime("%Y%m%d"))
    request.set_CertType('upload')
    request.set_SSLProtocol('on')
    request.set_SSLPub(cert)
    request.set_SSLPri(key)
    request.set_CertRegion('cn-hangzhou')

    response = client.do_action_with_exception(request)
    print(str(response, encoding='utf-8'))

def main():
    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    domains = [d.strip() for d in get_env_var('DOMAINS').split(',') if d.strip()]
    cdn_domains = [d.strip() for d in get_env_var('ALIYUN_CDN_DOMAINS').split(',') if d.strip()]

    if len(domains) != len(cdn_domains):
        raise ValueError(f"DOMAINS ({len(domains)}) 和 ALIYUN_CDN_DOMAINS ({len(cdn_domains)}) 的数量不匹配")

    # 提取所有根域名
    root_domains = set()
    for domain in domains:
        root = extract_root_domain(domain)
        root_domains.add(root)

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')

    print(f"开始上传证书到阿里云CDN...")
    print(f"根域名列表: {root_domains}")
    
    for cdn_domain in cdn_domains:
        print(f"\n处理CDN域名: {cdn_domain}")
        cert_info = find_certificate_path(cdn_domain, root_domains)
        
        if cert_info is None:
            raise FileNotFoundError(f"未找到CDN域名 {cdn_domain} 对应的证书文件")
        
        cert_path, key_path = cert_info
        print(f"使用证书: {cert_path}")
        upload_certificate(client, cdn_domain, cert_path, key_path)
    
    print("\n所有证书上传完成！")

if __name__ == "__main__":
    main()
