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
    # 证书名称（包含时间戳以确保唯一性）
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    request.set_CertName(f"{domain_name}-{timestamp}")
    request.set_CertType('upload')
    request.set_SSLProtocol('on')
    request.set_SSLPub(cert)
    request.set_SSLPri(key)
    request.set_CertRegion('cn-hangzhou')

    response = client.do_action_with_exception(request)
    print(str(response, encoding='utf-8'))

def is_main_domain(cdn_domain, main_domain):
    """判断CDN域名是否为主域名"""
    return cdn_domain.strip() == main_domain.strip()

def find_matching_main_domain(cdn_domain, main_domains):
    """为CDN域名找到匹配的主域名"""
    cdn_domain = cdn_domain.strip()
    for main_domain in main_domains:
        main_domain = main_domain.strip()
        # 如果CDN域名就是主域名，直接返回
        if cdn_domain == main_domain:
            return main_domain
        # 如果CDN域名是主域名的子域名，返回该主域名
        if cdn_domain.endswith('.' + main_domain):
            return main_domain
    # 如果没有找到匹配的主域名，返回第一个主域名（作为默认值）
    if main_domains:
        return main_domains[0].strip()
    return None

def main():
    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    domains = [d.strip() for d in get_env_var('DOMAINS').split(',')]
    cdn_domains = [d.strip() for d in get_env_var('ALIYUN_CDN_DOMAINS').split(',')]

    if not domains:
        raise ValueError("DOMAINS 不能为空")
    if not cdn_domains:
        raise ValueError("ALIYUN_CDN_DOMAINS 不能为空")

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')

    for cdn_domain in cdn_domains:
        # 为每个CDN域名找到匹配的主域名
        main_domain = find_matching_main_domain(cdn_domain, domains)
        if not main_domain:
            raise ValueError(f"无法为 CDN 域名 {cdn_domain} 找到匹配的主域名")
        
        # 根据CDN域名类型选择对应的证书
        # 主域名使用主域名证书，子域名使用泛域名证书
        if is_main_domain(cdn_domain, main_domain):
            cert_path = f'~/certs/{main_domain}/fullchain.pem'
            key_path = f'~/certs/{main_domain}/privkey.pem'
            print(f"为主域名 {cdn_domain} 使用主域名证书（主域名: {main_domain}）")
        else:
            cert_path = f'~/certs/{main_domain}/wildcard_fullchain.pem'
            key_path = f'~/certs/{main_domain}/wildcard_privkey.pem'
            print(f"为子域名 {cdn_domain} 使用泛域名证书（主域名: {main_domain}）")
        
        upload_certificate(client, cdn_domain, cert_path, key_path)

if __name__ == "__main__":
    main()