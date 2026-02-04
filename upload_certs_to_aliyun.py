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
    # 证书名称
    request.set_CertName(domain_name + datetime.datetime.now().strftime("%Y%m%d"))
    request.set_CertType('upload')
    request.set_SSLProtocol('on')
    request.set_SSLPub(cert)
    request.set_SSLPri(key)
    request.set_CertRegion('cn-hangzhou')

    response = client.do_action_with_exception(request)
    print(str(response, encoding='utf-8'))

def get_cert_path(main_domain, cdn_domain):
    """
    根据主域名和CDN域名自动判断使用哪个证书
    - 如果CDN域名等于主域名，使用主域名证书
    - 否则使用泛域名证书
    """
    if cdn_domain.strip() == main_domain.strip():
        # 主域名使用主域名证书
        return (
            f'~/certs/{main_domain}/fullchain.pem',
            f'~/certs/{main_domain}/privkey.pem'
        )
    else:
        # 子域名使用泛域名证书
        return (
            f'~/certs/wildcard.{main_domain}/fullchain.pem',
            f'~/certs/wildcard.{main_domain}/privkey.pem'
        )

def main():
    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    
    # 获取主域名（取第一个，去掉空格）
    domains_str = get_env_var('DOMAINS')
    main_domain = domains_str.split(',')[0].strip()
    
    # 获取CDN域名列表
    cdn_domains = [d.strip() for d in get_env_var('ALIYUN_CDN_DOMAINS').split(',')]

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')

    for cdn_domain in cdn_domains:
        # 自动判断使用哪个证书
        cert_path, key_path = get_cert_path(main_domain, cdn_domain)
        
        cert_type = "主域名证书" if cdn_domain == main_domain else "泛域名证书"
        print(f"为 CDN 域名 {cdn_domain} 使用 {cert_type}")
        
        upload_certificate(client, cdn_domain, cert_path, key_path)

if __name__ == "__main__":
    main()
