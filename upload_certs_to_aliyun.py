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

def main():
    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    domains = [d.strip() for d in get_env_var('DOMAINS').split(',')]
    cdn_domains = [d.strip() for d in get_env_var('ALIYUN_CDN_DOMAINS').split(',')]

    # 验证两个列表长度必须一致
    if len(domains) != len(cdn_domains):
        raise ValueError(
            f"DOMAINS 和 ALIYUN_CDN_DOMAINS 的数量必须一致。"
            f"DOMAINS 有 {len(domains)} 个，ALIYUN_CDN_DOMAINS 有 {len(cdn_domains)} 个"
        )

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')

    for domain, cdn_domain in zip(domains, cdn_domains):
        # 验证 CDN 域名是否与证书域名匹配（主域名或子域名）
        # 证书包含 example.com 和 *.example.com，所以可以匹配主域名和所有子域名
        if cdn_domain != domain and not cdn_domain.endswith('.' + domain):
            print(f"警告: CDN域名 {cdn_domain} 可能不匹配证书域名 {domain}。"
                  f"证书包含 {domain} 和 *.{domain}，请确保 {cdn_domain} 是 {domain} 的主域名或子域名。")
        
        cert_path = f'~/certs/{domain}/fullchain.pem'
        key_path = f'~/certs/{domain}/privkey.pem'
        upload_certificate(client, cdn_domain, cert_path, key_path)

if __name__ == "__main__":
    main()