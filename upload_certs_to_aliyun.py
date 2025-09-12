import datetime
import os
import time
import json
from aliyunsdkcore.client import AcsClient
from aliyunsdkcdn.request.v20180510 import SetCdnDomainSSLCertificateRequest
from aliyunsdkcdn.request.v20180510 import DescribeCdnDomainDetailRequest

def get_env_var(key):
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(f"Environment variable {key} not set")
    return value

def file_exists_and_not_empty(file_path):
    expanded_path = os.path.expanduser(file_path)
    return os.path.isfile(expanded_path) and os.path.getsize(expanded_path) > 0

def get_domain_detail(client, domain_name):
    """获取域名详情，检查当前配置"""
    try:
        request = DescribeCdnDomainDetailRequest.DescribeCdnDomainDetailRequest()
        request.set_DomainName(domain_name)
        response = client.do_action_with_exception(request)
        return json.loads(str(response, encoding='utf-8'))
    except Exception as e:
        print(f"Error getting domain details for {domain_name}: {e}")
        return None

def upload_certificate(client, domain_name, cert_path, key_path, is_root_domain=False):
    expanded_cert_path = os.path.expanduser(cert_path)
    expanded_key_path = os.path.expanduser(key_path)

    if not file_exists_and_not_empty(expanded_cert_path) or not file_exists_and_not_empty(expanded_key_path):
        raise FileNotFoundError(f"Certificate or key file for domain {domain_name} is missing or empty")
    
    with open(expanded_cert_path, 'r') as f:
        cert = f.read()

    with open(expanded_key_path, 'r') as f:
        key = f.read()

    # 为根域名和CDN域名创建不同的证书名称
    cert_suffix = "_root" if is_root_domain else "_cdn"
    cert_name = f"{domain_name}{cert_suffix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    request = SetCdnDomainSSLCertificateRequest.SetCdnDomainSSLCertificateRequest()
    request.set_DomainName(domain_name)
    request.set_CertName(cert_name)
    request.set_CertType('upload')
    request.set_SSLProtocol('on')
    request.set_SSLPub(cert)
    request.set_SSLPri(key)
    request.set_CertRegion('cn-hangzhou')

    try:
        response = client.do_action_with_exception(request)
        result = json.loads(str(response, encoding='utf-8'))
        print(f"✓ Certificate successfully deployed for {domain_name} (CertName: {cert_name})")
        return result
    except Exception as e:
        print(f"✗ Failed to deploy certificate for {domain_name}: {e}")
        return None

def main():
    try:
        access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
        access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
        domains = get_env_var('DOMAINS').split(',')
        cdn_domains = get_env_var('ALIYUN_CDN_DOMAINS').split(',')

        if len(domains) != len(cdn_domains):
            raise ValueError("DOMAINS and ALIYUN_CDN_DOMAINS must have the same number of elements")

        client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')
        
        print(f"Starting certificate deployment for {len(domains)} domain(s)")
        print(f"Root domains: {domains}")
        print(f"CDN domains: {cdn_domains}")

        for i, (domain, cdn_domain) in enumerate(zip(domains, cdn_domains)):
            print(f"\n--- Processing pair {i+1}: {domain} -> {cdn_domain} ---")
            
            cert_path = f'~/certs/{domain}/fullchain.pem'
            key_path = f'~/certs/{domain}/privkey.pem'
            
            # 检查证书文件是否存在
            if not file_exists_and_not_empty(cert_path) or not file_exists_and_not_empty(key_path):
                print(f"Certificate files not found for {domain}, skipping...")
                continue
            
            # 检查是否为根域名
            is_root_domain = (cdn_domain == domain)
            
            # 获取域名当前配置详情
            domain_detail = get_domain_detail(client, cdn_domain)
            if domain_detail:
                print(f"Current domain status: {domain_detail.get('DomainDetail', {}).get('DomainStatus', 'Unknown')}")
            
            # 上传证书到CDN域名
            result = upload_certificate(client, cdn_domain, cert_path, key_path, is_root_domain)
            
            if result:
                # 等待配置生效
                print(f"Waiting 5 seconds for configuration to propagate...")
                time.sleep(5)
            
            # 如果CDN域名不是根域名，还需要为根域名部署证书（如果有）
            if not is_root_domain and domain in cdn_domains:
                print(f"Also deploying certificate for root domain: {domain}")
                root_result = upload_certificate(client, domain, cert_path, key_path, True)
                
                if root_result:
                    print(f"Waiting 5 seconds for root domain configuration to propagate...")
                    time.sleep(5)
        
        print("\n✓ Certificate deployment process completed!")
        
    except Exception as e:
        print(f"✗ Error in main process: {e}")
        raise

if __name__ == "__main__":
    main()
