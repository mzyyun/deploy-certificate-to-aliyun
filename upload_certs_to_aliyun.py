import datetime
import os

from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.client import AcsClient
from aliyunsdkcdn.request.v20180510 import SetCdnDomainSSLCertificateRequest

from cert_utils import (
    cert_paths,
    find_covering_cert,
    get_env_var,
    get_optional_env_var,
    load_cert_domains,
    parse_csv,
)


def file_exists_and_not_empty(file_path):
    return os.path.isfile(file_path) and os.path.getsize(file_path) > 0


def upload_certificate(client, domain_name, cert_path, key_path, cert_domain):
    if not file_exists_and_not_empty(cert_path) or not file_exists_and_not_empty(key_path):
        raise FileNotFoundError(
            f"Certificate or key for CDN domain {domain_name} "
            f"(matched cert {cert_domain}) is missing or empty: {cert_path}, {key_path}"
        )

    with open(cert_path, 'r') as f:
        cert = f.read()
    with open(key_path, 'r') as f:
        key = f.read()

    request = SetCdnDomainSSLCertificateRequest.SetCdnDomainSSLCertificateRequest()
    request.set_DomainName(domain_name)
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    safe_name = cert_domain.replace('*', 'wildcard').replace('.', '-')
    request.set_CertName(f'{domain_name}-{safe_name}-{timestamp}')
    request.set_CertType('upload')
    request.set_SSLProtocol('on')
    request.set_SSLPub(cert)
    request.set_SSLPri(key)
    request.set_CertRegion('cn-hangzhou')

    try:
        response = client.do_action_with_exception(request)
    except ServerException as e:
        if e.get_error_code() == 'InvalidDomain.Offline':
            print(f'警告: CDN 域名 {domain_name} 已停用 (offline)，跳过证书上传')
            return False
        raise
    print(str(response, encoding='utf-8'))
    return True


def main():
    cdn_raw = get_optional_env_var('ALIYUN_CDN_DOMAINS')
    cdn_domains = parse_csv(cdn_raw)
    if not cdn_domains:
        print('未设置 ALIYUN_CDN_DOMAINS，跳过 CDN 证书上传')
        return

    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    cert_domains = load_cert_domains()

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')
    skipped_offline = []

    for cdn_domain in cdn_domains:
        cert_domain = find_covering_cert(cdn_domain, cert_domains)
        cert_path, key_path = cert_paths(cert_domain)
        print(f'为 CDN 域名 {cdn_domain} 使用证书 {cert_domain}')
        if not upload_certificate(client, cdn_domain, cert_path, key_path, cert_domain):
            skipped_offline.append(cdn_domain)

    if skipped_offline:
        print(f'\n摘要: 已跳过 {len(skipped_offline)} 个已停用的 CDN 域名: {", ".join(skipped_offline)}')


if __name__ == '__main__':
    main()
