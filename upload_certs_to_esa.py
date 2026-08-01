import datetime
import os

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest

from cert_utils import (
    cert_paths,
    get_env_var,
    get_optional_env_var,
    load_cert_domains,
    parse_esa_bindings,
    unique_covering_certs,
)


def file_exists_and_not_empty(file_path):
    return os.path.isfile(file_path) and os.path.getsize(file_path) > 0


def read_cert_pair(cert_domain):
    cert_path, key_path = cert_paths(cert_domain)
    if not file_exists_and_not_empty(cert_path) or not file_exists_and_not_empty(key_path):
        raise FileNotFoundError(
            f'Certificate or key for {cert_domain} is missing or empty: {cert_path}, {key_path}'
        )
    with open(cert_path, 'r') as f:
        cert = f.read()
    with open(key_path, 'r') as f:
        key = f.read()
    return cert, key


def upload_esa_certificate(client, site_id, cert_name, cert, key):
    request = CommonRequest()
    request.set_accept_format('json')
    request.set_domain('esa.cn-hangzhou.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_version('2024-09-10')
    request.set_action_name('SetCertificate')
    request.add_body_params('SiteId', str(site_id))
    request.add_body_params('Type', 'upload')
    request.add_body_params('Name', cert_name)
    request.add_body_params('Certificate', cert)
    request.add_body_params('PrivateKey', key)

    response = client.do_action_with_exception(request)
    print(str(response, encoding='utf-8'))


def main():
    bindings_raw = get_optional_env_var('ALIYUN_ESA_BINDINGS')
    if not bindings_raw:
        print('未设置 ALIYUN_ESA_BINDINGS，跳过 ESA 证书上传')
        return

    access_key_id = get_env_var('ALIYUN_ACCESS_KEY_ID')
    access_key_secret = get_env_var('ALIYUN_ACCESS_KEY_SECRET')
    cert_domains = load_cert_domains()
    bindings = parse_esa_bindings(bindings_raw)

    client = AcsClient(access_key_id, access_key_secret, 'cn-hangzhou')
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

    for site_id, hostnames in bindings:
        needed_certs = unique_covering_certs(hostnames, cert_domains)
        print(
            f'ESA 站点 {site_id} 域名 {", ".join(hostnames)} '
            f'需要证书: {", ".join(needed_certs)}'
        )
        for cert_domain in needed_certs:
            cert, key = read_cert_pair(cert_domain)
            safe_name = cert_domain.replace('*', 'wildcard').replace('.', '-')
            cert_name = f'{safe_name}-{timestamp}'
            upload_esa_certificate(client, site_id, cert_name, cert, key)
            print(f'已上传证书 {cert_domain} 到 ESA 站点 {site_id}')


if __name__ == '__main__':
    main()
