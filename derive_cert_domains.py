"""Derive CERT_DOMAINS from CDN/ESA lists (or optional override) and prepare cert dirs."""

import os

from cert_utils import cert_slug, get_optional_env_var, resolve_cert_domains


def main():
    cert_domains = resolve_cert_domains(
        cert_domains_override=get_optional_env_var('CERT_DOMAINS'),
        cdn_domains_raw=get_optional_env_var('ALIYUN_CDN_DOMAINS'),
        esa_bindings_raw=get_optional_env_var('ALIYUN_ESA_BINDINGS'),
    )
    if not cert_domains:
        raise SystemExit('推导结果为空，请检查域名配置')

    joined = ','.join(cert_domains)
    print(f'将申请以下证书: {joined}')

    github_env = os.getenv('GITHUB_ENV')
    if github_env:
        with open(github_env, 'a', encoding='utf-8') as f:
            f.write(f'CERT_DOMAINS={joined}\n')

    home_certs = os.path.expanduser('~/certs')
    os.makedirs(os.path.expanduser('~/.acme.sh'), exist_ok=True)
    for cert_domain in cert_domains:
        path = os.path.join(home_certs, cert_slug(cert_domain))
        os.makedirs(path, exist_ok=True)
        print(f'准备目录: {path}')


if __name__ == '__main__':
    main()
