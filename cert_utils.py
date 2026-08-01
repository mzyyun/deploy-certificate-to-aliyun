"""Shared helpers for CERT_DOMAINS parsing, paths, and hostname coverage."""

import os


def get_env_var(key):
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(f"Environment variable {key} not set")
    return value


def get_optional_env_var(key):
    value = os.getenv(key)
    return value.strip() if value and value.strip() else None


def parse_csv(value):
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def normalize_domain(domain):
    return domain.strip().lower().rstrip('.')


def cert_slug(cert_domain):
    """Filesystem-safe directory name for a cert domain (e.g. *.a.com -> _wildcard.a.com)."""
    return normalize_domain(cert_domain).replace('*', '_wildcard')


def cert_paths(cert_domain):
    slug = cert_slug(cert_domain)
    return (
        os.path.expanduser(f'~/certs/{slug}/fullchain.pem'),
        os.path.expanduser(f'~/certs/{slug}/privkey.pem'),
    )


def is_wildcard(cert_domain):
    return normalize_domain(cert_domain).startswith('*.')


def covers_hostname(cert_domain, hostname):
    """Return True if cert_domain covers hostname (exact or single-label wildcard)."""
    cert_domain = normalize_domain(cert_domain)
    hostname = normalize_domain(hostname)

    if is_wildcard(cert_domain):
        base = cert_domain[2:]
        if hostname == base or not hostname.endswith('.' + base):
            return False
        prefix = hostname[: -(len(base) + 1)]
        return bool(prefix) and '.' not in prefix

    return cert_domain == hostname


def find_covering_cert(hostname, cert_domains):
    """
    Pick the best CERT_DOMAINS entry for hostname.
    Prefer exact match over wildcard; among wildcards prefer the more specific (longer) one.
    """
    hostname = normalize_domain(hostname)
    exact = [c for c in cert_domains if not is_wildcard(c) and covers_hostname(c, hostname)]
    if exact:
        return exact[0]

    wildcards = [c for c in cert_domains if is_wildcard(c) and covers_hostname(c, hostname)]
    if wildcards:
        return max(wildcards, key=lambda c: len(normalize_domain(c)))

    raise ValueError(
        f"无法为域名 {hostname} 在 CERT_DOMAINS 中找到可覆盖的证书。"
        f"当前证书列表: {', '.join(cert_domains)}"
    )


def unique_covering_certs(hostnames, cert_domains):
    """Ordered unique cert domains needed to cover the given hostnames."""
    selected = []
    seen = set()
    for hostname in hostnames:
        cert = find_covering_cert(hostname, cert_domains)
        key = normalize_domain(cert)
        if key not in seen:
            seen.add(key)
            selected.append(cert)
    return selected


def parse_esa_bindings(raw):
    """
    Parse ALIYUN_ESA_BINDINGS.
    Format: siteId:host1+host2,siteId2:host3
    Returns list of (site_id, [hostnames]).
    """
    bindings = []
    for item in parse_csv(raw):
        if ':' not in item:
            raise ValueError(
                f"ALIYUN_ESA_BINDINGS 项格式错误: {item}。"
                f"正确示例: 123456789:example.com+www.example.com"
            )
        site_id, hosts_part = item.split(':', 1)
        site_id = site_id.strip()
        hostnames = [h.strip() for h in hosts_part.split('+') if h.strip()]
        if not site_id or not hostnames:
            raise ValueError(f"ALIYUN_ESA_BINDINGS 项缺少站点 ID 或域名: {item}")
        bindings.append((site_id, hostnames))
    return bindings


def load_cert_domains():
    cert_domains = parse_csv(get_env_var('CERT_DOMAINS'))
    if not cert_domains:
        raise ValueError('CERT_DOMAINS 不能为空')
    return cert_domains


# Common multi-part public suffixes (not exhaustive; override with CERT_DOMAINS if needed)
MULTI_PART_TLDS = frozenset({
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.hk', 'com.tw', 'com.sg',
    'co.uk', 'org.uk', 'ac.uk',
    'com.au', 'net.au', 'org.au',
    'co.jp', 'or.jp', 'ne.jp',
})


def split_apex_and_sublabels(hostname):
    """
    Split hostname into (apex, sub_labels).
    e.g. www.example.com.cn -> ('example.com.cn', ['www'])
         cdn.example.com    -> ('example.com', ['cdn'])
         example.com        -> ('example.com', [])
         a.b.example.com    -> ('example.com', ['a', 'b'])
    """
    hostname = normalize_domain(hostname)
    parts = hostname.split('.')
    if len(parts) < 2:
        raise ValueError(f'无效域名: {hostname}')

    for i in range(1, len(parts)):
        suffix = '.'.join(parts[i:])
        if suffix in MULTI_PART_TLDS and i >= 1:
            # Need at least one label before the multi-part TLD for apex
            if i == 1:
                # hostname is like example.com.cn
                return hostname, []
            apex = '.'.join(parts[i - 1 :])
            return apex, parts[: i - 1]

    # Default: apex = last two labels
    if len(parts) == 2:
        return hostname, []
    apex = '.'.join(parts[-2:])
    return apex, parts[:-2]


def derive_cert_domains(hostnames):
    """
    Derive certificate names from deploy hostnames:
      - apex host       -> exact cert (example.com)
      - single-level sub -> wildcard (*.example.com)
      - multi-level sub  -> exact cert for that host (a.b.example.com)
    """
    certs = []
    seen = set()
    for raw in hostnames:
        hostname = normalize_domain(raw)
        if not hostname:
            continue
        apex, sub_labels = split_apex_and_sublabels(hostname)
        if not sub_labels:
            cert = apex
        elif len(sub_labels) == 1:
            cert = f'*.{apex}'
        else:
            cert = hostname
        key = normalize_domain(cert)
        if key not in seen:
            seen.add(key)
            certs.append(cert)
    return certs


def collect_deploy_hostnames(cdn_domains_raw=None, esa_bindings_raw=None):
    """Collect unique hostnames from CDN list and ESA bindings."""
    hostnames = []
    seen = set()

    for host in parse_csv(cdn_domains_raw):
        key = normalize_domain(host)
        if key not in seen:
            seen.add(key)
            hostnames.append(host.strip())

    if esa_bindings_raw:
        for _site_id, hosts in parse_esa_bindings(esa_bindings_raw):
            for host in hosts:
                key = normalize_domain(host)
                if key not in seen:
                    seen.add(key)
                    hostnames.append(host)

    return hostnames


def resolve_cert_domains(cert_domains_override=None, cdn_domains_raw=None, esa_bindings_raw=None):
    """
    Prefer explicit CERT_DOMAINS override; otherwise derive from CDN + ESA hostnames.
    """
    override = parse_csv(cert_domains_override)
    if override:
        return override

    hostnames = collect_deploy_hostnames(cdn_domains_raw, esa_bindings_raw)
    if not hostnames:
        raise ValueError(
            '未设置 CERT_DOMAINS，且 ALIYUN_CDN_DOMAINS / ALIYUN_ESA_BINDINGS 均为空，无法推导证书列表'
        )
    return derive_cert_domains(hostnames)
