import pytest
from domain import Domain
import json


@pytest.mark.parametrize(
    'name, checkWwwName, checkName',[
    ('example.com', 'www.example.com', 'example.com'),
    ('www.example.com', 'www.example.com', 'example.com'),
])
def test___setName(name, checkWwwName, checkName):
    domain = Domain(is_debug=True)
    name, wwwName = domain._Domain__setName(name)
    
    assert wwwName == checkWwwName, \
        'wwwNameが正しく生成されていない'

    assert name == checkName, \
        'nameが正しく生成されていない'


@pytest.mark.parametrize(
    ','.join([
        'name',
        'ns_is_retrieved',
        'ns_name_is_retrieved',
    ]),[
    (
        'example.com', # 対象のドメイン
        True,  # NS が取得できたかどうか
        True,  # ns name が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # NS が取得できたかどうか
        False, # ns name が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # NS が取得できたかどうか
        True,  # ns name が取得できたかどうか
    ),
    ]
)
def test___getNsInfo(name, ns_is_retrieved, ns_name_is_retrieved):
    domain = Domain(is_debug=True)
    ns_name, ns = domain._Domain__getNsInfo(name)
    
    print(ns_name, ns)  
    assert (ns_name != '') == ns_name_is_retrieved, \
        'ns name の取得結果が正しくありません'
    assert (len(ns) > 0) == ns_is_retrieved, \
        'NS の取得結果が正しくありません'
    


@pytest.mark.parametrize(
    ','.join([
        'name',
        'ip_is_retrieved',
        'ptr_is_retrieved',
        'server_is_retrieved',
        'server_name_is_retrieved'
    ]), [
    (
        'example.com', # 対象のドメイン
        True,  # IP が取得できたかどうか
        False, # PTR が取得できたかどうか
        False, # server が取得できたかどうか
        False, # server name が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # IP が取得できたかどうか
        False, # PTR が取得できたかどうか
        False, # server が取得できたかどうか
        False, # server name が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # IP が取得できたかどうか
        True,  # PTR が取得できたかどうか
        True,  # server が取得できたかどうか
        True,  # server name が取得できたかどうか
    )
    ]
)
def test___getAInfo(
    name,
    ip_is_retrieved,
    ptr_is_retrieved,
    server_is_retrieved,
    server_name_is_retrieved
):
    domain = Domain(is_debug=True)
    server_name, ip, ptr, server  = domain._Domain__getAInfo(name)
    
    print(server_name, ip, ptr, server)
    assert (server_name != '') == server_name_is_retrieved, \
        'server name の取得結果が正しくありません'
    assert (ip != '') == ip_is_retrieved, \
        'IP の取得結果が正しくありません'
    assert (ptr != '') == ptr_is_retrieved, \
        'PTR の取得結果が正しくありません'
    assert (server != '') == server_is_retrieved, \
        'server の取得結果が正しくありません'


@pytest.mark.parametrize(
    ','.join([
        'name',
        'mxs_is_retrieved',
        'ip_is_retrieved',
        'ptr_is_retrieved',
        'server_is_retrieved',
        'server_name_is_retrieved'
    ]),[
    (
        'example.com', # 対象のドメイン
        True,  # MX が取得できたかどうか
        False, # IP が取得できたかどうか
        False, # PTR が取得できたかどうか
        False, # server が取得できたかどうか
        False, # server name が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # MX が取得できたかどうか
        False, # IP が取得できたかどうか
        False, # PTR が取得できたかどうか
        False, # server が取得できたかどうか
        False, # server name が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # MX が取得できたかどうか
        True,  # IP が取得できたかどうか
        True,  # PTR が取得できたかどうか
        True,  # server が取得できたかどうか
        True,  # server name が取得できたかどうか
    )
    ]
)
def test___getMxInfo(
    name,
    mxs_is_retrieved,
    ip_is_retrieved,
    ptr_is_retrieved,
    server_is_retrieved,
    server_name_is_retrieved
):
    domain = Domain(is_debug=True)
    mx_server_name, mxs, mx_ip, mx_ptr, mx_server = domain._Domain__getMxInfo(name)
    if mxs:
        print(', '.join([mx_server_name, mxs[0], mx_ip, mx_ptr, mx_server]))

    assert (mx_server_name != '') == server_name_is_retrieved, \
        'server name の取得結果が正しくありません'
    assert (len(mxs) > 0) == mxs_is_retrieved, \
        'MXレコードが正しく取得できていない'
    assert (mx_ip != '') == ip_is_retrieved, \
        'IP の取得結果が正しくありません'
    assert (mx_ptr != '') == ptr_is_retrieved, \
        'PTR の取得結果が正しくありません'
    assert (mx_server != '') == server_is_retrieved, \
        'server の取得結果が正しくありません'


@pytest.mark.parametrize(
    ','.join([
        'name',
        'txt_is_retrieved',
    ]),[
    (
        'example.com', # 対象のドメイン
        True,  # TXT が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # TXT が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # TXT が取得できたかどうか
    )
    ]
)
def test___getTxt(
    name,
    txt_is_retrieved
):
    domain = Domain(is_debug=True)
    txt = domain._Domain__getTxt(name)
    print(', '.join(txt))
    assert (len(txt) > 0) == txt_is_retrieved, \
        'TXTレコードが正しく取得できていない'

@pytest.mark.parametrize(
    ','.join([
        'name',
        'spf_is_retrieved',
    ]),[
    (
        'example.com', # 対象のドメイン
        True,  # SPF が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # SPF が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # SPF が取得できたかどうか
    )
    ]
)
def test___getSpf(
    name,
    spf_is_retrieved
):
    domain = Domain(is_debug=True)
    txt = domain._Domain__getTxt(name)
    spf = domain._Domain__getSpf(txt)
    print(', '.join(spf))
    assert (len(spf) > 0) == spf_is_retrieved, \
        'SPFレコードが正しく取得できていない'
    
@pytest.mark.parametrize(
    'name',[
    ('google.com')
    ]
)
def test___get_spf_mechanisms(name):
    domain = Domain(is_debug=True)
    spf_mechanisms, spf_ips = domain._Domain__get_spf_mechanisms(name)
    
    print(json.dumps(spf_mechanisms, indent=4, ensure_ascii=False))
    print(json.dumps(spf_ips, indent=4, ensure_ascii=False))
    # txt, spf = domain._Domain__getTxt(name)
    # domain._Domain__check_spf(name, "")
    
    assert len(spf_mechanisms) > 0, "mechanisms が取得できていない"
    assert len(spf_ips) > 0, "spf_ips が取得できていない"

@pytest.mark.parametrize(
    'name',[
    ('google.com'),
    ]
)
def test___check_spf(name):
    domain = Domain(is_debug=True)
    a_ip = domain._Domain__getA(name=domain._Domain__getMx(name=name)[0])
    print(a_ip)
    result = domain._Domain__check_spf(name, a_ip)
    
    assert result, "sfpレコードのチェックに失敗"

@pytest.mark.parametrize(
    ','.join([
        'name',
        'hinfo_is_retrieved',
        'a_server_is_retrieved',
        'a_server_name_is_retrieved',
        'mx_server_is_retrieved',
        'mx_server_name_is_retrieved'
    ]),[
    (
        'example.com', # 対象のドメイン
        False, # HINFO が取得できたかどうか
        False, # a server が取得できたかどうか
        False, # a server name が取得できたかどうか
        False, # mx server が取得できたかどうか
        False, # mx server name が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # HINFO が取得できたかどうか
        False, # a server が取得できたかどうか
        False, # a server name が取得できたかどうか
        False, # mx server が取得できたかどうか
        False, # mx server name が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        False, # HINFO が取得できたかどうか
        False, # a server が取得できたかどうか
        False, # a server name が取得できたかどうか
        False, # mx server が取得できたかどうか
        False, # mx server name が取得できたかどうか
    )
    ]
)
def test___getHinfo(
    name,
    hinfo_is_retrieved,
    a_server_is_retrieved,
    a_server_name_is_retrieved,
    mx_server_is_retrieved,
    mx_server_name_is_retrieved
):
    domain = Domain(is_debug=True)
    (
        hinfo,
        a_server, a_server_name,
        mx_server, mx_server_name
    ) = domain._Domain__getHinfo(name)
    if hinfo:
        print(', '.join(
            [
                hinfo[0],
                a_server, a_server_name,
                mx_server, mx_server_name
            ]
        ))

    assert (len(hinfo) > 0) == hinfo_is_retrieved, \
        'HINFOレコードが正しく取得できていない'
    assert (a_server != '') == a_server_is_retrieved, \
        'IP の取得結果が正しくありません'
    assert (a_server_name != '') == a_server_name_is_retrieved, \
        'PTR の取得結果が正しくありません'
    assert (mx_server != '') == mx_server_is_retrieved, \
        'server の取得結果が正しくありません'
    assert (mx_server_name != '') == mx_server_name_is_retrieved, \
        'server name の取得結果が正しくありません'


@pytest.mark.parametrize(
    ','.join([
        'name',
        'dmarc_is_retrieved'
    ]), [
    (
        'example.com', # 対象のドメイン
        False, # DMARC が取得できたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # DMARC が取得できたかどうか
    ),
    (
        'google.com', # 対象のドメイン
        True,  # DMARC が取得できたかどうか
    )
    ]
)
def test___getDmarc(
    name,
    dmarc_is_retrieved
):
    domain = Domain(is_debug=True)
    dmarc, dmarc_p, dmarc_rua = domain._Domain__getDmarc(name)
    
    print(dmarc, dmarc_p, dmarc_rua)
    assert (dmarc != '') == dmarc_is_retrieved, \
        'DMARC の取得結果が正しくありません'
    assert (dmarc_p != '') == dmarc_is_retrieved, \
        'dmarc_p の取得結果が正しくありません'
    assert (dmarc_rua != '') == dmarc_is_retrieved, \
        'dmarc_rua の取得結果が正しくありません'
    

@pytest.mark.parametrize(
    ','.join([
        'name',
        'is_accessed_http',
        'is_accessed_https',
    ]),[
    (
        'example.com', # 対象のドメイン
        True,  # http がアクセスできたかどうか
        True,  # https がアクセスできたかどうか
    ),
    (
        'example.jp', # 対象のドメイン
        False, # http がアクセスできたかどうか
        False, # https がアクセスできたかどうか
    ),
    (
        'www.google.com', # 対象のドメイン
        True,  # http がアクセスできたかどうか
        True,  # https がアクセスできたかどうか
    )
    ]
)
def test___isAccessibleHttp(
    name,
    is_accessed_http,
    is_accessed_https
):
    domain = Domain(is_debug=True)
    (
        is_accessible_http,
        is_accessible_https
    ) = domain._Domain__isAccessibleHttp(name)
    print(', '.join(
        [
            str(is_accessible_http),
            str(is_accessible_https)
        ]
    ))

    assert is_accessible_http == is_accessed_http, \
        'http でのアクセスの取得結果が正しくありません'
    assert is_accessible_https == is_accessed_https, \
        'https でのアクセスの取得結果が正しくありません'

@pytest.mark.parametrize(
    ('name'),[
    'example.com', # 対象のドメイン
    'example.jp', # 対象のドメイン
    'google.com' # 対象のドメイン
    ]
)
def test_instance(
    name
):
    domain = Domain(name, is_debug=True)

    check_keys = ['name', 'ns', 'a_ip', 'www_a_ip', 'mx', 'txt', 'hinfo', 'dmarc']
    for check_key in check_keys:
        assert check_key in domain.to_dict(), f'{check_key} が存在しない'