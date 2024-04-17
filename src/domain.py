from typing import Tuple
from wcwidth import wcswidth
import dns.resolver
import requests
import re
import json

class Domain():
    # ドメイン名
    name:str = ''
    wwwName:str = ''
    
    # ネームサーバ
    ns:list[str] = []
    ns_name:str
    
    # Aレコード
    a_ip:str = ''
    a_ptr:str = ''
    a_server:str = ''
    a_server_name:str = ''
    a_is_accessible_http: bool = False
    a_is_accessible_https: bool = False
    
    # www.Aレコード
    www_a_ip:str = ''
    www_a_ptr:str = ''
    www_a_server:str = ''
    www_a_server_name:str = ''
    www_a_is_accessible_http: bool = False
    www_a_is_accessible_https: bool = False
    
    # http アクセス（a or www で どれかがアクセスできれば True）
    is_accessible_http: bool = False

    # MXレコード
    mx:list[str] = []
    mx_ip:str = ''
    mx_ptr:str = ''
    mx_server:str = ''
    mx_server_name:str = ''
    
    # TXTレコード
    txt:list[str] = []
    spf:list[str] = []
    
    # HINFOレコード
    hinfo:list[str] = []

    # DMARCレコード
    dmarc:str = ''
    dmarc_p:str = ''
    dmarc_rua:str = ''

    __is_debug: bool
    __servers_info: json

    def __init__(self, name:str='', is_debug:bool=False) -> None:
        self.__is_debug = is_debug
        self.__load_servers_info()

        if name:
            # NSレコード
            self.name, self.wwwName = self.__setName(name)
            self.ns, self.ns_name = self.__getNs(name=self.name)
            
            # Aレコード
            (
                self.a_ip,
                self.a_ptr,
                self.a_server,
                self.a_server_name
            ) = self.__getA(name=self.name)
            (
                self.a_is_accessible_http,
                self.a_is_accessible_https,
            ) = self.__isAccessibleHttp(name=self.name)

            # www.Aレコード
            (
                self.www_a_ip, 
                self.www_a_ptr, 
                self.www_a_server, 
                self.www_a_server_name
            ) = self.__getA(name=self.wwwName)
            (
                self.www_a_is_accessible_http,
                self.www_a_is_accessible_https,
            ) = self.__isAccessibleHttp(name=self.wwwName)

            # is_accessible_http
            self.is_accessible_http = (
                self.a_is_accessible_http or
                self.a_is_accessible_https or
                self.www_a_is_accessible_http or
                self.www_a_is_accessible_https
            )

            # MXレコード
            (
                self.mx,
                self.mx_ip,
                self.mx_ptr,
                self.mx_server,
                self.mx_server_name
            ) = self.__getMx(name=self.name)

            # TXTレコード
            (
                self.txt,
                self.spf,
            ) = self.__getTxt(name=self.name)
            
            # HINFOレコード
            (
                self.hinfo,
                self.a_server,
                self.a_server_name,
                self.mx_server,
                self.mx_server_name
            ) = self.__getHinfo(name=self.name)

            # DMARCレコード
            (
                self.dmarc,
                self.dmarc_p,
                self.dmarc_rua,
            ) = self.__getDmarc(name=self.name)

    
    def to_dict(self) -> dict:
        data = {}
        for key, value in self.__dict__.items():
            if key.startswith('_Domain__'):
                # プライベート変数を除外
                continue

            if isinstance(value, list):
                # リストは改行で区切り、ダブルクォーテーションで囲む
                data[key] = "\"" + '\r\n'.join(value) + "\""
            else:
                data[key] = value
        return data
    
    def summary(self) -> dict:
        maxLength = 20
        def omit(value, maxLength):
            #return value[:maxLength]+'...' if len(value)>maxLength else value
            actual_length = 0
            for i, char in enumerate(value):
                char_width = wcswidth(char)
                if actual_length + char_width > maxLength:
                    return value[:i] + '...'
                actual_length += char_width
            return value

        
        return {
          'name': self.name,
          'ns': omit(self.ns[0] if len(self.ns) > 0 else '', maxLength),
          'ns_name': omit(self.ns_name, maxLength),
          'a_ptr': omit(self.a_ptr, maxLength),
          'a_server_name': omit(self.a_server_name, maxLength),
          'mx': omit(self.mx[0] if len(self.mx) > 0 else '', maxLength),
          'mx_ptr': omit(self.mx_ptr, maxLength),
          'mx_server_name': omit(self.mx_server_name, maxLength),
          'spf': omit(self.spf[0] if len(self.spf) > 0 else '', maxLength),
          'dmarc': omit(self.dmarc, maxLength),
        }

    def __load_servers_info(self):
        with open('src/servers_info.json', 'r', encoding="utf-8") as file:
            self.__servers_info = json.load(file)


    def __getNs(self, name:str) -> tuple[list[str], str]:
        """
        ドメイン名からNSレコードを取得する

        Args:
            name: ドメイン名

        Returns:
            NSレコード, NSレコードのサーバ名
        """
        try:
            # NSレコードを取得してNSレコードの値でソート
            ns:list[str] = sorted([
                ns.to_text() for ns in dns.resolver.query(name, 'NS')
            ])
            
            nsServerName = "設定なし"
            for name, providers in self.__servers_info['name_servers'].items():
                if ns[0] in providers:
                    nsServerName = name
                    break

            return ns, nsServerName
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get NS record for {name} ({e})")
            return [], ""
        

    def __setName(self, name:str) -> Tuple[str, str]:
        """
        ドメイン名からwwwなしのドメイン名、wwwありのドメイン名を返す

        Args:
            name: ドメイン名
        
        Returns:
            wwwなしのドメイン名、wwwありのドメイン名
        """
        nameWithoutWWW, nameWithWWW = '', ''
        
        if name:
            if name[:4] == 'www.':
                nameWithoutWWW = name[4:]
                nameWithWWW    = name
            else:
                nameWithoutWWW = name
                nameWithWWW    = f'www.{name}'
        
        return nameWithoutWWW, nameWithWWW


    def __getA(self, name:str) -> tuple[str, str, str, str]:
        """
        ドメイン名からIPアドレス(Aレコード)、PTRレコード、サーバ、サーバ名称を取得する

        Args:
            name: ドメイン名
        
        Returns:
            IPアドレス, PTRレコード, サーバ, サーバ名称
        """
        ip, ptr, server, server_name = '', '', '', ''

        try:
            ip  = dns.resolver.query(name, 'A')[0].address
            if ip:
                ptr = dns.resolver.query(
                    dns.reversename.from_address(ip),
                    'PTR'
                )[0].to_text()
                server = ptr
            if ptr:
                server_name = '設定なし'
                for name, patterns in self.__servers_info['web_servers'].items():
                    for pattern in patterns:
                        if re.match(pattern, ptr):
                            server_name = name
                            break
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return ip, ptr, server, server_name

        
    def __getMx(self, name:str) -> tuple[list[str], str, str, str, str]:
        """ 
        ドメイン名からMXレコード、MXレコードのIPアドレス、PTRレコード、MXレコードのサーバ名を取得する

        Args:
            name: ドメイン名

        Returns:
            MXレコード, MXレコードのIPアドレス, PTRレコード, MXレコードのサーバ名
        """
        mxs, mx_ip, mx_ptr, mx_server, mx_server_name = [], '', '', '', ''
        try:
            # MXレコードを取得して優先度とMXレコードの値でソート
            mxs = sorted(
                dns.resolver.query(name, 'MX'),
                key=lambda mx: (mx.preference, mx.exchange)
            )
            mxs = [mx.exchange.to_text() for mx in mxs]

            if len(mxs) > 0:
                mx_ip  = dns.resolver.query(mxs[0], 'A')[0].address
            if mx_ip:
                mx_ptr = dns.resolver.query(
                    dns.reversename.from_address(mx_ip),
                    'PTR'
                )[0].to_text()
                mx_server = mx_ptr
            if mx_ptr:
                mx_server_name = '設定なし'
                for name, patterns in self.__servers_info['mail_servers'].items():
                    for pattern in patterns:
                        if re.match(pattern, mxs[0]):
                            mx_server_name = name
                            break

                        if re.match(pattern, mx_ptr):
                            mx_server_name = name
                            break

        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")

        return mxs, mx_ip, mx_ptr, mx_server, mx_server_name
    
    
    def __getTxt(self, name:str) -> tuple[list[str], list[str]]:
        txts:list[str] = []
        spfs:list[str] = []

        try:
            # TXTレコードを取得して spf の文字列を含むものを抽出
            for txt in dns.resolver.query(name, 'TXT'):
                txts.extend(re.findall(r'"([^"]+)"', txt.to_text()))
            
            for txt in txts:
                if 'spf' in txt:
                    spfs.append(txt)
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return txts, spfs
    

    def __getHinfo(self, name:str) -> tuple[list[str], str, str, str, str]:
        """
        ドメイン名からHINFOレコード、Aレコード、Aレコードのサーバ、MXレコード、MXレコードのサーバを取得する

        Args:
            name: ドメイン名

        Returns:
            HINFOレコード,
            Aレコードのサーバ, Aレコードのサーバ名称,
            MXレコードのサーバ, MXレコードのサーバ名称
        """
        hinfos:list[str] = []
        a_server, a_server_name = self.a_server, self.a_server_name
        mx_server, mx_server_name = self.mx_server, self.mx_server_name

        try:
            hinfos = sorted([
                hinfo.os.decode("utf-8") for hinfo in dns.resolver.query(name, 'HINFO')
            ])
            if len(hinfos) > 0:
                # web_servers の情報更新
                for name, patterns in self.__servers_info['hinfo']['web_servers'].items():
                    for pattern in patterns:
                        for hinfo in hinfos:
                            if re.match(pattern, hinfo):
                                a_server = hinfo
                                a_server_name = name
                                break
                
                # mail_servers の情報更新
                for name, patterns in self.__servers_info['hinfo']['mail_servers'].items():
                    for pattern in patterns:
                        for hinfo in hinfos:
                            if re.match(pattern, hinfo):
                                mx_server = hinfo
                                mx_server_name = name
                                break
                        
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")

        return hinfos, a_server, a_server_name, mx_server, mx_server_name

    def __getDmarc(self, name:str) -> tuple[str, str, str]:
        dmarc, dmarc_p, dmarc_rua = '', '', ''

        try:
            # TXTレコードを取得して spf の文字列を含むものを抽出
            dmarc = dns.resolver.query(f'_dmarc.{name}', 'TXT')[0].to_text().replace('"', '')
            dmarc_p = re.search(r'p=([^;]+)', dmarc).group(1)
            dmarc_rua = re.search(r'rua=mailto:([^;]+)', dmarc).group(1)
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return dmarc, dmarc_p, dmarc_rua
    
    
    def __isAccessibleHttp(self, name:str) -> tuple[bool, bool]:
        """
        ドメイン名からHTTPアクセス可能かどうかを判定する

        Args:
            name: ドメイン名

        Returns:
            HTTPアクセス可能かどうか
        """
        def call(url:str) -> bool:
            """
            HTTPアクセスを行う

            Args:
                url: HTTPアクセスするURL

            Returns:
                HTTPアクセスの成否
            """
            try:
                if not url: return False

                response = requests.head(url, allow_redirects=True, timeout=30)
                if response.status_code == 200: return True

                return False

            except Exception as e:
                return False

        return call(f'http://{name}'), call(f'https://{name}')            