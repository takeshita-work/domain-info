from typing import Tuple
from wcwidth import wcswidth

import dns.resolver
import requests
import ipaddress

import re
import json
import ipaddress

class Domain():
    # ドメイン名
    name:str = ''
    wwwName:str = ''
    
    # ネームサーバ
    ns_name:str
    ns:list[str] = []
    
    # Aレコード
    a_server_name:str = ''
    a_ip:str = ''
    a_ptr:str = ''
    a_server:str = ''
    a_is_accessible_http: bool = False
    a_is_accessible_https: bool = False
    a_is_included_spf: bool = False
    
    # www.Aレコード
    www_a_server_name:str = ''
    www_a_ip:str = ''
    www_a_ptr:str = ''
    www_a_server:str = ''
    www_a_is_accessible_http: bool = False
    www_a_is_accessible_https: bool = False
    www_a_is_included_spf: bool = False
    
    # http アクセス（a or www で どれかがアクセスできれば True）
    is_accessible_http: bool = False

    # MXレコード
    mx_server_name:str = ''
    mx:list[str] = []
    mx_ip:str = ''
    mx_ptr:str = ''
    mx_server:str = ''
    mx_is_included_spf: bool = False
    
    # HINFOレコード
    hinfo:list[str] = []

    # TXTレコード
    txt:list[str] = []
    spf:list[str] = []

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
            self.ns_name, self.ns = self.__getNsInfo(name=self.name)
            
            # Aレコード
            (
                self.a_server_name,
                self.a_ip,
                self.a_ptr,
                self.a_server,
            ) = self.__getAInfo(name=self.name)
            (
                self.a_is_accessible_http,
                self.a_is_accessible_https,
            ) = self.__isAccessibleHttp(name=self.name)
            self.a_is_included_spf = self.__check_spf(self.name, self.a_ip)
            
            # www.Aレコード
            (
                self.www_a_server_name,
                self.www_a_ip, 
                self.www_a_ptr, 
                self.www_a_server, 
            ) = self.__getAInfo(name=self.wwwName)
            (
                self.www_a_is_accessible_http,
                self.www_a_is_accessible_https,
            ) = self.__isAccessibleHttp(name=self.wwwName)
            self.www_a_is_included_spf = self.__check_spf(self.name, self.www_a_ip)

            # is_accessible_http
            self.is_accessible_http = (
                self.a_is_accessible_http or
                self.a_is_accessible_https or
                self.www_a_is_accessible_http or
                self.www_a_is_accessible_https
            )

            # MXレコード
            (
                self.mx_server_name,
                self.mx,
                self.mx_ip,
                self.mx_ptr,
                self.mx_server,
            ) = self.__getMxInfo(name=self.name)
            self.mx_is_included_spf = self.__check_spf(self.name, self.mx_ip)

            # HINFOレコード
            (
                self.hinfo,
                self.a_server,
                self.a_server_name,
                self.mx_server,
                self.mx_server_name
            ) = self.__getHinfo(name=self.name)

            # TXTレコード, SPFレコード
            self.txt = self.__getTxt(name=self.name)
            self.spf = self.__getSpf(txts=self.txt)

            self.__check_spf(self.spf, self.a_ip)

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


    def __getNs(self, name:str) -> list[str]:
        ns = []
        try:
            # NSレコードを取得してNSレコードの値でソート
            ns:list[str] = sorted([
                ns.to_text() for ns in dns.resolver.query(name, 'NS')
            ])
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get NS record for {name} ({e})")
        
        return ns
    
    def __getA(self, name:str) -> str:
        ip = ''
        try:
            ip  = dns.resolver.query(name, 'A')[0].address
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return ip
    
    def __getMx(self, name:str) -> list[str]:
        mxs = []
        try:
            mxs = sorted(
                dns.resolver.query(name, 'MX'),
                key=lambda mx: (mx.preference, mx.exchange)
            )
            mxs = [mx.exchange.to_text() for mx in mxs]
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return mxs
    
    def __getPtr(self, ip:str) -> str:
        ptr = ''
        try:
            ptr = dns.resolver.query(
                dns.reversename.from_address(ip),
                'PTR'
            )[0].to_text()
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {ip} ({e})")
        
        return ptr
    
    def __getTxt(self, name:str) -> list[str]:
        txts:list[str] = []

        try:
            # TXTレコードを取得して spf の文字列を含むものを抽出
            for txt in dns.resolver.query(name, 'TXT'):
                txts.extend(re.findall(r'"([^"]+)"', txt.to_text()))
            
        except Exception as e:
            if self.__is_debug:
                print(f"NOTICE: Failed to get record for {name} ({e})")
        
        return txts
    

    def __getNsInfo(self, name:str) -> tuple[str, list[str]]:
        """
        ドメイン名からNSレコードを取得する

        Args:
            name: ドメイン名

        Returns:
            NSレコード, NSレコードのサーバ名
        """
        ns = self.__getNs(name=name)
        nsServerName = ""
        if ns:
            nsServerName = "設定なし"
            for name, providers in self.__servers_info['name_servers'].items():
                if ns[0] in providers:
                    nsServerName = name
                    break

        return nsServerName, ns
        
    def __getAInfo(self, name:str) -> tuple[str, str, str, str]:
        """
        ドメイン名からIPアドレス(Aレコード)、PTRレコード、サーバ、サーバ名称を取得する

        Args:
            name: ドメイン名
        
        Returns:
            IPアドレス, PTRレコード, サーバ, サーバ名称
        """
        ip = self.__getA(name=name)
        server_name, ptr, server  = '', '', ''
        if ip:
            ptr = self.__getPtr(ip=ip)
            server = ptr
        if ptr:
            server_name = '設定なし'
            for name, patterns in self.__servers_info['web_servers'].items():
                for pattern in patterns:
                    if re.match(pattern, ptr):
                        server_name = name
                        break
        
        return server_name, ip, ptr, server

        
    def __getMxInfo(self, name:str) -> tuple[list[str], str, str, str, str]:
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
            mxs = self.__getMx(name=name)

            if len(mxs) > 0:
                mx_ip  = self.__getA(name=mxs[0])
            if mx_ip:
                mx_ptr = self.__getPtr(ip=mx_ip)
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

        return mx_server_name, mxs, mx_ip, mx_ptr, mx_server
    
    
    def __getSpf(self, txts:list[str]) -> list[str]:
        spfs:list[str] = []
        
        for txt in txts:
            if any(value in txt for value in [
                'spf', 'a:', 'mx:', 'ip4:', 'ip6:', 'include:'
            ]):
                spfs.append(txt)
            
        return spfs
    

    def __get_spf_mechanisms(self, name:str) -> tuple[list[str], list[dict]]:
        spf_mechanism_patterns = {
            "a"        : r"\ba\b",
            "+a"       : r"\+\b(a?!\:)",
            "mx"       : r"\bmx\b",
            "+mx"      : r"\+\b(mx?!\:)",
            "a:"       : r"\ba:([\w\.\-]+)",
            "+a:"      : r"\+a:([\w\.\-]+)",
            "ip4:"     : r"\bip4:([\d\.\/]+)",
            "+ip4:"    : r"\bip4:([\d\.\/]+)",
            "ip6:"     : r"\bip6:([0-9a-fA-F:\.\/]+)",
            "+ip6:"    : r"\bip6:([0-9a-fA-F:\.\/]+)",
            "include:" : r"\binclude:([\w\.\-]+)",
            "+include:": r"\+include:([\w\.\-]+)",
        }

        # spf レコードの取得
        txts = self.__getTxt(name)
        spfs = self.__getSpf(txts)

        spf_mechanisms = [] # spf の構造を保存しておく
        spf_ips = [] # ipアドレスの評価に利用する
        
        for spf in spfs:
            # spf レコードのループ
            for key, pattern in spf_mechanism_patterns.items():
                # 取得するパターンをループして一致するものを抽出

                matches = re.findall(pattern, spf)
                if not matches: continue # 一致するものがなければスキップ
                 
                for match in matches:
                    # 抽出されたものをループ
                    if key in ["include:", "+include:"]:
                        # include があれば再帰的に処理する
                        _spf_mechanisms, _spf_ips = self.__get_spf_mechanisms(match)
                        
                        spf_mechanisms.append(
                            {
                                "mechanism": key,
                                "value": match,
                                "include": _spf_mechanisms,
                            }
                        )
                        spf_ips.extend(_spf_ips)
                    else:
                        ip = ""
                        if key in ["a", "+a"]:
                            ip = self.__getA(name=name)
                        if key in ["a:", "+a:"]:
                            ip = self.__getA(name=match)
                        if key in ["mx", "+mx"]:
                            mx = self.__getMx(name=match)
                            if mx:
                                ip = self.__getA(name=mx[0])
                        if key in ["ip4:", "+ip4:"]:
                            ip = match
                        if key in ["ip6:", "+ip6:"]:
                            pass #今は処理を考慮しない

                        spf_mechanisms.append(
                            {
                                "mechanism": key,
                                "value": match,
                            }
                        )
                        spf_ips.append(
                            {
                                "mechanism": key,
                                "value": match,
                                "ip": ip,    
                            }
                        )

        return spf_mechanisms, spf_ips
    
    def __check_spf(self, name:str, ip:str):
        try:
            if ip: 
                _, spf_ips = self.__get_spf_mechanisms(name)
                for spf_ip in spf_ips:
                    if spf_ip['ip']:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(spf_ip['ip']):
                            return True
        except Exception as e:
            #if self.__is_debug:
            print(f"ERROR: Failed to check SPF for {ip} at {name} ({e})")

        return False

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

        # TXTレコードを取得して spf の文字列を含むものを抽出
        try:
            dmarc = self.__getTxt(f'_dmarc.{name}')[0]
            dmarc_p = re.search(r'p=([^;]+)', dmarc).group(1)
            dmarc_rua = re.search(r'rua=mailto:([^;]+)', dmarc).group(1)
        except:
            pass

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