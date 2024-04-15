from domain import Domain
from tqdm import tqdm
from tabulate import tabulate

import pyperclip

import re

# パーサーの作成
import argparse
parser = argparse.ArgumentParser(
  prog='domainInfo',
  add_help=True,
  formatter_class=argparse.RawDescriptionHelpFormatter,
  description='Get domain information.'
)
parser.add_argument('domain_names',
    nargs='+',
    help='Enter domain names. '
)
parser.add_argument('--value-only',
    action='store_true',
    help='Return only values.'
)
parser.add_argument('--debug',
    action='store_true',
    help='Enable debug mode.'
)

if __name__ == "__main__":
    try:
        arsg = parser.parse_args()

        # 引数のドメイン名を区切り文字で分割
        domain_names:list[str] = []
        for domain_name in arsg.domain_names:
            domain_names.extend(
                filter(
                    None,
                    re.compile(r'[\s,　\t\r\n]+').split(domain_name) #区切り文字で分割
                ) # 空の文字列を除外
            ) 

        # # ドメイン名からドメイン情報を取得
        domains:list[Domain] = []
        domains_summary:list[dict] = []
        for domain_name in tqdm(domain_names):
            domain = Domain(domain_name, is_debug=arsg.debug)
            domains.append(domain)
            domains_summary.append(domain.summary())

        # サマリーの表示
        print("< SUMMARY >")
        print(tabulate(domains_summary, headers='keys'))
        print("")
        print("詳細な結果をクリップボードにコピーしました")

        # 結果を成形
        result:str = ''
        if domains:
            if not arsg.value_only:
                result = "\t".join(str(value) for value in domain.to_dict().keys()) + "\r\n"
            
            for domain in domains:
                resultOneline = "\t".join(str(value) for value in domain.to_dict().values())
                result += resultOneline + "\r\n"
        
        pyperclip.copy(result) # クリップボードにコピー

    except SystemExit:
        print("")
        parser.print_help()
    else:
        pass
    