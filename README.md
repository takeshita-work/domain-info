# domain info

ドメインの DNS レコードから情報を取得する

## 開発環境
```
> python -V
Python 3.11.1
```

## プロジェクトの開始

- 新規（仮想環境の作成）
    ```
    > cd プロジェクトディレクトリ
    > python -m venv .venv
    ```

## 開発
- 仮想環境
  - 開始
    ```
    > .venv/Scripts/activate
    ```

  - 停止
    ```
    > deactivate
    ```

- pip モジュール
  
  - ファイルからすべてのモジュールのインストール
    ```
    > pip install -r requirements.txt
    ```
    ※ requirements.txt に必要なパッケージとバージョンを記載しておく

- テスト

  - すべて実行
    ```
    > ./scriptscripts/test.ps1
    ```
  
  - ファイルを指定して実行
    ```
    > ./scripts/test.ps1 [ファイルパ]
    ```

## 実行
- 1件のドメイン
  ```
  > ./scriptscripts/run.ps1 example.com
  ```

- 複数件のドメイン
  ```
  > ./scriptscripts/run.ps1 example.com example.jp
  ```

  ```
  > ./scriptscripts/run.ps1 "example.com
  example.jp"
  ```
  ※ スプレッドシートなど縦に並んだリストからコピーしたものは全体を "（ダブルクォーテーション）で囲む
