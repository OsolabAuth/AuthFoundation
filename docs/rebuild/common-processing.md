# 共通処理系 移植設計

## 目的

AuthFoundation の各機能を小さいPRで移植できるように、先に最小のアプリ基盤と共通部品を用意する。

この段階では OIDC の業務機能は実装しない。APIの起動、共通エラー形式、入力検証、設定読み込み、最低限のテスト導線だけを対象にする。

## 対象

- ASP.NET Core Web API skeleton
- 共通エラー応答
- 入力検証 helper
- JSON console logging
- `/version` health endpoint
- 単体テスト project

## 非対象

- DB / Redis 接続
- `/authorize`
- `/login`
- `/token`
- `/userinfo`
- JWKS / 署名鍵管理
- signup / terms / MFA

## 完了条件

- `dotnet build` が通る。
- 共通 helper の単体テストを追加できる構成になっている。
- 後続PRがこのブランチをbaseにして機能移植できる。
