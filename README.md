# AuthFoundation

OsolabAuth の OIDC / OAuth 認証基盤です。

この `main` ブランチは、既存実装を機能単位で移植し直すための最小起点です。
現行実装は `legacy/current` ブランチに保持しています。

## Rebuild Policy

移植は次の順で進めます。

1. 共通処理系
2. 最低限の Authorization Code + PKCE
3. OIDC Discovery / JWKS / UserInfo
4. 新規登録とプロフィール属性
5. 規約 / Scope 同意
6. ログアウト / トークン失効
7. 多要素認証と強化認可
8. パスワード変更 / パスワードリセット / 退会
9. AI Agent Delegated Auth

各機能は、設計書を先に追加し、その後で実装・テストを追加します。
