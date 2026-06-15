# API Tester Scenarios

Talend API TesterにインポートするシナリオJSONを配置する。

機能追加時は、AuthDocのSequenceと同じ単位でシナリオを追加する。

## Files

- `AuthorizationCodeFlow.json`
- `MfaStepUp.json`
- `PasswordAccountFlow.json`
- `AgentDelegatedAuth.json`

## Response Reference

後続リクエストで前段レスポンスを使う場合は、API Testerの参照式を使う。

```text
${"AuthFoundation - AuthorizationCodeFlow"."02. Login for authorize session"."response"."body"."authorization_code"}
```
