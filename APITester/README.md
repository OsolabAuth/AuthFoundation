# API Tester Scenarios

Talend API Tester にインポートするためのシナリオJSONを配置する。

機能追加時は、AuthDoc の Sequence と同じ単位でシナリオを追加する。

## Files

- `AuthorizationCodeFlow.json`
- `MfaStepUp.json`
- `PasswordAccountFlow.json`
- `AgentDelegatedAuth.json`

## Response Reference

後続リクエストで前段レスポンスを使う場合は、API Tester の参照式を使う。

```text
${"AuthFoundation - AuthorizationCodeFlow"."01. Start authorize request"."response"."body"."response_code"}
```

