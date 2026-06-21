using System.Collections.Concurrent;
using System.Reflection;
using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryOidcStoreTests
{
    /// <summary>
    /// 目的: Take Request / Removes And Returns Known Request の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: 対象データを一度だけ取り出し、再利用を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeRequest_RemovesAndReturnsKnownRequest()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = CreateRequest(store);

        AuthorizationRequestRecord actual = store.TakeRequest(request.RequestId);

        Assert.AreEqual(request.RequestId, actual.RequestId);
        Assert.AreEqual(AppConfig.DevelopmentClientId, actual.ClientId);
        Assert.ThrowsExactly<ApiException>(() => store.TakeRequest(request.RequestId));
    }

    /// <summary>
    /// 目的: Take Request / Rejects Unknown Request の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeRequest_RejectsUnknownRequest()
    {
        var store = new InMemoryOidcStore();

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeRequest("missing"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Take Request / Rejects Expired Request の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeRequest_RejectsExpiredRequest()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = CreateRequest(store);
        Requests(store)[request.RequestId] = request with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeRequest(request.RequestId));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Take Code / Removes And Returns Known Code の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: 対象データを一度だけ取り出し、再利用を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeCode_RemovesAndReturnsKnownCode()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateCode(store);

        AuthorizationCodeRecord actual = store.TakeCode(code.Code);

        Assert.AreEqual(code.Code, actual.Code);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.ThrowsExactly<ApiException>(() => store.TakeCode(code.Code));
    }

    /// <summary>
    /// 目的: Take Code / Rejects Unknown Code の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeCode_RejectsUnknownCode()
    {
        var store = new InMemoryOidcStore();

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeCode("missing"));

        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid authorization code", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Take Code / Rejects Expired Code の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void TakeCode_RejectsExpiredCode()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateCode(store);
        Codes(store)[code.Code] = code with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeCode(code.Code));

        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid authorization code", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that an auth session can be created and read back for browser SSO.
    /// </summary>
    [TestMethod]
    public void FindAuthSession_ReturnsKnownSession()
    {
        var store = new InMemoryOidcStore();
        AuthSessionRecord session = store.CreateAuthSession("subject_1", "subject@example.com", "Subject One");

        AuthSessionRecord? actual = store.FindAuthSession(session.SessionId);

        Assert.IsNotNull(actual);
        Assert.AreEqual(session.SessionId, actual.SessionId);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.AreEqual("subject@example.com", actual.Email);
        Assert.AreEqual("Subject One", actual.Name);
    }

    /// <summary>
    /// Verifies that revoking an auth session prevents later SSO reuse.
    /// </summary>
    [TestMethod]
    public void RevokeAuthSession_RemovesKnownSession()
    {
        var store = new InMemoryOidcStore();
        AuthSessionRecord session = store.CreateAuthSession("subject_1", "subject@example.com", "Subject One");

        bool revoked = store.RevokeAuthSession(session.SessionId);

        Assert.IsTrue(revoked);
        Assert.IsNull(store.FindAuthSession(session.SessionId));
    }

    /// <summary>
    /// Verifies that expired auth sessions are ignored and removed from memory.
    /// </summary>
    [TestMethod]
    public void FindAuthSession_ReturnsNullForExpiredSession()
    {
        var store = new InMemoryOidcStore();
        AuthSessionRecord session = store.CreateAuthSession("subject_1", "subject@example.com", "Subject One");
        AuthSessions(store)[session.SessionId] = session with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        AuthSessionRecord? actual = store.FindAuthSession(session.SessionId);

        Assert.IsNull(actual);
        Assert.IsFalse(AuthSessions(store).ContainsKey(session.SessionId));
    }

    /// <summary>
    /// 目的: Find Access Token / Returns Known Access Token の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void FindAccessToken_ReturnsKnownAccessToken()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateCode(store);
        AccessTokenRecord token = store.CreateAccessToken(code);

        AccessTokenRecord actual = store.FindAccessToken(token.AccessToken);

        Assert.AreEqual(token.AccessToken, actual.AccessToken);
        Assert.AreEqual(AppConfig.DevelopmentClientId, actual.ClientId);
        Assert.AreEqual("openid profile email", actual.Scope);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.AreEqual("subject@example.com", actual.Email);
        Assert.AreEqual("Subject One", actual.Name);
        Assert.AreEqual("user", actual.PrincipalType);
        Assert.AreEqual(string.Empty, actual.OwnerSubject);
        Assert.AreEqual(string.Empty, actual.DelegationId);
    }

    /// <summary>
    /// 目的: Find Access Token / Rejects Unknown Access Token の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FindAccessToken_RejectsUnknownAccessToken()
    {
        var store = new InMemoryOidcStore();

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.FindAccessToken("missing"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Find Access Token / Rejects Expired Access Token の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FindAccessToken_RejectsExpiredAccessToken()
    {
        var store = new InMemoryOidcStore();
        AccessTokenRecord token = store.CreateAccessToken(CreateCode(store));
        AccessTokens(store)[token.AccessToken] = token with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.FindAccessToken(token.AccessToken));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    private static AuthorizationCodeRecord CreateCode(InMemoryOidcStore store)
    {
        return store.CreateCode(CreateRequest(store), "subject_1", "subject@example.com", "Subject One");
    }

    private static AuthorizationRequestRecord CreateRequest(InMemoryOidcStore store)
    {
        return store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
    }

    private static ConcurrentDictionary<string, AuthorizationRequestRecord> Requests(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AuthorizationRequestRecord>>(store, "_requests");
    }

    private static ConcurrentDictionary<string, AuthorizationCodeRecord> Codes(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AuthorizationCodeRecord>>(store, "_codes");
    }

    private static ConcurrentDictionary<string, AuthSessionRecord> AuthSessions(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AuthSessionRecord>>(store, "_authSessions");
    }

    private static ConcurrentDictionary<string, AccessTokenRecord> AccessTokens(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AccessTokenRecord>>(store, "_accessTokens");
    }

    private static T PrivateField<T>(object target, string name)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        object? value = field.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
