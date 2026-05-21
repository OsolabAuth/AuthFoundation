using AuthFoundation.Common;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

namespace AuthFoundationTest;

[TestClass]
public sealed class SessionTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: 認可セッション登録時に32桁session_idを生成し、Redis保存値へユーザーIDとscopeを保持すること。
    /// </summary>
    [TestMethod]
    public async Task RegisterAuthRequestSession_GeneratesSessionIdAndWritesRedisValue()
    {
        var redis = new FakeRedisClient();
        var session = new AuthRequestSession
        {
            ResponseType = "code",
            ClientId = "12345678901234567890123456789012",
            RedirectUri = "https://client.example.com/callback",
            State = "state-1",
            Scope = "openid email",
            CodeChallengeMethod = "S256",
            CodeChallenge = new string('a', 43),
            Nonce = "nonce-1"
        };

        string sessionId = await AuthorizeExecutionService.RegisterAuthRequestSession(redis, session, "user-1");
        string? raw = await redis.GetStringAsync(AuthRequestSession.GetRedisKey(sessionId));

        Assert.AreEqual(32, sessionId.Length);
        Assert.IsNotNull(raw);

        var saved = new AuthRequestSession();
        Assert.IsTrue(saved.SetValue(raw));
        Assert.AreEqual("user-1", saved.OsolabId);
        Assert.AreEqual("openid email", saved.Scope);
    }

    /// <summary>
    /// 検証項目: AuthSessionのJSON復元で主要プロパティとHasValueが復元されること。
    /// </summary>
    [TestMethod]
    public void AuthSession_SetValue_RestoresPropertiesAndMarksHasValue()
    {
        var source = new AuthSession("login-1", "user-1", "user@example.com", "client-1")
        {
            CreatedAt = "2026-01-01T00:00:00+09:00",
            ExpiresAt = "2026-01-02T00:00:00+09:00",
            LatestAuthAt = "2026-01-01T00:00:00+09:00"
        };

        var restored = new AuthSession();
        Assert.IsTrue(restored.SetValue(JsonConvert.SerializeObject(source)));

        Assert.IsTrue(restored.HasValue);
        Assert.AreEqual("login-1", restored.SessionId);
        Assert.AreEqual("user@example.com", restored.Email);
    }

    /// <summary>
    /// 検証項目: CookieからAuthSessionIdを優先取得し、互換session_idへフォールバックすること。
    /// </summary>
    [TestMethod]
    public void GetCookieSessionId_PrefersAuthSessionIdAndFallsBackToSessionId()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = "session_id=authz-1; AuthSessionId=login-1";

        Assert.AreEqual("login-1", AuthSession.GetCookieSessionId(context.Request));

        var fallbackContext = new DefaultHttpContext();
        fallbackContext.Request.Headers.Cookie = "session_id=authz-1";

        Assert.AreEqual("authz-1", AuthSession.GetCookieSessionId(fallbackContext.Request));
    }

    /// <summary>
    /// 検証項目: AuthSession Cookieと互換session_id Cookieがレスポンスへ設定されること。
    /// </summary>
    [TestMethod]
    public void AppendCookie_WritesAuthSessionAndCompatibilityCookie()
    {
        var context = new DefaultHttpContext();
        var session = new AuthSession("login-1", "user-1", "user@example.com", "client-1");

        session.AppendCookie(context.Response);

        string setCookie = string.Join("\n", context.Response.Headers.SetCookie.ToArray());
        StringAssert.Contains(setCookie, "AuthSessionId=login-1");
        StringAssert.Contains(setCookie, "session_id=login-1");
    }

    /// <summary>
    /// 検証項目: GetSessionIdがCookie読み取り時にAuthRequestSessionIdを優先し、互換session_idへフォールバックすること。
    /// </summary>
    [TestMethod]
    public void GetSessionId_PrefersAuthRequestCookieAndFallsBackToSessionId()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = "session_id=authz-legacy; AuthRequestSessionId=authz-new";
        var emptyForm = new FormCollection(new Dictionary<string, StringValues>());

        Assert.AreEqual("authz-new", Helper.GetSessionId(context.Request, emptyForm));

        var fallbackContext = new DefaultHttpContext();
        fallbackContext.Request.Headers.Cookie = "session_id=authz-legacy";
        Assert.AreEqual("authz-legacy", Helper.GetSessionId(fallbackContext.Request, emptyForm));
    }

    /// <summary>
    /// 検証項目: AuthCodeSessionのJSON復元とRedisキー生成が設計どおりであること。
    /// </summary>
    [TestMethod]
    public void AuthCodeSession_SetValue_RestoresSerializedPayload()
    {
        var source = new AuthCodeSession
        {
            Code = "code-1",
            OsolabId = "user-1",
            Email = "user@example.com",
            ClientId = "client-1",
            RedirectUri = "https://client.example.com/callback",
            Scope = "openid",
            CodeChallenge = new string('a', 43),
            CodeChallengeMethod = "S256",
            Nonce = "nonce-1",
            State = "state-1"
        };

        var restored = new AuthCodeSession();
        Assert.IsTrue(restored.SetValue(JsonConvert.SerializeObject(source)));

        Assert.AreEqual("code-1", restored.Code);
        Assert.AreEqual("user-1", restored.OsolabId);
        Assert.AreEqual("auth_code:code-1", AuthCodeSession.GetRedisKey("code-1"));
    }
}

