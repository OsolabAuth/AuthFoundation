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
    /// <summary>
    /// 前提条件
    /// 　DB：テスト実行前の初期データを投入可能
    /// 　リクエスト：なし（テスト初期化処理）
    /// 期待値
    /// 　共通設定とテスト実行環境が初期化される
    /// </summary>
    /// <returns></returns>
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Register Auth Request Session を 標準入力 条件で実行
    /// 期待値
    /// 　Generates Session Id And Writes Redis Value を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Auth Session を Set Value 条件で実行
    /// 期待値
    /// 　Restores Properties And Marks Has Value を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Cookie Session Id を 標準入力 条件で実行
    /// 期待値
    /// 　Prefers Auth Session Id And Falls Back To Session Id を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Append Cookie を 標準入力 条件で実行
    /// 期待値
    /// 　Writes Auth Session And Compatibility Cookie を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Session Id を 標準入力 条件で実行
    /// 期待値
    /// 　Prefers Auth Request Cookie And Falls Back To Session Id を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Build Session Cookie Options を Cross Origin Https 条件で実行
    /// 期待値
    /// 　Uses Same Site None And Secure を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void BuildSessionCookieOptions_CrossOriginHttps_UsesSameSiteNoneAndSecure()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("auth.osolab-auth.jp");
        context.Request.Headers.Origin = "https://portal.osolab-auth.jp";
        context.Request.Headers["X-Forwarded-Proto"] = "https";

        CookieOptions options = Helper.BuildSessionCookieOptions(context.Request, 300);

        Assert.AreEqual(SameSiteMode.None, options.SameSite);
        Assert.IsTrue(options.Secure);
        Assert.IsTrue(options.HttpOnly);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Build Session Cookie Options を Same Origin 条件で実行
    /// 期待値
    /// 　Uses Same Site Lax を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void BuildSessionCookieOptions_SameOrigin_UsesSameSiteLax()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("auth.osolab-auth.jp");
        context.Request.Headers.Origin = "https://auth.osolab-auth.jp";
        context.Request.Headers["X-Forwarded-Proto"] = "https";

        CookieOptions options = Helper.BuildSessionCookieOptions(context.Request, 300);

        Assert.AreEqual(SameSiteMode.Lax, options.SameSite);
        Assert.IsTrue(options.Secure);
        Assert.IsTrue(options.HttpOnly);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Auth Code Session を Set Value 条件で実行
    /// 期待値
    /// 　Restores Serialized Payload を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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

