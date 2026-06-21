using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthorizationCodeFlowEndpointShapeTests
{
    private const string LoginEmail = "login-flow@example.com";
    private const string LoginPassword = "Passw0rd!";

    /// <summary>
    /// 目的: Authorize / Returns Json Login Redirect And Request Cookie の仕様を検証する。
    /// 入力値: Authorize / Returns Json Login Redirect And Request Cookie を確認するためにテスト内で作成したデータ。
    /// 期待値: Authorize / Returns Json Login Redirect And Request Cookie の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Authorize_ReturnsJsonLoginRedirectAndRequestCookie()
    {
        var store = new InMemoryOidcStore();
        var controller = CreateAuthorizeController(store);
        AddAuthorizeQuery(controller.HttpContext, AppConfig.DevelopmentClientId, AppConfig.DevelopmentRedirectUri);
        controller.Request.Headers["x-auth-ui-response-mode"] = "json";

        IActionResult action = controller.Get();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual($"{AppConfig.AuthUiBaseUrl}/login", ReadProperty<string>(ok.Value, "redirect_url"));
        Assert.IsTrue(controller.Response.Headers.SetCookie.ToString().Contains("AuthRequestId=", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that a valid AuthSessionId cookie lets authorize issue an authorization code without showing the login page.
    /// </summary>
    [TestMethod]
    public void Authorize_ReturnsCodeRedirectWhenAuthSessionCookieIsValid()
    {
        var store = new InMemoryOidcStore();
        AuthSessionRecord session = store.CreateAuthSession("subject_1", LoginEmail, "Login User");
        var controller = CreateAuthorizeController(store);
        AddAuthorizeQuery(controller.HttpContext, AppConfig.DevelopmentClientId, AppConfig.DevelopmentRedirectUri);
        controller.Request.Headers["x-auth-ui-response-mode"] = "json";
        controller.Request.Headers.Cookie = $"AuthSessionId={session.SessionId}";

        IActionResult action = controller.Get();

        var ok = AssertOk(action);
        Assert.AreEqual("redirect", ReadProperty<string>(ok.Value, "result"));
        string redirectUrl = ReadProperty<string>(ok.Value, "redirect_url");
        string authorizationCode = ReadProperty<string>(ok.Value, "authorization_code");
        Assert.IsFalse(string.IsNullOrWhiteSpace(authorizationCode));
        Assert.IsTrue(redirectUrl.StartsWith($"{AppConfig.DevelopmentRedirectUri}?code=", StringComparison.Ordinal));
        Assert.IsTrue(redirectUrl.Contains($"code={authorizationCode}", StringComparison.Ordinal));
        Assert.IsTrue(redirectUrl.Contains("&state=state_1", StringComparison.Ordinal));
        Assert.IsFalse(controller.Response.Headers.SetCookie.ToString().Contains("AuthRequestId=", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Authorize / Returns Invalid Client For Unknown Client の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: invalid_client のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Authorize_ReturnsInvalidClientForUnknownClient()
    {
        var controller = CreateAuthorizeController(new InMemoryOidcStore());
        AddAuthorizeQuery(controller.HttpContext, "99999999999999999999999999999999", AppConfig.DevelopmentRedirectUri);

        IActionResult action = controller.Get();

        var error = AssertError(action, 400);
        Assert.AreEqual("00002", error.ResponseCode);
        Assert.AreEqual("00002", error.ErrorCode);
        Assert.AreEqual("illegal client", error.Message);
        Assert.AreEqual("invalid_client", error.Error);
        Assert.AreEqual("illegal client", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Authorize / Redirects To Login When Json Mode Is Not Requested の仕様を検証する。
    /// 入力値: Authorize / Redirects To Login When Json Mode Is Not Requested を確認するためにテスト内で作成したデータ。
    /// 期待値: Authorize / Redirects To Login When Json Mode Is Not Requested の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Authorize_RedirectsToLoginWhenJsonModeIsNotRequested()
    {
        var controller = CreateAuthorizeController(new InMemoryOidcStore());
        AddAuthorizeQuery(controller.HttpContext, AppConfig.DevelopmentClientId, AppConfig.DevelopmentRedirectUri);

        IActionResult action = controller.Get();

        var redirect = action as RedirectResult;
        Assert.IsNotNull(redirect);
        Assert.AreEqual($"{AppConfig.AuthUiBaseUrl}/login", redirect.Url);
    }

    /// <summary>
    /// 目的: Authorize / Returns Invalid Scope When Open Id Is Missing の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_scope のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Authorize_ReturnsInvalidScopeWhenOpenIdIsMissing()
    {
        var controller = CreateAuthorizeController(new InMemoryOidcStore());
        AddAuthorizeQuery(
            controller.HttpContext,
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            scope: "profile email");

        IActionResult action = controller.Get();

        var error = AssertError(action, 400);
        Assert.AreEqual("00009", error.ResponseCode);
        Assert.AreEqual("00009", error.ErrorCode);
        Assert.AreEqual("invalid scope", error.Message);
        Assert.AreEqual("invalid_scope", error.Error);
        Assert.AreEqual("invalid scope", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Login / Returns Authorization Code Redirect Url の仕様を検証する。
    /// 入力値: Login / Returns Authorization Code Redirect Url を確認するためにテスト内で作成したデータ。
    /// 期待値: Login / Returns Authorization Code Redirect Url の期待結果になること。
    /// </summary>
    [TestMethod]
    public async Task Login_ReturnsAuthorizationCodeRedirectUrl()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
        var users = CreateLoginUsers();
        var controller = CreateLoginController(store, users);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = LoginEmail,
            ["password"] = LoginPassword,
            ["request_id"] = request.RequestId
        });

        IActionResult action = await controller.Post();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("redirect", ReadProperty<string>(ok.Value, "result"));
        string redirectUrl = ReadProperty<string>(ok.Value, "redirect_url");
        string authorizationCode = ReadProperty<string>(ok.Value, "authorization_code");
        Assert.IsFalse(string.IsNullOrWhiteSpace(authorizationCode));
        Assert.IsTrue(redirectUrl.StartsWith($"{AppConfig.DevelopmentRedirectUri}?code=", StringComparison.Ordinal));
        Assert.IsTrue(redirectUrl.Contains($"code={authorizationCode}", StringComparison.Ordinal));
        Assert.IsTrue(redirectUrl.Contains("&state=state_1", StringComparison.Ordinal));
        Assert.AreEqual(redirectUrl, controller.Response.Headers.Location.ToString());
        Assert.IsTrue(controller.Response.Headers.SetCookie.ToString().Contains("AuthSessionId=", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Login / Returns Unauthorized For Invalid Password の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Login_ReturnsUnauthorizedForInvalidPassword()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
        var users = CreateLoginUsers();
        var controller = CreateLoginController(store, users);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = LoginEmail,
            ["password"] = "WrongPassw0rd!",
            ["request_id"] = request.RequestId
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 401);
        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("00008", error.ErrorCode);
        Assert.AreEqual("unauthorized", error.Message);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("unauthorized", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Login / Returns Unauthorized For Unknown Email の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Login_ReturnsUnauthorizedForUnknownEmail()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
        var controller = CreateLoginController(store, new InMemoryUserStore());
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "other@example.com",
            ["password"] = LoginPassword,
            ["request_id"] = request.RequestId
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 401);
        Assert.AreEqual("00008", error.ResponseCode);
    }

    /// <summary>
    /// 目的: Login / Uses Request Cookie When Form Request Id Is Missing の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: Login / Uses Request Cookie When Form Request Id Is Missing の期待結果になること。
    /// </summary>
    [TestMethod]
    public async Task Login_UsesRequestCookieWhenFormRequestIdIsMissing()
    {
        var store = new InMemoryOidcStore();
        string redirectUri = $"{AppConfig.DevelopmentRedirectUri}?source=test";
        AuthorizationRequestRecord request = store.CreateRequest(
            AppConfig.DevelopmentClientId,
            redirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
        var users = CreateLoginUsers();
        var controller = CreateLoginController(store, users);
        controller.Request.Headers.Cookie = $"AuthRequestId={request.RequestId}";
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = LoginEmail,
            ["password"] = LoginPassword
        });

        IActionResult action = await controller.Post();

        var ok = AssertOk(action);
        string redirectUrl = ReadProperty<string>(ok.Value, "redirect_url");
        Assert.IsTrue(redirectUrl.StartsWith($"{redirectUri}&code=", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Login / Returns Bad Request When Request Id Is Missing の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Login_ReturnsBadRequestWhenRequestIdIsMissing()
    {
        var controller = CreateLoginController(new InMemoryOidcStore(), CreateLoginUsers());
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = LoginEmail,
            ["password"] = LoginPassword
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("request_id is required", error.Message);
    }

    /// <summary>
    /// 目的: Login / Returns Bad Request For Invalid Email の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Login_ReturnsBadRequestForInvalidEmail()
    {
        var controller = CreateLoginController(new InMemoryOidcStore(), new InMemoryUserStore());
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "invalid",
            ["password"] = LoginPassword,
            ["request_id"] = "req_1"
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("email is invalid", error.Message);
    }

    /// <summary>
    /// 目的: Token / Returns Bearer Tokens For Valid Code And Verifier の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsBearerTokensForValidCodeAndVerifier()
    {
        var store = new InMemoryOidcStore();
        const string verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
        AuthorizationCodeRecord code = CreateAuthorizationCode(store, verifier);
        var controller = CreateTokenController(store);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = code.ClientId,
            ["code"] = code.Code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = code.RedirectUri
        });

        IActionResult action = await controller.Post();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        var response = ok.Value as TokenResponse;
        Assert.IsNotNull(response);
        Assert.IsTrue(response.access_token.StartsWith("dev_", StringComparison.Ordinal));
        Assert.AreEqual("Bearer", response.token_type);
        Assert.AreEqual(900, response.expires_in);
        Assert.AreEqual("openid profile email", response.scope);
        Assert.AreEqual(3, response.id_token.Split('.').Length);
    }

    /// <summary>
    /// 目的: Token / Returns Invalid Grant And No Store For Bad Verifier の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_grant のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsInvalidGrantAndNoStoreForBadVerifier()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateAuthorizationCode(store, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
        var controller = CreateTokenController(store);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = code.ClientId,
            ["code"] = code.Code,
            ["code_verifier"] = "badabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO",
            ["redirect_uri"] = code.RedirectUri
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("00001", error.ErrorCode);
        Assert.AreEqual("invalid token request", error.Message);
        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid token request", error.ErrorDescription);
        Assert.AreEqual("no-store", controller.Response.Headers.CacheControl.ToString());
        Assert.AreEqual("no-cache", controller.Response.Headers.Pragma.ToString());
    }

    /// <summary>
    /// 目的: Token / Returns Bad Request For Unsupported Grant Type の仕様を検証する。
    /// 入力値: Token / Returns Bad Request For Unsupported Grant Type を確認するためにテスト内で作成したデータ。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsBadRequestForUnsupportedGrantType()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateAuthorizationCode(store, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
        var controller = CreateTokenController(store);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = code.ClientId,
            ["code"] = code.Code,
            ["code_verifier"] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            ["redirect_uri"] = code.RedirectUri
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("no-store", controller.Response.Headers.CacheControl.ToString());
        Assert.AreEqual("no-cache", controller.Response.Headers.Pragma.ToString());
    }

    /// <summary>
    /// 目的: Token / Returns Invalid Grant For Client Mismatch の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_grant のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsInvalidGrantForClientMismatch()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateAuthorizationCode(store, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
        var controller = CreateTokenController(store);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "11111111111111111111111111111111",
            ["code"] = code.Code,
            ["code_verifier"] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            ["redirect_uri"] = code.RedirectUri
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid token request", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Token / Returns Invalid Grant For Redirect Uri Mismatch の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_grant のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsInvalidGrantForRedirectUriMismatch()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateAuthorizationCode(store, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
        var controller = CreateTokenController(store);
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = code.ClientId,
            ["code"] = code.Code,
            ["code_verifier"] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            ["redirect_uri"] = "http://localhost:5700/other"
        });

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid token request", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Token / Returns Bad Request For Missing Grant Type の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Token_ReturnsBadRequestForMissingGrantType()
    {
        var controller = CreateTokenController(new InMemoryOidcStore());
        SetForm(controller.HttpContext, new Dictionary<string, StringValues>());

        IActionResult action = await controller.Post();

        var error = AssertError(action, 400);
        Assert.AreEqual("grant_type is required", error.Message);
    }

    private static AuthorizeController CreateAuthorizeController(InMemoryOidcStore store)
    {
        return new AuthorizeController(store)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }

    private static LoginController CreateLoginController(InMemoryOidcStore store, InMemoryUserStore users)
    {
        return new LoginController(store, users)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }

    private static InMemoryUserStore CreateLoginUsers()
    {
        var users = new InMemoryUserStore();
        users.CreateUser(LoginEmail, LoginPassword, "Login User", new DateOnly(2000, 1, 1), "login_user");
        return users;
    }

    private static TokenController CreateTokenController(InMemoryOidcStore store)
    {
        return new TokenController(store, TestSigningKeys.CreateTokenService(store))
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }

    private static AuthorizationCodeRecord CreateAuthorizationCode(InMemoryOidcStore store, string verifier)
    {
        AuthorizationRequestRecord request = store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge(verifier));
        return store.CreateCode(request, "subject_1", "subject@example.com", "Subject One");
    }

    private static void AddAuthorizeQuery(
        HttpContext context,
        string clientId,
        string redirectUri,
        string scope = "openid profile email")
    {
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = "state_1",
            ["nonce"] = "nonce_1",
            ["code_challenge_method"] = "S256",
            ["code_challenge"] = PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
        });
    }

    private static void SetForm(HttpContext context, Dictionary<string, StringValues> values)
    {
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(string.Empty));
        context.Features.Set<IFormFeature>(new FormFeature(new FormCollection(values)));
    }

    private static OkObjectResult AssertOk(IActionResult action)
    {
        var ok = action as OkObjectResult;
        Assert.IsNotNull(ok);
        Assert.IsNotNull(ok.Value);
        return ok;
    }

    private static ErrorOutput AssertError(IActionResult action, int statusCode)
    {
        var result = action as ObjectResult;
        Assert.IsNotNull(result);
        Assert.AreEqual(statusCode, result.StatusCode);
        var output = result.Value as ErrorOutput;
        Assert.IsNotNull(output);
        return output;
    }

    private static T ReadProperty<T>(object? target, string name)
    {
        Assert.IsNotNull(target);
        var property = target.GetType().GetProperty(name);
        Assert.IsNotNull(property);

        object? value = property.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
