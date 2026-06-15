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
    /// 逶ｮ逧・ Authorize / Returns Json Login Redirect And Request Cookie 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Authorize / Returns Json Login Redirect And Request Cookie 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Authorize / Returns Json Login Redirect And Request Cookie 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Authorize / Returns Invalid Client For Unknown Client 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: invalid_client 縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Authorize / Redirects To Login When Json Mode Is Not Requested 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Authorize / Redirects To Login When Json Mode Is Not Requested 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Authorize / Redirects To Login When Json Mode Is Not Requested 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Authorize / Returns Invalid Scope When Open Id Is Missing 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: invalid_scope 縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Login / Returns Authorization Code Redirect Url 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Login / Returns Authorization Code Redirect Url 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Login / Returns Authorization Code Redirect Url 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    }

    /// <summary>
    /// 逶ｮ逧・ Login / Returns Unauthorized For Invalid Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Login / Returns Unauthorized For Unknown Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Login / Uses Request Cookie When Form Request Id Is Missing 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: Login / Uses Request Cookie When Form Request Id Is Missing 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Login / Returns Bad Request When Request Id Is Missing 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Login / Returns Bad Request For Invalid Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Token / Returns Bearer Tokens For Valid Code And Verifier 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
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
        var response = ok.Value as TokenOutput;
        Assert.IsNotNull(response);
        Assert.IsTrue(response.access_token.StartsWith("dev_", StringComparison.Ordinal));
        Assert.AreEqual("Bearer", response.token_type);
        Assert.AreEqual(900, response.expires_in);
        Assert.AreEqual("openid profile email", response.scope);
        Assert.AreEqual(3, response.id_token.Split('.').Length);
    }

    /// <summary>
    /// 逶ｮ逧・ Token / Returns Invalid Grant And No Store For Bad Verifier 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: invalid_grant 縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Token / Returns Bad Request For Unsupported Grant Type 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Token / Returns Bad Request For Unsupported Grant Type 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Token / Returns Invalid Grant For Client Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: invalid_grant 縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Token / Returns Invalid Grant For Redirect Uri Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: invalid_grant 縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Token / Returns Bad Request For Missing Grant Type 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
