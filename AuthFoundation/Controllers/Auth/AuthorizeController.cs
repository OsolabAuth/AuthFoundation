using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("authorize")]
public sealed class AuthorizeController : ControllerBase
{
    private const string AuthRequestCookieName = "AuthRequestId";
    private const string AuthSessionCookieName = "AuthSessionId";
    private const string TaigaClientId = "30000000000000000000000000000028";
    private const string TaigaRedirectUri = "https://taiga.osolab.jp/oidc/callback";
    private readonly IOidcStore _store;

    public AuthorizeController(IOidcStore store)
    {
        _store = store;
    }

    [HttpGet]
    public IActionResult Get()
    {
        try
        {
            RequiredQuery(Code.HttpQueries.RESPONSE_TYPE);
            string clientId = RequiredQuery(Code.HttpQueries.CLIENT_ID);
            string redirectUri = RequiredQuery(Code.HttpQueries.REDIRECT_URI);
            string scope = RequiredQuery(Code.HttpQueries.SCOPE);
            string state = RequiredQuery(Code.HttpQueries.STATE);
            string nonce = RequiredQuery(Code.HttpQueries.NONCE);
            RequiredQuery(Code.HttpQueries.CODE_CHALLENGE_METHOD);
            string codeChallenge = RequiredQuery(Code.HttpQueries.CODE_CHALLENGE);

            RequireRegisteredClient(clientId, redirectUri);
            string[] scopes = Helper.ParseScopes(scope);
            if (!scopes.Contains(Code.Scope.OPENID, StringComparer.Ordinal))
            {
                throw Code.INVALID_SCOPE;
            }

            AuthSessionRecord? authSession = FindAuthSession();
            if (authSession is not null)
            {
                var ssoRequest = new AuthorizationRequestRecord(
                    string.Empty,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    nonce,
                    codeChallenge,
                    DateTimeOffset.UtcNow.AddMinutes(5));
                AuthorizationCodeRecord code = _store.CreateCode(
                    ssoRequest,
                    authSession.Subject,
                    authSession.Email,
                    authSession.Name);
                string ssoRedirectUrl = BuildRedirectUrl(ssoRequest.RedirectUri, code.Code, ssoRequest.State);

                if (Request.Headers.TryGetValue("x-auth-ui-response-mode", out var responseMode)
                    && string.Equals(responseMode.ToString(), "json", StringComparison.OrdinalIgnoreCase))
                {
                    return Ok(new { result = "redirect", redirect_url = ssoRedirectUrl, authorization_code = code.Code });
                }

                return Redirect(ssoRedirectUrl);
            }

            AuthorizationRequestRecord request = _store.CreateRequest(clientId, redirectUri, scope, state, nonce, codeChallenge);
            Response.Cookies.Append(AuthRequestCookieName, request.RequestId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = Request.IsHttps
            });

            string redirectUrl = $"{AppConfig.AuthUiBaseUrl}/login";
            if (Request.Headers.TryGetValue("x-auth-ui-response-mode", out var mode)
                && string.Equals(mode.ToString(), "json", StringComparison.OrdinalIgnoreCase))
            {
                return Ok(new { redirect_url = redirectUrl });
            }

            return Redirect(redirectUrl);
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    private string RequiredQuery(Code.RequestValidation validation)
    {
        string value = Request.Query[validation.Key].ToString();
        ValidateUtil.FormatParam(value, validation.Key, validation.Regex);
        return value;
    }

    private AuthSessionRecord? FindAuthSession()
    {
        string? sessionId = Request.Cookies[AuthSessionCookieName];
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return null;
        }

        AuthSessionRecord? session = _store.FindAuthSession(sessionId);
        if (session is null)
        {
            Response.Cookies.Delete(AuthSessionCookieName);
        }

        return session;
    }

    private static string BuildRedirectUrl(string redirectUri, string code, string state)
    {
        string separator = redirectUri.Contains('?') ? "&" : "?";
        return $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
    }

    private static void RequireRegisteredClient(string clientId, string redirectUri)
    {
        if (string.Equals(clientId, AppConfig.DevelopmentClientId, StringComparison.Ordinal)
            && string.Equals(redirectUri, AppConfig.DevelopmentRedirectUri, StringComparison.Ordinal))
        {
            return;
        }

        if (string.Equals(clientId, TaigaClientId, StringComparison.Ordinal)
            && string.Equals(redirectUri, TaigaRedirectUri, StringComparison.Ordinal))
        {
            return;
        }

        throw Code.ILLEGAL_CLIENT;
    }
}
