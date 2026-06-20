using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("authorize")]
public sealed class AuthorizeController : ControllerBase
{
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

            AuthorizationRequestRecord request = _store.CreateRequest(clientId, redirectUri, scope, state, nonce, codeChallenge);
            Response.Cookies.Append("AuthRequestId", request.RequestId, new CookieOptions
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

    private static void RequireRegisteredClient(string clientId, string redirectUri)
    {
        if (!AppConfig.IsOidcClientRedirectUriAllowed(clientId, redirectUri))
        {
            throw Code.ILLEGAL_CLIENT;
        }
    }
}
