using AuthFoundation.Common;
using AuthFoundation.Contracts;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;

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
            var input = new AuthorizeRequest(
                RequiredQuery(Code.HttpQueries.RESPONSE_TYPE),
                RequiredQuery(Code.HttpQueries.CLIENT_ID),
                RequiredQuery(Code.HttpQueries.REDIRECT_URI),
                RequiredQuery(Code.HttpQueries.SCOPE),
                RequiredQuery(Code.HttpQueries.STATE),
                RequiredQuery(Code.HttpQueries.NONCE),
                RequiredQuery(Code.HttpQueries.CODE_CHALLENGE_METHOD),
                RequiredQuery(Code.HttpQueries.CODE_CHALLENGE));

            RequireDevelopmentClient(input.ClientId, input.RedirectUri);
            string[] scopes = Helper.ParseScopes(input.Scope);
            if (!scopes.Contains(Code.Scope.OPENID, StringComparer.Ordinal))
            {
                throw Code.INVALID_SCOPE;
            }

            AuthorizationRequestRecord request = _store.CreateRequest(
                input.ClientId,
                input.RedirectUri,
                input.Scope,
                input.State,
                input.Nonce,
                input.CodeChallenge);
            Response.Cookies.Append("AuthRequestId", request.RequestId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = ShouldUseSecureCookie(),
                Path = "/",
                Expires = request.ExpiresAt
            });

            string redirectUrl = $"{AppConfig.AuthUiBaseUrl}/login";
            if (Request.Headers.TryGetValue("x-auth-ui-response-mode", out var mode)
                && string.Equals(mode.ToString(), "json", StringComparison.OrdinalIgnoreCase))
            {
                return Ok(new RedirectOutput("redirect", redirectUrl));
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

    private static void RequireDevelopmentClient(string clientId, string redirectUri)
    {
        if (!string.Equals(clientId, AppConfig.DevelopmentClientId, StringComparison.Ordinal)
            || !string.Equals(redirectUri, AppConfig.DevelopmentRedirectUri, StringComparison.Ordinal))
        {
            throw Code.ILLEGAL_CLIENT;
        }
    }

    private bool ShouldUseSecureCookie()
    {
        if (Request.IsHttps)
        {
            return true;
        }

        IServiceProvider? services = HttpContext.RequestServices;
        if (services is null)
        {
            return true;
        }

        IHostEnvironment? environment = services.GetService<IHostEnvironment>();
        return environment is null || !environment.IsDevelopment();
    }
}
