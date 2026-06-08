using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("userinfo")]
public sealed class UserInfoController : ControllerBase
{
    private readonly IOidcStore _store;

    public UserInfoController(IOidcStore store)
    {
        _store = store;
    }

    [HttpGet]
    public IActionResult Get()
    {
        try
        {
            AccessTokenRecord token = _store.FindAccessToken(ReadBearerToken());
            if (!string.Equals(token.PrincipalType, "user", StringComparison.Ordinal)
                || !HasScope(token.Scope, "openid"))
            {
                throw Code.UNAUTHORIZED;
            }

            var claims = new Dictionary<string, string>
            {
                ["sub"] = token.Subject
            };

            if (HasScope(token.Scope, Code.Scope.EMAIL))
            {
                claims["email"] = token.Email;
            }

            if (HasScope(token.Scope, Code.Scope.PROFILE))
            {
                claims["name"] = token.Name;
            }

            return Ok(claims);
        }
        catch (ApiException ex)
        {
            Response.Headers.WWWAuthenticate = "Bearer";
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    private string ReadBearerToken()
    {
        string header = Request.Headers.Authorization.ToString();
        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw Code.UNAUTHORIZED;
        }

        string token = header[prefix.Length..].Trim();
        ValidateUtil.IndispensableParam(token, "access_token");
        return token;
    }

    private static bool HasScope(string scope, string requiredScope)
    {
        return scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, requiredScope, StringComparison.Ordinal));
    }
}
