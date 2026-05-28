using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("userinfo")]
public sealed class UserInfoController : ControllerBase
{
    private readonly InMemoryOidcStore _store;

    public UserInfoController(InMemoryOidcStore store)
    {
        _store = store;
    }

    [HttpGet]
    public IActionResult Get()
    {
        try
        {
            AccessTokenRecord token = _store.FindAccessToken(ReadBearerToken());
            return Ok(new
            {
                sub = token.Subject,
                email = token.Email,
                name = token.Name
            });
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
}
