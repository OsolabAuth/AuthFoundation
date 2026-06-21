using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("logout")]
public sealed class LogoutController : ControllerBase
{
    private const string AuthRequestCookieName = "AuthRequestId";
    private const string AuthSessionCookieName = "AuthSessionId";
    private readonly IOidcStore _store;

    public LogoutController(IOidcStore store)
    {
        _store = store;
    }

    [HttpPost]
    public IActionResult Post()
    {
        string? sessionId = Request.Cookies[AuthSessionCookieName];
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            _store.RevokeAuthSession(sessionId);
        }

        Response.Cookies.Delete(AuthRequestCookieName);
        Response.Cookies.Delete(AuthSessionCookieName);
        return Ok(new { result = "logged_out" });
    }
}
