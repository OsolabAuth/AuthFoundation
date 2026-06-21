using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("login")]
public sealed class LoginController : ControllerBase
{
    private const string AuthRequestCookieName = "AuthRequestId";
    private const string AuthSessionCookieName = "AuthSessionId";
    private readonly IOidcStore _store;
    private readonly IUserStore _users;

    public LoginController(IOidcStore store, IUserStore users)
    {
        _store = store;
        _users = users;
    }

    [HttpPost]
    public async Task<IActionResult> Post()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string email = form["email"].ToString();
            string password = form["password"].ToString();
            ValidateUtil.FormatParam(email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.IndispensableParam(password, Code.HttpBodies.PASSWORD.Key);

            UserRecord user = _users.Authenticate(email, password);

            string requestId = form["request_id"].ToString();
            if (string.IsNullOrWhiteSpace(requestId))
            {
                requestId = Request.Cookies[AuthRequestCookieName] ?? string.Empty;
            }

            ValidateUtil.IndispensableParam(requestId, "request_id");
            AuthorizationRequestRecord request = _store.TakeRequest(requestId);
            AuthSessionRecord session = _store.CreateAuthSession(user.Subject, user.Email, user.Name);
            Response.Cookies.Append(AuthSessionCookieName, session.SessionId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = Request.IsHttps,
                Expires = session.ExpiresAt,
                MaxAge = session.ExpiresAt - DateTimeOffset.UtcNow
            });
            Response.Cookies.Delete(AuthRequestCookieName);

            AuthorizationCodeRecord code = _store.CreateCode(
                request,
                user.Subject,
                user.Email,
                user.Name);

            string separator = request.RedirectUri.Contains('?') ? "&" : "?";
            string redirectUrl = $"{request.RedirectUri}{separator}code={Uri.EscapeDataString(code.Code)}&state={Uri.EscapeDataString(request.State)}";
            Response.Headers.Location = redirectUrl;
            return Ok(new { result = "redirect", redirect_url = redirectUrl, authorization_code = code.Code });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
