using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("login")]
public sealed class LoginController : ControllerBase
{
    private readonly InMemoryOidcStore _store;
    private readonly InMemoryUserStore _users;
    private readonly AuditLogService _auditLogs;

    public LoginController(InMemoryOidcStore store, InMemoryUserStore users, AuditLogService auditLogs)
    {
        _store = store;
        _users = users;
        _auditLogs = auditLogs;
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
                requestId = Request.Cookies["AuthRequestId"] ?? string.Empty;
            }

            ValidateUtil.IndispensableParam(requestId, "request_id");
            AuthorizationRequestRecord request = _store.TakeRequest(requestId);
            AuthorizationCodeRecord code = _store.CreateCode(
                request,
                user.Subject,
                user.Email,
                user.Name);
            _auditLogs.Record(
                "user.login",
                "success",
                user.Subject,
                "user",
                request.ClientId,
                request.Scope,
                Convert.ToString(HttpContext.Connection.RemoteIpAddress),
                Request.Headers.UserAgent.ToString());

            string separator = request.RedirectUri.Contains('?') ? "&" : "?";
            string redirectUrl = $"{request.RedirectUri}{separator}code={Uri.EscapeDataString(code.Code)}&state={Uri.EscapeDataString(request.State)}";
            Response.Headers.Location = redirectUrl;
            return Ok(new { result = "redirect", redirect_url = redirectUrl });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
