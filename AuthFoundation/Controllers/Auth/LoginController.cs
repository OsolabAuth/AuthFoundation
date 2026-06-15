using AuthFoundation.Common;
using AuthFoundation.Contracts;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("login")]
public sealed class LoginController : ControllerBase
{
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
            string requestId = form["request_id"].ToString();
            if (string.IsNullOrWhiteSpace(requestId))
            {
                requestId = Request.Cookies["AuthRequestId"] ?? string.Empty;
            }

            var input = new LoginRequest(
                form["email"].ToString(),
                form["password"].ToString(),
                requestId);

            ValidateUtil.FormatParam(input.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.IndispensableParam(input.Password, Code.HttpBodies.PASSWORD.Key);

            UserRecord user = _users.Authenticate(input.Email, input.Password);

            ValidateUtil.IndispensableParam(input.RequestId, "request_id");
            AuthorizationRequestRecord request = _store.TakeRequest(input.RequestId);
            AuthorizationCodeRecord code = _store.CreateCode(
                request,
                user.Subject,
                user.Email,
                user.Name);

            string separator = request.RedirectUri.Contains('?') ? "&" : "?";
            string redirectUrl = $"{request.RedirectUri}{separator}code={Uri.EscapeDataString(code.Code)}&state={Uri.EscapeDataString(request.State)}";
            Response.Headers.Location = redirectUrl;
            return Ok(new RedirectOutput("redirect", redirectUrl, code.Code));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
