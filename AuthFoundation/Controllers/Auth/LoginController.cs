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

    /// <summary>
    /// ログイン処理用controllerを生成する。
    /// </summary>
    /// <param name="store">認可リクエストと認可コード保存用ストア。</param>
    /// <param name="users">ユーザー認証用ストア。</param>
    public LoginController(InMemoryOidcStore store, InMemoryUserStore users)
    {
        _store = store;
        _users = users;
    }

    /// <summary>
    /// ユーザー認証後に認可コード付きredirect_urlを返却する。
    /// </summary>
    /// <returns>認可コード付きredirect_url、またはエラー応答。</returns>
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
