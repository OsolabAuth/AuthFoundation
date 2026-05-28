using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("authorize")]
public sealed class AuthorizeController : ControllerBase
{
    private readonly InMemoryOidcStore _store;

    /// <summary>
    /// Authorization Code Flow開始用controllerを生成する。
    /// </summary>
    /// <param name="store">認可リクエスト保存用ストア。</param>
    public AuthorizeController(InMemoryOidcStore store)
    {
        _store = store;
    }

    /// <summary>
    /// 認可リクエストを検証し、ログイン画面への遷移情報を返却する。
    /// </summary>
    /// <returns>ログイン画面へのリダイレクト、またはJSON形式のログイン画面URL。</returns>
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

            RequireDevelopmentClient(clientId, redirectUri);
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

    /// <summary>
    /// 指定されたquery項目を取得し、必須チェックと形式チェックを行う。
    /// </summary>
    /// <param name="validation">検証対象queryのキーと正規表現。</param>
    /// <returns>検証済みquery値。</returns>
    private string RequiredQuery(Code.RequestValidation validation)
    {
        string value = Request.Query[validation.Key].ToString();
        ValidateUtil.FormatParam(value, validation.Key, validation.Regex);
        return value;
    }

    /// <summary>
    /// 開発用client_idとredirect_uriの組み合わせを検証する。
    /// </summary>
    /// <param name="clientId">検証対象のclient_id。</param>
    /// <param name="redirectUri">検証対象のredirect_uri。</param>
    private static void RequireDevelopmentClient(string clientId, string redirectUri)
    {
        if (!string.Equals(clientId, AppConfig.DevelopmentClientId, StringComparison.Ordinal)
            || !string.Equals(redirectUri, AppConfig.DevelopmentRedirectUri, StringComparison.Ordinal))
        {
            throw Code.ILLEGAL_CLIENT;
        }
    }
}
