using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("token")]
public sealed class TokenController : ControllerBase
{
    private readonly InMemoryOidcStore _store;
    private readonly OidcTokenService _tokenService;

    /// <summary>
    /// トークン発行処理用controllerを生成する。
    /// </summary>
    /// <param name="store">認可コード取得用ストア。</param>
    /// <param name="tokenService">token response生成サービス。</param>
    public TokenController(InMemoryOidcStore store, OidcTokenService tokenService)
    {
        _store = store;
        _tokenService = tokenService;
    }

    /// <summary>
    /// 認可コードとPKCEを検証し、Bearer token responseを返却する。
    /// </summary>
    /// <returns>TokenResponse、またはエラー応答。</returns>
    [HttpPost]
    public async Task<IActionResult> Post()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string grantType = RequiredForm(form, Code.HttpBodies.GRANT_TYPE);
            string clientId = RequiredForm(form, Code.HttpBodies.CLIENT_ID);
            string code = RequiredForm(form, Code.HttpBodies.CODE);
            string codeVerifier = RequiredForm(form, Code.HttpBodies.CODE_VERIFIER);
            string redirectUri = form["redirect_uri"].ToString();
            ValidateUtil.FormatParam(redirectUri, Code.HttpQueries.REDIRECT_URI.Key, Code.HttpQueries.REDIRECT_URI.Regex);

            AuthorizationCodeRecord record = _store.TakeCode(code);
            if (!string.Equals(clientId, record.ClientId, StringComparison.Ordinal)
                || !string.Equals(redirectUri, record.RedirectUri, StringComparison.Ordinal)
                || !PkceUtil.VerifyS256(codeVerifier, record.CodeChallenge))
            {
                throw new ApiException(
                    Code.REQUEST_PARAMETER_ERROR.InternalCode,
                    Code.REQUEST_PARAMETER_ERROR.StatusCode,
                    "invalid_grant",
                    "invalid token request");
            }

            return Ok(_tokenService.CreateTokenResponse(record));
        }
        catch (ApiException ex)
        {
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    /// <summary>
    /// 指定されたform項目を取得し、必須チェックと形式チェックを行う。
    /// </summary>
    /// <param name="form">検証対象のform collection。</param>
    /// <param name="validation">検証対象form項目のキーと正規表現。</param>
    /// <returns>検証済みform値。</returns>
    private static string RequiredForm(IFormCollection form, Code.RequestValidation validation)
    {
        string value = form[validation.Key].ToString();
        ValidateUtil.FormatParam(value, validation.Key, validation.Regex);
        return value;
    }
}
