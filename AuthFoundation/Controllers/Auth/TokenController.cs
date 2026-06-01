using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("token")]
public sealed class TokenController : ControllerBase
{
    private readonly IOidcStore _store;
    private readonly OidcTokenService _tokenService;

    public TokenController(IOidcStore store, OidcTokenService tokenService)
    {
        _store = store;
        _tokenService = tokenService;
    }

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

    private static string RequiredForm(IFormCollection form, Code.RequestValidation validation)
    {
        string value = form[validation.Key].ToString();
        ValidateUtil.FormatParam(value, validation.Key, validation.Regex);
        return value;
    }
}
