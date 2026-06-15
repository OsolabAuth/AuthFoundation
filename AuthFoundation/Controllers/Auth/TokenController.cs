using AuthFoundation.Common;
using AuthFoundation.Contracts;
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
            var input = new TokenRequest(
                RequiredForm(form, Code.HttpBodies.GRANT_TYPE),
                RequiredForm(form, Code.HttpBodies.CLIENT_ID),
                RequiredForm(form, Code.HttpBodies.CODE),
                RequiredForm(form, Code.HttpBodies.CODE_VERIFIER),
                form["redirect_uri"].ToString());
            ValidateUtil.FormatParam(input.RedirectUri, Code.HttpQueries.REDIRECT_URI.Key, Code.HttpQueries.REDIRECT_URI.Regex);

            AuthorizationCodeRecord record = _store.TakeCode(input.Code);
            if (!string.Equals(input.ClientId, record.ClientId, StringComparison.Ordinal)
                || !string.Equals(input.RedirectUri, record.RedirectUri, StringComparison.Ordinal)
                || !PkceUtil.VerifyS256(input.CodeVerifier, record.CodeChallenge))
            {
                throw new ApiException(
                    Code.REQUEST_PARAMETER_ERROR.InternalCode,
                    Code.REQUEST_PARAMETER_ERROR.StatusCode,
                    "invalid_grant",
                    "invalid token request");
            }

            SetTokenResponseCacheHeaders();
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

    private void SetTokenResponseCacheHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }
}
