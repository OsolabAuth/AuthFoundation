using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("revoke")]
public sealed class RevokeController : ControllerBase
{
    private readonly InMemoryOidcStore _store;

    public RevokeController(InMemoryOidcStore store)
    {
        _store = store;
    }

    [HttpPost]
    public async Task<IActionResult> Post()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string token = form["token"].ToString();
            ValidateUtil.IndispensableParam(token, "token");
            _store.RevokeAccessToken(token);
            return Ok(new { result = "revoked" });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
