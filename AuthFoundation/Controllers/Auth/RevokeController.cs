using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("revoke")]
public sealed class RevokeController : ControllerBase
{
    private readonly InMemoryOidcStore _store;
    private readonly AuditLogService _auditLogs;

    public RevokeController(InMemoryOidcStore store, AuditLogService auditLogs)
    {
        _store = store;
        _auditLogs = auditLogs;
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
            _auditLogs.Record(
                "token.revoked",
                "success",
                actorType: "user",
                ipAddress: Convert.ToString(HttpContext.Connection.RemoteIpAddress),
                userAgent: Request.Headers.UserAgent.ToString());
            return Ok(new { result = "revoked" });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
