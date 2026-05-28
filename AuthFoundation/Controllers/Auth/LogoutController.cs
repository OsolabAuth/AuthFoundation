using Microsoft.AspNetCore.Mvc;
using AuthFoundation.Services;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("logout")]
public sealed class LogoutController : ControllerBase
{
    private readonly AuditLogService _auditLogs;

    public LogoutController(AuditLogService auditLogs)
    {
        _auditLogs = auditLogs;
    }

    [HttpPost]
    public IActionResult Post()
    {
        Response.Cookies.Delete("AuthRequestId");
        _auditLogs.Record(
            "user.logout",
            "success",
            actorType: "user",
            ipAddress: Convert.ToString(HttpContext.Connection.RemoteIpAddress),
            userAgent: Request.Headers.UserAgent.ToString());
        return Ok(new { result = "logged_out" });
    }
}
