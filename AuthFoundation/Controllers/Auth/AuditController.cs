using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("audit/logs")]
public sealed class AuditController : ControllerBase
{
    private readonly AuditLogService _auditLogs;

    public AuditController(AuditLogService auditLogs)
    {
        _auditLogs = auditLogs;
    }

    [HttpGet]
    public IActionResult Get([FromQuery] int limit = 100)
    {
        return Ok(new
        {
            logs = _auditLogs.Latest(limit)
        });
    }
}
