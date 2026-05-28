using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("health")]
public sealed class HealthController : ControllerBase
{
    [HttpGet("live")]
    public IActionResult Live()
    {
        return Ok(new
        {
            status = "ok",
            check = "live",
            checked_at = DateTimeOffset.UtcNow
        });
    }

    [HttpGet("ready")]
    public IActionResult Ready()
    {
        return Ok(new
        {
            status = "ok",
            check = "ready",
            issuer = AppConfig.Issuer.TrimEnd('/'),
            auth_ui_base_url = AppConfig.AuthUiBaseUrl,
            checked_at = DateTimeOffset.UtcNow
        });
    }
}
