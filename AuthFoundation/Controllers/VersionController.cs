using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers;

[ApiController]
[Route("version")]
public sealed class VersionController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new
        {
            service = "AuthFoundation",
            version = "rebuild-common",
            status = "ok"
        });
    }
}
