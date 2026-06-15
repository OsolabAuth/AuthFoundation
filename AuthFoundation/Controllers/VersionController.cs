using AuthFoundation.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers;

[ApiController]
[Route("version")]
public sealed class VersionController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new VersionOutput("AuthFoundation", "rebuild-common", "ok"));
    }
}
