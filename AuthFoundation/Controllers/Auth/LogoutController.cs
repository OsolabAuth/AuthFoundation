using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("logout")]
public sealed class LogoutController : ControllerBase
{
    [HttpPost]
    public IActionResult Post()
    {
        Response.Cookies.Delete("AuthRequestId");
        return Ok(new { result = "logged_out" });
    }
}
