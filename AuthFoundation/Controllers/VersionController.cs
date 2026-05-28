using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers;

[ApiController]
[Route("version")]
public sealed class VersionController : ControllerBase
{
    /// <summary>
    /// AuthFoundationのバージョン情報を返却する。
    /// </summary>
    /// <returns>サービス稼働情報。</returns>
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
