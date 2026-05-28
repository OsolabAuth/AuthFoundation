using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("terms")]
public sealed class TermsController : ControllerBase
{
    private readonly TermsService _terms;

    public TermsController(TermsService terms)
    {
        _terms = terms;
    }

    [HttpGet("current")]
    public IActionResult Current()
    {
        TermsDocument terms = _terms.Current();
        return Ok(new
        {
            terms_id = terms.TermsId,
            version = terms.Version,
            title = terms.Title,
            body = terms.Body,
            client_id = AppConfig.DevelopmentClientId
        });
    }
}
