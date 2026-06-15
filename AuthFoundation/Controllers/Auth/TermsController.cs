using AuthFoundation.Common;
using AuthFoundation.Contracts;
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
        return Ok(new TermsCurrentOutput(
            terms.TermsId,
            terms.Version,
            terms.Title,
            terms.Body,
            AppConfig.DevelopmentClientId));
    }
}
