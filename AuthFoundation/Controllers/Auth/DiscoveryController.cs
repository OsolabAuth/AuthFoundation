using AuthFoundation.Common;
using AuthFoundation.Contracts;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
public sealed class DiscoveryController : ControllerBase
{
    private readonly OidcTokenService _tokenService;

    public DiscoveryController(OidcTokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpGet(".well-known/openid-configuration")]
    public IActionResult Discovery()
    {
        string issuer = AppConfig.Issuer.TrimEnd('/');
        return Ok(new DiscoveryOutput(
            issuer,
            $"{issuer}/authorize",
            $"{issuer}/token",
            $"{issuer}/userinfo",
            $"{issuer}/jwks",
            ["code"],
            ["authorization_code"],
            ["public"],
            ["RS256"],
            [Code.Scope.OPENID, Code.Scope.EMAIL, Code.Scope.PROFILE],
            ["none"],
            ["S256"],
            ["sub", "email", "name"]));
    }

    [HttpGet("jwks")]
    public IActionResult Jwks()
    {
        return Ok(_tokenService.CreateJwksResponse());
    }
}
