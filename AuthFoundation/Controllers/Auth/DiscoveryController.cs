using AuthFoundation.Common;
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
        return Ok(new
        {
            issuer,
            authorization_endpoint = $"{issuer}/authorize",
            token_endpoint = $"{issuer}/token",
            userinfo_endpoint = $"{issuer}/userinfo",
            jwks_uri = $"{issuer}/jwks",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            scopes_supported = new[] { Code.Scope.OPENID, Code.Scope.EMAIL, Code.Scope.PROFILE },
            token_endpoint_auth_methods_supported = new[] { "none" },
            code_challenge_methods_supported = new[] { "S256" },
            claims_supported = new[] { "sub", "email", "name" }
        });
    }

    [HttpGet("jwks")]
    public IActionResult Jwks()
    {
        return Ok(_tokenService.CreateJwksResponse());
    }
}
