using AuthFoundation.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers;

[ApiController]
[Route("features")]
public sealed class FeaturesController : ControllerBase
{
    private static readonly FeatureInfo[] ImplementedFeatures =
    [
        new("service.version", "Version API", "available", "Service identity and release status endpoint."),
        new("oidc.discovery", "OIDC discovery", "available", "OpenID Provider metadata and JWKS publication."),
        new("oidc.authorization_code_pkce", "Authorization Code + PKCE", "available", "OIDC authorization request, login, code issuance, and token exchange."),
        new("oidc.userinfo", "UserInfo API", "available", "Bearer token based OIDC UserInfo claims endpoint."),
        new("account.signup_terms", "Signup with terms", "available", "Account signup flow with client terms and user consent."),
        new("mfa.step_up", "MFA step-up", "available", "Email code or authenticator app verification for elevated authorization."),
        new("account.password_change", "Password change", "available", "Step-up protected password change for authenticated users."),
        new("account.password_reset", "Password reset", "available", "Email and birthdate based password reset flow."),
        new("session.logout_revoke", "Logout and token revoke", "available", "Logout and token revocation endpoints."),
        new("account.withdrawal", "Account withdrawal", "available", "Step-up protected account withdrawal endpoint."),
        new("agent.delegated_auth", "AI agent delegated auth", "available", "Agent registration, delegated token issue, and agent self-check endpoints.")
    ];

    /// <summary>
    /// Returns the public catalog of features implemented in this build.
    /// </summary>
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new FeaturesOutput("AuthFoundation", "ok", ImplementedFeatures));
    }
}
