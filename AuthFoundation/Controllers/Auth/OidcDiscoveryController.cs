using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// OIDC Discovery ドキュメントを返却します。
    /// </summary>
    [ApiController]
    [Route(".well-known/openid-configuration")]
    public class OidcDiscoveryController : ControllerBase
    {
        /// <summary>
        /// OIDC Discovery メタデータを返却します。
        /// </summary>
        /// <returns>Discovery メタデータ</returns>
        [HttpGet]
        public IActionResult GetConfiguration()
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
                token_endpoint_auth_methods_supported = new[] { "none", "client_secret_basic" },
                scopes_supported = new[] { Code.Scope.OPENID, Code.Scope.EMAIL, Code.Scope.PROFILE },
                claims_supported = new[] { "sub", "name", "email", "iss", "aud", "exp", "iat", "picture", "birthdate" },
                service_documentation = AppConfig.ServiceDocumentationUrl,
                code_challenge_methods_supported = new[] { "S256" }
            });
        }
    }
}
