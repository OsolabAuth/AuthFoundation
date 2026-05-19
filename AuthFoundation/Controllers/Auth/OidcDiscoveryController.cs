using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route(".well-known/openid-configuration")]
    /// <summary>     /// OidcDiscoveryController class.     /// </summary>
    public class OidcDiscoveryController : ControllerBase
    {
        [HttpGet]
        /// <summary>         /// Executes GetConfiguration.         /// </summary>
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
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                scopes_supported = new[] { Code.Scope.OPENID, Code.Scope.EMAIL, Code.Scope.PROFILE },
                claims_supported = new[] { "sub", "email" },
                service_documentation = AppConfig.ServiceDocumentationUrl
            });
        }
    }
}
