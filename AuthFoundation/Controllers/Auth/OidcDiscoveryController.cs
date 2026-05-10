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
                jwks_uri = $"{issuer}/.well-known/jwks.json",
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

    [ApiController]
    [Route(".well-known/jwks.json")]
    /// <summary>     /// JwksController class.     /// </summary>
    public class JwksController : ControllerBase
    {
        private readonly OidcSigningService _oidcSigningService;

        /// <summary>         /// Initializes a new instance of JwksController.         /// </summary>
        public JwksController(OidcSigningService oidcSigningService)
        {
            _oidcSigningService = oidcSigningService;
        }

        [HttpGet]
        /// <summary>         /// Executes GetJwks.         /// </summary>
        public IActionResult GetJwks()
        {
            try
            {
                return Ok(_oidcSigningService.CreateJwks());
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new
                {
                    response_code = apiEx.Code,
                    message = apiEx.ErrorMessage
                })
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }
    }
}
