using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("jwks")]
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
