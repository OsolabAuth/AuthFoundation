using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("jwks")]
    public class JwksController : ControllerBase
    {
        private readonly OidcSigningService _oidcSigningService;

        public JwksController(OidcSigningService oidcSigningService)
        {
            _oidcSigningService = oidcSigningService;
        }

        [HttpGet]
        public async Task<IActionResult> GetJwks()
        {
            try
            {
                return Ok(await _oidcSigningService.CreateJwksAsync());
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new
                {
                    response_code = apiEx.InternalCode,
                    message = apiEx.ErrorDescription
                })
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }
    }
}
