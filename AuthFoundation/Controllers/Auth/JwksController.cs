using AuthFoundation.Common;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// JWKS 配信処理を提供します。
    /// </summary>
    [ApiController]
    [Route("jwks")]
    public class JwksController : ControllerBase
    {
        private readonly OidcSigningService _oidcSigningService;

        /// <summary>
        /// <see cref="JwksController"/> の新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="oidcSigningService">OIDC 署名サービス</param>
        public JwksController(OidcSigningService oidcSigningService)
        {
            _oidcSigningService = oidcSigningService;
        }

        /// <summary>
        /// 公開鍵セット (JWKS) を返却します。
        /// </summary>
        /// <returns>JWKS レスポンス</returns>
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
                    message = apiEx.ErrorDescription,
                    error = apiEx.Error,
                    error_code = apiEx.InternalCode,
                    error_description = apiEx.ErrorDescription
                })
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }
    }
}
