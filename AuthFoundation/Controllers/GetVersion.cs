using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers
{
    [ApiController]
    [Route("Version")]
    public class VersionController : ControllerBase
    {
        private const string version = "develop1.0.0";

        [HttpGet(Name = "GetVersion")]
        public async Task<IActionResult> Get()
        {
            HttpContext context = Request.HttpContext;
            Input input = new Input(context);
            return new OkObjectResult(new Output(version));
        }
        /// <summary>
        /// 入力値クラス
        /// </summary>
        public class Input
        {
            public string Value { get; set; }

            public Input(HttpContext context)
            {
                Value = string.Empty;
            }
        }
        /// <summary>
        /// 返却値クラス
        /// </summary>
        private class Output
        {
            public string StatusCode { get; }
            public string Message { get; }

            public string? Version { get; }

            /// <summary>
            /// 例外
            /// </summary>
            /// <param name="ex">例外</param>
            public Output(Common.ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>
            /// 正常
            /// </summary>
            /// <param name="version"></param>
            public Output(string version)
            {
                StatusCode = Common.Code.SUCCESS.Code;
                Message = Common.Code.SUCCESS.ErrorMessage;
                Version = version;
            }
        }
    }
}