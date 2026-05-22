using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers
{
    [ApiController]
    [Route("Version")]
    /// <summary>
    /// VersionController class.
    /// </summary>
    public class VersionController : ControllerBase
    {
        private const string version = "develop1.0.0";

        [HttpGet(Name = "GetVersion")]
        /// <summary>
        /// Executes GetVersion.
        /// </summary>
        public async Task<IActionResult> GetVersion()
        {
            HttpContext context = Request.HttpContext;
            Input input = new Input(context);
            return new OkObjectResult(new Output(version));
        }
        /// <summary>
        /// Input class.
        /// </summary>
        public class Input
        {
            /// <summary>
            /// Gets or sets Value.
            /// </summary>
            public string Value { get; set; }

            /// <summary>
            /// Initializes a new instance of Input.
            /// </summary>
            public Input(HttpContext context)
            {
                Value = string.Empty;
            }
        }
        /// <summary>
        /// Output class.
        /// </summary>
        private class Output
        {
            /// <summary>
            /// Gets or sets StatusCode.
            /// </summary>
            public string StatusCode { get; }

            /// <summary>
            /// Gets or sets Message.
            /// </summary>
            public string Message { get; }

            /// <summary>
            /// Gets or sets Version.
            /// </summary>
            public string? Version { get; }

            /// <summary>
            /// Initializes a new instance of Output.
            /// </summary>
            public Output(Common.ApiException ex)
            {
                StatusCode = ex.InternalCode;
                Message = ex.ErrorDescription;
            }

            /// <summary>
            /// Initializes a new instance of Output.
            /// </summary>
            public Output(string version)
            {
                StatusCode = Common.Code.SUCCESS.Code;
                Message = Common.Code.SUCCESS.ErrorDescription;
                Version = version;
            }
        }
    }
}
