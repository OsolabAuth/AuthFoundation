
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using ServiceStack.Script;
using System.Text;
using static ServiceStack.Diagnostics.Events;

namespace AuthFoundation.Controllers.Signup
{
    [ApiController]
    [Route("Signup/Account")]
    public class AccountController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IConfiguration _configuration;
        public AccountController(OsolabAuthContext dbContext, IRedisClient redis, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _redis = redis;
            _configuration = configuration;
        }

        [HttpPost(Name = "PostSignupAccount")]
        public async Task<IActionResult> PostAccount()
        {
            try 
            {
                HttpContext context = Request.HttpContext;
                Input input = await Input.CreateAsync(context);

                client_master client = Helper.CertClient(_dbContext, input.ClientId);

                Helper.CertEmail(_dbContext, input.Body.Email);

                osolab_user user = TableHelper.CreateNewOsolabUser(_dbContext, input.Body.Email, input.Body.Password);

                string sessionId = Helper.GenerateRandomCode(Code.Session.LENGTH, Code.Session.CHARACTORS);
                AuthSession session = new AuthSession(sessionId, user.osolab_id, user.email, input.ClientId);

                session.CreateSession(_redis);

                _dbContext.Add(user);
                _dbContext.SaveChanges();

                return new OkObjectResult(new Output(sessionId));

            }
            catch (Common.ApiException aex)
            {
                return new ObjectResult(new Output(aex))
                {
                    StatusCode = (int)aex.Status
                };
            }
            catch (Exception ex)
            {
                return new ObjectResult(
                    new Output(new ApiException(Common.Code.INTERNAL_SERVER_ERROR, ex.Message))
                )
                {
                    StatusCode = (int)Common.Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        /// <summary>
        /// 入力値クラス
        /// </summary>
        public class Input
        {
            public string ContentType { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public JsonBody Body { get; set; } = new();

            public class JsonBody
            {
                [JsonProperty("email")]
                public string Email { get; set; } = string.Empty;

                [JsonProperty("password")]
                public string Password { get; set; } = string.Empty;
            }

            private Input() { }

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;

                Helper.ValidateTypeApplicationJson(request.ContentType);

                using var reader = new StreamReader(request.Body, Encoding.UTF8);
                string rawJson = await reader.ReadToEndAsync();
                JsonBody? body = null;
                try
                {
                    body = JsonConvert.DeserializeObject<JsonBody>(rawJson);
                }
                catch 
                {
                }
                if (body == null)
                {
                    throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, "JSONオブジェクトが不正です");
                }

                return new Input
                {
                    ContentType = request.ContentType ?? string.Empty,
                    ClientId = request.Headers[Code.HttpHeaders.X_AUTH_CLIENT_ID.Key].ToString(),
                    Body = body
                };
            }

            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpHeaders.X_AUTH_CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpHeaders.X_AUTH_CLIENT_ID.Key, Code.HttpHeaders.X_AUTH_CLIENT_ID.Regex);

            }
        }
        /// <summary>
        /// 返却値クラス
        /// </summary>
        private class Output
        {
            public string StatusCode { get; }
            public string Message { get; }

            public string? SessionId { get; }

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
            public Output(string sessionId)
            {
                StatusCode = Common.Code.SUCCESS.Code;
                Message = Common.Code.SUCCESS.ErrorMessage;
                SessionId = sessionId;
            }
        }
    }
}