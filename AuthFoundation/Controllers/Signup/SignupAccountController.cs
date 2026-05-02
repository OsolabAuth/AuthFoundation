using System.IO;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Signup
{
    [ApiController]
    [Route("Signup/Account")]
    public class SignupAccountController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        public SignupAccountController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        [HttpGet("view")]
        public IActionResult GetSignupView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("signup-account.html").Replace("__SID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Signup", fileName);
            return System.IO.File.ReadAllText(path);
        }

        [HttpPost(Name = "PostSignupAccount")]
        public async Task<IActionResult> PostAccount()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.ValidationCheck();

                AuthorizationSession authz = await GetAuthorizationSessionAsync(input.SessionId);
                client_master client = Helper.CertClient(_dbContext, authz.ClientId);
                if (client.status != Code.Status.ACTIVE) throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);

                bool exists = _dbContext.osolab_users.Any(x => x.email == input.Body.Email && (x.status == Code.Status.TENTATIVE || x.status == Code.Status.ACTIVE));
                if (exists) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");

                osolab_user user = TableHelper.CreateNewOsolabUser(_dbContext, input.Body.Email, input.Body.Password);
                user.status = Code.Status.TENTATIVE;
                _dbContext.Add(user);
                _dbContext.SaveChanges();

                MailVerificationSession verify = new MailVerificationSession
                {
                    VerificationToken = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS),
                    OsolabId = user.osolab_id,
                    Email = user.email,
                    SessionId = input.SessionId
                };
                await verify.CreateSession(_redis);

                string verifyUrl = $"/Signup/Verify?token={Uri.EscapeDataString(verify.VerificationToken)}";
                return Ok(new Output(verifyUrl));
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                { StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status };
            }
        }

        private async Task<AuthorizationSession> GetAuthorizationSessionAsync(string sessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw)) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            AuthorizationSession? s = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (s == null) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            return s;
        }

        public class Input
        {
            public string SessionId { get; set; } = string.Empty;
            public JsonBody Body { get; set; } = new();

            public class JsonBody
            {
                [JsonProperty("email")] public string Email { get; set; } = string.Empty;
                [JsonProperty("password")] public string Password { get; set; } = string.Empty;
            }

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeApplicationJson(request.ContentType);
                using var reader = new StreamReader(request.Body, Encoding.UTF8);
                JsonBody? body = JsonConvert.DeserializeObject<JsonBody>(await reader.ReadToEndAsync());
                if (body == null) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                return new Input { SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(), Body = body };
            }

            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(Body.Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Body.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
                ValidateUtil.IndispensableParam(Body.Password, Code.HttpBodies.PASSWORD.Key);
                ValidateUtil.FormatParam(Body.Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            }
        }

        private class Output
        {
            public string StatusCode { get; }
            public string Message { get; }
            public string? VerifyUrl { get; }
            public Output(ApiException ex) { StatusCode = ex.Code; Message = ex.ErrorMessage; }
            public Output(string verifyUrl)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
                VerifyUrl = verifyUrl;
            }
        }
    }
}
