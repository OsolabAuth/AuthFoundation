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
    /// <summary>     /// SignupAccountController class.     /// </summary>
    public class SignupAccountController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        /// <summary>         /// Initializes a new instance of SignupAccountController.         /// </summary>
        public SignupAccountController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        [HttpGet("view")]
        /// <summary>         /// Executes GetSignupView.         /// </summary>
        public IActionResult GetSignupView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("signup-account.html").Replace("__SID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        /// <summary>         /// Executes LoadTemplate.         /// </summary>
        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Signup", fileName);
            return System.IO.File.ReadAllText(path);
        }

        [HttpPost(Name = "PostSignupAccount")]
        /// <summary>         /// Executes PostAccount.         /// </summary>
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

        /// <summary>         /// Executes GetAuthorizationSessionAsync.         /// </summary>
        private async Task<AuthorizationSession> GetAuthorizationSessionAsync(string sessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw)) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            AuthorizationSession? s = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (s == null) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            return s;
        }

        /// <summary>         /// Input class.         /// </summary>
        public class Input
        {
            /// <summary>             /// Gets or sets SessionId.             /// </summary>
            public string SessionId { get; set; } = string.Empty;
            /// <summary>             /// Gets or sets Body.             /// </summary>
            public JsonBody Body { get; set; } = new();

            /// <summary>             /// JsonBody class.             /// </summary>
            public class JsonBody
            {
                public string Email { get; set; } = string.Empty;
                public string Password { get; set; } = string.Empty;
            }

            /// <summary>             /// Executes CreateAsync.             /// </summary>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(),
                    Body = new JsonBody
                    {
                        Email = form["email"].ToString(),
                        Password = form["password"].ToString()
                    }
                };
            }

            /// <summary>             /// Executes ValidationCheck.             /// </summary>
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

        /// <summary>         /// Output class.         /// </summary>
        private class Output
        {
            /// <summary>             /// Gets or sets StatusCode.             /// </summary>
            public string StatusCode { get; }
            /// <summary>             /// Gets or sets Message.             /// </summary>
            public string Message { get; }
            /// <summary>             /// Gets or sets VerifyUrl.             /// </summary>
            public string? VerifyUrl { get; }
            /// <summary>             /// Initializes a new instance of Output.             /// </summary>
            public Output(ApiException ex) { StatusCode = ex.Code; Message = ex.ErrorMessage; }
            /// <summary>             /// Initializes a new instance of Output.             /// </summary>
            public Output(string verifyUrl)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
                VerifyUrl = verifyUrl;
            }
        }
    }
}

