using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Temp
{
    /// <summary>
    /// 隱榊庄蜃ｦ逅・ｒ謠蝉ｾ帙＠縺ｾ縺吶・
    /// </summary>
    [ApiController]
    [Route("temp/client")]
    public class ClientController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly AuthorizeExecutionService _authorizeExecutionService;

        /// <summary>
        /// AuthorizeController 繧貞・譛溷喧縺励∪縺吶・
        /// </summary>
        /// <param name="dbContext">DB繧ｳ繝ｳ繝・く繧ｹ繝・/param>
        /// <param name="authorizeExecutionService">隱榊庄螳溯｡後し繝ｼ繝薙せ</param>
        public ClientController(OsolabAuthContext dbContext, AuthorizeExecutionService authorizeExecutionService)
        {
            _dbContext = dbContext;
            _authorizeExecutionService = authorizeExecutionService;
        }

        /// <summary>
        /// 隱榊庄蜃ｦ逅・ｒ螳溯｡後＠縺ｾ縺吶・
        /// </summary>
        /// <returns>隱榊庄邨先棡</returns>
        [HttpGet]
        public async Task<IActionResult> GetAuthorize()
        {
            try
            {
                Input input = Input.Create(Request.HttpContext);
                input.Validate();

                Models.client_master client = Helper.CertClient(_dbContext, input.ClientId);
                List<string> clientScopes = _dbContext.client_scopes.Where(x => x.client_id == client.client_id).Select(x=> x.scope).ToList();
                
                List<string> clientRedirectUris = _dbContext.client_redirect_uris.Where(x => x.client_id == client.client_id).Select(x => x.redirect_uri).ToList();

                return Ok(new
                {
                    result = "redirect",
                    client_scope = clientScopes,
                    client_redirect_uri = clientRedirectUris,
                    response_code = Code.SUCCESS.Code,
                    message = Code.SUCCESS.ErrorDescription
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new { response_code = ex.InternalCode, message = ex.ErrorDescription })
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new { response_code = apiEx.InternalCode, message = apiEx.ErrorDescription })
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        private static bool ShouldReturnBodySession(HttpRequest request)
        {
            return string.Equals(
                request.Headers["x-auth-ui-session-mode"].ToString(),
                "body",
                StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractSessionId(string location)
        {
            string query = GetQuery(location);
            foreach (string part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] pair = part.Split('=', 2);
                if (pair.Length == 2 && string.Equals(pair[0], "session_id", StringComparison.OrdinalIgnoreCase))
                {
                    return Uri.UnescapeDataString(pair[1]);
                }
            }

            return string.Empty;
        }

        private static string RemoveSessionIdFromUrl(string location)
        {
            int questionIndex = location.IndexOf('?', StringComparison.Ordinal);
            if (questionIndex < 0)
            {
                return location;
            }

            string basePart = location[..questionIndex];
            string queryPart = location[(questionIndex + 1)..];
            string filteredQuery = string.Join("&", queryPart
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(part => !part.StartsWith("session_id=", StringComparison.OrdinalIgnoreCase)));

            return string.IsNullOrWhiteSpace(filteredQuery)
                ? basePart
                : $"{basePart}?{filteredQuery}";
        }

        private static string GetQuery(string location)
        {
            int questionIndex = location.IndexOf('?', StringComparison.Ordinal);
            if (questionIndex < 0 || questionIndex == location.Length - 1)
            {
                return string.Empty;
            }

            return location[(questionIndex + 1)..];
        }

        /// <summary>
        /// 隱榊庄蜈･蜉帙ｒ陦ｨ縺励∪縺吶・
        /// </summary>
        public sealed class Input
        {
            public string ResponseType { get; set; } = string.Empty;

            public string ClientId { get; set; } = string.Empty;

            public string RedirectUri { get; set; } = string.Empty;

            public string State { get; set; } = string.Empty;

            public string Scope { get; set; } = string.Empty;

            public string CodeChallengeMethod { get; set; } = string.Empty;

            public string CodeChallenge { get; set; } = string.Empty;

            public string Nonce { get; set; } = string.Empty;

            /// <summary>
            /// HTTP 繝ｪ繧ｯ繧ｨ繧ｹ繝医°繧芽ｪ榊庄蜈･蜉帙ｒ逕滓・縺励∪縺吶・
            /// </summary>
            /// <param name="context">HTTP 繧ｳ繝ｳ繝・く繧ｹ繝・/param>
            /// <returns>隱榊庄蜈･蜉・/returns>
            public static Input Create(HttpContext context)
            {
                HttpRequest request = context.Request;
                return new Input
                {
                    ClientId = request.Query["client_id"].ToString(),
                };
            }
            /// <summary>
            /// 蜈･蜉帛､繧呈､懆ｨｼ縺励∪縺吶・
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
            }
        }
    }
}
