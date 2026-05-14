using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("userinfo")]
    /// <summary>     /// UserInfoController class.     /// </summary>
    public class UserInfoController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>         /// Initializes a new instance of UserInfoController.         /// </summary>
        public UserInfoController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpGet]
        /// <summary>         /// Executes GetUserInfo.         /// </summary>
        public async Task<IActionResult> GetUserInfo()
        {
            try
            {
                string authorization = Request.Headers.Authorization.ToString();
                ValidateUtil.IndispensableParam(authorization, "Authorization");
                if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorMessage);
                }

                string accessToken = authorization.Substring("Bearer ".Length).Trim();
                ValidateUtil.IndispensableParam(accessToken, "access_token");

                string? raw = await _redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken));
                if (string.IsNullOrWhiteSpace(raw))
                {
                    throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorMessage);
                }

                AccessTokenSession? tokenSession = JsonConvert.DeserializeObject<AccessTokenSession>(raw);
                if (tokenSession == null)
                {
                    throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorMessage);
                }

                osolab_user? user = await _dbContext.osolab_users.AsNoTracking()
                    .SingleOrDefaultAsync(x => x.osolab_id == tokenSession.OsolabId && x.status == Code.Status.ACTIVE);
                if (user == null)
                {
                    throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorMessage);
                }

                List<string> scopes = Helper.ParseScopes(tokenSession.Scope);
                Dictionary<string, object> claims = new(StringComparer.Ordinal)
                {
                    ["sub"] = user.osolab_id
                };

                if (scopes.Contains(Code.Scope.EMAIL, StringComparer.Ordinal))
                {
                    claims["email"] = user.email;
                    claims["email_verified"] = true;
                }

                List<user_info> infos = await _dbContext.user_infos.AsNoTracking()
                    .Where(x => x.osolab_id == tokenSession.OsolabId
                        && x.client_id == tokenSession.ClientId
                        && x.status == Code.Status.ACTIVE)
                    .ToListAsync();

                foreach (user_info info in infos)
                {
                    claims[info.data_key] = info.data_value;
                }

                return Ok(claims);
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }

        /// <summary>         /// ErrorOutput class.         /// </summary>
        private sealed class ErrorOutput
        {
            /// <summary>             /// Gets or sets response_code.             /// </summary>
            public string response_code { get; }
            /// <summary>             /// Gets or sets message.             /// </summary>
            public string message { get; }

            /// <summary>             /// Initializes a new instance of ErrorOutput.             /// </summary>
            public ErrorOutput(ApiException ex)
            {
                response_code = ex.Code;
                message = ex.ErrorMessage;
            }
        }
    }
}
