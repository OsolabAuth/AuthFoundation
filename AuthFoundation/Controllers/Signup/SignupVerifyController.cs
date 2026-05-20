using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Signup
{
    /// <summary>
    /// メール確認後の有効化を処理します。
    /// </summary>
    [ApiController]
    [Route("Signup/Verify")]
    public class SignupVerifyController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly AuthorizeExecutionService _authorizeExecutionService;

        /// <summary>
        /// SignupVerifyController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="authorizeExecutionService">認可実行サービス</param>
        public SignupVerifyController(
            OsolabAuthContext dbContext,
            IRedisClient redis,
            AuthorizeExecutionService authorizeExecutionService)
        {
            _dbContext = dbContext;
            _redis = redis;
            _authorizeExecutionService = authorizeExecutionService;
        }

        /// <summary>
        /// メール確認を完了します。
        /// </summary>
        /// <returns>遷移結果</returns>
        [HttpGet]
        public async Task<IActionResult> Verify()
        {
            try
            {
                string token = Request.Query["token"].ToString();
                ValidateUtil.IndispensableParam(token, "token");

                MailVerificationSession verify = new MailVerificationSession();
                string? raw = await verify.ReadValueFromRedisAsync(_redis, token);
                if (string.IsNullOrWhiteSpace(raw))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification token is invalid");
                }

                if (!verify.SetValue(raw))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification session is invalid");
                }

                osolab_user? user = _dbContext.osolab_users.SingleOrDefault(x => x.osolab_id == verify.OsolabId && x.status == Code.Status.TENTATIVE);
                if (user == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "tentative user is not found");
                }

                user.status = Code.Status.ACTIVE;
                user.update_datetime = DateTime.UtcNow;
                _dbContext.SaveChanges();
                await _redis.DeleteAsync(MailVerificationSession.GetRedisKey(token),Code.RedisDbNo.MAIL_VERIFICATION_SESSION);

                string loginSessionId = Helper.GenerateRandomCode(Code.Session.LENGTH, Code.Session.CHARACTORS);
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, string.Empty);
                await loginSession.WriteToRedisAsync(_redis);
                loginSession.AppendCookie(Response);

                string? location = await _authorizeExecutionService.TryExecuteFromSessionAsync(verify.SessionId, loginSessionId);
                if (string.IsNullOrWhiteSpace(location))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
                }

                return Redirect(location);
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }
    }
}
