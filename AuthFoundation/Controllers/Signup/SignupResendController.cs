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
    [Route("Signup/Resend")]
    public class SignupResendController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly BrevoMail _brevoMail;

        /// <summary>
        /// SignupResendController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="brevoMail">メールクライアント</param>
        public SignupResendController(OsolabAuthContext dbContext, IRedisClient redis, BrevoMail brevoMail)
        {
            _dbContext = dbContext;
            _redis = redis;
            _brevoMail = brevoMail;
        }

        /// <summary>
        /// メール確認を完了します。
        /// </summary>
        /// <returns>遷移結果</returns>
        [HttpPost]
        public async Task<IActionResult> Resend()
        {
            try
            {
                string token = Request.Query[Code.HttpQueries.TOKEN.Key].ToString();
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

                string code = await Helper.SendMailAsync(_brevoMail, user.email);
                verify.Code = code;
                await verify.CreateSession(_redis);

                return Ok(new Output());
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        /// <summary>
        /// サインアップ応答を表します。
        /// </summary>
        private class Output
        {
            public string StatusCode { get; }

            public string Message { get; }

            /// <summary>
            /// エラー応答を初期化します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>
            /// 正常応答を初期化します。
            /// </summary>
            public Output()
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
            }
        }
    }
}
