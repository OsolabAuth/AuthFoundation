using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Text;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// クライアント登録 API を提供します。
    /// </summary>
    [ApiController]
    [Route("Client/Register")]
    [Route("register")]
    public class ClientRegistrationController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// <see cref="ClientRegistrationController"/> の新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="dbContext">DB コンテキスト</param>
        public ClientRegistrationController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        /// <summary>
        /// クライアントを登録し、発行したクライアントIDとシークレットを返却します。
        /// </summary>
        /// <returns>クライアント登録結果</returns>
        [HttpPost]
        public async Task<IActionResult> RegisterClient()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                DateTime now = DateTime.UtcNow;
                string clientId = GenerateUniqueClientId();
                string clientSecret = Helper.GenerateHex(64).ToLowerInvariant();

                client_master client = new client_master
                {
                    client_id = clientId,
                    client_name = input.ClientName,
                    client_secret = clientSecret,
                    create_datetime = now,
                    update_datetime = now,
                    status = Code.Status.ACTIVE
                };

                _dbContext.client_masters.Add(client);
                await _dbContext.SaveChangesAsync();

                return Ok(new Output(clientId, clientSecret, input.ClientName));
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new Output(ex)) { StatusCode = (int)ex.StatusCode };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.StatusCode };
            }
        }

        /// <summary>
        /// 重複しないクライアントIDを採番します。
        /// </summary>
        /// <returns>採番したクライアントID</returns>
        private string GenerateUniqueClientId()
        {
            for (int i = 0; i < 10; i++)
            {
                string candidate = GenerateNumericString(32);
                bool exists = _dbContext.client_masters.Any(x => x.client_id == candidate);
                if (!exists)
                {
                    return candidate;
                }
            }

            throw new ApiException(Code.ID_GENERATION_ERROR, "failed to generate client_id");
        }

        /// <summary>
        /// 指定桁数の数字文字列を生成します。
        /// </summary>
        /// <param name="length">生成桁数</param>
        /// <returns>生成した数字文字列</returns>
        private static string GenerateNumericString(int length)
        {
            const string digits = "0123456789";
            return Helper.GenerateRandomCode(length, digits);
        }

        /// <summary>
        /// クライアント登録入力を表します。
        /// </summary>
        private class Input
        {
            [JsonProperty("client_name")]
            /// <summary>
            /// クライアント名です。
            /// </summary>
            public string ClientName { get; set; } = string.Empty;

            /// <summary>
            /// HTTP リクエストから入力値を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>入力値</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                Helper.ValidateTypeApplicationJson(context.Request.ContentType);
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                string raw = await reader.ReadToEndAsync();
                Input? body = JsonConvert.DeserializeObject<Input>(raw);
                if (body == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                }
                return body;
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientName, "client_name");
            }
        }

        /// <summary>
        /// クライアント登録レスポンスを表します。
        /// </summary>
        private class Output
        {
            /// <summary>
            /// アプリケーション固有のレスポンスコードです。
            /// </summary>
            public string StatusCode { get; }

            /// <summary>
            /// メッセージです。
            /// </summary>
            public string Message { get; }

            /// <summary>
            /// クライアントIDです。
            /// </summary>
            public string? ClientId { get; }

            /// <summary>
            /// クライアントシークレットです。
            /// </summary>
            public string? ClientSecret { get; }

            /// <summary>
            /// クライアント名です。
            /// </summary>
            public string? ClientName { get; }

            /// <summary>
            /// 例外情報からエラーレスポンスを生成します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public Output(ApiException ex)
            {
                StatusCode = ex.InternalCode;
                Message = ex.ErrorDescription;
            }

            /// <summary>
            /// 正常系レスポンスを生成します。
            /// </summary>
            /// <param name="clientId">クライアントID</param>
            /// <param name="clientSecret">クライアントシークレット</param>
            /// <param name="clientName">クライアント名</param>
            public Output(string clientId, string clientSecret, string clientName)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorDescription;
                ClientId = clientId;
                ClientSecret = clientSecret;
                ClientName = clientName;
            }
        }
    }
}
