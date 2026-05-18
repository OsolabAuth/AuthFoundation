using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Text;

namespace AuthFoundation.Controllers.Client
{
    [ApiController]
    [Route("Client")]
    /// <summary>
    /// ClientRegistrationController class.
    /// </summary>
    public class ClientController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// Initializes a new instance of ClientRegistrationController.
        /// </summary>
        public ClientController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        [HttpPost]
        /// <summary>
        /// Executes RegisterClient.
        /// </summary>
        public async Task<IActionResult> PostClient()
        {
            try
            {
                PostInput input = await PostInput.CreateAsync(Request.HttpContext);
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

                return Ok(new PostOutput(clientId, clientSecret, input.ClientName));
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new PostOutput(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new PostOutput(aex)) { StatusCode = (int)aex.Status };
            }
        }

        /// <summary>
        /// Executes GenerateUniqueClientId.
        /// </summary>
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
        /// Executes GenerateNumericString.
        /// </summary>
        private static string GenerateNumericString(int length)
        {
            const string digits = "0123456789";
            return Helper.GenerateRandomCode(length, digits);
        }

        /// <summary>
        /// Input class.
        /// </summary>
        private class PostInput
        {
            [JsonProperty("client_name")]
            /// <summary>
            /// Gets or sets ClientName.
            /// </summary>
            public string ClientName { get; set; } = string.Empty;

            /// <summary>
            /// Executes CreateAsync.
            /// </summary>
            public static async Task<PostInput> CreateAsync(HttpContext context)
            {
                Helper.ValidateTypeApplicationJson(context.Request.ContentType);
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                string raw = await reader.ReadToEndAsync();
                PostInput? body = JsonConvert.DeserializeObject<PostInput>(raw);
                if (body == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                }
                return body;
            }

            /// <summary>
            /// Executes Validate.
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientName, "client_name");
            }
        }

        /// <summary>
        /// Output class.
        /// </summary>
        private class PostOutput
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
            /// Gets or sets ClientId.
            /// </summary>
            public string? ClientId { get; }

            /// <summary>
            /// Gets or sets ClientSecret.
            /// </summary>
            public string? ClientSecret { get; }

            /// <summary>
            /// Gets or sets ClientName.
            /// </summary>
            public string? ClientName { get; }

            /// <summary>
            /// Initializes a new instance of Output.
            /// </summary>
            public PostOutput(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>
            /// Initializes a new instance of Output.
            /// </summary>
            public PostOutput(string clientId, string clientSecret, string clientName)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
                ClientId = clientId;
                ClientSecret = clientSecret;
                ClientName = clientName;
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetClient()
        {
            try
            {
                GetInput input = GetInput.Create(Request.HttpContext);
                input.Validate();

                Models.client_master client = Helper.CertClient(_dbContext, input.ClientId);
                List<string> clientScopes = _dbContext.client_scopes.Where(x => x.client_id == client.client_id).Select(x => x.scope).ToList();

                List<string> clientRedirectUris = _dbContext.client_redirect_uris.Where(x => x.client_id == client.client_id).Select(x => x.redirect_uri).ToList();

                return Ok(new
                {
                    result = "redirect",
                    client_scope = clientScopes,
                    client_redirect_uri = clientRedirectUris,
                    response_code = Code.SUCCESS.Code,
                    message = Code.SUCCESS.ErrorMessage
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new { response_code = ex.Code, message = ex.ErrorMessage })
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new { response_code = apiEx.Code, message = apiEx.ErrorMessage })
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }
        public sealed class GetInput
        {
            public string ClientId { get; set; } = string.Empty;
            /// <summary>
            /// HTTP リクエストから認可入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>認可入力</returns>
            public static GetInput Create(HttpContext context)
            {
                HttpRequest request = context.Request;
                return new GetInput
                {
                    ClientId = request.Query["client_id"].ToString(),
                };
            }
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
            }

        }


    }
    }
