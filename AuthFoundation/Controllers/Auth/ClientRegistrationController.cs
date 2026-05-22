using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Text;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("Client/Register")]
    [Route("register")]
    /// <summary>
    /// ClientRegistrationController class.
    /// </summary>
    public class ClientRegistrationController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// Initializes a new instance of ClientRegistrationController.
        /// </summary>
        public ClientRegistrationController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        [HttpPost]
        /// <summary>
        /// Executes RegisterClient.
        /// </summary>
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
        private class Input
        {
            [JsonProperty("client_name")]
            /// <summary>
            /// Gets or sets ClientName.
            /// </summary>
            public string ClientName { get; set; } = string.Empty;

            /// <summary>
            /// Executes CreateAsync.
            /// </summary>
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
            public Output(ApiException ex)
            {
                StatusCode = ex.InternalCode;
                Message = ex.ErrorDescription;
            }

            /// <summary>
            /// Initializes a new instance of Output.
            /// </summary>
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
