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
    public class ClientRegistrationController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        public ClientRegistrationController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterClient()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                DateTime now = DateTime.UtcNow;
                string clientId = GenerateUniqueClientId();
                string clientSecret = Helper.GenerateRandomCode(32, Code.AccessToken.CHARACTORS);

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
                return new ObjectResult(new Output(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.Status };
            }
        }

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

            throw new ApiException(Code.ID_GENERATION_ERORR, "failed to generate client_id");
        }

        private static string GenerateNumericString(int length)
        {
            const string digits = "0123456789";
            return Helper.GenerateRandomCode(length, digits);
        }

        private class Input
        {
            [JsonProperty("client_name")]
            public string ClientName { get; set; } = string.Empty;

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

            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientName, "client_name");
            }
        }

        private class Output
        {
            public string StatusCode { get; }
            public string Message { get; }
            public string? ClientId { get; }
            public string? ClientSecret { get; }
            public string? ClientName { get; }

            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            public Output(string clientId, string clientSecret, string clientName)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
                ClientId = clientId;
                ClientSecret = clientSecret;
                ClientName = clientName;
            }
        }
    }
}
