using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Controllers.Inner
{
    [ApiController]
    [Route("inner/users")]
    /// <summary>
    /// InnerUserController class.
    /// </summary>
    public class InnerUserController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// Initializes a new instance of InnerUserController.
        /// </summary>
        public InnerUserController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        [HttpGet]
        /// <summary>
        /// Executes GetUsers.
        /// </summary>
        public async Task<IActionResult> GetUsers([FromQuery] string? email = null, [FromQuery] byte? status = null)
        {
            try
            {
                await ValidateInnerClientAsync();

                IQueryable<osolab_user> query = _dbContext.osolab_users.AsNoTracking();
                if (!string.IsNullOrWhiteSpace(email))
                {
                    string e = email.Trim();
                    query = query.Where(x => x.email.Contains(e));
                }

                if (status.HasValue)
                {
                    query = query.Where(x => x.status == status.Value);
                }

                List<osolab_user> users = await query
                    .OrderByDescending(x => x.update_datetime)
                    .Take(200)
                    .ToListAsync();

                return Ok(new
                {
                    users = users.Select(x => new
                    {
                        osolab_id = x.osolab_id,
                        email = x.email,
                        status = x.status,
                        create_datetime = x.create_datetime,
                        update_datetime = x.update_datetime
                    })
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        [HttpGet("{osolabId}/claims")]
        /// <summary>
        /// Executes GetClaims.
        /// </summary>
        public async Task<IActionResult> GetClaims(string osolabId, [FromQuery(Name = "client_id")] string clientId)
        {
            try
            {
                await ValidateInnerClientAsync();
                ValidateUtil.IndispensableParam(osolabId, "osolab_id");
                ValidateUtil.IndispensableParam(clientId, "client_id");
                ValidateUtil.FormatParam(clientId, "client_id", Code.HttpQueries.CLIENT_ID.Regex);

                osolab_user? user = await _dbContext.osolab_users.AsNoTracking()
                    .SingleOrDefaultAsync(x => x.osolab_id == osolabId);
                if (user == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "user is not found");
                }

                List<user_info> infos = await _dbContext.user_infos.AsNoTracking()
                    .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                    .OrderBy(x => x.data_key)
                    .ToListAsync();

                return Ok(new
                {
                    osolab_id = user.osolab_id,
                    email = user.email,
                    status = user.status,
                    client_id = clientId,
                    claims = infos.ToDictionary(x => x.data_key, x => x.data_value)
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        [HttpPut("{osolabId}/claims")]
        /// <summary>
        /// Executes PutClaims.
        /// </summary>
        public async Task<IActionResult> PutClaims(string osolabId, [FromBody] UpsertClaimsInput input)
        {
            try
            {
                await ValidateInnerClientAsync();
                input.Validate(osolabId);

                osolab_user? user = await _dbContext.osolab_users
                    .SingleOrDefaultAsync(x => x.osolab_id == osolabId);
                if (user == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "user is not found");
                }

                if (!string.IsNullOrWhiteSpace(input.Email))
                {
                    bool emailInUse = await _dbContext.osolab_users.AnyAsync(x =>
                        x.email == input.Email
                        && x.osolab_id != osolabId
                        && (x.status == Code.Status.ACTIVE || x.status == Code.Status.TENTATIVE));
                    if (emailInUse)
                    {
                        throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already used");
                    }

                    user.email = input.Email;
                }

                if (input.Status.HasValue)
                {
                    user.status = input.Status.Value;
                }
                user.update_datetime = DateTime.UtcNow;

                HashSet<string> allowedKeys = await _dbContext.data_key_masters
                    .Select(x => x.data_key)
                    .ToHashSetAsync(StringComparer.Ordinal);

                List<string> requestedKeys = input.Claims.Keys.ToList();
                List<user_info> existingRows = await _dbContext.user_infos
                    .Where(x => x.osolab_id == osolabId
                        && x.client_id == input.ClientId
                        && requestedKeys.Contains(x.data_key))
                    .ToListAsync();
                Dictionary<string, user_info> existingByKey = existingRows.ToDictionary(x => x.data_key, StringComparer.Ordinal);

                DateTime now = DateTime.UtcNow;
                foreach ((string dataKey, string dataValue) in input.Claims)
                {
                    if (!allowedKeys.Contains(dataKey))
                    {
                        throw new ApiException(Code.REQUEST_PARAMETER_ERROR, $"unsupported data_key: {dataKey}");
                    }

                    if (!existingByKey.TryGetValue(dataKey, out user_info? row))
                    {
                        row = new user_info
                        {
                            osolab_id = osolabId,
                            client_id = input.ClientId,
                            data_key = dataKey,
                            data_value = dataValue,
                            create_datetime = now,
                            update_datetime = now,
                            status = Code.Status.ACTIVE
                        };
                        _dbContext.user_infos.Add(row);
                    }
                    else
                    {
                        row.data_value = dataValue;
                        row.update_datetime = now;
                        row.status = Code.Status.ACTIVE;
                    }
                }

                await _dbContext.SaveChangesAsync();
                return Ok(new { result = "updated" });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        /// <summary>
        /// Executes ValidateInnerClientAsync.
        /// </summary>
        private async Task ValidateInnerClientAsync()
        {
            string authorization = Request.Headers.Authorization.ToString();
            ValidateUtil.IndispensableParam(authorization, Code.HttpHeaders.AUTHORIZATION_BASIC.Key);
            ValidateUtil.FormatParam(authorization, Code.HttpHeaders.AUTHORIZATION_BASIC.Key, Code.HttpHeaders.AUTHORIZATION_BASIC.Regex);

            string encoded = authorization["Basic ".Length..].Trim();
            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            }
            catch
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }

            string[] parts = decoded.Split(':', 2);
            if (parts.Length != 2)
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }

            string clientId = parts[0];
            string secret = parts[1];
            ValidateUtil.FormatParam(clientId, "client_id", Code.HttpQueries.CLIENT_ID.Regex);

            if (!string.Equals(clientId, AppConfig.InnerClientId, StringComparison.Ordinal))
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }

            client_master client = Helper.CertClient(_dbContext, clientId);
            if (!Helper.IsSameValue(client.client_secret, secret))
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }
        }

        /// <summary>
        /// UpsertClaimsInput class.
        /// </summary>
        public sealed class UpsertClaimsInput
        {
            /// <summary>
            /// Gets or sets ClientId.
            /// </summary>
            public string ClientId { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets Email.
            /// </summary>
            public string? Email { get; set; }

            /// <summary>
            /// Gets or sets Status.
            /// </summary>
            public byte? Status { get; set; }

            /// <summary>
            /// Gets or sets Claims.
            /// </summary>
            public Dictionary<string, string> Claims { get; set; } = new();

            /// <summary>
            /// Executes Validate.
            /// </summary>
            public void Validate(string osolabId)
            {
                ValidateUtil.IndispensableParam(osolabId, "osolab_id");
                ValidateUtil.IndispensableParam(ClientId, "client_id");
                ValidateUtil.FormatParam(ClientId, "client_id", Code.HttpQueries.CLIENT_ID.Regex);

                if (!string.IsNullOrWhiteSpace(Email))
                {
                    ValidateUtil.EmailParam(Email, "email", true);
                }

                if (Status.HasValue && Status.Value is not (Code.Status.ACTIVE or Code.Status.TENTATIVE or Code.Status.INACTIVE))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "status is invalid");
                }
            }
        }

        /// <summary>
        /// ErrorOutput class.
        /// </summary>
        private sealed class ErrorOutput
        {
            /// <summary>
            /// Gets or sets response_code.
            /// </summary>
            public string response_code { get; }

            /// <summary>
            /// Gets or sets message.
            /// </summary>
            public string message { get; }

            /// <summary>
            /// Initializes a new instance of ErrorOutput.
            /// </summary>
            public ErrorOutput(ApiException ex)
            {
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
            }
        }
    }
}
