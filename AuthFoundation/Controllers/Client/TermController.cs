using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR.Protocol;
using Newtonsoft.Json;
using System.Numerics;
using System.Text;

namespace AuthFoundation.Controllers.Client
{
    [ApiController]
    [Route("Term")]
    /// <summary>
    /// ClientRegistrationController class.
    /// </summary>
    public class TermController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// Initializes a new instance of ClientRegistrationController.
        /// </summary>
        public TermController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        /// <summary>
        /// RP規約登録
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> PostTerm()
        {
            try
            {
                PostInput input = await PostInput.CreateAsync(Request.HttpContext);
                input.Validate();

                Helper.CertClient(_dbContext, input.ClientId);

                DateTime now = DateTime.UtcNow;
                client_term? clientTerm;
                if (input.SeqIdLong < 0)
                {
                    int displayOrder = 0;

                    client_term? maxDisplayOrder = _dbContext.client_terms.OrderByDescending(x => x.display_order).FirstOrDefault(x => x.client_id == input.ClientId);
                    if (maxDisplayOrder != null)
                    {
                        displayOrder += maxDisplayOrder.display_order;
                    }
                    clientTerm = new client_term
                    {
                        client_id = input.ClientId,
                        term_id = input.TermName,
                        term_version = input.TermVersion,
                        required = input.byteRequired,
                        display_order = displayOrder,
                        create_datetime = now,
                        update_datetime = now,
                        status = Code.Status.ACTIVE
                    };
                    _dbContext.client_terms.Add(clientTerm);
                }
                else
                {
                     clientTerm = _dbContext.client_terms.FirstOrDefault(x => x.sequence_id == input.SeqIdLong && x.client_id == input.ClientId);

                }
                await _dbContext.SaveChangesAsync();

                return Ok(new PostOutput(clientTerm));
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
        /// Input class.
        /// </summary>
        private class PostInput
        {
            /// <summary>
            /// Gets or sets ClientName.
            /// </summary>
            public string ClientId { get; set; } = string.Empty;
            public string TermSeqId { get; set; } = string.Empty;
            public string TermName { get; set; } = string.Empty;
            public string TermVersion { get; set; } = string.Empty;
            public string Required { get; set; } = string.Empty;
            public string TermUrl { get; set; } = string.Empty;
            public long SeqIdLong { get; set; } = -1;
            public byte byteRequired { get; set; } = 0;
            /// <summary>
            /// Executes CreateAsync.
            /// </summary>
            public static async Task<PostInput> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();
                return new PostInput
                {
                    ClientId = form[Code.HttpBodies.CLIENT_ID.Key].ToString(),
                    TermSeqId = form[Code.HttpBodies.TERM_SEQ_ID.Key].ToString(),
                    TermName = form[Code.HttpBodies.TERM_NAME.Key].ToString(),
                    TermUrl = form[Code.HttpBodies.TERM_URL.Key].ToString()
                };
            }

            /// <summary>
            /// Executes Validate.
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpBodies.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);

                ValidateUtil.FormatParam(TermSeqId, Code.HttpBodies.TERM_SEQ_ID.Key, Code.HttpBodies.TERM_SEQ_ID.Regex);
                if (!string.IsNullOrWhiteSpace(TermSeqId) && !long.TryParse(TermSeqId, out long SeqIdLong))
                {
                    throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{Code.HttpBodies.TERM_SEQ_ID.Key}の形式が不正です");
                }
                ValidateUtil.IndispensableParam(TermName, Code.HttpBodies.TERM_NAME.Key);
                ValidateUtil.FormatParam(TermName, Code.HttpBodies.TERM_NAME.Key, Code.HttpBodies.TERM_NAME.Regex);

                ValidateUtil.IndispensableParam(TermUrl, Code.HttpBodies.TERM_URL.Key);
                ValidateUtil.FormatParam(TermUrl, Code.HttpBodies.TERM_URL.Key, Code.HttpBodies.TERM_URL.Regex);

                if (!Uri.TryCreate(TermUrl, UriKind.Absolute, out Uri? _))
                {
                    throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{Code.HttpBodies.TERM_SEQ_ID.Key}の形式が不正です");
                }


            }
        }

        /// <summary>
        /// Output class.
        /// </summary>
        private class PostOutput
        {
            public string StatusCode { get; }
            public string Message { get; }
            public string? ClientId { get; }
            public string? ClientSecret { get; }
            public string? ClientName { get; }

            /// <summary>
            /// コンストラクタ(例外)
            /// </summary>
            public PostOutput(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>
            /// コンストラクタ(正常)
            /// </summary>
            public PostOutput(client_term clientTerm)
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
