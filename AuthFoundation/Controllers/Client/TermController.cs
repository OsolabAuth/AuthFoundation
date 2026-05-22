using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Controllers.Client
{
    [ApiController]
    [Route("Term")]
    /// <summary>
    /// クライアント規約登録API
    /// </summary>
    public class TermController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;

        /// <summary>
        /// コンストラクタ
        /// </summary>
        public TermController(OsolabAuthContext dbContext)
        {
            _dbContext = dbContext;
        }

        /// <summary>
        /// RP規約登録
        /// </summary>
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
                    clientTerm = new client_term
                    {
                        client_id = input.ClientId,
                        term_id = input.TermName,
                        term_version = input.TermVersion,
                        term_url = input.TermUrl,
                        required = input.RequiredByte,
                        create_datetime = now,
                        update_datetime = now,
                        status = Code.Status.ACTIVE
                    };
                    _dbContext.client_terms.Add(clientTerm);
                }
                else
                {
                    clientTerm = await _dbContext.client_terms.FirstOrDefaultAsync(x =>
                        x.sequence_id == input.SeqIdLong && x.client_id == input.ClientId);
                    if (clientTerm is null)
                    {
                        throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "term not found");
                    }

                    clientTerm.term_id = input.TermName;
                    clientTerm.term_version = input.TermVersion;
                    clientTerm.term_url = input.TermUrl;
                    clientTerm.required = input.RequiredByte;
                    clientTerm.update_datetime = now;
                    clientTerm.status = Code.Status.ACTIVE;
                }

                await _dbContext.SaveChangesAsync();
                return Ok(new PostOutput(clientTerm));
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new PostOutput(ex)) { StatusCode = (int)ex.StatusCode };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new PostOutput(aex)) { StatusCode = (int)aex.StatusCode };
            }
        }

        /// <summary>
        /// 入力クラス
        /// </summary>
        private sealed class PostInput
        {
            public string ClientId { get; set; } = string.Empty;

            public string TermSeqId { get; set; } = string.Empty;

            public string TermName { get; set; } = string.Empty;

            public string TermVersion { get; set; } = "1";

            public string Required { get; set; } = "1";

            public string TermUrl { get; set; } = string.Empty;

            public long SeqIdLong { get; set; } = -1;

            public byte RequiredByte { get; set; } = Code.Status.ACTIVE;

            /// <summary>
            /// フォーム入力の作成
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
                    TermVersion = form["term_version"].ToString(),
                    Required = form["required"].ToString(),
                    TermUrl = form[Code.HttpBodies.TERM_URL.Key].ToString()
                };
            }

            /// <summary>
            /// 入力値の検証
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpBodies.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);

                ValidateUtil.FormatParam(TermSeqId, Code.HttpBodies.TERM_SEQ_ID.Key, Code.HttpBodies.TERM_SEQ_ID.Regex);
                if (!string.IsNullOrWhiteSpace(TermSeqId))
                {
                    if (!long.TryParse(TermSeqId, out long parsedSeqId))
                    {
                        throw new ApiException(Code.REQUEST_PARAMETER_ERROR, $"{Code.HttpBodies.TERM_SEQ_ID.Key} is invalid");
                    }

                    SeqIdLong = parsedSeqId;
                }

                ValidateUtil.IndispensableParam(TermName, Code.HttpBodies.TERM_NAME.Key);
                ValidateUtil.FormatParam(TermName, Code.HttpBodies.TERM_NAME.Key, Code.HttpBodies.TERM_NAME.Regex);

                if (string.IsNullOrWhiteSpace(TermVersion))
                {
                    TermVersion = "1";
                }

                if (string.IsNullOrWhiteSpace(Required))
                {
                    Required = Code.Status.ACTIVE.ToString();
                }
                if (!byte.TryParse(Required, out byte requiredValue) || (requiredValue != Code.Status.ACTIVE && requiredValue != Code.Status.INACTIVE))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "required is invalid");
                }
                RequiredByte = requiredValue;

                ValidateUtil.IndispensableParam(TermUrl, Code.HttpBodies.TERM_URL.Key);
                ValidateUtil.FormatParam(TermUrl, Code.HttpBodies.TERM_URL.Key, Code.HttpBodies.TERM_URL.Regex);
                if (!Uri.TryCreate(TermUrl, UriKind.Absolute, out _))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, $"{Code.HttpBodies.TERM_URL.Key} is invalid");
                }
            }
        }

        /// <summary>
        /// 出力クラス
        /// </summary>
        private sealed class PostOutput
        {
            public string StatusCode { get; }

            public string Message { get; }

            public long? SequenceId { get; }

            public string? ClientId { get; }

            public string? TermId { get; }

            public string? TermVersion { get; }

            public string? TermUrl { get; }

            public bool? Required { get; }

            /// <summary>
            /// エラー応答
            /// </summary>
            public PostOutput(ApiException ex)
            {
                StatusCode = ex.InternalCode;
                Message = ex.ErrorDescription;
            }

            /// <summary>
            /// 正常応答
            /// </summary>
            public PostOutput(client_term clientTerm)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorDescription;
                SequenceId = clientTerm.sequence_id;
                ClientId = clientTerm.client_id;
                TermId = clientTerm.term_id;
                TermVersion = clientTerm.term_version;
                TermUrl = clientTerm.term_url;
                Required = clientTerm.required == Code.Status.ACTIVE;
            }
        }
    }
}
