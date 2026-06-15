using AuthFoundation.Common;
using AuthFoundation.Contracts;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("password")]
public sealed class PasswordController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly StepUpService _stepUp;

    public PasswordController(IUserStore users, StepUpService stepUp)
    {
        _users = users;
        _stepUp = stepUp;
    }

    /// <summary>
    /// メールアドレスと生年月日を確認し、条件が一致する場合だけパスワードリセット用メールコードを送信する。
    /// </summary>
    [HttpPost("reset/start")]
    public IActionResult StartReset([FromBody] ResetPasswordStartRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.FormatParam(request.BirthDate, Code.HttpBodies.BIRTH_DATE.Key, Code.HttpBodies.BIRTH_DATE.Regex);
            if (!DateOnly.TryParseExact(request.BirthDate, "yyyy-MM-dd", out DateOnly birthDate))
            {
                throw Code.REQUEST_PARAMETER_ERROR;
            }

            _ = _stepUp.TryStartPasswordResetChallenge(request.Email, birthDate);
            return Ok(new PasswordResetStartOutput("reset_challenge_started", "email"));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    /// <summary>
    /// メールコード、生年月日、新しいパスワードを検証してパスワードを再設定する。
    /// </summary>
    [HttpPost("reset")]
    public IActionResult Reset([FromBody] ResetPasswordRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.FormatParam(request.BirthDate, Code.HttpBodies.BIRTH_DATE.Key, Code.HttpBodies.BIRTH_DATE.Regex);
            ValidateUtil.FormatParam(request.EmailCode, Code.HttpBodies.EMAIL_CODE.Key, Code.HttpBodies.EMAIL_CODE.Regex);
            ValidateUtil.FormatParam(request.NewPassword, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            if (!DateOnly.TryParseExact(request.BirthDate, "yyyy-MM-dd", out DateOnly birthDate))
            {
                throw Code.REQUEST_PARAMETER_ERROR;
            }

            _stepUp.VerifyPasswordResetChallenge(request.Email, request.EmailCode);

            UserRecord user = _users.FindByEmail(request.Email);
            if (user.BirthDate != birthDate)
            {
                throw Code.UNAUTHORIZED;
            }

            _users.ResetPassword(request.Email, birthDate, request.NewPassword);
            return Ok(new ResultOutput("password_reset"));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
