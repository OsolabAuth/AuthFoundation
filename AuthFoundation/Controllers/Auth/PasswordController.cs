using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

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

            UserRecord user = _users.FindByEmail(request.Email);
            if (user.BirthDate != birthDate)
            {
                throw Code.UNAUTHORIZED;
            }

            _stepUp.VerifyEmailChallenge(request.Email, request.EmailCode);
            _users.ResetPassword(request.Email, birthDate, request.NewPassword);
            return Ok(new { result = "password_reset" });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}

public sealed record ResetPasswordRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("birth_date")]
    string BirthDate,
    [property: JsonPropertyName("email_code")]
    string EmailCode,
    [property: JsonPropertyName("new_password")]
    string NewPassword);
