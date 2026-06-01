using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("account")]
public sealed class AccountController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly StepUpService _stepUp;

    public AccountController(IUserStore users, StepUpService stepUp)
    {
        _users = users;
        _stepUp = stepUp;
    }

    [HttpPost("password")]
    public IActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.IndispensableParam(request.CurrentPassword, "current_password");
            ValidateUtil.FormatParam(request.NewPassword, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            ValidateUtil.IndispensableParam(request.StepUpToken, "step_up_token");

            UserRecord user = _users.FindByEmail(request.Email);
            StepUpGrant grant = _stepUp.ValidateStepUpToken(request.StepUpToken);
            if (!string.Equals(grant.Subject, user.Subject, StringComparison.Ordinal))
            {
                throw Code.UNAUTHORIZED;
            }

            _users.ChangePassword(request.Email, request.CurrentPassword, request.NewPassword);
            return Ok(new { result = "password_changed" });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("withdrawal")]
    public IActionResult Withdraw([FromBody] WithdrawalRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.IndispensableParam(request.Password, "password");
            ValidateUtil.IndispensableParam(request.StepUpToken, "step_up_token");

            UserRecord user = _users.FindByEmail(request.Email);
            StepUpGrant grant = _stepUp.ValidateStepUpToken(request.StepUpToken);
            if (!string.Equals(grant.Subject, user.Subject, StringComparison.Ordinal))
            {
                throw Code.UNAUTHORIZED;
            }

            _users.Withdraw(request.Email, request.Password);
            return Ok(new { result = "account_withdrawn" });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}

public sealed record ChangePasswordRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("current_password")]
    string CurrentPassword,
    [property: JsonPropertyName("new_password")]
    string NewPassword,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record WithdrawalRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("password")]
    string Password,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);
