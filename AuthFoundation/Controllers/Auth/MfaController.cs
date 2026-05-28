using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("mfa")]
public sealed class MfaController : ControllerBase
{
    private readonly StepUpService _stepUp;

    public MfaController(StepUpService stepUp)
    {
        _stepUp = stepUp;
    }

    [HttpPost("email/start")]
    public IActionResult StartEmail([FromBody] EmailRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            MfaEmailChallenge challenge = _stepUp.StartEmailChallenge(request.Email);
            return Ok(new
            {
                result = "challenge_created",
                delivery = "development_response",
                email = challenge.Email,
                code = challenge.Code,
                expires_at = challenge.ExpiresAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("email/verify")]
    public IActionResult VerifyEmail([FromBody] VerifyRequest request)
    {
        return Verify(() => _stepUp.VerifyEmailChallenge(request.Email, request.Code));
    }

    [HttpPost("authenticator/setup")]
    public IActionResult SetupAuthenticator([FromBody] EmailRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            AuthenticatorSetup setup = _stepUp.SetupAuthenticator(request.Email);
            return Ok(new
            {
                email = setup.Email,
                secret = setup.Secret,
                otpauth_uri = setup.OtpAuthUri
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("authenticator/verify")]
    public IActionResult VerifyAuthenticator([FromBody] VerifyRequest request)
    {
        return Verify(() => _stepUp.VerifyAuthenticator(request.Email, request.Code));
    }

    private IActionResult Verify(Func<StepUpGrant> verify)
    {
        try
        {
            StepUpGrant grant = verify();
            return Ok(new
            {
                step_up_token = grant.StepUpToken,
                token_type = "StepUp",
                expires_at = grant.ExpiresAt,
                method = grant.Method
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}

public sealed record EmailRequest(
    [property: JsonPropertyName("email")]
    string Email);

public sealed record VerifyRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("code")]
    string Code);
