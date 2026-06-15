using AuthFoundation.Common;
using AuthFoundation.Contracts;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;

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
            return Ok(new MfaEmailStartOutput("challenge_created", "email", challenge.Email, challenge.ExpiresAt));
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
    public IActionResult SetupAuthenticator([FromBody] SetupAuthenticatorRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.IndispensableParam(request.StepUpToken, "step_up_token");
            AuthenticatorSetup setup = _stepUp.SetupAuthenticator(request.Email, request.StepUpToken);
            return Ok(new AuthenticatorSetupOutput(setup.Email, setup.Secret, setup.OtpAuthUri));
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
            return Ok(new StepUpTokenOutput(grant.StepUpToken, "StepUp", grant.ExpiresAt, grant.Method));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }
}
