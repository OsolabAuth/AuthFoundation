using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("signup")]
public sealed class SignupController : ControllerBase
{
    private const string SignupSessionCookieName = "AuthSignupSessionId";
    private readonly IUserStore _users;
    private readonly TermsService _terms;
    private readonly SignupSessionService _signupSessions;

    public SignupController(IUserStore users, TermsService terms, SignupSessionService? signupSessions = null)
    {
        _users = users;
        _terms = terms;
        _signupSessions = signupSessions ?? new SignupSessionService(new DevelopmentEmailSender(), new AttemptLimiter());
    }

    [HttpPost]
    public IActionResult Post([FromBody] SignupRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.FormatParam(request.Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            ValidateUtil.FormatParam(request.Name, Code.HttpBodies.NAME.Key, Code.HttpBodies.NAME.Regex);
            ValidateUtil.FormatParam(request.BirthDate, Code.HttpBodies.BIRTH_DATE.Key, Code.HttpBodies.BIRTH_DATE.Regex);
            if (!DateOnly.TryParseExact(request.BirthDate, "yyyy-MM-dd", out DateOnly birthDate))
            {
                throw Code.REQUEST_PARAMETER_ERROR;
            }
            RequireTermsConsent(request.TermsAccepted);

            string verifiedEmail = _signupSessions.ConsumeVerifiedEmail(ReadSignupSessionId());
            if (!string.Equals(verifiedEmail, request.Email, StringComparison.OrdinalIgnoreCase))
            {
                throw Code.UNAUTHORIZED;
            }

            TermsDocument terms = _terms.Current();
            UserRecord user = _users.CreateUser(verifiedEmail, request.Password, request.Name, birthDate, acceptedTermsId: terms.TermsId);
            Response.Cookies.Delete(SignupSessionCookieName, SignupCookieOptions(DateTimeOffset.UtcNow));
            return Ok(new
            {
                sub = user.Subject,
                email = user.Email,
                name = user.Name,
                birth_date = user.BirthDate.ToString("yyyy-MM-dd"),
                accepted_terms_id = user.AcceptedTermsId
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("email")]
    public async Task<IActionResult> Email()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string email = form["email"].ToString();
            ValidateUtil.FormatParam(email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);

            SignupEmailChallenge challenge = _signupSessions.StartEmailChallenge(email);
            Response.Cookies.Append(
                SignupSessionCookieName,
                challenge.SessionId,
                SignupCookieOptions(challenge.ExpiresAt));
            return Ok(new
            {
                result = "verification_code_sent",
                delivery = "email",
                email = challenge.Email,
                expires_at = challenge.ExpiresAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("verify")]
    public async Task<IActionResult> Verify()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string code = form["code"].ToString();
            ValidateUtil.FormatParam(code, Code.HttpBodies.EMAIL_CODE.Key, Code.HttpBodies.EMAIL_CODE.Regex);
            SignupVerifiedSession verified = _signupSessions.VerifyEmailChallenge(ReadSignupSessionId(), code);
            Response.Cookies.Append(
                SignupSessionCookieName,
                verified.SessionId,
                SignupCookieOptions(verified.ExpiresAt));
            return Ok(new
            {
                result = "verified",
                email = verified.Email,
                expires_at = verified.ExpiresAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("account")]
    public async Task<IActionResult> Account()
    {
        try
        {
            IFormCollection form = await Request.ReadFormAsync();
            string password = form["password"].ToString();
            string name = form["name"].ToString();
            string birthDateValue = form["birthdate"].ToString();
            string termsAcceptedValue = form["terms_accepted"].ToString();
            ValidateUtil.FormatParam(password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            ValidateUtil.FormatParam(name, Code.HttpBodies.NAME.Key, Code.HttpBodies.NAME.Regex);
            ValidateUtil.FormatParam(birthDateValue, Code.HttpBodies.BIRTH_DATE.Key, Code.HttpBodies.BIRTH_DATE.Regex);
            if (!DateOnly.TryParseExact(birthDateValue, "yyyy-MM-dd", out DateOnly birthDate))
            {
                throw Code.REQUEST_PARAMETER_ERROR;
            }
            RequireTermsConsent(IsTermsAccepted(termsAcceptedValue));

            string email = _signupSessions.ConsumeVerifiedEmail(ReadSignupSessionId());
            TermsDocument terms = _terms.Current();
            UserRecord user = _users.CreateUser(email, password, name, birthDate, acceptedTermsId: terms.TermsId);
            Response.Cookies.Delete(SignupSessionCookieName, SignupCookieOptions(DateTimeOffset.UtcNow));
            string redirectUrl = $"{AppConfig.AuthUiBaseUrl}/login";
            Response.Headers.Location = redirectUrl;
            return Ok(new
            {
                result = "redirect",
                redirect_url = redirectUrl,
                sub = user.Subject,
                email = user.Email,
                name = user.Name,
                birth_date = user.BirthDate.ToString("yyyy-MM-dd"),
                accepted_terms_id = user.AcceptedTermsId
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    private string ReadSignupSessionId()
    {
        string sessionId = Request.Cookies[SignupSessionCookieName] ?? string.Empty;
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw Code.UNAUTHORIZED;
        }

        return sessionId;
    }

    private static bool IsTermsAccepted(string value)
    {
        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "1", StringComparison.Ordinal)
            || string.Equals(value, "on", StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireTermsConsent(bool termsAccepted)
    {
        if (!termsAccepted)
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                "invalid_request",
                "terms consent is required");
        }
    }

    private static CookieOptions SignupCookieOptions(DateTimeOffset expiresAt)
    {
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = expiresAt
        };
    }
}

public sealed record SignupRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("password")]
    string Password,
    [property: JsonPropertyName("name")]
    string Name,
    [property: JsonPropertyName("birth_date")]
    string BirthDate,
    [property: JsonPropertyName("terms_accepted")]
    bool TermsAccepted);
