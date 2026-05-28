using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("signup")]
public sealed class SignupController : ControllerBase
{
    private readonly InMemoryUserStore _users;
    private readonly TermsService _terms;

    public SignupController(InMemoryUserStore users, TermsService terms)
    {
        _users = users;
        _terms = terms;
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
            if (!request.TermsAccepted)
            {
                throw new ApiException(
                    Code.REQUEST_PARAMETER_ERROR.InternalCode,
                    Code.REQUEST_PARAMETER_ERROR.StatusCode,
                    "invalid_request",
                    "terms consent is required");
            }

            TermsDocument terms = _terms.Current();
            UserRecord user = _users.CreateUser(request.Email, request.Password, request.Name, birthDate, acceptedTermsId: terms.TermsId);
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
