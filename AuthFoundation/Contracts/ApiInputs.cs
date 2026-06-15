using System.Text.Json.Serialization;

namespace AuthFoundation.Contracts;

public sealed record AuthorizeRequest(
    string ResponseType,
    string ClientId,
    string RedirectUri,
    string Scope,
    string State,
    string Nonce,
    string CodeChallengeMethod,
    string CodeChallenge);

public sealed record LoginRequest(
    string Email,
    string Password,
    string RequestId);

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

public sealed record CreateAgentRequest(
    [property: JsonPropertyName("owner_email")]
    string OwnerEmail,
    [property: JsonPropertyName("agent_name")]
    string AgentName,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("scope")]
    string Scope,
    [property: JsonPropertyName("expires_days")]
    int ExpiresDays,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record AgentOwnerStepUpRequest(
    [property: JsonPropertyName("owner_email")]
    string OwnerEmail,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record AgentTokenRequest(
    [property: JsonPropertyName("agent_id")]
    string AgentId,
    [property: JsonPropertyName("agent_secret")]
    string AgentSecret,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("scope")]
    string Scope);

public sealed record AgentMeRequest(
    string ClientId,
    string Scope);

public sealed record ResetPasswordStartRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("birth_date")]
    string BirthDate);

public sealed record ResetPasswordRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("birth_date")]
    string BirthDate,
    [property: JsonPropertyName("email_code")]
    string EmailCode,
    [property: JsonPropertyName("new_password")]
    string NewPassword);

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

public sealed record SignupEmailRequest(string Email);

public sealed record SignupVerifyRequest(string Code);

public sealed record SignupAccountRequest(
    string Password,
    string Name,
    string BirthDate,
    string TermsAccepted);

public sealed record EmailRequest(
    [property: JsonPropertyName("email")]
    string Email);

public sealed record SetupAuthenticatorRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record VerifyRequest(
    [property: JsonPropertyName("email")]
    string Email,
    [property: JsonPropertyName("code")]
    string Code);

public sealed record TokenRequest(
    string GrantType,
    string ClientId,
    string Code,
    string CodeVerifier,
    string RedirectUri);

public sealed record RevokeTokenRequest(string Token);

public sealed record UserInfoRequest(string AccessToken);
