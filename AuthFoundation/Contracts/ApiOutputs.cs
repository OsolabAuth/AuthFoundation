using System.Text.Json.Serialization;
namespace AuthFoundation.Contracts;

public sealed record ResultOutput(string result);

public sealed record RedirectOutput(
    string result,
    [property: JsonPropertyName("redirect_url")] string redirect_url,
    [property: JsonPropertyName("authorization_code")] string? authorization_code = null);

public sealed record PasswordResetStartOutput(string result, string delivery);

public sealed record SignupAccountOutput(
    string sub,
    string email,
    string name,
    [property: JsonPropertyName("birth_date")] string birth_date,
    [property: JsonPropertyName("accepted_terms_id")] string? accepted_terms_id);

public sealed record SignupAccountRedirectOutput(
    string result,
    [property: JsonPropertyName("redirect_url")] string redirect_url,
    string sub,
    string email,
    string name,
    [property: JsonPropertyName("birth_date")] string birth_date,
    [property: JsonPropertyName("accepted_terms_id")] string? accepted_terms_id);

public sealed record SignupEmailOutput(
    string result,
    string delivery,
    string email,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at);

public sealed record SignupVerifyOutput(
    string result,
    string email,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at);

public sealed record MfaEmailStartOutput(
    string result,
    string delivery,
    string email,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at);

public sealed record AuthenticatorSetupOutput(
    string email,
    string secret,
    [property: JsonPropertyName("otpauth_uri")] string otpauth_uri);

public sealed record StepUpTokenOutput(
    [property: JsonPropertyName("step_up_token")] string step_up_token,
    [property: JsonPropertyName("token_type")] string token_type,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at,
    string method);

public sealed record AgentCreateOutput(
    [property: JsonPropertyName("agent_id")] string agent_id,
    [property: JsonPropertyName("agent_secret")] string agent_secret,
    [property: JsonPropertyName("delegation_id")] string delegation_id,
    string scope,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at);

public sealed record AgentSecretOutput(
    [property: JsonPropertyName("agent_id")] string agent_id,
    [property: JsonPropertyName("agent_secret")] string agent_secret,
    [property: JsonPropertyName("rotated_at")] DateTimeOffset rotated_at);

public sealed record AgentRevokeOutput(
    [property: JsonPropertyName("agent_id")] string agent_id,
    string status,
    [property: JsonPropertyName("revoked_at")] DateTimeOffset? revoked_at);

public sealed record AgentMeOutput(
    [property: JsonPropertyName("principal_type")] string principal_type,
    [property: JsonPropertyName("agent_id")] string agent_id,
    [property: JsonPropertyName("agent_name")] string agent_name,
    [property: JsonPropertyName("owner_sub")] string owner_sub,
    [property: JsonPropertyName("delegation_id")] string delegation_id,
    [property: JsonPropertyName("client_id")] string client_id,
    string scope,
    [property: JsonPropertyName("expires_at")] DateTimeOffset expires_at,
    string status);

public sealed record TermsCurrentOutput(
    [property: JsonPropertyName("terms_id")] string terms_id,
    string version,
    string title,
    string body,
    [property: JsonPropertyName("client_id")] string client_id);

public sealed record FeaturesOutput(string service, string status, FeatureInfo[] features);

public sealed record FeatureInfo(
    string Key,
    string Name,
    string Status,
    string Description);

public sealed record VersionOutput(string service, string version, string status);

public sealed record DiscoveryOutput(
    string issuer,
    [property: JsonPropertyName("authorization_endpoint")] string authorization_endpoint,
    [property: JsonPropertyName("token_endpoint")] string token_endpoint,
    [property: JsonPropertyName("userinfo_endpoint")] string userinfo_endpoint,
    [property: JsonPropertyName("jwks_uri")] string jwks_uri,
    [property: JsonPropertyName("response_types_supported")] string[] response_types_supported,
    [property: JsonPropertyName("grant_types_supported")] string[] grant_types_supported,
    [property: JsonPropertyName("subject_types_supported")] string[] subject_types_supported,
    [property: JsonPropertyName("id_token_signing_alg_values_supported")] string[] id_token_signing_alg_values_supported,
    [property: JsonPropertyName("scopes_supported")] string[] scopes_supported,
    [property: JsonPropertyName("token_endpoint_auth_methods_supported")] string[] token_endpoint_auth_methods_supported,
    [property: JsonPropertyName("code_challenge_methods_supported")] string[] code_challenge_methods_supported,
    [property: JsonPropertyName("claims_supported")] string[] claims_supported);

public sealed record JwksOutput(JwkOutput[] keys);

public sealed record JwkOutput(
    string kty,
    string use,
    string kid,
    string alg,
    string n,
    string e);

public sealed record TokenOutput(
    [property: JsonPropertyName("access_token")] string access_token,
    [property: JsonPropertyName("id_token")] string id_token,
    [property: JsonPropertyName("token_type")] string token_type,
    [property: JsonPropertyName("expires_in")] int expires_in,
    string scope);

public sealed record AgentTokenOutput(
    [property: JsonPropertyName("access_token")] string access_token,
    [property: JsonPropertyName("id_token")] string id_token,
    [property: JsonPropertyName("token_type")] string token_type,
    [property: JsonPropertyName("expires_in")] int expires_in,
    string scope);

public sealed class UserInfoOutput : Dictionary<string, string>
{
}
