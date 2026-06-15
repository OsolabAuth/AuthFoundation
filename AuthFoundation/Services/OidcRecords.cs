namespace AuthFoundation.Services;

public sealed record AuthorizationRequestRecord(
    string RequestId,
    string ClientId,
    string RedirectUri,
    string Scope,
    string State,
    string Nonce,
    string CodeChallenge,
    DateTimeOffset ExpiresAt);

public sealed record AuthorizationCodeRecord(
    string Code,
    string ClientId,
    string RedirectUri,
    string Scope,
    string Nonce,
    string CodeChallenge,
    string Subject,
    string Email,
    string Name,
    DateTimeOffset ExpiresAt);

public sealed record AccessTokenRecord(
    string AccessToken,
    string ClientId,
    string Scope,
    string Subject,
    string Email,
    string Name,
    string PrincipalType,
    string OwnerSubject,
    string DelegationId,
    DateTimeOffset ExpiresAt);
