using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class InMemoryOidcStore
{
    private static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, AuthorizationRequestRecord> _requests = new();
    private readonly ConcurrentDictionary<string, AuthorizationCodeRecord> _codes = new();

    /// <summary>
    /// 認可リクエストを一時保存し、request_id付きのレコードを返却する。
    /// </summary>
    /// <param name="clientId">認可要求元のclient_id。</param>
    /// <param name="redirectUri">認可コード返却先のredirect_uri。</param>
    /// <param name="scope">要求scope文字列。</param>
    /// <param name="state">CSRF対策用state。</param>
    /// <param name="nonce">ID Token紐づけ用nonce。</param>
    /// <param name="codeChallenge">PKCE S256 code_challenge。</param>
    /// <returns>保存済み認可リクエストレコード。</returns>
    public AuthorizationRequestRecord CreateRequest(
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string codeChallenge)
    {
        string requestId = Helper.GenerateHex(32);
        var record = new AuthorizationRequestRecord(
            requestId,
            clientId,
            redirectUri,
            scope,
            state,
            nonce,
            codeChallenge,
            DateTimeOffset.UtcNow.Add(RequestLifetime));
        _requests[requestId] = record;
        return record;
    }

    /// <summary>
    /// 認可リクエストを取得し、ストアから削除する。
    /// </summary>
    /// <param name="requestId">取得対象の認可リクエストID。</param>
    /// <returns>取得済み認可リクエストレコード。</returns>
    public AuthorizationRequestRecord TakeRequest(string requestId)
    {
        if (!_requests.TryRemove(requestId, out AuthorizationRequestRecord? record)
            || record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return record;
    }

    /// <summary>
    /// 認証済みユーザー情報に紐づく認可コードを作成する。
    /// </summary>
    /// <param name="request">消費済み認可リクエスト。</param>
    /// <param name="subject">認証済みユーザーのsubject。</param>
    /// <param name="email">認証済みユーザーのメールアドレス。</param>
    /// <param name="name">認証済みユーザーの表示名。</param>
    /// <returns>保存済み認可コードレコード。</returns>
    public AuthorizationCodeRecord CreateCode(AuthorizationRequestRecord request, string subject, string email, string name)
    {
        string code = Helper.GenerateHex(64);
        var record = new AuthorizationCodeRecord(
            code,
            request.ClientId,
            request.RedirectUri,
            request.Scope,
            request.Nonce,
            request.CodeChallenge,
            subject,
            email,
            name,
            DateTimeOffset.UtcNow.Add(CodeLifetime));
        _codes[code] = record;
        return record;
    }

    /// <summary>
    /// 認可コードを取得し、ストアから削除する。
    /// </summary>
    /// <param name="code">取得対象の認可コード。</param>
    /// <returns>取得済み認可コードレコード。</returns>
    public AuthorizationCodeRecord TakeCode(string code)
    {
        if (!_codes.TryRemove(code, out AuthorizationCodeRecord? record)
            || record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                "invalid_grant",
                "invalid authorization code");
        }

        return record;
    }
}

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
