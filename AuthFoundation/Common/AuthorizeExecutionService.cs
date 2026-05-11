using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Common
{
    /// <summary>
    /// Authorize の実行処理を提供します。
    /// </summary>
    public class AuthorizeExecutionService
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>
        /// AuthorizeExecutionService を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        public AuthorizeExecutionService(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        /// <summary>
        /// 認可処理を実行し、遷移先 URL を返します。
        /// </summary>
        /// <param name="session">認可セッション</param>
        /// <param name="loginSessionId">ログインセッションID</param>
        /// <param name="reuseAuthorizationSession">既存認可セッションを再利用するかどうか</param>
        /// <returns>遷移先 URL</returns>
        public async Task<string> ExecuteAsync(
            AuthorizationSession session,
            string? loginSessionId,
            bool reuseAuthorizationSession = false)
        {
            AuthSession? loginSession = await LoadLoginSessionAsync(loginSessionId);
            bool hasConsent = loginSession != null
                && await HasRequiredConsentAsync(loginSession.OsolabId, session.ClientId, session.Scope);

            if (loginSession != null && hasConsent)
            {
                AuthCodeSession codeSession = CreateAuthCodeSession(session, loginSession);
                await codeSession.WriteToRedisAsync(_redis);

                return Helper.BuildRedirectUri(session.RedirectUri, new Dictionary<string, string>
                {
                    ["code"] = codeSession.Code,
                    ["state"] = session.State
                });
            }

            if (!reuseAuthorizationSession || string.IsNullOrWhiteSpace(session.SessionId))
            {
                session.SessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
            }

            session.OsolabId = loginSession?.OsolabId ?? string.Empty;
            await session.WriteToRedisAsync(_redis);

            if (loginSession == null)
            {
                return $"/login?session_id={Uri.EscapeDataString(session.SessionId)}";
            }

            return $"/terms/view?session_id={Uri.EscapeDataString(session.SessionId)}";
        }

        /// <summary>
        /// 認可セッションIDを元に認可処理を再実行します。
        /// </summary>
        /// <param name="authorizationSessionId">認可セッションID</param>
        /// <param name="loginSessionId">ログインセッションID</param>
        /// <returns>遷移先 URL。認可セッションが無効な場合は null</returns>
        public async Task<string?> TryExecuteFromSessionAsync(string authorizationSessionId, string? loginSessionId)
        {
            AuthorizationSession session = await LoadAuthorizationSessionAsync(authorizationSessionId);
            if (string.IsNullOrWhiteSpace(session.SessionId))
            {
                return null;
            }

            return await ExecuteAsync(session, loginSessionId, true);
        }

        /// <summary>
        /// 認可セッションを読み込みます。
        /// </summary>
        /// <param name="sessionId">認可セッションID</param>
        /// <returns>認可セッション</returns>
        public async Task<AuthorizationSession> LoadAuthorizationSessionAsync(string? sessionId)
        {
            AuthorizationSession session = new AuthorizationSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, sessionId);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                return new AuthorizationSession();
            }

            return session;
        }

        /// <summary>
        /// 認可コードセッションを生成します。
        /// </summary>
        /// <param name="session">認可セッション</param>
        /// <param name="loginSession">ログインセッション</param>
        /// <returns>認可コードセッション</returns>
        public AuthCodeSession CreateAuthCodeSession(AuthorizationSession session, AuthSession loginSession)
        {
            return new AuthCodeSession
            {
                Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
                OsolabId = loginSession.OsolabId,
                Email = loginSession.Email,
                ClientId = session.ClientId,
                RedirectUri = session.RedirectUri,
                Scope = session.Scope,
                CodeChallenge = session.CodeChallenge,
                CodeChallengeMethod = session.CodeChallengeMethod,
                Nonce = session.Nonce,
                State = session.State
            };
        }

        /// <summary>
        /// ログインセッションを読み込みます。
        /// </summary>
        /// <param name="sessionId">ログインセッションID</param>
        /// <returns>ログインセッション</returns>
        private async Task<AuthSession?> LoadLoginSessionAsync(string? sessionId)
        {
            AuthSession session = new AuthSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, sessionId);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                return null;
            }

            return session;
        }

        /// <summary>
        /// 必須同意がそろっているか判定します。
        /// </summary>
        /// <param name="osolabId">Osolab ID</param>
        /// <param name="clientId">クライアントID</param>
        /// <param name="requestedScope">要求 Scope</param>
        /// <returns>同意済みの場合は true</returns>
        private async Task<bool> HasRequiredConsentAsync(string osolabId, string clientId, string requestedScope)
        {
            string[] requestedScopes = Helper.ParseScopes(requestedScope);

            List<client_term> requiredTerms = await _dbContext.client_terms
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .ToListAsync();

            List<user_term> agreedTermRows = await _dbContext.user_terms
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .ToListAsync();

            if (!requiredTerms.All(rt => agreedTermRows.Any(ut => ut.term_id == rt.term_id && ut.term_version == rt.term_version)))
            {
                return false;
            }

            HashSet<string> requiredScopeSet = await _dbContext.client_scopes
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);

            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                return false;
            }

            HashSet<string> agreedScopes = await _dbContext.user_client_scopes
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);

            return requiredScopeSet.All(agreedScopes.Contains) && requestedScopes.All(agreedScopes.Contains);
        }
    }
}
