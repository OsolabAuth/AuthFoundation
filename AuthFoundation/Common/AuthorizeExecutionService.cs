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
        /// <returns>遷移先 URL</returns>
        public async Task<string> ExecuteAsync(
            AuthRequestSession session,
            string? loginSessionId)
        {
            string sessionId = string.Empty;
            List<string> requestedScopes = Helper.ParseScopes(session.Scope);
            // 要求Scopeの検証
            HashSet<string> requiredScopeSet = await LoadRequiredScopesAsync(session.ClientId);
            CertRequestScope(requiredScopeSet, requestedScopes);

            // ログイン検証
            AuthSession loginSession = new AuthSession();
            await loginSession.ReadFromRedisAsync(_redis, loginSessionId);

            if (loginSession.HasValue)
            {
                //ログイン済みの場合、同意状況の検証を行う
                bool hasTermConsent = await HasRequiredConsentTerm(loginSession.OsolabId, session.ClientId);
                bool hasScopeConsent = await HasRequiredConsentScope(
                    loginSession.OsolabId,
                    session.ClientId,
                    requestedScopes,
                    requiredScopeSet);
                if (hasTermConsent && hasScopeConsent)
                {
                    //同意済みの場合、認可コードの発行を行う
                    AuthCodeSession codeSession = CreateAuthCodeSession(session, loginSession);
                    await codeSession.WriteToRedisAsync(_redis);
                    // 認可セッションは削除する
                    await _redis.DeleteAsync(AuthRequestSession.GetRedisKey(session.SessionId), Code.RedisDbNo.AUTH_REQUEST_SESSION);
                    // リクエストのリダイレクトURIにクエリを付与して、リダイレクトURIを生成
                    Dictionary<string, string> queries = new Dictionary<string, string>
                    {
                        ["code"] = codeSession.Code,
                        ["state"] = session.State
                    };
                    return Helper.BuildRedirectUri(session.RedirectUri, queries);
                }
                // 未同意の場合は、認可セッションを登録し、同意画面にセッションIDを付与してリダイレクトURIを生成
                sessionId = await RegisterAuthRequestSession(_redis, session, loginSession.OsolabId);
                return AuthUiUrl.Build("/terms", sessionId);
            }
            // 未ログインの場合、認可セッションを登録し、ログイン画面にセッションIDを付与してリダイレクトURIを生成
            sessionId = await RegisterAuthRequestSession(_redis, session, string.Empty);
            return AuthUiUrl.Build("/login", sessionId);
        }

        /// <summary>
        /// 認可セッションIDを元に認可処理を再実行します。
        /// </summary>
        /// <param name="authorizationSessionId">認可セッションID</param>
        /// <param name="loginSessionId">ログインセッションID</param>
        /// <returns>遷移先 URL。認可セッションが無効な場合は null</returns>
        public async Task<string?> TryExecuteFromSessionAsync(string authorizationSessionId, string? loginSessionId)
        {
            AuthRequestSession session = await LoadAuthRequestSessionAsync(authorizationSessionId);
            if (string.IsNullOrWhiteSpace(session.SessionId))
            {
                return null;
            }

            return await ExecuteAsync(session, loginSessionId);
        }

        /// <summary>
        /// 認可セッションを読み込みます。
        /// </summary>
        /// <param name="sessionId">認可セッションID</param>
        /// <returns>認可セッション</returns>
        public async Task<AuthRequestSession> LoadAuthRequestSessionAsync(string? sessionId)
        {
            AuthRequestSession session = new AuthRequestSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, sessionId);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                return new AuthRequestSession();
            }

            return session;
        }

        /// <summary>
        /// 認可コードセッションを生成します。
        /// </summary>
        /// <param name="session">認可セッション</param>
        /// <param name="loginSession">ログインセッション</param>
        /// <returns>認可コードセッション</returns>
        public AuthCodeSession CreateAuthCodeSession(AuthRequestSession session, AuthSession loginSession)
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
        /// 認可セッションを発行
        /// </summary>
        /// <param name="redis">Redisクライアント</param>
        /// <param name="session">認可セッション</param>
        /// <param name="osolabId">ユーザーID</param>
        /// <returns></returns>
        public static async Task<string> RegisterAuthRequestSession(IRedisClient redis, AuthRequestSession session, string osolabId)
        {
            if (string.IsNullOrWhiteSpace(session.SessionId))
            {
                session.SessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
            }

            session.OsolabId = osolabId;
            await session.WriteToRedisAsync(redis);
            return session.SessionId;
        }

        /// <summary>
        /// 利用規約への同意を判定
        /// </summary>
        /// <param name="osolabId">Osolab ID</param>
        /// <param name="clientId">クライアントID</param>
        /// <returns>true:規約同意済み,false:未同意規約有</returns>
        private async Task<bool> HasRequiredConsentTerm(string? osolabId, string? clientId)
        {
            List<client_term> clientTerms = await _dbContext.client_terms
                .Where(x => (x.client_id == clientId || x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID)
                    && x.status == Code.Status.ACTIVE
                    && x.required == Code.Status.ACTIVE)
                .ToListAsync();

            List<user_term_consent> userTerms = await _dbContext.user_term_consents
                .Where(x => x.osolab_id == osolabId
                    && (x.client_id == clientId || x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID)
                    && x.consent_result == Code.Status.ACTIVE)
                .ToListAsync();

            return clientTerms.All(ct => userTerms.Any(ut => ut.term_id == ct.term_id && ut.term_version == ct.term_version));
        }

        /// <summary>
        /// スコープ連携への同意を判定
        /// </summary>
        /// <param name="osolabId">Osolab ID</param>
        /// <param name="clientId">クライアントID</param>
        /// <param name="requestedScopes">要求 Scope</param>
        /// <returns></returns>
        private async Task<bool> HasRequiredConsentScope(
            string? osolabId,
            string? clientId,
            List<string> requestedScopes,
            HashSet<string> requiredScopeSet)
        {
            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                return false;
            }

            HashSet<string> agreedScopes = await _dbContext.user_client_scope_consents
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);

            return requiredScopeSet.All(agreedScopes.Contains) && requestedScopes.All(agreedScopes.Contains);
        }

        /// <summary>
        /// 要求scopeの検証
        /// </summary>
        /// <param name="clientId">クライアントID</param>
        /// <param name="requestedScopes">要求 Scope</param>
        private async Task<HashSet<string>> LoadRequiredScopesAsync(string clientId)
        {
            return await _dbContext.client_scopes
                .Where(x => x.client_id == clientId
                    && x.status == Code.Status.ACTIVE
                    && x.required == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);
        }

        private static void CertRequestScope(HashSet<string> requiredScopeSet, List<string> requestedScopes)
        {
            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                throw new ApiException(Code.INVALID_SCOPE, Code.INVALID_SCOPE.ErrorMessage);
            };
        }
    }
}
