using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class RedisOidcStoreTests
{
    /// <summary>
    /// Redis-backed stores share authorization requests across application instances.
    /// </summary>
    [TestMethod]
    public void TakeRequest_ReturnsRequestCreatedByAnotherStore()
    {
        var redis = new FakeRedisStringStore();
        var writer = new RedisOidcStore(redis);
        var reader = new RedisOidcStore(redis);
        AuthorizationRequestRecord request = CreateRequest(writer);

        AuthorizationRequestRecord actual = reader.TakeRequest(request.RequestId);

        Assert.AreEqual(request.RequestId, actual.RequestId);
        Assert.AreEqual(AppConfig.DevelopmentClientId, actual.ClientId);
        Assert.ThrowsExactly<ApiException>(() => reader.TakeRequest(request.RequestId));
    }

    /// <summary>
    /// Redis-backed authorization codes remain one-time use across application instances.
    /// </summary>
    [TestMethod]
    public void TakeCode_ReturnsCodeCreatedByAnotherStoreOnlyOnce()
    {
        var redis = new FakeRedisStringStore();
        var writer = new RedisOidcStore(redis);
        var reader = new RedisOidcStore(redis);
        AuthorizationCodeRecord code = writer.CreateCode(
            CreateRequest(writer),
            "subject_1",
            "subject@example.com",
            "Subject One");

        AuthorizationCodeRecord actual = reader.TakeCode(code.Code);

        Assert.AreEqual(code.Code, actual.Code);
        Assert.AreEqual("subject_1", actual.Subject);
        ApiException error = Assert.ThrowsExactly<ApiException>(() => reader.TakeCode(code.Code));
        Assert.AreEqual("invalid_grant", error.Error);
    }

    /// <summary>
    /// Redis-backed access tokens can be validated and revoked across application instances.
    /// </summary>
    [TestMethod]
    public void FindAndRevokeAccessToken_UsesSharedRedisState()
    {
        var redis = new FakeRedisStringStore();
        var writer = new RedisOidcStore(redis);
        var reader = new RedisOidcStore(redis);
        AccessTokenRecord token = writer.CreateAccessToken(CreateCode(writer));

        AccessTokenRecord actual = reader.FindAccessToken(token.AccessToken);
        bool revoked = reader.RevokeAccessToken(token.AccessToken);

        Assert.AreEqual(token.AccessToken, actual.AccessToken);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.IsTrue(revoked);
        Assert.ThrowsExactly<ApiException>(() => writer.FindAccessToken(token.AccessToken));
    }

    /// <summary>
    /// Redis-backed auth sessions can be read and revoked across application instances for browser SSO.
    /// </summary>
    [TestMethod]
    public void FindAndRevokeAuthSession_UsesSharedRedisState()
    {
        var redis = new FakeRedisStringStore();
        var writer = new RedisOidcStore(redis);
        var reader = new RedisOidcStore(redis);
        AuthSessionRecord session = writer.CreateAuthSession("subject_1", "subject@example.com", "Subject One");

        AuthSessionRecord? actual = reader.FindAuthSession(session.SessionId);
        bool revoked = reader.RevokeAuthSession(session.SessionId);

        Assert.IsNotNull(actual);
        Assert.AreEqual(session.SessionId, actual.SessionId);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.IsTrue(revoked);
        Assert.IsNull(writer.FindAuthSession(session.SessionId));
    }

    /// <summary>
    /// Redis-backed agent access tokens preserve delegated principal claims.
    /// </summary>
    [TestMethod]
    public void CreateAgentAccessToken_StoresDelegatedPrincipalClaims()
    {
        var redis = new FakeRedisStringStore();
        var store = new RedisOidcStore(redis);
        var agent = new AgentRecord(
            "agent_1",
            "owner_1",
            "Issue Agent",
            "secret_hash",
            "active",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null);
        var delegation = new AgentDelegationRecord(
            "delegation_1",
            "agent_1",
            "owner_1",
            AppConfig.DevelopmentClientId,
            "task_read task_comment",
            DateTimeOffset.UtcNow.AddDays(1),
            DateTimeOffset.UtcNow);

        AccessTokenRecord token = store.CreateAgentAccessToken(agent, delegation, "task_read");
        AccessTokenRecord actual = store.FindAccessToken(token.AccessToken);

        StringAssert.StartsWith(actual.AccessToken, "agt_");
        Assert.AreEqual("ai_agent", actual.PrincipalType);
        Assert.AreEqual("owner_1", actual.OwnerSubject);
        Assert.AreEqual("delegation_1", actual.DelegationId);
        Assert.AreEqual("task_read", actual.Scope);
    }

    private static AuthorizationCodeRecord CreateCode(RedisOidcStore store)
    {
        return store.CreateCode(CreateRequest(store), "subject_1", "subject@example.com", "Subject One");
    }

    private static AuthorizationRequestRecord CreateRequest(RedisOidcStore store)
    {
        return store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
    }

    private sealed class FakeRedisStringStore : IRedisStringStore
    {
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

        public void SetString(string key, string value, TimeSpan expiresIn)
        {
            _entries[key] = new Entry(value, DateTimeOffset.UtcNow.Add(expiresIn));
        }

        public bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn)
        {
            if (GetString(key) is not null)
            {
                return false;
            }

            SetString(key, value, expiresIn);
            return true;
        }

        public string? GetString(string key)
        {
            if (!_entries.TryGetValue(key, out Entry? entry))
            {
                return null;
            }

            if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                _entries.Remove(key);
                return null;
            }

            return entry.Value;
        }

        public string? TakeString(string key)
        {
            string? value = GetString(key);
            _entries.Remove(key);
            return value;
        }

        public bool DeleteString(string key)
        {
            return _entries.Remove(key);
        }

        private sealed record Entry(string Value, DateTimeOffset ExpiresAt);
    }
}
