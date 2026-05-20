using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundationTest.TestSupport;

internal static class ApiTestData
{
    public static async Task AssertDatabaseAvailableAsync(OsolabAuthContext context)
    {
        Assert.IsTrue(
            await context.Database.CanConnectAsync(),
            "SQL Server is not available. Run the SQL folder initialization before this test.");
    }

    public static string NewClientId()
    {
        return RandomNumberGenerator.GetInt32(100000000, 999999999).ToString()
            + RandomNumberGenerator.GetInt32(100000000, 999999999)
            + RandomNumberGenerator.GetInt32(100000000, 999999999)
            + RandomNumberGenerator.GetInt32(10000, 99999);
    }

    public static string NewOsolabId()
    {
        return Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
    }

    public static string NewPassword()
    {
        return $"Password{RandomNumberGenerator.GetInt32(100000, 999999)}";
    }

    public static string Sha256Hex(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    public static string CodeChallengeFor(string verifier)
    {
        byte[] bytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static async Task<client_master> CreateClientAsync(
        OsolabAuthContext context,
        string clientId,
        string clientSecret = "secret",
        string redirectUri = "https://portal.osolab-auth.jp/callback",
        params string[] requiredScopes)
    {
        DateTime now = DateTime.UtcNow;
        var client = new client_master
        {
            client_id = clientId,
            client_name = $"test-client-{clientId}",
            client_secret = clientSecret,
            create_datetime = now,
            update_datetime = now,
            status = Code.Status.ACTIVE
        };

        context.client_masters.Add(client);
        context.client_redirect_uris.Add(new client_redirect_uri
        {
            client_id = clientId,
            redirect_uri = redirectUri,
            is_default = Code.Status.ACTIVE,
            create_datetime = now,
            update_datetime = now,
            status = Code.Status.ACTIVE
        });

        foreach (string scope in requiredScopes.Distinct(StringComparer.Ordinal))
        {
            context.client_scopes.Add(new client_scope
            {
                client_id = clientId,
                scope = scope,
                required = Code.Status.ACTIVE,
                create_datetime = now,
                update_datetime = now,
                status = Code.Status.ACTIVE
            });
        }

        await context.SaveChangesAsync();
        return client;
    }

    public static async Task<osolab_user> CreateUserAsync(
        OsolabAuthContext context,
        string osolabId,
        string email,
        string password,
        byte status = Code.Status.ACTIVE)
    {
        string nonce = Helper.GenerateRandomCode(Code.Nonce.LENGTH, Code.Nonce.CHARACTORS);
        string storedPasswordHash = Helper.GetPassHash(password, nonce);
        DateTime now = DateTime.UtcNow;

        var user = new osolab_user
        {
            osolab_id = osolabId,
            email = email,
            password = storedPasswordHash,
            nonce = nonce,
            create_datetime = now,
            update_datetime = now,
            status = status
        };

        context.osolab_users.Add(user);
        await context.SaveChangesAsync();
        return user;
    }

    public static async Task AddScopeConsentsAsync(
        OsolabAuthContext context,
        string osolabId,
        string clientId,
        params string[] scopes)
    {
        DateTime now = DateTime.UtcNow;
        foreach (string scope in scopes)
        {
            context.user_client_scope_consents.Add(new user_client_scope_consent
            {
                osolab_id = osolabId,
                client_id = clientId,
                scope = scope,
                consented_datetime = now,
                create_datetime = now,
                update_datetime = now,
                status = Code.Status.ACTIVE
            });
        }

        await context.SaveChangesAsync();
    }

    public static async Task<client_term> CreateRequiredTermAsync(
        OsolabAuthContext context,
        string clientId,
        string termId)
    {
        DateTime now = DateTime.UtcNow;
        var term = new client_term
        {
            client_id = clientId,
            term_id = termId,
            term_version = "1",
            term_url = $"https://portal.osolab-auth.jp/terms/{termId}",
            required = Code.Status.ACTIVE,
            create_datetime = now,
            update_datetime = now,
            status = Code.Status.ACTIVE
        };

        context.client_terms.Add(term);
        await context.SaveChangesAsync();
        return term;
    }

    public static AuthorizationSession CreateAuthorizationSession(
        string sessionId,
        string clientId,
        string redirectUri,
        string scope = "openid email",
        string osolabId = "")
    {
        return new AuthorizationSession
        {
            SessionId = sessionId,
            ResponseType = "code",
            ClientId = clientId,
            RedirectUri = redirectUri,
            State = "state-api-test",
            Scope = scope,
            CodeChallengeMethod = "S256",
            CodeChallenge = CodeChallengeFor(new string('v', 64)),
            Nonce = "nonce-api-test",
            OsolabId = osolabId
        };
    }

    public static async Task<string> WriteAuthorizationSessionAsync(
        FakeRedisClient redis,
        AuthorizationSession session)
    {
        await session.WriteToRedisAsync(redis);
        return session.SessionId;
    }

    public static async Task<string> WriteLoginSessionAsync(
        FakeRedisClient redis,
        string osolabId,
        string email,
        string clientId = "")
    {
        string sessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        var session = new AuthSession(sessionId, osolabId, email, clientId);
        await session.WriteToRedisAsync(redis);
        return sessionId;
    }
}
