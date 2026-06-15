using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Data.Scaffolded;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Services;

public sealed class SqlAgentStore : IAgentStore
{
    private static readonly HashSet<string> AllowedDelegatedScopes = new(StringComparer.Ordinal)
    {
        "task_read",
        "task_create",
        "task_comment"
    };

    private readonly IDbContextFactory<OsolabAuthContext> _contextFactory;
    private readonly AttemptLimiter _attempts;

    public SqlAgentStore(IDbContextFactory<OsolabAuthContext> contextFactory, AttemptLimiter attempts)
    {
        _contextFactory = contextFactory;
        _attempts = attempts;
    }

    public AgentCreateResult CreateAgent(
        UserRecord owner,
        string agentName,
        string clientId,
        string scope,
        DateTimeOffset expiresAt)
    {
        ValidateDelegatedScopes(scope);

        string agentId = $"agent_{Helper.GenerateHex(16)}";
        string secret = $"ags_{Helper.GenerateHex(48)}";
        string delegationId = $"del_{Helper.GenerateHex(16)}";
        DateTime now = DateTime.UtcNow;

        var agent = new Agent
        {
            AgentId = agentId,
            OwnerOsolabId = owner.Subject,
            AgentName = agentName,
            SecretHash = PasswordUtil.Hash(secret),
            Status = "active",
            CreateDatetime = now,
            UpdateDatetime = now
        };
        var delegation = new AgentDelegation
        {
            DelegationId = delegationId,
            AgentId = agentId,
            OwnerOsolabId = owner.Subject,
            ClientId = clientId,
            Scope = scope,
            ExpiresDatetime = expiresAt.UtcDateTime,
            CreateDatetime = now,
            Status = 1
        };

        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        db.Agents.Add(agent);
        db.AgentDelegations.Add(delegation);
        db.SaveChanges();

        return new AgentCreateResult(ToRecord(agent), ToRecord(delegation), secret);
    }

    public AgentTokenGrant VerifyTokenRequest(string agentId, string agentSecret, string clientId, string requestedScope)
    {
        string[] requestedScopes = ValidateDelegatedScopes(requestedScope);
        string attemptKey = $"agent_secret:{agentId}";
        _attempts.EnsureAllowed(attemptKey);

        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        Agent? agent = db.Agents.SingleOrDefault(item =>
            item.AgentId == agentId
            && item.Status == "active");
        if (agent is null || !PasswordUtil.Verify(agentSecret, agent.SecretHash))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        DateTime now = DateTime.UtcNow;
        AgentDelegation? delegation = db.AgentDelegations
            .Where(item =>
                item.AgentId == agentId
                && item.ClientId == clientId
                && item.Status == 1
                && item.ExpiresDatetime > now)
            .OrderByDescending(item => item.CreateDatetime)
            .FirstOrDefault();
        if (delegation is null)
        {
            throw Code.UNAUTHORIZED;
        }

        string[] allowedScopes = Helper.ParseScopes(delegation.Scope);
        if (requestedScopes.Any(scope => !allowedScopes.Contains(scope, StringComparer.Ordinal)))
        {
            throw Code.INVALID_SCOPE;
        }

        return new AgentTokenGrant(ToRecord(agent), ToRecord(delegation), string.Join(' ', requestedScopes));
    }

    public AgentSecretRotationResult RotateSecret(UserRecord owner, string agentId)
    {
        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        Agent agent = FindOwnedAgent(db, owner, agentId);
        if (!string.Equals(agent.Status, "active", StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        string secret = $"ags_{Helper.GenerateHex(48)}";
        agent.SecretHash = PasswordUtil.Hash(secret);
        agent.UpdateDatetime = DateTime.UtcNow;
        db.SaveChanges();
        return new AgentSecretRotationResult(ToRecord(agent), secret);
    }

    public AgentRecord RevokeAgent(UserRecord owner, string agentId)
    {
        using OsolabAuthContext db = _contextFactory.CreateDbContext();
        Agent agent = FindOwnedAgent(db, owner, agentId);
        DateTime now = DateTime.UtcNow;
        agent.Status = "revoked";
        agent.RevokedDatetime = now;
        agent.UpdateDatetime = now;
        db.SaveChanges();
        return ToRecord(agent);
    }

    private static Agent FindOwnedAgent(OsolabAuthContext db, UserRecord owner, string agentId)
    {
        return db.Agents.SingleOrDefault(item =>
                item.AgentId == agentId
                && item.OwnerOsolabId == owner.Subject)
            ?? throw Code.UNAUTHORIZED;
    }

    private static string[] ValidateDelegatedScopes(string scope)
    {
        string[] scopes = Helper.ParseScopes(scope);
        if (scopes.Length == 0 || scopes.Any(item => !AllowedDelegatedScopes.Contains(item)))
        {
            throw Code.INVALID_SCOPE;
        }

        return scopes;
    }

    private static AgentRecord ToRecord(Agent agent)
    {
        return new AgentRecord(
            agent.AgentId,
            agent.OwnerOsolabId,
            agent.AgentName,
            agent.SecretHash,
            agent.Status,
            ToOffset(agent.CreateDatetime),
            ToOffset(agent.UpdateDatetime),
            agent.RevokedDatetime is null ? null : ToOffset(agent.RevokedDatetime.Value));
    }

    private static AgentDelegationRecord ToRecord(AgentDelegation delegation)
    {
        return new AgentDelegationRecord(
            delegation.DelegationId,
            delegation.AgentId,
            delegation.OwnerOsolabId,
            delegation.ClientId,
            delegation.Scope,
            ToOffset(delegation.ExpiresDatetime),
            ToOffset(delegation.CreateDatetime));
    }

    private static DateTimeOffset ToOffset(DateTime value)
    {
        return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
    }
}
