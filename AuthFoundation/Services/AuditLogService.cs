using System.Collections.Concurrent;
using System.Text.Json.Serialization;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class AuditLogService
{
    private const int MaxRecords = 500;
    private readonly ConcurrentQueue<AuditLogRecord> _records = new();

    public AuditLogRecord Record(
        string eventType,
        string result,
        string? subject = null,
        string? actorType = null,
        string? clientId = null,
        string? scope = null,
        string? ipAddress = null,
        string? userAgent = null,
        IReadOnlyDictionary<string, string>? metadata = null)
    {
        var record = new AuditLogRecord(
            $"aud_{Helper.GenerateHex(16)}",
            DateTimeOffset.UtcNow,
            eventType,
            result,
            subject,
            actorType,
            clientId,
            scope,
            ipAddress,
            userAgent,
            metadata ?? new Dictionary<string, string>());
        _records.Enqueue(record);
        while (_records.Count > MaxRecords && _records.TryDequeue(out _))
        {
        }

        return record;
    }

    public IReadOnlyList<AuditLogRecord> Latest(int limit = 100)
    {
        int normalizedLimit = Math.Clamp(limit, 1, MaxRecords);
        return _records
            .Reverse()
            .Take(normalizedLimit)
            .ToArray();
    }
}

public sealed record AuditLogRecord(
    [property: JsonPropertyName("audit_log_id")]
    string AuditLogId,
    [property: JsonPropertyName("occurred_at")]
    DateTimeOffset OccurredAt,
    [property: JsonPropertyName("event_type")]
    string EventType,
    [property: JsonPropertyName("result")]
    string Result,
    [property: JsonPropertyName("subject")]
    string? Subject,
    [property: JsonPropertyName("actor_type")]
    string? ActorType,
    [property: JsonPropertyName("client_id")]
    string? ClientId,
    [property: JsonPropertyName("scope")]
    string? Scope,
    [property: JsonPropertyName("ip_address")]
    string? IpAddress,
    [property: JsonPropertyName("user_agent")]
    string? UserAgent,
    [property: JsonPropertyName("metadata")]
    IReadOnlyDictionary<string, string> Metadata);
