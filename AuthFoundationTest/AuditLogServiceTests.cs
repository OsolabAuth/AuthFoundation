using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuditLogServiceTests
{
    [TestMethod]
    public void Latest_ReturnsNewestRecordsFirst()
    {
        var auditLogs = new AuditLogService();

        AuditLogRecord first = auditLogs.Record("first.event", "success", "subject_1");
        AuditLogRecord second = auditLogs.Record("second.event", "success", "subject_2");

        IReadOnlyList<AuditLogRecord> latest = auditLogs.Latest(10);

        Assert.AreEqual(second.AuditLogId, latest[0].AuditLogId);
        Assert.AreEqual(first.AuditLogId, latest[1].AuditLogId);
    }

    [TestMethod]
    public void Latest_ClampsLimitToAtLeastOne()
    {
        var auditLogs = new AuditLogService();
        AuditLogRecord record = auditLogs.Record("event", "success", "subject_1");

        IReadOnlyList<AuditLogRecord> latest = auditLogs.Latest(0);

        Assert.AreEqual(1, latest.Count);
        Assert.AreEqual(record.AuditLogId, latest[0].AuditLogId);
    }

    [TestMethod]
    public void Record_StoresMetadataAndOptionalFields()
    {
        var auditLogs = new AuditLogService();

        AuditLogRecord record = auditLogs.Record(
            "agent.token_issued",
            "success",
            "agent_1",
            "ai_agent",
            "30000000000000000000000000000001",
            "task_read",
            "127.0.0.1",
            "test-agent",
            new Dictionary<string, string> { ["owner_sub"] = "user_1" });

        Assert.IsTrue(record.AuditLogId.StartsWith("aud_", StringComparison.Ordinal));
        Assert.IsTrue(record.OccurredAt <= DateTimeOffset.UtcNow);
        Assert.AreEqual("agent.token_issued", record.EventType);
        Assert.AreEqual("success", record.Result);
        Assert.AreEqual("agent_1", record.Subject);
        Assert.AreEqual("ai_agent", record.ActorType);
        Assert.AreEqual("30000000000000000000000000000001", record.ClientId);
        Assert.AreEqual("task_read", record.Scope);
        Assert.AreEqual("127.0.0.1", record.IpAddress);
        Assert.AreEqual("test-agent", record.UserAgent);
        Assert.AreEqual("user_1", record.Metadata["owner_sub"]);
    }

    [TestMethod]
    public void Record_TrimsOldRecordsAtCapacity()
    {
        var auditLogs = new AuditLogService();

        for (int i = 0; i < 501; i++)
        {
            auditLogs.Record($"event.{i}", "success", $"subject_{i}");
        }

        IReadOnlyList<AuditLogRecord> latest = auditLogs.Latest(500);

        Assert.AreEqual(500, latest.Count);
        Assert.AreEqual("event.500", latest[0].EventType);
        Assert.IsFalse(latest.Any(item => item.EventType == "event.0"));
    }
}
