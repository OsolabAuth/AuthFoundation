using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuditEndpointShapeTests
{
    [TestMethod]
    public void Get_ReturnsLatestAuditLogs()
    {
        var auditLogs = new AuditLogService();
        AuditLogRecord first = auditLogs.Record("first.event", "success", "subject_1");
        AuditLogRecord second = auditLogs.Record("second.event", "success", "subject_2");
        var controller = EndpointTestHelper.WithHttpContext(new AuditController(auditLogs));

        var ok = EndpointTestHelper.AssertOk(controller.Get(1));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        IReadOnlyList<AuditLogRecord> logs = EndpointTestHelper.ReadProperty<IReadOnlyList<AuditLogRecord>>(ok.Value, "logs");
        Assert.AreEqual(1, logs.Count);
        Assert.AreEqual(second.AuditLogId, logs[0].AuditLogId);
        Assert.AreNotEqual(first.AuditLogId, logs[0].AuditLogId);
    }
}
