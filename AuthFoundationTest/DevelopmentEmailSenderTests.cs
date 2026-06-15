using AuthFoundation.Services;
using Microsoft.Extensions.Logging;

namespace AuthFoundationTest;

[TestClass]
public sealed class DevelopmentEmailSenderTests
{
    /// <summary>
    /// Purpose: make local screen-based email-code scenarios executable without a real mailbox.
    /// Input: development email sender with a logger, test email, verification code, and expiry.
    /// Expected: the sender writes the email, code, and expiry to the development log.
    /// </summary>
    [TestMethod]
    public void SendMfaCode_LogsDevelopmentCode()
    {
        var logger = new CapturingLogger<DevelopmentEmailSender>();
        var sender = new DevelopmentEmailSender(logger);
        DateTimeOffset expiresAt = DateTimeOffset.Parse("2026-06-14T08:18:38Z");

        sender.SendMfaCode("screen-test@example.com", "123456", expiresAt);

        Assert.AreEqual(1, logger.Messages.Count);
        string log = logger.Messages[0];
        StringAssert.Contains(log, "screen-test@example.com");
        StringAssert.Contains(log, "123456");
        StringAssert.Contains(log, "2026-06-14");
    }

    /// <summary>
    /// Purpose: keep tests and direct service construction independent from logging infrastructure.
    /// Input: development email sender constructed without a logger.
    /// Expected: sending a code does not throw.
    /// </summary>
    [TestMethod]
    public void SendMfaCode_AllowsMissingLogger()
    {
        var sender = new DevelopmentEmailSender();

        sender.SendMfaCode("screen-test@example.com", "123456", DateTimeOffset.UtcNow);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
        {
            return null;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }
}
