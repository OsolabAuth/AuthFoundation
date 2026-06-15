using AuthFoundation.Services;
using Microsoft.Extensions.Logging;

namespace AuthFoundation.Services;

public sealed class DevelopmentEmailSender : IEmailSender
{
    private readonly ILogger<DevelopmentEmailSender>? _logger;

    public DevelopmentEmailSender()
    {
    }

    public DevelopmentEmailSender(ILogger<DevelopmentEmailSender> logger)
    {
        _logger = logger;
    }

    public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
    {
        _logger?.LogInformation(
            "Development email code issued for {Email}. Code={Code} ExpiresAt={ExpiresAt}",
            email,
            code,
            expiresAt.ToString("O"));
    }
}
