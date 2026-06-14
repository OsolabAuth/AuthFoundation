namespace AuthFoundation.Services;

using Microsoft.Extensions.Logging;

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
            "Development email verification code issued. Email={Email}; Code={Code}; ExpiresAt={ExpiresAt:O}",
            email,
            code,
            expiresAt);
    }
}
