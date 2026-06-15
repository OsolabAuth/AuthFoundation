using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class ExampleDomainEmailSender : IEmailSender
{
    private readonly ILogger<ExampleDomainEmailSender> _logger;

    public ExampleDomainEmailSender(ILogger<ExampleDomainEmailSender> logger)
    {
        _logger = logger;
    }

    public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
    {
        if (!IsVerificationAddress(email))
        {
            throw new ApiException(
                Code.INTERNAL_SERVER_ERROR.InternalCode,
                Code.INTERNAL_SERVER_ERROR.StatusCode,
                "mail_not_configured",
                "mail sender is not configured for non-example domains");
        }

        _logger.LogInformation(
            "Verification email code issued for {Email}. Code={Code} ExpiresAt={ExpiresAt}",
            email,
            code,
            expiresAt);
    }

    private static bool IsVerificationAddress(string email)
    {
        return email.EndsWith("@example.com", StringComparison.OrdinalIgnoreCase)
            || email.EndsWith("@example.org", StringComparison.OrdinalIgnoreCase)
            || email.EndsWith("@example.net", StringComparison.OrdinalIgnoreCase);
    }
}
