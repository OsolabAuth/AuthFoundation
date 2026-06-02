namespace AuthFoundation.Services;

public sealed class DevelopmentEmailSender : IEmailSender
{
    public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
    {
    }
}
