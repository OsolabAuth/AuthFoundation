namespace AuthFoundation.Services;

public interface IEmailSender
{
    void SendMfaCode(string email, string code, DateTimeOffset expiresAt);
}
