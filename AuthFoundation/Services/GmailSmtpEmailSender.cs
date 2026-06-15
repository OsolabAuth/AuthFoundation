using System.Net;
using System.Net.Mail;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class GmailSmtpEmailSender : IEmailSender
{
    /// <summary>
    /// メール認証コードをGmail SMTP経由で送信する。
    /// </summary>
    public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
    {
        using var message = new MailMessage
        {
            From = new MailAddress(AppConfig.MailFromEmail, AppConfig.MailFromName),
            Subject = "AuthFoundation verification code",
            Body = CreateBody(code, expiresAt),
            IsBodyHtml = false
        };
        message.To.Add(email);

        using var client = new SmtpClient(AppConfig.GmailSmtpHost, AppConfig.GmailSmtpPort)
        {
            EnableSsl = AppConfig.GmailSmtpEnableSsl,
            Credentials = new NetworkCredential(AppConfig.GmailSmtpUsername, AppConfig.GmailSmtpAppPassword)
        };
        client.Send(message);
    }

    private static string CreateBody(string code, DateTimeOffset expiresAt)
    {
        return string.Join(
            Environment.NewLine,
            "AuthFoundation verification code",
            string.Empty,
            $"Code: {code}",
            $"Expires at: {expiresAt:O}",
            string.Empty,
            "If you did not request this code, ignore this email.");
    }
}
