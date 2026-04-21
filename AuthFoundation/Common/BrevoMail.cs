using System.Text;
using System.Text.Json;

public class BrevoMail
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly string _senderEmail;
    private readonly string _senderName;

    public BrevoMail(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;

        _apiKey = config["Brevo:ApiKey"]
                  ?? throw new InvalidOperationException("ApiKey missing");

        _senderEmail = config["Brevo:SenderEmail"]
                       ?? throw new InvalidOperationException("SenderEmail missing");

        _senderName = config["Brevo:SenderName"] ?? "App";
    }

    public async Task SendMailAsync(string toEmail, string toName, string subject, string html)
    {
        var body = new
        {
            sender = new
            {
                name = _senderName,
                email = _senderEmail
            },
            to = new[]
            {
                new { email = toEmail, name = toName }
            },
            subject = subject,
            htmlContent = html
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email");

        request.Headers.Add("api-key", _apiKey);

        request.Content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        var response = await _httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }
}