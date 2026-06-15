using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Services;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics.CodeAnalysis;

var builder = WebApplication.CreateBuilder(args);
const string PortalCorsPolicy = "PortalCorsPolicy";

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();

AppConfig.Initialize(builder.Configuration);
ValidateStateStoreConfiguration(builder.Environment);

builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddPolicy(
        PortalCorsPolicy,
        policy => policy
            .WithOrigins(AppConfig.CorsAllowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()
            .WithExposedHeaders("Location", "WWW-Authenticate"));
});
builder.Services.AddDbContextFactory<OsolabAuthContext>(options =>
    options.UseSqlServer(AppConfig.AuthDbConnectionString));
builder.Services.AddSingleton<IRedisStringStore>(_ => new StackExchangeRedisStringStore(AppConfig.RedisConnectionString));
builder.Services.AddSingleton<IOidcStore>(services => new RedisOidcStore(services.GetRequiredService<IRedisStringStore>()));
builder.Services.AddSingleton<IUserStore, SqlUserStore>();
builder.Services.AddSingleton<IAgentStore, SqlAgentStore>();
builder.Services.AddSingleton<TermsService>();
builder.Services.AddSingleton(services => new AttemptLimiter(services.GetRequiredService<IRedisStringStore>()));
builder.Services.AddSingleton(services => new EmailSendCooldown(services.GetRequiredService<IRedisStringStore>()));
builder.Services.AddSingleton<IEmailSender>(services =>
{
    if (AppConfig.IsGmailSmtpConfigured())
    {
        return new GmailSmtpEmailSender();
    }

    return new ExampleDomainEmailSender(services.GetRequiredService<ILogger<ExampleDomainEmailSender>>());
});
builder.Services.AddSingleton(services => new SignupSessionService(
    services.GetRequiredService<IEmailSender>(),
    services.GetRequiredService<AttemptLimiter>(),
    services.GetRequiredService<EmailSendCooldown>(),
    services.GetRequiredService<IRedisStringStore>()));
builder.Services.AddSingleton(_ => SigningKeyProvider.FromConfig());
builder.Services.AddSingleton(services =>
{
    return new StepUpService(
        services.GetRequiredService<IUserStore>(),
        services.GetRequiredService<IEmailSender>(),
        services.GetRequiredService<AttemptLimiter>(),
        services.GetRequiredService<EmailSendCooldown>(),
        services.GetRequiredService<IRedisStringStore>());
});
builder.Services.AddSingleton<OidcTokenService>();

var app = builder.Build();

if (!AppConfig.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseCors(PortalCorsPolicy);
app.UseAuthorization();
app.MapControllers();
app.Run();

[ExcludeFromCodeCoverage]
public partial class Program
{
    private static void ValidateStateStoreConfiguration(IHostEnvironment environment)
    {
        if (!AppConfig.IsAuthDbConfigured())
        {
            throw new InvalidOperationException("AuthDb connection is required.");
        }

        if (!AppConfig.IsRedisConfigured())
        {
            throw new InvalidOperationException("Redis connection is required.");
        }

        if (environment.IsProduction() && !AppConfig.IsSigningKeyConfigured())
        {
            throw new InvalidOperationException("Signing key is required in production.");
        }
    }
}
