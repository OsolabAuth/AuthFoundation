using AuthFoundation.Common;
using AuthFoundation.Services;
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
if (AppConfig.IsRedisConfigured())
{
    builder.Services.AddSingleton<IRedisStringStore>(_ => new StackExchangeRedisStringStore(AppConfig.RedisConnectionString));
    builder.Services.AddSingleton<IOidcStore>(services => new RedisOidcStore(services.GetRequiredService<IRedisStringStore>()));
}
else
{
    builder.Services.AddSingleton<IOidcStore, InMemoryOidcStore>();
}
builder.Services.AddSingleton<IUserStore>(_ =>
    AppConfig.IsAuthDbConfigured()
        ? new SqlUserStore(AppConfig.AuthDbConnectionString)
        : new InMemoryUserStore());
builder.Services.AddSingleton<IAgentStore, InMemoryAgentStore>();
builder.Services.AddSingleton<TermsService>();
builder.Services.AddSingleton(services => new AttemptLimiter(services.GetService<IRedisStringStore>()));
builder.Services.AddSingleton<IEmailSender>(_ =>
    AppConfig.IsGmailSmtpConfigured()
        ? new GmailSmtpEmailSender()
        : new DevelopmentEmailSender());
builder.Services.AddSingleton(services => new SignupSessionService(
    services.GetRequiredService<IEmailSender>(),
    services.GetRequiredService<AttemptLimiter>(),
    services.GetService<IRedisStringStore>()));
builder.Services.AddSingleton(_ => SigningKeyProvider.FromConfig());
builder.Services.AddSingleton(services =>
{
    IRedisStringStore? redisStore = AppConfig.IsRedisConfigured()
        ? services.GetRequiredService<IRedisStringStore>()
        : null;
    return new StepUpService(
        services.GetRequiredService<IUserStore>(),
        services.GetRequiredService<IEmailSender>(),
        services.GetRequiredService<AttemptLimiter>(),
        redisStore);
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
        bool cloudRun = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("K_SERVICE"));
        bool externalStateRequired = environment.IsProduction() || cloudRun;
        if (!externalStateRequired)
        {
            return;
        }

        if (!AppConfig.IsAuthDbConfigured())
        {
            throw new InvalidOperationException("AuthDb connection is required when running in production.");
        }

        if (!AppConfig.IsRedisConfigured())
        {
            throw new InvalidOperationException("Redis connection is required when running in production.");
        }
    }
}
