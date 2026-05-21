using AuthFoundation.Common;
using AuthFoundation.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();

AppConfig.Initialize(builder.Configuration);
string[] allowedCorsOrigins = ResolveCorsAllowedOrigins(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddHttpClient();
if (allowedCorsOrigins.Length > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AuthUiCors", policy =>
        {
            policy
                .WithOrigins(allowedCorsOrigins)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials()
                .WithExposedHeaders("Location");
        });
    });
}

builder.Services.AddDbContext<OsolabAuthContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")
    ));

var redisConnectionString =
    builder.Configuration.GetConnectionString("Redis")
    ?? throw new InvalidOperationException("Redis connection string is not configured.");

builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
    var options = ConfigurationOptions.Parse(redisConnectionString);
    options.AbortOnConnectFail = false;
    return ConnectionMultiplexer.Connect(options);
});

builder.Services.AddSingleton<IRedisClient, RedisClient>();
builder.Services.AddSingleton<OidcSigningService>();
builder.Services.AddScoped<AuthorizeExecutionService>();

builder.Services.AddSingleton<GmailSmtpMail>();

var app = builder.Build();

var disableHttpsRedirection = builder.Configuration.GetValue<bool>("DisableHttpsRedirection");
if (!disableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

if (allowedCorsOrigins.Length > 0)
{
    app.UseCors("AuthUiCors");
}

app.UseAuthorization();
app.MapControllers();
app.Run();

static string[] ResolveCorsAllowedOrigins(IConfiguration config)
{
    List<string> origins = new List<string>();

    foreach (IConfigurationSection section in config.GetSection("Cors:AllowedOrigins").GetChildren())
    {
        AddOrigin(origins, section.Value);
    }

    string? rawOrigins = config["Cors:AllowedOrigins"];
    if (!string.IsNullOrWhiteSpace(rawOrigins))
    {
        foreach (string origin in rawOrigins.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
        {
            AddOrigin(origins, origin);
        }
    }

    AddOrigin(origins, config["AuthUiBaseUrl"]);

    return origins
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}

static void AddOrigin(List<string> origins, string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return;
    }

    string trimmed = value.Trim().TrimEnd('/');
    if (!Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri)
        || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
    {
        return;
    }

    origins.Add(uri.GetLeftPart(UriPartial.Authority));
}

