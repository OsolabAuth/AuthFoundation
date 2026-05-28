using AuthFoundation.Common;
using AuthFoundation.Services;
using System.Diagnostics.CodeAnalysis;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();

AppConfig.Initialize(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddSingleton<InMemoryOidcStore>();
builder.Services.AddSingleton<InMemoryUserStore>();
builder.Services.AddSingleton<TermsService>();
builder.Services.AddSingleton<StepUpService>();
builder.Services.AddSingleton<OidcTokenService>();

var app = builder.Build();

if (!AppConfig.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseAuthorization();
app.MapControllers();
app.Run();

[ExcludeFromCodeCoverage]
public partial class Program
{
}
