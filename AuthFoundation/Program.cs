using AuthFoundation.Common;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();

AppConfig.Initialize(builder.Configuration);

builder.Services.AddControllers();

var app = builder.Build();

if (!AppConfig.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseAuthorization();
app.MapControllers();
app.Run();

public partial class Program
{
}
