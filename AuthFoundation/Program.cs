using AuthFoundation.Common;
using AuthFoundation.Data;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

AppConfig.Initialize(builder.Configuration);

builder.Services.AddControllers();

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

var app = builder.Build();

var disableHttpsRedirection = builder.Configuration.GetValue<bool>("DisableHttpsRedirection");
if (!disableHttpsRedirection)
{
    app.UseHttpsRedirection();
}
app.UseAuthorization();
app.MapControllers();
app.Run();
