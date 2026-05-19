using AuthFoundation.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest.TestSupport;

internal static class TestDbContextFactory
{
    public static OsolabAuthContext Create()
    {
        var options = new DbContextOptionsBuilder<OsolabAuthContext>()
            .UseSqlServer(ResolveConnectionString())
            .Options;

        return new OsolabAuthContext(options);
    }

    public static string ResolveConnectionString()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection");
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return fromEnvironment;
        }

        IConfiguration config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile(Path.Combine("AuthFoundation", "appsettings.json"), optional: true)
            .Build();

        return config.GetConnectionString("DefaultConnection")
            ?? "Server=(localdb)\\MSSQLLocalDB;Database=OsolabAuth;Trusted_Connection=True;";
    }
}
