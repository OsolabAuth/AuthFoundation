using AuthFoundation.Common;
using AuthFoundation.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthFoundationTest.TestSupport;

internal static class SigningTestHelper
{
    public static OidcSigningService CreateSigningService()
    {
        var services = new ServiceCollection();
        services.AddDbContext<OsolabAuthContext>(options =>
            options.UseSqlServer(TestDbContextFactory.ResolveConnectionString()));

        ServiceProvider provider = services.BuildServiceProvider();
        return new OidcSigningService(provider.GetRequiredService<IServiceScopeFactory>());
    }
}
