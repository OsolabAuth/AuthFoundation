using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;

namespace AuthFoundationTest.TestSupport;

internal sealed class TestWebHostEnvironment : IWebHostEnvironment
{
    public string EnvironmentName { get; set; } = "Test";

    public string ApplicationName { get; set; } = "AuthFoundationTest";

    public string WebRootPath { get; set; } = Directory.GetCurrentDirectory();

    public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();

    public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();

    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
}
