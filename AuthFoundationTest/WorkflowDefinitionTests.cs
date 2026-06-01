namespace AuthFoundationTest;

[TestClass]
public sealed class WorkflowDefinitionTests
{
    /// <summary>
    /// Purpose: verify the unit test workflow can run for pull requests and manual checks.
    /// Input: .github/workflows/unit-test-coverage.yml.
    /// Expected: pull_request and workflow_dispatch triggers are present.
    /// </summary>
    [TestMethod]
    public void UnitTestCoverageWorkflow_DefinesReviewTriggers()
    {
        string workflow = ReadWorkflow("unit-test-coverage.yml");

        StringAssert.Contains(workflow, "pull_request:");
        StringAssert.Contains(workflow, "workflow_dispatch:");
    }

    /// <summary>
    /// Purpose: verify the unit test workflow also runs for main and codex branch pushes.
    /// Input: .github/workflows/unit-test-coverage.yml.
    /// Expected: main and codex/** branches are present under push branches.
    /// </summary>
    [TestMethod]
    public void UnitTestCoverageWorkflow_DefinesMainAndCodexPushBranches()
    {
        string workflow = ReadWorkflow("unit-test-coverage.yml");

        StringAssert.Contains(workflow, "- main");
        StringAssert.Contains(workflow, "- \"codex/**\"");
    }

    /// <summary>
    /// Purpose: verify the unit test workflow publishes coverage data.
    /// Input: .github/workflows/unit-test-coverage.yml.
    /// Expected: dotnet test uses coverage options and uploads the Cobertura artifact.
    /// </summary>
    [TestMethod]
    public void UnitTestCoverageWorkflow_RunsCoverageAndUploadsArtifact()
    {
        string workflow = ReadWorkflow("unit-test-coverage.yml");

        StringAssert.Contains(workflow, "dotnet test --project AuthFoundationTest/AuthFoundationTest.csproj");
        StringAssert.Contains(workflow, "--coverage-output-format cobertura");
        StringAssert.Contains(workflow, "actions/upload-artifact@v4");
    }

    /// <summary>
    /// Purpose: verify release build dispatch no longer targets Windows home deployment.
    /// Input: .github/workflows/build-push-dispatch.yml.
    /// Expected: deploy/windows-home is not a push branch trigger.
    /// </summary>
    [TestMethod]
    public void BuildPushDispatchWorkflow_DoesNotTargetWindowsHomeBranch()
    {
        string workflow = ReadWorkflow("build-push-dispatch.yml");

        Assert.IsFalse(workflow.Contains("deploy/windows-home", StringComparison.Ordinal));
    }

    private static string ReadWorkflow(string fileName)
    {
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), ".github", "workflows", fileName));
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".github", "workflows")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(".github/workflows directory was not found.");
    }
}
