using System.Text.Json;

namespace AuthFoundationTest;

[TestClass]
public sealed class APITesterScenarioTests
{
    private static readonly string[] ScenarioFiles =
    [
        "AuthorizationCodeFlow.json",
        "MfaStepUp.json",
        "PasswordAccountFlow.json",
        "AgentDelegatedAuth.json"
    ];

    /// <summary>
    /// Purpose: verify all API Tester scenario files are valid import JSON.
    /// Input: APITester/*.json.
    /// Expected: every file parses as JSON and declares version 6.
    /// </summary>
    [TestMethod]
    public void ScenarioFiles_AreValidVersion6Json()
    {
        foreach (string file in ScenarioFiles)
        {
            using JsonDocument document = ReadScenario(file);

            Assert.AreEqual(6, document.RootElement.GetProperty("version").GetInt32());
            Assert.AreEqual(JsonValueKind.Array, document.RootElement.GetProperty("entities").ValueKind);
            Assert.AreEqual(JsonValueKind.Array, document.RootElement.GetProperty("environments").ValueKind);
        }
    }

    /// <summary>
    /// Purpose: verify each scenario contains a Talend project, scenario, and request tree.
    /// Input: APITester/*.json.
    /// Expected: each file has one project with one scenario and at least two requests.
    /// </summary>
    [TestMethod]
    public void ScenarioFiles_ContainProjectScenarioAndRequests()
    {
        foreach (string file in ScenarioFiles)
        {
            using JsonDocument document = ReadScenario(file);

            JsonElement project = document.RootElement.GetProperty("entities")[0];
            Assert.AreEqual("Project", project.GetProperty("entity").GetProperty("type").GetString());

            JsonElement scenario = project.GetProperty("children")[0];
            Assert.AreEqual("Scenario", scenario.GetProperty("entity").GetProperty("type").GetString());

            JsonElement requests = scenario.GetProperty("children");
            Assert.IsTrue(requests.GetArrayLength() >= 2, file);
            foreach (JsonElement request in requests.EnumerateArray())
            {
                Assert.AreEqual("Request", request.GetProperty("entity").GetProperty("type").GetString());
                Assert.IsFalse(string.IsNullOrWhiteSpace(request.GetProperty("entity").GetProperty("name").GetString()));
            }
        }
    }

    /// <summary>
    /// Purpose: verify scenarios use API Tester response references only when the API safely exposes the value.
    /// Input: AuthorizationCodeFlow and AgentDelegatedAuth JSON.
    /// Expected: request bodies or headers include ${"..."} response reference expressions for non-MFA secrets.
    /// </summary>
    [TestMethod]
    public void ScenarioFiles_UseResponseReferenceExpressions()
    {
        HashSet<string> authorization = ReadScenarioValues("AuthorizationCodeFlow.json");
        HashSet<string> agent = ReadScenarioValues("AgentDelegatedAuth.json");

        Assert.IsTrue(authorization.Any(value => value.Contains("${\"AuthFoundation - AuthorizationCodeFlow\".\"01. Start authorize request\".\"response\".\"body\".\"response_code\"}", StringComparison.Ordinal)));
        Assert.IsTrue(authorization.Any(value => value.Contains("${\"AuthFoundation - AuthorizationCodeFlow\".\"01. Start authorize request\".\"response\".\"headers\".\"set-cookie\"}", StringComparison.Ordinal)));
        Assert.IsTrue(agent.Any(value => value.Contains("${\"AuthFoundation - AgentDelegatedAuth\".\"01. Create delegated agent\".\"response\".\"body\".\"agent_id\"}", StringComparison.Ordinal)));
        Assert.IsTrue(agent.Any(value => value.Contains("${\"AuthFoundation - AgentDelegatedAuth\".\"01. Create delegated agent\".\"response\".\"body\".\"agent_secret\"}", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Purpose: verify MFA API Tester scenarios do not rely on email code exposure from API responses and chain safe step-up tokens.
    /// Input: MfaStepUp JSON.
    /// Expected: email verification uses private EmailCode variable, not response.body.code, and setup uses response.body.step_up_token.
    /// </summary>
    [TestMethod]
    public void MfaScenario_UsesPrivateEmailCodeVariable()
    {
        HashSet<string> mfa = ReadScenarioValues("MfaStepUp.json");
        string startBody = ReadRequestTextBody("MfaStepUp.json", "01. Start email MFA challenge");
        string setupBody = ReadRequestTextBody("MfaStepUp.json", "03. Setup authenticator MFA");

        Assert.IsTrue(mfa.Any(value => value.Contains("${\"EmailCode\"}", StringComparison.Ordinal)));
        Assert.IsTrue(mfa.Any(value => value.Contains("${\"AuthFoundation - MfaStepUp\".\"02. Verify email MFA challenge\".\"response\".\"body\".\"step_up_token\"}", StringComparison.Ordinal)));
        Assert.IsFalse(startBody.Contains("\"step_up_token\"", StringComparison.Ordinal));
        Assert.IsTrue(setupBody.Contains("\"step_up_token\"", StringComparison.Ordinal));
        Assert.IsFalse(mfa.Any(value => value.Contains("\"response\".\"body\".\"code\"", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Purpose: verify production scenario environments do not expose secrets.
    /// Input: APITester/*.json production environment variables.
    /// Expected: sensitive variables are marked private.
    /// </summary>
    [TestMethod]
    public void ScenarioFiles_MarkSensitiveProductionVariablesPrivate()
    {
        HashSet<string> sensitiveNames =
        [
            "Email",
            "Password",
            "NewPassword",
            "BirthDate",
            "StepUpToken",
            "CodeVerifier",
            "CodeChallenge",
            "EmailCode",
            "AuthenticatorCode"
        ];

        foreach (string file in ScenarioFiles)
        {
            using JsonDocument document = ReadScenario(file);
            JsonElement variables = document.RootElement.GetProperty("environments")[0].GetProperty("variables");

            foreach (JsonProperty property in variables.EnumerateObject())
            {
                JsonElement variable = property.Value;
                string? name = variable.GetProperty("name").GetString();
                if (name is not null && sensitiveNames.Contains(name))
                {
                    Assert.IsTrue(variable.GetProperty("private").GetBoolean(), $"{file}:{name}");
                }
            }
        }
    }

    private static JsonDocument ReadScenario(string fileName)
    {
        return JsonDocument.Parse(ReadScenarioText(fileName));
    }

    private static string ReadScenarioText(string fileName)
    {
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), "APITester", fileName));
    }

    private static HashSet<string> ReadScenarioValues(string fileName)
    {
        using JsonDocument document = ReadScenario(fileName);
        HashSet<string> values = [];
        CollectStringValues(document.RootElement, values);
        return values;
    }

    private static string ReadRequestTextBody(string fileName, string requestName)
    {
        using JsonDocument document = ReadScenario(fileName);
        JsonElement requests = document.RootElement
            .GetProperty("entities")[0]
            .GetProperty("children")[0]
            .GetProperty("children");

        foreach (JsonElement request in requests.EnumerateArray())
        {
            JsonElement entity = request.GetProperty("entity");
            if (string.Equals(entity.GetProperty("name").GetString(), requestName, StringComparison.Ordinal))
            {
                return entity.GetProperty("body").GetProperty("textBody").GetString() ?? string.Empty;
            }
        }

        Assert.Fail($"Request was not found: {requestName}");
        return string.Empty;
    }

    private static void CollectStringValues(JsonElement element, HashSet<string> values)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    CollectStringValues(property.Value, values);
                }

                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in element.EnumerateArray())
                {
                    CollectStringValues(item, values);
                }

                break;
            case JsonValueKind.String:
                string? value = element.GetString();
                if (value is not null)
                {
                    values.Add(value);
                }

                break;
        }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "APITester")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("APITester directory was not found.");
    }
}
