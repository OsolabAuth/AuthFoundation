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
    /// 目的: Scenario Files / Are Valid Version6 Json の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: Scenario Files / Are Valid Version6 Json の期待結果になること。
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
    /// 目的: Scenario Files / Contain Project Scenario And Requests の仕様を検証する。
    /// 入力値: Scenario Files / Contain Project Scenario And Requests を確認するためにテスト内で作成したデータ。
    /// 期待値: Scenario Files / Contain Project Scenario And Requests の期待結果になること。
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
    /// 目的: Scenario Files / Use Response Reference Expressions の仕様を検証する。
    /// 入力値: Scenario Files / Use Response Reference Expressions を確認するためにテスト内で作成したデータ。
    /// 期待値: Scenario Files / Use Response Reference Expressions の期待結果になること。
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
    /// 目的: Mfa Scenario / Uses Private Email Code Variable の仕様を検証する。
    /// 入力値: Mfa Scenario / Uses Private Email Code Variable を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void MfaScenario_UsesPrivateEmailCodeVariable()
    {
        HashSet<string> mfa = ReadScenarioValues("MfaStepUp.json");

        Assert.IsTrue(mfa.Any(value => value.Contains("${\"EmailCode\"}", StringComparison.Ordinal)));
        Assert.IsTrue(mfa.Any(value => value.Contains("${\"AuthFoundation - MfaStepUp\".\"02. Verify email MFA challenge\".\"response\".\"body\".\"step_up_token\"}", StringComparison.Ordinal)));
        Assert.IsFalse(mfa.Any(value => value.Contains("\"response\".\"body\".\"code\"", StringComparison.Ordinal)));
    }

    /// <summary>
    /// 目的: Password Scenario / Uses Private Email Code Variable の仕様を検証する。
    /// 入力値: Password Scenario / Uses Private Email Code Variable を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void PasswordScenario_UsesPrivateEmailCodeVariable()
    {
        HashSet<string> password = ReadScenarioValues("PasswordAccountFlow.json");

        Assert.IsTrue(password.Any(value => value.Contains("\"email_code\"", StringComparison.Ordinal)));
        Assert.IsTrue(password.Any(value => value.Contains("${\"EmailCode\"}", StringComparison.Ordinal)));
    }

    /// <summary>
    /// 目的: Scenario Files / Mark Sensitive Production Variables Private の仕様を検証する。
    /// 入力値: Scenario Files / Mark Sensitive Production Variables Private を確認するためにテスト内で作成したデータ。
    /// 期待値: Scenario Files / Mark Sensitive Production Variables Private の期待結果になること。
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
