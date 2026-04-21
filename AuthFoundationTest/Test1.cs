using System.Security.Cryptography;

namespace AuthFoundationTest
{
    [TestClass]
    public sealed class Test1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var key = new byte[32];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);

            string keyString =  Convert.ToBase64String(key);

            Assert.IsFalse(string.IsNullOrWhiteSpace(keyString));
        }
    }
}
