namespace AuthFoundation.Common
{
    /// <summary>
    /// Builds URLs for the external auth UI.
    /// </summary>
    public static class AuthUiUrl
    {
        /// <summary>
        /// Gets a value indicating whether the external auth UI base URL is configured.
        /// </summary>
        public static bool IsConfigured => !string.IsNullOrWhiteSpace(AppConfig.AuthUiBaseUrl);

        /// <summary>
        /// Builds an auth UI URL with an authorization session id.
        /// </summary>
        public static string Build(string path, string? sessionId)
        {
            string normalizedPath = path.StartsWith("/", StringComparison.Ordinal)
                ? path
                : "/" + path;

            string query = string.IsNullOrWhiteSpace(sessionId)
                ? string.Empty
                : $"?session_id={Uri.EscapeDataString(sessionId)}";

            if (!IsConfigured)
            {
                return $"{normalizedPath}{query}";
            }

            return $"{AppConfig.AuthUiBaseUrl}{normalizedPath}{query}";
        }
    }
}
