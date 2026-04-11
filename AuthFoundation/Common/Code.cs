using System.Net;
using System.Security.Cryptography.Pkcs;

namespace AuthFoundation.Common
{
    public static class Code
    {
        public static readonly ApiException SUCCESS = new ApiException("00000", HttpStatusCode.OK, "OK" );
        public static readonly ApiException REQUEST_PARAMETER_ERROR = new ApiException("00001", HttpStatusCode.BadRequest, "リクエストの内容が異常です");

        public static readonly ApiException INTERNAL_SERVER_ERROR = new ApiException("90000", HttpStatusCode.BadRequest, "ハンドルされていないエラーが発生しました");

        public class RequestValidation
        {
            public string Key { get; set; }
            public string Regex { get; set; }
            public RequestValidation(string key, string regex)
            {
                Key = key;
                Regex = regex;
            }
        }
        public static class HttpHeaders
        { 
        
        }

        public static class HttpQueries
        {
            public static readonly RequestValidation UID =new RequestValidation( "uid", @"^[0-9]{9,10}$");
        }
        public static class HttpBodies
        {

        }

    }
}
