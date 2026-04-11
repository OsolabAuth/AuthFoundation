using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Common
{
    // ヘルパーメソッドをここに実装
    public static class Helper
    {
        public static IResult CreateOKResponse()
        {
            IResult response = Results.Ok();

            return response;
        }
    }
}
