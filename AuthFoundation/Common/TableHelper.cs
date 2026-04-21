using AuthFoundation.Data;
using AuthFoundation.Models;

namespace AuthFoundation.Common
{
    public class TableHelper
    {
        /// <summary>
        /// 新規ユーザー登録処理
        /// </summary>
        /// <param name="osolabAuthContext"></param>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="ApiException"></exception>
        public static osolab_user CreateNewOsolabUser(OsolabAuthContext osolabAuthContext, string email, string password)
        {
            string newOsolabId = string.Empty;
            for (int retryCount = 0; retryCount < Code.OsolabId.MAX_RETRY_COUNT; retryCount++)
            {
                newOsolabId = Helper.GenerateHex(Code.OsolabId.LENGTH);
                if (osolabAuthContext.osolab_users.Any(x => x.osolab_id == newOsolabId))
                {
                    newOsolabId = string.Empty;
                    continue;
                }
                break;
            }
            if (string.IsNullOrEmpty(newOsolabId))
            {
                throw new ApiException(Common.Code.ID_GENERATION_ERORR, Common.Code.ID_GENERATION_ERORR.ErrorMessage);
            }

            string nonce = Helper.GenerateRandomCode(Code.Nonce.LENGTH, Code.Nonce.CHARACTORS);
            string passHash = Helper.GetPassHash(password, nonce);
            return new osolab_user()
            {
                osolab_id = newOsolabId,
                email = email,
                nonce = nonce,
                password = passHash,
                create_datetime = DateTime.Now,
                update_datetime = DateTime.Now,
                status = Code.Status.TENTATIVE
            };
        }
    }
}
