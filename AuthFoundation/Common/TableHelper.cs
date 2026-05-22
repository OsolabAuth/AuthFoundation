using AuthFoundation.Data;
using AuthFoundation.Models;

namespace AuthFoundation.Common
{
    /// <summary>
    /// TableHelper class.
    /// </summary>
    public class TableHelper
    {
        /// <summary>
        /// Executes CreateNewOsolabUser.
        /// </summary>
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
                throw new ApiException(Common.Code.ID_GENERATION_ERROR, Common.Code.ID_GENERATION_ERROR.ErrorDescription);
            }

            string nonce = Helper.GenerateRandomCode(Code.Nonce.LENGTH, Code.Nonce.CHARACTORS);
            string passHash = Helper.GetPassHash(password, nonce);
            DateTime now = DateTime.UtcNow;
            return new osolab_user()
            {
                osolab_id = newOsolabId,
                email = email,
                nonce = nonce,
                password = passHash,
                create_datetime = now,
                update_datetime = now,
                status = Code.Status.TENTATIVE
            };
        }
    }
}
