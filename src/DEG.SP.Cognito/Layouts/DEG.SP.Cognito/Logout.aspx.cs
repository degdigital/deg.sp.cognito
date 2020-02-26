using DEG.SP.Cognito.Providers;
using DEG.SP.Cognito.Utilities;
using System;
using Microsoft.SharePoint;
using Microsoft.SharePoint.IdentityModel;
using Microsoft.SharePoint.WebControls;
using System.Web.Security;
using System.Web;
using System.Security.Principal;
using Microsoft.IdentityModel.Web;

namespace DEG.SP.Cognito.Layouts.DEG.SP.Cognito
{
    public partial class Logout : UnsecuredLayoutsPageBase
    {
        public string CognitoLogoutTarget { get; set; }
        public string AuthenticationType { get; set; }
        public bool IsAuthenticated { get; set;}

        protected void Page_Load(object sender, EventArgs e)
        {
            UlsLogger.LogError("Cognito logout page load");
            try
            {
                IsAuthenticated = Context.User.Identity.IsAuthenticated;
                UlsLogger.LogError("Cognito logout IsAuthenticated " + IsAuthenticated.ToString());
                if (IsAuthenticated)
                {
                    CognitoLogoutTarget = CognitoConnectionProvider.GetLogoutUrl();
                    FederatedAuthentication.SessionAuthenticationModule.SignOut();
                    if (HttpContext.Current.Session != null) HttpContext.Current.Session.Abandon();
                }
            }
            catch (Exception ex)
            {
                UlsLogger.LogError("Cognito - " + ex.Message + " " + ex.Source);
                throw ex;
            }
        }
    }
}
