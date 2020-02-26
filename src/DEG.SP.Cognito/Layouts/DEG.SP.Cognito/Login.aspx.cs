using DEG.SP.Cognito.Providers;
using DEG.SP.Cognito.Utilities;
using Microsoft.SharePoint;
using Microsoft.SharePoint.Administration;
using Microsoft.SharePoint.IdentityModel;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web.UI;

namespace DEG.SP.Cognito.Layouts.DEG.SP.Cognito
{
    public partial class Login : Page
    {
        public string CognitoLoginTarget { get; set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            UlsLogger.LogError("Cognito Login page load 1");
            try
            {
                var landingPage = SPFarm.Local.Properties.Contains("COGNITO_LANDING") ? SPFarm.Local.Properties["COGNITO_LANDING"].ToString() : "/";
                CognitoLoginTarget = CognitoConnectionProvider.GetHostedUiUrl();
                string text = Context.Request.QueryString["id_token"];
                UlsLogger.LogError("Cognito token - " + text);
                if (!string.IsNullOrEmpty(text))
                {
                    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                    JwtSecurityToken jwtSecurityToken = jwtSecurityTokenHandler.ReadJwtToken(text) as JwtSecurityToken;
                    if (jwtSecurityToken != null)
                    {
                        string text2 = jwtSecurityToken.Payload.ContainsKey("preferred_username") ?
                            jwtSecurityToken.Payload["preferred_username"].ToString() :
                            jwtSecurityToken.Payload["cognito:username"].ToString();
                        UlsLogger.LogError("Cognito user name - " + text2);
                        if (SPClaimsUtility.AuthenticateFormsUser(Context.Request.Url, text2, text))
                        {
                            UlsLogger.LogError("Cognito redirect - " + landingPage);
                            Response.Redirect(landingPage);
                        }
                        else
                        {
                            UlsLogger.LogError("Cognito - Page Authentication Failed");
                        }
                    }
                    else
                    {
                        UlsLogger.LogError("Cognito - Token unable to be read");
                    }
                }
            }
            catch (Exception ex)
            {
                UlsLogger.LogError("Cognito - " + ex.Message);
                throw ex;
            }
        }
    }
}
