using Amazon;
using Amazon.CognitoIdentityProvider;
using Microsoft.SharePoint.Administration;

namespace DEG.SP.Cognito.Providers
{
    public static class CognitoConnectionProvider
    {
        private const string RegionProperty = "AWS_REGION";
        private const string ClientIdProperty = "AWS_CLIENT_ID";
        private const string ClientSecretProperty = "AWS_CLIENT_SECRET";
        private const string AccessKeyIdProperty = "AWS_ACCESS_KEY_ID";
        private const string AccessKeySecretProperty = "AWS_ACCESS_KEY_SECRET";
        private const string UserPoolIdProperty = "AWS_USER_POOL_ID";
        private const string IdentityPoolIdProperty = "AWS_IDENTITY_POOL_ID";
        private const string HostedUiProperty = "AWS_HOSTED_UI";

        private const string ResponseType = "token";
        private const string LoginScope = "profile+phone+email+openid+aws.cognito.signin.user.admin";
        private const string RedirectUriVariable = @"{REDIRECT_URI}";

        private const string DefaultRegion = "us-east-1";
        private const string DefaultHostedUi = "aaaaaaaaa.auth.us-east-1.amazoncognito.com";
        private const string DefaultClientId = "";
        private const string DefaultAccessKeyId = "";
        private const string DefaultAccessKeySecret = "";
        private const string DefaultUserPoolId = "us-east-1_AAAAAAAAAA";

        public static string UserPoolId
        {
            get
            {
                if (SPFarm.Local.Properties.Contains(UserPoolIdProperty))
                {
                    return SPFarm.Local.Properties[UserPoolIdProperty].ToString();
                }
                return DefaultUserPoolId;
            }
        }

        public static string GetHostedUiUrl()
        {
            var hostedUi = DefaultHostedUi;
            var clientId = DefaultClientId;
            if(SPFarm.Local.Properties.Contains(HostedUiProperty))
            {
                hostedUi = SPFarm.Local.Properties[HostedUiProperty].ToString();
            }
            if (SPFarm.Local.Properties.Contains(ClientIdProperty))
            {
                clientId = SPFarm.Local.Properties[ClientIdProperty].ToString();
            }
            return $"https://{hostedUi}/login?response_type={ResponseType}&client_id={clientId}&redirect_uri={RedirectUriVariable}";
        }

        public static string GetLogoutUrl()
        {
            var hostedUi = DefaultHostedUi;
            var clientId = DefaultClientId;
            if (SPFarm.Local.Properties.Contains(HostedUiProperty))
            {
                hostedUi = SPFarm.Local.Properties[HostedUiProperty].ToString();
            }
            if (SPFarm.Local.Properties.Contains(ClientIdProperty))
            {
                clientId = SPFarm.Local.Properties[ClientIdProperty].ToString();
            }
            return $"https://{hostedUi}/logout?client_id={clientId}&logout_uri={RedirectUriVariable}";
        }

        public static AmazonCognitoIdentityProviderClient GetClient()
        {
            var accessKeyId = DefaultAccessKeyId;
            var accessKeySecret = DefaultAccessKeySecret;
            var region = RegionEndpoint.USEast1;//DefaultRegion;
            if (SPFarm.Local.Properties.Contains(AccessKeyIdProperty))
            {
                accessKeyId = SPFarm.Local.Properties[AccessKeyIdProperty].ToString();
            }
            if (SPFarm.Local.Properties.Contains(AccessKeySecretProperty))
            {
                accessKeySecret = SPFarm.Local.Properties[AccessKeySecretProperty].ToString();
            }
            if (SPFarm.Local.Properties.Contains(RegionProperty))
            {
                region = RegionEndpoint.GetBySystemName(SPFarm.Local.Properties[RegionProperty].ToString());
            }
            return new AmazonCognitoIdentityProviderClient(accessKeyId, accessKeySecret, region);
        }
    }
}