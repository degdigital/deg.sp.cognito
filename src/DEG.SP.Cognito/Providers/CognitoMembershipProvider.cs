using Amazon.CognitoIdentityProvider.Model;
using DEG.SP.Cognito.Utilities;
using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Web.Security;
using Microsoft.SharePoint.Administration;
using System.Security.Cryptography;

namespace DEG.SP.Cognito.Providers
{
    public class CognitoMembershipProvider : MembershipProvider
    {
        //private const string _accountNameFormat = "i:0#.f|cognitomembershipprovider|{0}";

        private static JwtSecurityTokenHandler _jwtHandler;

        private static string _issuer;
        private static SecurityKey _signingKey;
        private static string _audience;

        public const string ProviderName = "CognitoMembershipProvider";

        public override bool EnablePasswordRetrieval
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override bool EnablePasswordReset
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override string ApplicationName
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override int PasswordAttemptWindow
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override bool RequiresUniqueEmail
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override int MinRequiredPasswordLength
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override string PasswordStrengthRegularExpression
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        private void _init()
        {
            UlsLogger.LogError(string.Format("{0} - init", ProviderName));
            _jwtHandler = new JwtSecurityTokenHandler();
            _issuer = SPFarm.Local.Properties.Contains("COGNITO_ISSUER") ? SPFarm.Local.Properties["COGNITO_ISSUER"].ToString() : string.Empty;
            _audience = SPFarm.Local.Properties.Contains("COGNITO_AUDIENCE") ? SPFarm.Local.Properties["COGNITO_AUDIENCE"].ToString() : string.Empty;
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters()
                {
                    Modulus = SPFarm.Local.Properties.Contains("COGNITO_SIGNING_KEY") ? Base64UrlEncoder.DecodeBytes(SPFarm.Local.Properties["COGNITO_SIGNING_KEY"].ToString()) : new byte[0],
                    Exponent = SPFarm.Local.Properties.Contains("COGNITO_SIGNING_EXPO") ? Base64UrlEncoder.DecodeBytes(SPFarm.Local.Properties["COGNITO_SIGNING_EXPO"].ToString()) : new byte[0]
                });

            _signingKey = new RsaSecurityKey(rsa);
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            throw new NotSupportedException();
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            throw new NotSupportedException();
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection membershipUserCollection = new MembershipUserCollection();
            using (var idProvider = CognitoConnectionProvider.GetClient())
            {
                var response = idProvider.ListUsers(new ListUsersRequest()
                {
                    UserPoolId = CognitoConnectionProvider.UserPoolId,
                    Limit = pageSize
                });
                var paginationToken = response.PaginationToken;
                for (var i = 0; i < pageIndex; i++)
                {
                    response = idProvider.ListUsers(new ListUsersRequest()
                    {
                        UserPoolId = CognitoConnectionProvider.UserPoolId,
                        Limit = pageSize,
                        PaginationToken = paginationToken
                    });
                    paginationToken = response.PaginationToken;
                }
                foreach(var awsUser in response.Users)
                {
                    var username = awsUser.Attributes.Find(a => a.Name == "preferred_username") == null ? awsUser.Username : awsUser.Attributes.Find(a => a.Name == "preferred_username").Value;
                    var providerUserKey = awsUser.Username;
                    var email = awsUser.Attributes.Find(a => a.Name == "email") == null ? string.Empty : awsUser.Attributes.Find(a => a.Name == "email").Value;
                    var creationDate = awsUser.UserCreateDate;
                    var lastLoginDate = awsUser.UserLastModifiedDate;
                    membershipUserCollection.Add(new MembershipUser(ProviderName, username, providerUserKey, email, string.Empty, string.Empty, true, false, creationDate, lastLoginDate, lastLoginDate, lastLoginDate, lastLoginDate));
                }
            }
            totalRecords = membershipUserCollection.Count;
            return membershipUserCollection;
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        { 
            UlsLogger.LogError($"GetUser({username}, {userIsOnline})");
            using (var idProvider = CognitoConnectionProvider.GetClient())
            {
                var response = idProvider.AdminGetUser(new AdminGetUserRequest() {
                    UserPoolId = CognitoConnectionProvider.UserPoolId,
                    Username = username
                });
                if (response == null)
                    return null;
                var awsUserName = response.UserAttributes.Find(a => a.Name == "preferred_username") == null ? response.Username : response.UserAttributes.Find(a => a.Name == "preferred_username").Value;
                var providerUserKey = response.Username;
                var email = response.UserAttributes.Find(a => a.Name == "email") == null ? string.Empty : response.UserAttributes.Find(a => a.Name == "email").Value;
                var creationDate = response.UserCreateDate;
                var lastLoginDate = response.UserLastModifiedDate;
                return new MembershipUser(ProviderName, awsUserName, providerUserKey, email, string.Empty, string.Empty, true, false, creationDate, lastLoginDate, lastLoginDate, lastLoginDate, lastLoginDate);
            }
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotSupportedException();
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotSupportedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }

        public override bool ValidateUser(string username, string password)
        {
            UlsLogger.LogError($"ValidateUser({username}, {password})");
            if (_jwtHandler == null)
            {
                _init();
            }
            try
            {
                SecurityToken validatedToken;
                try
                {
                    // TODO: Place SigningKey into secure store service.
                    _jwtHandler.ValidateToken(password, new TokenValidationParameters() {
                        IssuerSigningKey = _signingKey,
                        ValidIssuer = _issuer,
                        ValidAudience = _audience,
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateAudience = true,
                        ClockSkew = TimeSpan.FromSeconds(120)
                    }, out validatedToken);
                }
                catch (Exception ex)
                {
                    UlsLogger.LogError(ex.Message);
                    return false;
                }
                JwtSecurityToken jwtSecurityToken = _jwtHandler.ReadToken(password) as JwtSecurityToken;
                if (jwtSecurityToken != null)
                {                    
                    var jwtUsername = jwtSecurityToken.Payload.ContainsKey("preferred_username") ? jwtSecurityToken.Payload["preferred_username"].ToString() : jwtSecurityToken.Payload["cognito:username"].ToString();
                    UlsLogger.LogError(string.Format("Cognito jwt - {0}", jwtUsername));
                    if(string.Compare(username, jwtUsername) == 0)
                    {
                        try
                        {
                            using (var idProvider = CognitoConnectionProvider.GetClient())
                            {
                                var updateAttributes = new List<AttributeType>();
                                updateAttributes.Add(new AttributeType()
                                {
                                    Name = "custom:LastLogin",
                                    Value = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC")
                                });
                                idProvider.AdminUpdateUserAttributes(new AdminUpdateUserAttributesRequest()
                                {
                                    UserPoolId = CognitoConnectionProvider.UserPoolId,
                                    Username = username,
                                    UserAttributes = updateAttributes
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            UlsLogger.LogError($"Cognito Update Attribute Error - {ex.Message}");
                        }
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                UlsLogger.LogError($"Cognito Validation Error - {ex.Message}");
                return false;
            }
        }
    }
}
