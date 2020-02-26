using Amazon.CognitoIdentityProvider.Model;
using System;
using System.Linq;
using System.Web.Security;

namespace DEG.SP.Cognito.Providers
{
    class CognitoRoleProvider : RoleProvider
    {
        public override string ApplicationName { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            throw new NotImplementedException();
        }

        public override void CreateRole(string roleName)
        {
            throw new NotImplementedException();
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            throw new NotImplementedException();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            throw new NotImplementedException();
        }

        public override string[] GetAllRoles()
        {
            using (var idProvider = CognitoConnectionProvider.GetClient())
            {
                var response = idProvider.ListGroups(new ListGroupsRequest()
                {
                    UserPoolId = CognitoConnectionProvider.UserPoolId
                });
                return response.Groups.Select(g => g.GroupName).ToArray();
            }
        }

        public override string[] GetRolesForUser(string username)
        {
            using (var idProvider = CognitoConnectionProvider.GetClient())
            {

                var response = idProvider.AdminListGroupsForUser(new AdminListGroupsForUserRequest() {
                    UserPoolId = CognitoConnectionProvider.UserPoolId,
                    Username = username
                });
                return response.Groups.Select(g => g.GroupName).ToArray();
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            throw new NotImplementedException();
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            var roles = GetRolesForUser(username);
            return roles.Contains(roleName, StringComparer.OrdinalIgnoreCase);
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            throw new NotImplementedException();
        }

        public override bool RoleExists(string roleName)
        {
            using (var idProvider = CognitoConnectionProvider.GetClient())
            {
                var response = idProvider.ListGroups(new ListGroupsRequest()
                {
                    UserPoolId = CognitoConnectionProvider.UserPoolId
                });
                return response.Groups.Find(g => string.Compare(g.GroupName, roleName, true) == 0) != null;
            }
        }
    }
}
