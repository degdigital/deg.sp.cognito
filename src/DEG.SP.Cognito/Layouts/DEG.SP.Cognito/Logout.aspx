<%@ Assembly Name="$SharePoint.Project.AssemblyFullName$" %>
<%@ Import Namespace="Microsoft.SharePoint.ApplicationPages" %>
<%@ Register Tagprefix="SharePoint" Namespace="Microsoft.SharePoint.WebControls" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register Tagprefix="Utilities" Namespace="Microsoft.SharePoint.Utilities" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register Tagprefix="asp" Namespace="System.Web.UI" Assembly="System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" %>
<%@ Import Namespace="Microsoft.SharePoint" %>
<%@ Assembly Name="Microsoft.Web.CommandUI, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Logout.aspx.cs" Inherits="DEG.SP.Cognito.Layouts.DEG.SP.Cognito.Logout" %>

<script type="text/javascript">
    const redirectUriRegEx = /({REDIRECT_URI})/g;
    if ('<%=IsAuthenticated %>' === 'True') {
        var currentPage = window.location.protocol + '//' + window.location.host;
        localStorage.removeItem('id_token');
        localStorage.removeItem('access_token');
        localStorage.removeItem('is_admin');
        localStorage.removeItem('participant_id');
        localStorage.removeItem('token_expiration');
        sessionStorage.removeItem("ubgLastActivity");
        window.location.replace('<%=CognitoLogoutTarget %>'.replace(redirectUriRegEx, currentPage));
    }
</script>
