<%@ Assembly Name="$SharePoint.Project.AssemblyFullName$" %>
<%@ Import Namespace="Microsoft.SharePoint.ApplicationPages" %>
<%@ Register Tagprefix="SharePoint" Namespace="Microsoft.SharePoint.WebControls" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register Tagprefix="Utilities" Namespace="Microsoft.SharePoint.Utilities" Assembly="Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Register Tagprefix="asp" Namespace="System.Web.UI" Assembly="System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" %>
<%@ Import Namespace="Microsoft.SharePoint" %>
<%@ Assembly Name="Microsoft.Web.CommandUI, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>
<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="DEG.SP.Cognito.Layouts.DEG.SP.Cognito.Login" %>

<script type="text/javascript">
    const hashParseRegEx = /([^#&=]+)=([^&]+)/g;
    const redirectUriRegEx = /({REDIRECT_URI})/g;
    var getHashParams = function() {
        let params = {};
        let current = hashParseRegEx.exec(window.location.hash);
        while(current != null) {
            params[current[1]] = current[2];
            current = hashParseRegEx.exec(window.location.hash);
        }
        return params;
    }
    var hashParams = getHashParams();
    if (hashParams['id_token']) {
        window.location.search = 'id_token=' + hashParams['id_token'];
    }
    else if (window.location.search.indexOf('id_token') < 0) {
        var currentPage = window.location.protocol + '//' + window.location.host + window.location.pathname;
        window.location.replace('<%=CognitoLoginTarget %>'.replace(redirectUriRegEx, currentPage));
    }
    sessionStorage.removeItem("ubgLastActivity");
</script>
