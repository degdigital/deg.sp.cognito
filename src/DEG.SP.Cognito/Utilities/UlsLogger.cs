using Microsoft.SharePoint.Administration;
using System;
using System.Collections.Generic;

namespace DEG.SP.Cognito.Utilities
{
    public class UlsLogger : SPDiagnosticsServiceBase
    {
        public enum CategoryID
        {
            None = 0,
            Processing = 100,
            Faulting = 200
        }

        public static string AreaName = "Cognito";

        public static string CategoryName = "Authentication";

        private static UlsLogger _Current;

        public static UlsLogger Current
        {
            get
            {
                if (_Current == null)
                {
                    _Current = new UlsLogger();
                }
                return _Current;
            }
        }

        public UlsLogger()
            : base("Cognito Claim Provider Logging Service", SPFarm.Local)
        {
        }

        public UlsLogger(string Name, SPFarm Farm)
            : base(Name, Farm)
        {
        }

        protected override IEnumerable<SPDiagnosticsArea> ProvideAreas()
        {
            yield return new SPDiagnosticsArea(categories: new List<SPDiagnosticsCategory>
        {
            new SPDiagnosticsCategory(categoryId: (uint)(int)Enum.Parse(typeof(CategoryID), CategoryID.None.ToString()), name: CategoryID.None.ToString(), traceDefault: TraceSeverity.Verbose, eventDefault: EventSeverity.None, messageId: 0u),
            new SPDiagnosticsCategory(categoryId: (uint)(int)Enum.Parse(typeof(CategoryID), CategoryID.Processing.ToString()), name: CategoryID.Processing.ToString(), traceDefault: TraceSeverity.Verbose, eventDefault: EventSeverity.Information, messageId: 0u),
            new SPDiagnosticsCategory(categoryId: (uint)(int)Enum.Parse(typeof(CategoryID), CategoryID.Faulting.ToString()), name: CategoryID.Faulting.ToString(), traceDefault: TraceSeverity.Unexpected, eventDefault: EventSeverity.Error, messageId: 0u)
        }, name: AreaName);
        }

        public static void LogError(string errorMessage)
        {
            SPDiagnosticsCategory category = Current.Areas[AreaName].Categories[CategoryID.Faulting.ToString()];
            Current.WriteTrace(0u, category, TraceSeverity.Unexpected, errorMessage);
        }

        public static void LogInfo(string infoMessage)
        {
            SPDiagnosticsCategory category = Current.Areas[AreaName].Categories[CategoryID.Processing.ToString()];
            Current.WriteTrace(0u, category, TraceSeverity.Verbose, infoMessage);
        }
    }
}
