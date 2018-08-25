namespace SpeculativeExecutionAssessment {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks; 
    #endregion

    internal static class InternalExtensions {

        /// <summary>
        /// Stack trace, target site, and error message of outer and inner exception, formatted with newlines
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="exception"></param>
        /// <returns></returns>
        [DebuggerStepThroughAttribute]
        public static string VerboseExceptionString<T>(this T exception) where T : Exception {
            var exceptionString = new StringBuilder();

            exceptionString.AppendLine($" Exception: {exception.GetType().Name} Message: {exception.Message ?? "NULL"}");
            exceptionString.AppendLine($" StackTrace: {exception.StackTrace ?? "NULL"}");
            exceptionString.AppendLine($" TargetSite: {(exception.TargetSite != null ? exception.TargetSite.ToString() : "NULL")}");

            if (exception.InnerException != null) {
                exceptionString.AppendLine();
                exceptionString.AppendLine("Inner Exception:");
                exceptionString.AppendLine(exception.InnerException.VerboseExceptionString());
            }

            return exceptionString.ToString();
        }
    }
}
