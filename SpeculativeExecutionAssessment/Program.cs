namespace SpeculativeExecutionAssessment {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Management;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    using System.Xml.Serialization;
    #endregion

    /// <summary>
    /// Assesses a system for the "speculative execution" vulnerabilities described in:
    ///  CVE-2017-5715 (branch target injection)
    ///  CVE-2017-5753 (bounds check bypass)
    ///  CVE-2017-5754 (rogue data cache load)
    /// </summary>
    /// <remarks>
    /// WARNING: Ensure that "Prefer 32-bit" is not checked in the build options.
    /// Requires elevated permissions
    /// Mitigiation requires:
    ///  1. Set the registry value indicating the antivirus/security product is compatible with the Windows update
    ///  2. Install the Windows operating system update (part of the January 2018 Security Monthly Quality Rollup)
    ///  3. Enable the registry settings
    ///  4. Update the hardware/firmware
    ///  5. On virtual platforms, the hypervisor must be updated (or for Hyper-V, it may be reconfigured)
    /// https://gallery.technet.microsoft.com/scriptcenter/Speculation-Control-e36f0050
    /// https://support.microsoft.com/en-gb/help/4074629/understanding-the-output-of-get-speculationcontrolsettings-powershell
    /// https://blogs.technet.microsoft.com/ralphkyttle/2018/01/05/verifying-spectre-meltdown-protections-remotely/
    /// https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
    /// https://support.microsoft.com/en-gb/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
    /// https://community.hpe.com/t5/Servers-The-Right-Compute/Resources-to-help-mitigate-Speculative-Execution-vulnerability/ba-p/6992955
    /// https://support.microsoft.com/kn-in/help/4073225/guidance-for-sql-server
    /// https://kb.vmware.com/s/article/52245
    /// https://github.com/ionescu007/SpecuCheck/blob/master/specucheck.c
    /// </remarks>
    class Program {

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtQuerySystemInformation")]
        internal static extern long NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            IntPtr ReturnLength);

        static void Main(string[] args) {

            var speculativeExecutionAssessment = new SpeculativeExecutionAssessment();

            try {

                GetBranchTargetInjectionInformation(speculativeExecutionAssessment);
                if (string.IsNullOrWhiteSpace(speculativeExecutionAssessment.ErrorMessage)) {
                    GetKernelVAShadowInformation(speculativeExecutionAssessment);
                }

                #region Display/log guidance
                if (string.IsNullOrWhiteSpace(speculativeExecutionAssessment.ErrorMessage)) {
                    var actions = new List<string>();
                    if (!speculativeExecutionAssessment.BTIHardwarePresent) {
                        actions.Add("Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation.");
                    }

                    if (!speculativeExecutionAssessment.BTIWindowsSupportPresent || !speculativeExecutionAssessment.KVAShadowWindowsSupportPresent) {
                        actions.Add("Install the latest available updates for Windows with support for speculation control mitigations.");
                    }

                    if ((speculativeExecutionAssessment.BTIHardwarePresent && !speculativeExecutionAssessment.BTIWindowsSupportEnabled)
                        || (speculativeExecutionAssessment.KVAShadowRequired && !speculativeExecutionAssessment.KVAShadowWindowsSupportEnabled)) {

                        var guidanceUri = string.Empty;
                        var guidanceType = string.Empty;

                        var productTypeWmiErrorMessage = GetWindowsProductTypeWmiInformation(out int productType);
                        if (string.IsNullOrWhiteSpace(productTypeWmiErrorMessage) && productType > 0) {
                            if (productType == 1) {
                                guidanceUri = "https://support.microsoft.com/help/4073119";
                                guidanceType = "Client";
                            }
                            else {
                                guidanceUri = "https://support.microsoft.com/help/4072698";
                                guidanceType = "Server";
                            }

                            actions.Add($"Follow the guidance for enabling Windows {guidanceType} support for speculation control mitigations described in: {guidanceUri}");
                        }
                        else {
                            speculativeExecutionAssessment.ErrorMessage = productTypeWmiErrorMessage;
                        }
                    }

                    if (actions.Count > 0) {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine();
                        Console.WriteLine("Suggested actions:");
                        Console.WriteLine();
                        foreach (var item in actions) {
                            Console.WriteLine(item);
                        }
                        Console.ResetColor();
                    }
                }
                #endregion
            }
            catch (Exception e) {
                speculativeExecutionAssessment.ErrorMessage = e.Message;
            }
            finally {
                var systemRootFolder = Environment.ExpandEnvironmentVariables("%SYSTEMROOT%");
                var filePath = Path.Combine(systemRootFolder, $"{Environment.MachineName}-SpeculativeExecutionAssessment.xml");
                Console.WriteLine();
                Console.Write($"Creating assessment report file: {filePath}...");
                using (var fileStream = new FileStream(filePath, FileMode.Create))
                using (var streamWriter = new StreamWriter(fileStream, Encoding.UTF8)) {
                    var xmlSerializer = new XmlSerializer(typeof(SpeculativeExecutionAssessment));
                    xmlSerializer.Serialize(streamWriter, speculativeExecutionAssessment);
                }
                Console.WriteLine("Done.");
            }
        }

        private static void GetBranchTargetInjectionInformation(SpeculativeExecutionAssessment speculativeExecutionAssessment) {

            IntPtr systemInformationPtr = Marshal.AllocHGlobal(4);
            IntPtr returnLengthPtr = Marshal.AllocHGlobal(4);

            try {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("Speculation control settings for CVE-2017-5715 [branch target injection]");
                Console.WriteLine("For more information about the output below, please refer to https://support.microsoft.com/en-in/help/4074629");
                Console.WriteLine();
                Console.ResetColor();

                uint systemInformationLength = 4;

                long retval = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemBranchTargetInjection,
                    systemInformationPtr, systemInformationLength, returnLengthPtr);

                if (retval != 0) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    var message = $"Unexpected value returned from NtQuerySystemInformation: {retval}";
                    Console.WriteLine(message);
                    speculativeExecutionAssessment.ErrorMessage = message;
                    Console.ResetColor();
                    return;
                }
                else {
                    speculativeExecutionAssessment.SetBranchTargetInjectionProperties(systemInformationPtr);

                    if (string.IsNullOrWhiteSpace(speculativeExecutionAssessment.ErrorMessage)) {

                        #region Debug logging
                        Debug.WriteLine($"BpbEnabled: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFBpbEnabled)}");
                        Debug.WriteLine($"BpbDisabledSystemPolicy: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledSystemPolicy)}");
                        Debug.WriteLine($"BpbDisabledNoHardwareSupport: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledNoHardwareSupport)}");
                        Debug.WriteLine($"HwReg1Enumerated: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFHwReg1Enumerated)}");
                        Debug.WriteLine($"HwReg2Enumerated: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFHwReg2Enumerated)}");
                        Debug.WriteLine($"HwMode1Present: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFHwMode1Present)}");
                        Debug.WriteLine($"HwMode2Present: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFHwMode2Present)}");
                        Debug.WriteLine($"SmepPresent: {speculativeExecutionAssessment.BTIFlags.HasFlag(BTIFlags.SCFHwMode2Present)}");
                        #endregion

                        Console.Write("Hardware support for branch target injection mitigation is present: ");
                        Console.ForegroundColor = speculativeExecutionAssessment.BTIHardwarePresent ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.WriteLine(speculativeExecutionAssessment.BTIHardwarePresent.ToString().ToUpperInvariant());
                        Console.ResetColor();

                        Console.Write("Windows OS support for branch target injection mitigation is present: ");
                        Console.ForegroundColor = speculativeExecutionAssessment.BTIWindowsSupportPresent ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.WriteLine(speculativeExecutionAssessment.BTIWindowsSupportPresent.ToString().ToUpperInvariant());
                        Console.ResetColor();

                        Console.Write("Windows OS support for branch target injection mitigation is enabled: ");
                        Console.ForegroundColor = speculativeExecutionAssessment.BTIWindowsSupportEnabled ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.WriteLine(speculativeExecutionAssessment.BTIWindowsSupportEnabled.ToString().ToUpperInvariant());
                        Console.ResetColor();

                        #region If Windows support for branch target injection mitigation is present but not enabled, log the reason (absence of settings or lack of hardware support)
                        if (speculativeExecutionAssessment.BTIWindowsSupportPresent && !speculativeExecutionAssessment.BTIWindowsSupportEnabled) {
                            Console.Write($"Windows OS support for branch target injection mitigation is disabled by system policy: ");
                            Console.ForegroundColor = speculativeExecutionAssessment.BTIDisabledBySystemPolicy ? ConsoleColor.Red : ConsoleColor.Green;
                            Console.WriteLine(speculativeExecutionAssessment.BTIDisabledBySystemPolicy.ToString().ToUpperInvariant());
                            Console.ResetColor();

                            Console.Write($"Windows OS support for branch target injection mitigation is disabled by absence of hardware support: ");
                            Console.ForegroundColor = speculativeExecutionAssessment.BTIDisabledByNoHardwareSupport ? ConsoleColor.Red : ConsoleColor.Green;
                            Console.WriteLine(speculativeExecutionAssessment.BTIDisabledByNoHardwareSupport.ToString().ToUpperInvariant());
                            Console.ResetColor();
                        }
                        #endregion

                    }
                }
            }
            finally {
                if (systemInformationPtr != IntPtr.Zero) {
                    Marshal.FreeHGlobal(systemInformationPtr);
                }

                if (returnLengthPtr != IntPtr.Zero) {
                    Marshal.FreeHGlobal(returnLengthPtr);
                }
            }
        }

        private static void GetKernelVAShadowInformation(SpeculativeExecutionAssessment speculativeExecutionAssessment) {

            IntPtr systemInformationPtr = Marshal.AllocHGlobal(4);
            IntPtr returnLengthPtr = Marshal.AllocHGlobal(4);

            try {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine();
                Console.WriteLine("Speculation control settings for CVE-2017-5754 [rogue data cache load]");
                Console.WriteLine();
                Console.ResetColor();

                GetProcessorWmiInformation(speculativeExecutionAssessment);

                if (!string.IsNullOrWhiteSpace(speculativeExecutionAssessment.ErrorMessage)) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Exiting due to error getting processor WMI information: {speculativeExecutionAssessment.ErrorMessage}");
                    Console.ResetColor();
                    return;
                }

                uint systemInformationLength = 4;

                long retval = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelVAShadow, systemInformationPtr, systemInformationLength, returnLengthPtr);

                if (retval != 0) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    var message = $"Unexpected value returned from NtQuerySystemInformation: {retval}";
                    Console.WriteLine(message);
                    speculativeExecutionAssessment.ErrorMessage = message;
                    Console.ResetColor();
                    return;
                }
                else {
                    speculativeExecutionAssessment.SetKernelVAShadowProperties(systemInformationPtr);

                    if (string.IsNullOrWhiteSpace(speculativeExecutionAssessment.ErrorMessage)) {
                        Debug.WriteLine($"KVAShadowWindowsSupportEnabled: {speculativeExecutionAssessment.KVAShadowWindowsSupportEnabled}");
                        Debug.WriteLine($"KvaShadowUserGlobal: {speculativeExecutionAssessment.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowUserGlobalFlag)}");
                        Debug.WriteLine($"KvaShadowPcid: {speculativeExecutionAssessment.KVAShadowPcidEnabled}");
                        Debug.WriteLine($"KvaShadowInvpcid: {speculativeExecutionAssessment.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowInvpcidFlag)}");

                        Console.WriteLine($"Hardware requires kernel VA shadowing: {speculativeExecutionAssessment.KVAShadowRequired.ToString().ToUpperInvariant()}");

                        if (speculativeExecutionAssessment.KVAShadowRequired) {
                            Console.Write("Windows OS support for kernel VA shadow is present: ");
                            Console.ForegroundColor = speculativeExecutionAssessment.KVAShadowWindowsSupportPresent ? ConsoleColor.Green : ConsoleColor.Red;
                            Console.WriteLine(speculativeExecutionAssessment.KVAShadowWindowsSupportPresent.ToString().ToUpperInvariant());
                            Console.ResetColor();

                            Console.Write("Windows OS support for kernel VA shadow is enabled: ");
                            Console.ForegroundColor = speculativeExecutionAssessment.KVAShadowWindowsSupportEnabled ? ConsoleColor.Green : ConsoleColor.Red;
                            Console.WriteLine(speculativeExecutionAssessment.KVAShadowWindowsSupportEnabled.ToString().ToUpperInvariant());
                            Console.ResetColor();

                            if (speculativeExecutionAssessment.KVAShadowWindowsSupportEnabled) {
                                Console.Write("Windows OS support for PCID performance optimization is enabled [not required for security]: ");
                                Console.ForegroundColor = speculativeExecutionAssessment.KVAShadowPcidEnabled ? ConsoleColor.Green : ConsoleColor.White;
                                Console.WriteLine(speculativeExecutionAssessment.KVAShadowPcidEnabled.ToString().ToUpperInvariant());
                                Console.ResetColor();
                            }
                        }
                    }
                }
            }
            finally {
                if (systemInformationPtr != IntPtr.Zero) {
                    Marshal.FreeHGlobal(systemInformationPtr);
                }

                if (returnLengthPtr != IntPtr.Zero) {
                    Marshal.FreeHGlobal(returnLengthPtr);
                }
            }
        }

        private static void GetProcessorWmiInformation(SpeculativeExecutionAssessment speculativeExecutionAssessment) {

            var processorManufacturer = string.Empty;
            var processorDescription = string.Empty;

            try {
                var scope = new ManagementScope($@"\root\CIMV2");
                var query = new ObjectQuery("SELECT Manufacturer,Description FROM Win32_Processor");
                using (var searcher = new ManagementObjectSearcher(scope, query)) {
                    searcher.Options.Timeout = TimeSpan.FromMinutes(5);
                    foreach (ManagementObject managementObject in searcher.Get()) {
                        foreach (PropertyData prop in managementObject.Properties) {

                            if (prop.Name == "Manufacturer") processorManufacturer = prop.Value.ToString();
                            if (prop.Name == "Description") processorDescription = prop.Value.ToString();
                        } // foreach (PropertyData prop in managementObject.Properties) {
                        break;
                    } // foreach (ManagementObject managementObject in searcher.Get()) {
                } // using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))

                Console.WriteLine($"Processor: Manufacturer: {(!string.IsNullOrWhiteSpace(processorManufacturer) ? processorManufacturer : "N/A")} Description: {(!string.IsNullOrWhiteSpace(processorDescription) ? processorDescription : "N/A")}");

                if (string.IsNullOrWhiteSpace(processorManufacturer)) {
                    speculativeExecutionAssessment.ErrorMessage = "Unable to get Processor Manufacturer from WMI";
                }
                if (string.Equals(processorManufacturer, "AuthenticAMD", StringComparison.OrdinalIgnoreCase)) {
                    speculativeExecutionAssessment.KVAShadowRequired = false;
                    return;
                }
                if (!string.Equals(processorManufacturer, "GenuineIntel", StringComparison.OrdinalIgnoreCase)) {
                    speculativeExecutionAssessment.ErrorMessage = $"Unsupported processor manufacturer: {processorManufacturer}";
                }

                if (string.IsNullOrWhiteSpace(processorDescription)) {
                    speculativeExecutionAssessment.ErrorMessage = "Unable to get Processor Description from WMI";
                    return;
                }

                if (processorDescription.IndexOf("Family") == -1) {
                    speculativeExecutionAssessment.ErrorMessage = "Processor Description from WMI does not contain Family";
                    return;
                }

                if (processorDescription.IndexOf("Model") == -1) {
                    speculativeExecutionAssessment.ErrorMessage = "Processor Description from WMI does not contain Model";
                    return;
                }

                // Example processor description:
                // Intel64 Family 6 Model 58 Stepping 9

                processorDescription = processorDescription.Substring(processorDescription.IndexOf("Family"));
                if (processorDescription.IndexOf("Stepping", StringComparison.OrdinalIgnoreCase) > -1) {
                    processorDescription = processorDescription.Substring(0, processorDescription.IndexOf("Stepping", StringComparison.OrdinalIgnoreCase));
                }
                processorDescription = processorDescription.Trim();
                // Family 6 Model 58

                var processorDescriptionElements = processorDescription.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (processorDescriptionElements.Length == 4) {
                    if (!int.TryParse(processorDescriptionElements[1], out int processorFamily)) {
                        speculativeExecutionAssessment.ErrorMessage = $"Unable to parse numeric Processor Family from WMI Description: {processorDescription}";
                        return;
                    }
                    if (!int.TryParse(processorDescriptionElements[3], out int processorModel)) {
                        speculativeExecutionAssessment.ErrorMessage = $"Unable to parse numeric Processor Model from WMI Description: {processorDescription}";
                        return;
                    }

                    if (processorFamily == 0x6) {
                        if ((processorModel == 0x1C) || (processorModel == 0x26) || (processorModel == 0x27)
                            || (processorModel == 0x36) || (processorModel == 0x35)) {
                            speculativeExecutionAssessment.KVAShadowRequired = false;
                        }
                    }
                }
                else {
                    speculativeExecutionAssessment.ErrorMessage = $"Unable to parse expected number (four) elements from from WMI Processor Description: {processorDescription}";
                }
            }
            catch (Exception e) {
                speculativeExecutionAssessment.ErrorMessage = $"Exception: {e.Message} TargetSite: {e.TargetSite.Name}";
            }

        }

        private static string GetWindowsProductTypeWmiInformation(out int productType) {

            var returnErrorMessage = string.Empty;
            productType = -1;

            try {
                var scope = new ManagementScope($@"\root\CIMV2");
                var query = new ObjectQuery("SELECT ProductType FROM Win32_OperatingSystem");
                using (var searcher = new ManagementObjectSearcher(scope, query)) {
                    searcher.Options.Timeout = TimeSpan.FromMinutes(5);
                    foreach (ManagementObject managementObject in searcher.Get()) {
                        foreach (PropertyData prop in managementObject.Properties) {

                            if (prop.Name == "ProductType") productType = Convert.ToInt32(prop.Value.ToString());

                        } // foreach (PropertyData prop in managementObject.Properties) {
                        break;
                    } // foreach (ManagementObject managementObject in searcher.Get()) {
                } // using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
            }
            catch (Exception e) {
                returnErrorMessage = $"Exception: {e.Message} TargetSite: {e.TargetSite.Name}";
            }

            return returnErrorMessage;
        }
    }
}
