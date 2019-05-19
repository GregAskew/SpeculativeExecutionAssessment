namespace SpeculativeExecutionAssessment {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.Linq;
    using System.Management;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    #endregion

    [Serializable]
    public class SpeculativeExecutionAssessment {

        #region Members

        #region Fields
        public const string CSVHeader =
            "\"ComputerName\",\"DateTimeUTC\",\"ErrorMessage\"," +
            "\"IntelProcessorFamily\",\"IntelProcessorModel\"," +
            "\"ProcessorManufacturer\",\"ProcessorDescription\",\"ProcessorArchitecture\"," +
            "\"BTIFlags\",\"BTIHardwarePresent\",\"BTIWindowsSupportPresent\",\"BTIWindowsSupportEnabled\"," +
            "\"BTIDisabledByNoHardwareSupport\",\"BTIDisabledBySystemPolicy\"," +
            "\"BTIImportOptimizationEnabled\",\"BTIRetpolineEnabled\"," +
            "\"KernelVAFlags\",\"KVAShadowRequired\",\"KVAShadowWindowsSupportPresent\"," +
            "\"KVAShadowWindowsSupportEnabled\",\"KVAShadowPCIDEnabled\"," +
            "\"SSBDRequired\",\"SSBDHardwarePresent\",\"SSBDAvailable\",\"SSBDSystemWide\"," +
            "\"L1TFRequired\",\"L1TFMitigationPresent\",\"L1TFMitigationEnabled\",\"L1TFFlushSupported\"," +
            "\"L1TFInvalidPTEBit\",\"MDSMBClearReported\",\"MDSHardwareProtected\",\"MDSMBClearEnabled\"";
        #endregion

        public string ComputerName { get; set; }

        public DateTime DateTimeUTC { get; set; }

        public string ErrorMessage { get; set; }

        #region Processor Information Properties
        /// <summary>
        /// The Intel processor family
        /// </summary>
        public int? IntelProcessorFamily { get; set; }

        /// <summary>
        /// The Intel processor model
        /// </summary>
        public int? IntelProcessorModel { get; set; }

        /// <summary>
        /// The processor manufacturer
        /// </summary>
        public string ProcessorManufacturer { get; set; }

        /// <summary>
        /// The processor description
        /// </summary>
        public string ProcessorDescription { get; set; }

        /// <summary>
        /// The processor architecture
        /// </summary>
        public ProcessorArchitecture ProcessorArchitecture { get; set; }
        #endregion

        #region Branch Target Injection Properties

        public BTIFlags BTIFlags { get; set; }

        /// <summary>
        /// Hardware support for branch target injection mitigation is present.
        /// </summary>
        /// <remarks>
        /// True if hardware/firmware features are present to support the branch target injection mitigation.
        /// The device OEM is responsible for providing the updated BIOS/firmware that contains the microcode
        /// provided by CPU manufacturers.
        /// True if the required hardware features are present.
        /// False if the required hardware features are not present, and therefore the branch target injection
        /// mitigation cannot be enabled.
        /// Note: BTIHardwarePresent will be True in guest VMs if the OEM update has been applied to the host
        /// and guidance is followed:
        /// https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        /// </remarks>
        public bool BTIHardwarePresent { get; set; }

        /// <summary>
        /// Windows OS support for branch target injection mitigation is present.
        /// </summary>
        /// <remarks>
        /// True if the operating system supports enabling the branch target injection mitigation
        /// (the January 2018 security update has been installed).
        /// False if the January 2018 update has not been installed on the system, and the branch target injection
        /// mitigation cannot be enabled.
        /// If the update is not installed, NtQuerySystemInformation may return:
        /// Unexpected value returned from NtQuerySystemInformation: 3221225475
        /// </remarks>
        public bool BTIWindowsSupportPresent { get; set; }

        /// <summary>
        /// Windows OS support for branch target injection mitigation is enabled.
        /// </summary>
        /// <remarks>
        /// True if Windows operating system support is enabled for the branch target injection mitigation.
        /// If True, hardware support and OS support for the branch target injection mitigation is enabled
        /// for the device, thus protecting against CVE-2017-5715.
        /// If False, one of the following conditions is true:
        ///  - Hardware support is not present.
        ///  - OS support is not present.
        ///  - The mitigation has been disabled by system policy.
        /// Note: If a guest VM cannot detect the host hardware update, BTIWindowsSupportEnabled will be False.
        /// </remarks>
        public bool BTIWindowsSupportEnabled {
            get { return this.BTIHardwarePresent && this.BTIWindowsSupportPresent && btiWindowsSupportEnabled; }
            set { btiWindowsSupportEnabled = value; }
        }
        private bool btiWindowsSupportEnabled;

        /// <summary>
        /// Windows OS support for branch target injection mitigation is disabled by absence of hardware support.
        /// </summary>
        /// <remarks>
        /// True if the branch target injection mitigation has been disabled due to the absence of hardware support.
        /// True if absence of hardware support is responsible for disabling the mitigation.
        /// False if the mitigation is disabled by a different cause.
        /// Note: If a guest VM cannot detect the host hardware update, BTIDisabledByNoHardwareSupport will always be True.
        /// </remarks>
        public bool BTIDisabledByNoHardwareSupport { get; set; }

        /// <summary>
        /// Windows OS support for branch target injection mitigation is disabled by system policy.
        /// </summary>
        /// <remarks>
        /// True if the branch target injection mitigation has been disabled by system policy
        /// (such as an administrator-defined policy).
        /// System policy refers to the registry controls as documented in:
        /// https://support.microsoft.com/en-gb/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
        /// True if the system policy is responsible for disabling the mitigation.
        /// False when the mitigation is disabled by a different cause.
        /// </remarks>
        public bool BTIDisabledBySystemPolicy { get; set; }

        /// <summary>
        ///  Import call targets are determined at driver load time by processing the import address table (IAT)
        ///  and remain constant throughout the driver’s lifetime. This means that most of the work provided by the
        ///  retpoline import stub is unnecessary because we know at driver load time exactly where each of these
        ///  calls will end up going and we know whether the target binary supports retpoline or not.
        ///  Hence, we can use a much faster calling sequence.
        /// </summary>
        public bool BTIImportOptimizationEnabled { get; set; }

        /// <summary>
        /// Retpoline is a performance optimization for Spectre Variant 2.
        /// It requires that hardware and OS support for branch target injection to be present and enabled.
        /// Skylake and later generations of Intel processors are not compatible with Retpoline,
        /// so only Import Optimization will be enabled on these processors.
        /// </summary>
        public bool BTIRetpolineEnabled { get; set; }

        #endregion

        #region Kernel VA Shadow Properties

        public KernelVAFlags KernelVAFlags { get; set; }

        /// <summary>
        /// True if the hardware is believed to be vulnerable to CVE-2017-5754.
        /// False if the hardware is known to not be vulnerable to CVE-2017-5754.
        /// </summary>
        /// <remarks>
        /// False for AMD processors.
        /// </remarks>
        public bool KVAShadowRequired { get; set; }

        /// <summary>
        ///  True if the January 2018 update is installed on the device, and kernel VA shadow is supported.
        ///  False if the January 2018 update is not installed, and kernel VA shadow support does not exist.
        /// </summary>
        /// <remarks>
        /// If the update is not installed, NtQuerySystemInformation may return:
        /// Unexpected value returned from NtQuerySystemInformation: 3221225475
        /// </remarks>
        public bool KVAShadowWindowsSupportPresent { get; set; }

        /// <summary>
        /// Kernel VA shadow feature has been enabled.
        /// </summary>
        /// <remarks>
        /// True if the hardware is believed to be vulnerable to CVE-2017-5754, Windows operating system support is present,
        /// and the feature has been enabled.
        /// The Kernel VA shadow feature is currently enabled by default on client versions of Windows and is disabled by
        /// default on versions of Windows Server.
        /// False if either Windows operating system support is not present, or the feature has not been enabled.
        /// </remarks>
        public bool KVAShadowWindowsSupportEnabled { get; set; }

        /// <summary>
        /// Additional performance optimization has been enabled for kernel VA shadow.
        /// </summary>
        /// <remarks>
        /// True if kernel VA shadow is enabled, hardware support for PCID is present, and PCID optimization for
        /// kernel VA shadow has been enabled.
        /// False if either the hardware or the OS may not support PCID.
        /// It is not a security weakness for the PCID optimization to not be enabled.
        /// </remarks>
        public bool KVAShadowPCIDEnabled { get; set; }
        #endregion

        #region SSBD Properties

        /// <summary>
        /// True if the hardware is vulnerable to speculative store bypass
        /// </summary>
        public bool? SSBDRequired { get; set; }

        /// <summary>
        /// True if hardware support for speculative store bypass mitigation is present
        /// </summary>
        public bool SSBDHardwarePresent { get; set; }

        /// <summary>
        /// True if Windows OS support for speculative store bypass mitigation is present.
        /// </summary>
        public bool SSBDAvailable { get; set; }

        /// <summary>
        /// True if Windows OS support for speculative store bypass mitigation is enabled system-wide
        /// This requires installing the operating system update, and setting the registry values:
        /// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverride REG_DWORD 8
        /// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverrideMask REG_DWORD 3
        /// </summary>
        public bool SSBDSystemWide { get; set; }

        #endregion

        #region L1 Terminal Fault Properties

        /// <summary>
        /// True if L1 Terminal Fault mitigation is required
        /// </summary>
        public bool L1TFRequired { get; set; }

        /// <summary>
        /// True if L1 Terminal Fault mitigation is present
        /// </summary>
        public bool L1TFMitigationPresent { get; set; }

        /// <summary>
        /// True if L1 Terminal Fault mitigation is enabled
        /// </summary>
        public bool L1TFMitigationEnabled { get; set; }

        /// <summary>
        /// True if L1 Terminal Fault flush is supported
        /// </summary>
        public bool L1TFFlushSupported { get; set; }

        public uint? L1TFInvalidPTEBit { get; set; }

        #endregion

        #region Microarchitectural Data Sampling Properties

        /// <summary>
        /// True if MDS MB clear is reported
        /// </summary>
        public bool MDSMBClearReported { get; set; }

        /// <summary>
        /// True if MDS hardware is protected
        /// </summary>
        public bool MDSHardwareProtected { get; set; }

        /// <summary>
        /// True if MDS MB clear is enabled
        /// </summary>
        public bool MDSMBClearEnabled { get; set; }

        #endregion
        #endregion

        #region Constructor
        public SpeculativeExecutionAssessment() {
            this.ComputerName = Environment.MachineName;
            this.DateTimeUTC = DateTime.UtcNow;
            this.ErrorMessage = string.Empty;

            this.ProcessorArchitecture = ProcessorArchitecture.Undefined;

            this.BTIDisabledByNoHardwareSupport = true;
            this.KVAShadowRequired = true;

            this.L1TFRequired = true;

            this.GetProcessorWmiInformation();
        }
        #endregion

        #region Methods

        private void GetProcessorWmiInformation() {

            try {
                var scope = new ManagementScope($@"\root\CIMV2");
                var query = new ObjectQuery("SELECT Architecture,Description,Manufacturer FROM Win32_Processor");
                using (var searcher = new ManagementObjectSearcher(scope, query)) {
                    searcher.Options.Timeout = TimeSpan.FromMinutes(5);
                    foreach (ManagementObject managementObject in searcher.Get()) {
                        foreach (PropertyData prop in managementObject.Properties) {

                            switch (prop.Name) {
                                case "Manufacturer":
                                    this.ProcessorManufacturer = prop.Value.ToString();
                                    break;
                                case "Description":
                                    this.ProcessorDescription = prop.Value.ToString();
                                    break;
                                case "Architecture":
                                    if (ushort.TryParse(prop.Value.ToString(), out ushort temp)) {
                                        if (Enum.TryParse<ProcessorArchitecture>(temp.ToString(), out ProcessorArchitecture processorArchitecture)) {
                                            this.ProcessorArchitecture = processorArchitecture;
                                        }
                                    }
                                    break;
                            }
                        } // foreach (PropertyData prop in managementObject.Properties) {

                        break;

                    } // foreach (ManagementObject managementObject in searcher.Get()) {
                } // using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))

                Console.WriteLine($"Processor: Manufacturer: {(!string.IsNullOrWhiteSpace(this.ProcessorManufacturer) ? this.ProcessorManufacturer : "N/A")} Description: {(!string.IsNullOrWhiteSpace(this.ProcessorDescription) ? this.ProcessorDescription : "N/A")} Architecture: {this.ProcessorArchitecture}");

                // Get Intel specific Processor Family
                if (string.IsNullOrWhiteSpace(this.ProcessorManufacturer) || string.IsNullOrWhiteSpace(this.ProcessorDescription)) return;
                if (!string.Equals(this.ProcessorManufacturer, "GenuineIntel", StringComparison.OrdinalIgnoreCase)) return;
                if (this.ProcessorDescription.IndexOf("Family", StringComparison.OrdinalIgnoreCase) == -1) return;

                // Example processor description:
                // Intel64 Family 6 Model 58 Stepping 9

                var processorDescription = this.ProcessorDescription.Substring(this.ProcessorDescription.IndexOf("Family", StringComparison.OrdinalIgnoreCase));
                if (processorDescription.IndexOf("Stepping", StringComparison.OrdinalIgnoreCase) > -1) {
                    processorDescription = processorDescription.Substring(0, processorDescription.IndexOf("Stepping", StringComparison.OrdinalIgnoreCase));
                }
                processorDescription = processorDescription.Trim();
                // Family 6 Model 58

                var processorDescriptionElements = processorDescription.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (processorDescriptionElements.Length == 4) {
                    if (!int.TryParse(processorDescriptionElements[1], out int processorFamily)) {
                        this.ErrorMessage += $"Unable to parse numeric Processor Family from WMI Description: {this.ProcessorDescription};";
                        return;
                    }
                    if (!int.TryParse(processorDescriptionElements[3], out int processorModel)) {
                        this.ErrorMessage += $"Unable to parse numeric Processor Model from WMI Description: {this.ProcessorDescription};";
                        return;
                    }

                    this.IntelProcessorFamily = processorFamily;
                    this.IntelProcessorModel = processorModel;

                }
                else {
                    this.ErrorMessage += $"Unable to parse expected number (four) elements from from WMI Processor Description: {this.ProcessorDescription};";
                }

            }
            catch (Exception e) {
                this.ErrorMessage += $"Exception: {e.Message} TargetSite: {e.TargetSite.Name};";
            }

        }

        private bool IsEnumValid<TEnum>(TEnum enumToTest) {
            bool isvalid = false;

            if (!enumToTest.GetType().IsEnum) {
                return false;
            }

            if (Enum.IsDefined(enumToTest.GetType(), enumToTest)) {
                isvalid = true;
            }
            else {
                // for flags, converting to a string will always be a friendly text. If a number, it isn't valid.
                char firstDigit = enumToTest.ToString()[0];
                if (!char.IsDigit(firstDigit) && (firstDigit != '-')) {
                    isvalid = true;
                }
            }

            return isvalid;
        }

        internal void SetBranchTargetInjectionProperties(IntPtr systemInformationPtr) {
            if (systemInformationPtr == null) {
                throw new ArgumentNullException(nameof(systemInformationPtr));
            }

            this.BTIFlags = (BTIFlags)(uint)Marshal.ReadInt32(systemInformationPtr);
            if (!this.IsEnumValid<BTIFlags>(this.BTIFlags)) {
                var message = $"IsEnumValid<BTIFlags>(this.BTIFlags) returned false. BTIFlags value: {this.BTIFlags}";
                this.ErrorMessage = message;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(message);
                Console.ResetColor();
                return;
            }

            this.BTIHardwarePresent =
                this.BTIFlags.HasFlag(BTIFlags.SCFHwReg1Enumerated)
                || this.BTIFlags.HasFlag(BTIFlags.SCFHwReg2Enumerated);

            this.BTIWindowsSupportPresent = true;
            this.BTIWindowsSupportEnabled = this.BTIFlags.HasFlag(BTIFlags.SCFBpbEnabled);
            this.BTIRetpolineEnabled = this.BTIFlags.HasFlag(BTIFlags.SCFSpecCtrlRetpolineEnabled);
            this.BTIImportOptimizationEnabled = this.BTIFlags.HasFlag(BTIFlags.SCFSpecCtrlImportOptimizationEnabled);

            if (!this.BTIWindowsSupportEnabled) {
                this.BTIDisabledBySystemPolicy = this.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledSystemPolicy);
                this.BTIDisabledByNoHardwareSupport = this.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledNoHardwareSupport);
            }
            else {
                this.BTIDisabledBySystemPolicy = false;
                this.BTIDisabledByNoHardwareSupport = false;
            }

            if (this.BTIFlags.HasFlag(BTIFlags.SCFSSBDAvailable)) {
                this.SSBDAvailable = true;
                this.SSBDHardwarePresent = this.BTIFlags.HasFlag(BTIFlags.SCFSSBDSupported);
                this.SSBDSystemWide = this.BTIFlags.HasFlag(BTIFlags.SCFSSBDSystemWide);
                this.SSBDRequired = this.BTIFlags.HasFlag(BTIFlags.SCFSSBDRequired);
            }

            this.MDSHardwareProtected = this.BTIFlags.HasFlag(BTIFlags.SCFMDSHardwareProtected);
            this.MDSMBClearEnabled = this.BTIFlags.HasFlag(BTIFlags.SCFMBClearEnabled);
            this.MDSMBClearReported = this.BTIFlags.HasFlag(BTIFlags.SCFMBClearReported);

            if ((this.ProcessorArchitecture == ProcessorArchitecture.ARM)
                || string.Equals(this.ProcessorManufacturer ?? string.Empty, "AuthenticAMD", StringComparison.OrdinalIgnoreCase)) {
                this.MDSHardwareProtected = true;
            }
        }

        internal void SetKernelVAShadowProperties(IntPtr systemInformationPtr) {
            if (systemInformationPtr == null) {
                throw new ArgumentNullException(nameof(systemInformationPtr));
            }

            uint systemInformation = (uint)Marshal.ReadInt32(systemInformationPtr);
            this.KernelVAFlags = (KernelVAFlags)systemInformation;
            if (!this.IsEnumValid<KernelVAFlags>(this.KernelVAFlags)) {
                var message = $"IsEnumValid<KernelVAFlags>(this.KernelVAFlags) returned false. KernelVAFlags value: {this.KernelVAFlags}";
                this.ErrorMessage = message;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(message);
                Console.ResetColor();
                return;
            }

            this.KVAShadowWindowsSupportPresent = true;
            this.KVAShadowWindowsSupportEnabled = this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowEnabledFlag);
            this.KVAShadowPCIDEnabled =
                this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowPCIDFlag)
                && this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowInvPCIDFlag);

            if (this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowRequiredAvailableFlag)) {
                this.KVAShadowRequired = this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowRequiredFlag);
            }
            else {

                if (string.Equals(this.ProcessorManufacturer, "AuthenticAMD", StringComparison.OrdinalIgnoreCase)) {
                    this.KVAShadowRequired = false;
                    return;
                }
                if (!string.Equals(this.ProcessorManufacturer, "GenuineIntel", StringComparison.OrdinalIgnoreCase)) {
                    this.ErrorMessage += $"Unable to set KVA Information due to unsupported processor manufacturer: {this.ProcessorManufacturer}";
                    return;
                }

                if (!this.IntelProcessorFamily.HasValue || !this.IntelProcessorModel.HasValue) {
                    this.ErrorMessage += "Unable to determine if KVA not required due to Intel processor family/model not available from WMI";
                    return;
                }

                if (this.IntelProcessorFamily == 0x6) {
                    if ((this.IntelProcessorModel == 0x1C)
                        || (this.IntelProcessorModel == 0x26)
                        || (this.IntelProcessorModel == 0x27)
                        || (this.IntelProcessorModel == 0x36)
                        || (this.IntelProcessorModel == 0x35)) {
                        this.KVAShadowRequired = false;
                    }
                }
            }

            if (this.ProcessorArchitecture == ProcessorArchitecture.ARM) {
                this.L1TFRequired = false;
            }
            else {
                this.L1TFRequired = this.KVAShadowRequired;
            }

            uint l1TFInvalidPTEBitShift = 0x00000006;
            uint l1TFInvalidPTEBitMask = 0x00000FC0;

            //this.L1TFInvalidPTEBit = ((uint)this.KernelVAFlags & l1TFInvalidPTEBitMask)
            //    >> (int)l1TFInvalidPTEBitShift;

            this.L1TFInvalidPTEBit = (uint)Math.Floor(((uint)this.KernelVAFlags & l1TFInvalidPTEBitMask) * Math.Pow(2, -l1TFInvalidPTEBitShift));

            this.L1TFMitigationEnabled = this.L1TFInvalidPTEBit.HasValue && (this.L1TFInvalidPTEBit != 0)
                && this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowEnabledFlag);
            this.L1TFFlushSupported = this.KernelVAFlags.HasFlag(KernelVAFlags.L1TFFlushSupported);

            if (this.KernelVAFlags.HasFlag(KernelVAFlags.L1TFMitigationPresent)
                || this.L1TFMitigationEnabled || this.L1TFFlushSupported) {
                this.L1TFMitigationPresent = true;
            }
        }

        [DebuggerStepThroughAttribute]
        public string ToCSVString() {
            var info = new StringBuilder();

            info.Append($"\"{this.ComputerName ?? string.Empty}\",");
            info.Append($"\"{this.DateTimeUTC.YMDHMSFriendly()}\",");
            info.Append($"\"{(this.ErrorMessage ?? string.Empty).Replace("\"", "'")}\",");
            info.Append($"\"{(this.IntelProcessorFamily.HasValue ? this.IntelProcessorFamily.Value.ToString() : string.Empty)}\",");
            info.Append($"\"{(this.IntelProcessorModel.HasValue ? this.IntelProcessorModel.Value.ToString() : string.Empty)}\",");
            info.Append($"\"{this.ProcessorManufacturer ?? string.Empty}\",");
            info.Append($"\"{this.ProcessorDescription ?? string.Empty}\",");
            info.Append($"\"{this.ProcessorArchitecture}\",");
            info.Append($"\"{this.BTIFlags}\",");
            info.Append($"\"{this.BTIHardwarePresent.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIWindowsSupportPresent.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIWindowsSupportEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIDisabledByNoHardwareSupport.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIDisabledBySystemPolicy.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIImportOptimizationEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.BTIRetpolineEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.KernelVAFlags}\",");
            info.Append($"\"{this.KVAShadowRequired.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.KVAShadowWindowsSupportPresent.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.KVAShadowWindowsSupportEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.KVAShadowPCIDEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{(this.SSBDRequired.HasValue ? this.SSBDRequired.ToString().ToUpperInvariant() : string.Empty)}\",");
            info.Append($"\"{this.SSBDHardwarePresent.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.SSBDAvailable.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.SSBDSystemWide.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.L1TFRequired.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.L1TFMitigationPresent.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.L1TFMitigationEnabled.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.L1TFFlushSupported.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{(this.L1TFInvalidPTEBit.HasValue ? this.L1TFInvalidPTEBit.Value.ToString() : string.Empty)}\",");
            info.Append($"\"{this.MDSMBClearReported.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.MDSHardwareProtected.ToString().ToUpperInvariant()}\",");
            info.Append($"\"{this.MDSMBClearEnabled.ToString().ToUpperInvariant()}\"");

            return info.ToString();
        }

        #endregion
    }
}
