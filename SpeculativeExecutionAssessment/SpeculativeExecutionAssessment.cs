﻿namespace SpeculativeExecutionAssessment {

    #region Usings
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    #endregion

    [Serializable]
    public class SpeculativeExecutionAssessment {

        #region Members

        public string ComputerName { get; set; }

        public DateTime DateTimeUTC { get; set; }

        public string ErrorMessage { get; set; }

        #region Branch Target Injection Members

        public BTIFlags BTIFlags { get; set; }

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
        #endregion

        #region Kernel VA Shadow Members

        public KernelVAFlags KernelVAFlags { get; set; }

        /// <summary>
        /// Additional performance optimization has been enabled for kernel VA shadow. 
        /// </summary>
        /// <remarks>
        /// True if kernel VA shadow is enabled, hardware support for PCID is present, and PCID optimization for 
        /// kernel VA shadow has been enabled. 
        /// False if either the hardware or the OS may not support PCID. 
        /// It is not a security weakness for the PCID optimization to not be enabled.
        /// </remarks>
        public bool KVAShadowPcidEnabled { get; set; }

        /// <summary>
        /// True if the hardware is believed to be vulnerable to CVE-2017-5754. 
        /// False if the hardware is known to not be vulnerable to CVE-2017-5754.
        /// </summary>
        /// <remarks>
        /// False for AMD processors.
        /// </remarks>
        public bool KVAShadowRequired { get; set; }

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
        ///  True if the January 2018 update is installed on the device, and kernel VA shadow is supported. 
        ///  False if the January 2018 update is not installed, and kernel VA shadow support does not exist.
        /// </summary>
        /// <remarks>
        /// If the update is not installed, NtQuerySystemInformation may return:
        /// Unexpected value returned from NtQuerySystemInformation: 3221225475
        /// </remarks>
        public bool KVAShadowWindowsSupportPresent { get; set; }
        #endregion

        #endregion

        #region Constructor
        public SpeculativeExecutionAssessment() {
            this.ComputerName = Environment.MachineName;
            this.DateTimeUTC = DateTime.UtcNow;
            this.ErrorMessage = string.Empty;

            this.BTIDisabledByNoHardwareSupport = true;
            this.KVAShadowRequired = true;
        }
        #endregion

        #region Methods

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
                throw new ArgumentNullException("systemInformationPointer");
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

            if (!this.BTIWindowsSupportEnabled) {
                this.BTIDisabledBySystemPolicy = this.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledSystemPolicy);
                this.BTIDisabledByNoHardwareSupport = this.BTIFlags.HasFlag(BTIFlags.SCFBpbDisabledNoHardwareSupport);
            }
        }

        internal void SetKernelVAShadowProperties(IntPtr systemInformationPtr) {
            if (systemInformationPtr == null) {
                throw new ArgumentNullException("systemInformationPointer");
            }

            this.KernelVAFlags = (KernelVAFlags)(uint)Marshal.ReadInt32(systemInformationPtr);
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
            this.KVAShadowPcidEnabled =
                this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowPcidFlag)
                || this.KernelVAFlags.HasFlag(KernelVAFlags.KVAShadowInvpcidFlag);
        }

        #endregion
    }
}
