using System;

namespace SpeculativeExecutionAssessment {

    [Flags]
    public enum BTIFlags : uint {
        Undefined = 0x00000000,
        SCFBpbEnabled = 0x00000001,
        SCFBpbDisabledSystemPolicy = 0x00000002,
        SCFBpbDisabledNoHardwareSupport = 0x00000004,
        SCFHwReg1Enumerated = 0x00000008,
        SCFHwReg2Enumerated = 0x00000010,
        SCFHwMode1Present = 0x00000020,
        SCFHwMode2Present = 0x00000040,
        SCFSmepPresent = 0x00000080
    }

    [Flags]
    public enum KernelVAFlags : uint {
        Undefined = 0x00000000,
        KVAShadowEnabledFlag = 0x00000001,
        KVAShadowUserGlobalFlag = 0x00000002,
        KVAShadowPcidFlag = 0x00000004,
        KVAShadowInvpcidFlag = 0x00000008,
        KVAShadowRequiredFlag = 0x00000010,
        KVAShadowRequiredAvailableFlag = 0x00000020
    }

    internal enum SYSTEM_INFORMATION_CLASS : uint {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemHandleInformation = 16,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemRegistryQuotaInformation = 37,
        SystemLookasideInformation = 45,
        SystemKernelVAShadow = 196,
        SystemBranchTargetInjection = 201
    }

}
