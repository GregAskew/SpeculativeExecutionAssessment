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
        SCFSmepPresent = 0x00000080,
        SCFSSBDAvailable = 0x00000100,
        SCFSSBDSupported = 0x00000200,
        SCFSSBDSystemWide = 0x00000400,
        SCFSSBDRequired = 0x00001000
    }

    [Flags]
    public enum KernelVAFlags : uint {
        Undefined = 0x00000000,
        KVAShadowEnabledFlag = 0x00000001,
        KVAShadowUserGlobalFlag = 0x00000002,
        KVAShadowPcidFlag = 0x00000004,
        KVAShadowInvpcidFlag = 0x00000008,
        KVAShadowRequiredFlag = 0x00000010,
        KVAShadowRequiredAvailableFlag = 0x00000020,
        UnknownXX40 = 0x00000040,
        UnknownXX80 = 0x00000080,
        UnknownXX100 = 0x00000100,
        UnknownXX200 = 0x00000200,
        UnknownXX400 = 0x00000400,
        UnknownXX800 = 0x00000800,
        L1TFFlushSupported = 0x00001000,
        L1TFMitigationPresent = 0x00002000,
        UnknownXX4000 = 0x00004000,
        UnknownXX8000 = 0x00008000
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
