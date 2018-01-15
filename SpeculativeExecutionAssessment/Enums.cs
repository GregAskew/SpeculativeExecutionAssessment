using System;

namespace SpeculativeExecutionAssessment {

    [Flags]
    public enum BTIFlags : uint {
        Undefined = 0x0,
        SCFBpbEnabled = 0x1,
        SCFBpbDisabledSystemPolicy = 0x2,
        SCFBpbDisabledNoHardwareSupport = 0x4,
        SCFHwReg1Enumerated = 0x8,
        SCFHwReg2Enumerated = 0x10,
        SCFHwMode1Present = 0x20,
        SCFHwMode2Present = 0x40,
        SCFSmepPresent = 0x80
    }

    [Flags]
    public enum KernelVAFlags : uint {
        Undefined = 0x0,
        KVAShadowEnabledFlag = 0x01,
        KVAShadowUserGlobalFlag = 0x02,
        KVAShadowPcidFlag = 0x04,
        KVAShadowInvpcidFlag = 0x08
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
