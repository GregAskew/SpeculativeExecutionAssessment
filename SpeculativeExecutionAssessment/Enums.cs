namespace SpeculativeExecutionAssessment {

    using System;

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
        UnknownXX800 = 0x00000800,
        SCFSSBDRequired = 0x00001000,
        UnknownXX2000 = 0x000002000,
        SCFSpecCtrlRetpolineEnabled = 0x00004000,
        SCFSpecCtrlImportOptimizationEnabled = 0x00008000,
        SCFEnhancedIbrs = 0x00010000,
        SCFHVL1TFStatusAvailable = 0x00020000,
        SCFHVL1TFProcessorNotAffected = 0x00040000,
        SCFHVL1TFMigitationEnabled = 0x00080000,
        SCFHVL1TFMigitationNotEnabledHardware = 0x00100000,
        SCFHVL1TFMigitationNotEnabledLoadOption = 0x00200000,
        SCFHVL1TFMigitationNotEnabledCoreScheduler = 0x00400000,
        SCFEnhancedIBRSReported = 0x00800000,
        SCFMDSHardwareProtected = 0x01000000,
        SCFMBClearEnabled = 0x02000000,
        SCFMBClearReported = 0x04000000,
        UnknownXX8000000 = 0x08000000,
        UnknownXX01000000 = 0x10000000,
        UnknownXX02000000 = 0x20000000,
        UnknownXX04000000 = 0x40000000,
        UnknownXX08000000 = 0x80000000
    }

    [Flags]
    public enum KernelVAFlags : uint {
        Undefined = 0x00000000,
        KVAShadowEnabledFlag = 0x00000001,
        KVAShadowUserGlobalFlag = 0x00000002,
        KVAShadowPCIDFlag = 0x00000004,
        KVAShadowInvPCIDFlag = 0x00000008,
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

    public enum ProcessorArchitecture : ushort {
        x86 = 0,
        MIPS = 1,
        Alpha = 2,
        PowerPC = 3,
        ARM = 5,
        IA64 = 6,
        x64 = 9,
        ARM64 = 12,
        Undefined = 255
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
