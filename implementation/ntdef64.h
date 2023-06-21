#ifndef NTDEF64
#define NTDEF64

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>



struct NT_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID DllBase;
	LPVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
};

using PNT_LDR_DATA_TABLE_ENTRY = NT_LDR_DATA_TABLE_ENTRY*;


struct NT_PEB_LDR_DATA
{
	DWORD Length;
	DWORD Initialized;
	LPVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID EntryInProgress;
};

using PNT_PEB_LDR_DATA = NT_PEB_LDR_DATA*;


struct NT_PEB
{
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE SpareBool;
	LPVOID Mutant;
	LPVOID ImageBaseAddress;
	PNT_PEB_LDR_DATA Ldr;
	LPVOID ProcessParameters;
	LPVOID SubSystemData;
	LPVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	LPVOID FastPebLockRoutine;
	LPVOID FastPebUnlockRoutine;
	DWORD EnvironmentUpdateCount;
	LPVOID KernelCallbackTable;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	LPVOID FreeList;
	DWORD TlsExpansionCounter;
	LPVOID TlsBitmap;
	DWORD TlsBitmapBits[2];
	LPVOID ReadOnlySharedMemoryBase;
	LPVOID ReadOnlySharedMemoryHeap;
	LPVOID ReadOnlyStaticServerData;
	LPVOID AnsiCodePageData;
	LPVOID OemCodePageData;
	LPVOID UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	DWORD NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	DWORD HeapSegmentReserve;
	DWORD HeapSegmentCommit;
	DWORD HeapDeCommitTotalFreeThreshold;
	DWORD HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	LPVOID ProcessHeaps;
	LPVOID GdiSharedHandleTable;
	LPVOID ProcessStarterHelper;
	DWORD GdiDCAttributeList;
	LPVOID LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	DWORD ImageSubsystemMinorVersion;
	DWORD ImageProcessAffinityMask;
	DWORD GdiHandleBuffer[34];
	LPVOID PostProcessInitRoutine;
	LPVOID TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	DWORD SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	LPVOID ShimData;
	LPVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	LPVOID ActivationContextData;
	LPVOID ProcessAssemblyStorageMap;
	LPVOID SystemDefaultActivationContextData;
	LPVOID SystemAssemblyStorageMap;
	DWORD MinimumStackCommit;
};

using PNT_PEB = NT_PEB*;



#endif
