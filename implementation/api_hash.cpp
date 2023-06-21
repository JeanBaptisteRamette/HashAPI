#include <cstdint>
#include <iostream>
#include <string_view>

#include "intrin.h"
#include "ntdef64.h"


// Make a template because module name are stored as wide strings in the PEB
template<typename char_type>
constexpr
uint32_t SymHash(char_type* Symbol)
{
    // Adler32 hash implementation
    constexpr uint16_t MOD_ADLER = 0xFFF1;

    uint32_t csum1 = 1;
    uint32_t csum2 = 0;

    for (const char_type c : std::basic_string_view<char_type>(Symbol))
    {
        csum1 = (csum1 +     c) % MOD_ADLER;
        csum2 = (csum2 + csum1) % MOD_ADLER;
    }

    return (csum2 << 16) | csum1;
}

PNT_PEB NtCurrentPeb()
{
    return reinterpret_cast<PNT_PEB>(__readgsqword(0x60));
}


PNT_LDR_DATA_TABLE_ENTRY ResolveInMemoryModule(uint32_t ModuleHash)
{
    const auto Peb = NtCurrentPeb();
    const auto LoaderData = Peb->Ldr;

    const PLIST_ENTRY Head = &LoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY ModuleNode = nullptr;

    for (ModuleNode = Head->Flink; ModuleNode != Head ; ModuleNode = ModuleNode->Flink)
    {
        const auto LoadedModule = CONTAINING_RECORD(ModuleNode, NT_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
        const auto ModuleName = LoadedModule->BaseDllName.Buffer;

        if (SymHash(ModuleName) == ModuleHash)
            return LoadedModule;
    }

    return nullptr;
}


LPVOID ResolveProcedure(LPBYTE ImageBase, uint32_t ProcedureHash)
{
    const auto DosHdr = (PIMAGE_DOS_HEADER)ImageBase;

    if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    const auto NtHdrs = (PIMAGE_NT_HEADERS64)(ImageBase + DosHdr->e_lfanew);

    auto VerifyImage = [](auto NtHeaders) -> bool
    {
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return false;

        if ((NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
            return false;

        const auto DirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        const auto DirVirt = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if (DirSize == 0 || DirVirt == 0)
            return false;

        return true;
    };

    if (!VerifyImage(NtHdrs))
        return nullptr;

    const auto& OptHdr = NtHdrs->OptionalHeader;

    const auto ExportDirVirt = OptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const auto ExportDir = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + ExportDirVirt);

    auto Ordinals  = (LPWORD) (ImageBase + ExportDir->AddressOfNameOrdinals);
    auto Functions = (LPDWORD)(ImageBase + ExportDir->AddressOfFunctions);
    auto Symbols   = (LPDWORD)(ImageBase + ExportDir->AddressOfNames);

    for (size_t i = 0; i < ExportDir->NumberOfNames; ++i)
    {
        const char* SymName = (char*)(ImageBase + Symbols[i]);

        if (SymHash(SymName) == ProcedureHash)
            return (LPVOID)(ImageBase + Functions[Ordinals[i]]);
    }

    return nullptr;
}


LPVOID ResolveAPI(uint32_t ModuleHash, uint32_t ProcedureHash)
{
    const PNT_LDR_DATA_TABLE_ENTRY Module = ResolveInMemoryModule(ModuleHash);

    if (!Module)
        return nullptr;

    return ResolveProcedure((LPBYTE)Module->DllBase, ProcedureHash);
}


int main(int argc, char** argv)
{
    constexpr auto DigestModule      = SymHash(L"USER32.dll");
    constexpr auto DigestMessageBoxA = SymHash("MessageBoxA");

    using pMessageBoxA = int(*)(HWND, LPCSTR, LPCSTR, UINT);

    const auto MessageBoxA = reinterpret_cast<pMessageBoxA>(ResolveAPI(DigestModule, DigestMessageBoxA));

    MessageBoxA(nullptr, "XXX", "YYY", 0);

    return 0;
}
