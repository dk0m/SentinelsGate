#include <iostream>
#include <windows.h>
#include<vector>

#pragma pack(1)
typedef struct _IMAGE_CFG_ENTRY {
    DWORD Rva;
    struct {
        BOOLEAN SuppressedCall : 1;
        BOOLEAN ExportSuppressed : 1;
        BOOLEAN LangExcptHandler : 1;
        BOOLEAN Xfg : 1;
        BOOLEAN Reserved : 4;
    } Flags;
} IMAGE_CFG_ENTRY, * PIMAGE_CFG_ENTRY;

struct GuardTableEntry {
    DWORD64 dwHash;
    WORD wSystemCall;
    PVOID functionAddress;

};

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

std::vector<GuardTableEntry> GetAllGuardEntries() {

    auto peBase = (DWORD_PTR)GetModuleHandleA("NTDLL");
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)(peBase + dosHdr->e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs->OptionalHeader;

    PIMAGE_LOAD_CONFIG_DIRECTORY loadConfigDir = (PIMAGE_LOAD_CONFIG_DIRECTORY)(peBase + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(peBase + optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addrOfNames = (PDWORD)(peBase + expDir->AddressOfNames);
    PDWORD addrOfFuncs = (PDWORD)(peBase + expDir->AddressOfFunctions);
    PWORD addrOfOrds = (PWORD)(peBase + expDir->AddressOfNameOrdinals);

    PIMAGE_CFG_ENTRY gcfTable = (PIMAGE_CFG_ENTRY)loadConfigDir->GuardCFFunctionTable;

    int x = 0;
    int ssn = 0;
    std::vector<GuardTableEntry> systemCalls;

    while (gcfTable[x].Rva != NULL) {
        DWORD gfRva = gcfTable[x].Rva;


        for (size_t i = 0; i < expDir->NumberOfFunctions; i++)
        {
            LPCSTR fnName = (LPCSTR)(peBase + addrOfNames[i]);
            WORD fnOrd = (WORD)(addrOfOrds[i]);
            DWORD fnRva = (DWORD)(addrOfFuncs[fnOrd]);

            if (strncmp(fnName, "Zw", 2) == 0) {

                if (fnRva == gfRva) {

                    systemCalls.push_back(
                        GuardTableEntry{
                            djb2((PBYTE)fnName),
                            (WORD)ssn,
                            (PVOID)((DWORD_PTR)peBase + fnRva)
                        }
                    );

                    ssn++;
                    break;

                }
            }

        }


        x++;

    }

    return systemCalls;
}


GuardTableEntry LookUpByHash(DWORD64 dwHash, std::vector<GuardTableEntry> entries) {

    for (auto& entry : entries) {
        if (entry.dwHash == dwHash) {
            return entry;
        }
    }

    return GuardTableEntry{ 0 };
}



void RunExample() {
    auto entries = GetAllGuardEntries();

    DWORD64 ntQuerySystemInfoHash = djb2((PBYTE)"ZwQuerySystemInformation");
    auto NTQSIEntry = LookUpByHash(ntQuerySystemInfoHash, entries);

    printf("NtQuerySystemInformation Ssn: %ld\n", NTQSIEntry.wSystemCall);

}

int main()
{
    RunExample();
}
