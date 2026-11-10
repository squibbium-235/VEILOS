#!/bin/sh
# Build VEILOS's Windows system DLLs and install them into storage/system.
# Run from anywhere: sh win32/build.sh
set -e
# Git Bash would rewrite /flags as paths.
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
LLVM="/c/Program Files/LLVM/bin"
OUT=target/x86_64-pc-windows-msvc/release
# Each DLL's preferred base, so it's at the same address in every process (the
# MSYS2 runtime relies on that, as on Windows): 16 MiB apart from 0x7E0000000000.
# The Cargo-built ones have 0x00..0x09 (their build.rs), secur32 0x0A, and the
# ones made here count on from 0x10.
BASE_N=16
next_base() { BASE=$(printf '0x%x' $((0x7E0000000000 + BASE_N * 0x1000000))); BASE_N=$((BASE_N + 1)); }
cargo build --release
mkdir -p ../storage/system
for dll in ntdll kernel32 ucrtbase gdi32 user32 comctl32 shell32 comdlg32 riched20 ws2_32; do
    cp "$OUT/$dll.dll" "../storage/system/$dll.dll"
done

# msftedit.dll (and the older riched32.dll): the same rich edit DLL.
cp "$OUT/riched20.dll" ../storage/system/msftedit.dll
cp "$OUT/riched20.dll" ../storage/system/riched32.dll

# msvcrt.dll and vcruntime140(_1).dll: forwarders to ucrtbase.dll, made
# from its export list (no code, no entry point).
mkdir -p target/forwarders
python crt_forwarders.py "$(cygpath -w "$LLVM/llvm-objdump.exe")" "$OUT/ucrtbase.dll" target/forwarders
echo "" > target/forwarders/empty.c
"$LLVM/clang-cl.exe" /nologo /c target/forwarders/empty.c /Fotarget/forwarders/empty.obj
for dll in msvcrt vcruntime140 vcruntime140_1; do
    next_base
    "$LLVM/lld-link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /BASE:$BASE \
        /DEF:target/forwarders/$dll.def target/forwarders/empty.obj /OUT:target/forwarders/$dll.dll
    cp target/forwarders/$dll.dll "../storage/system/$dll.dll"
done

# msimg32.dll: AlphaBlend and TransparentBlt live in gdi32, as on Windows.
printf 'LIBRARY msimg32.dll\nEXPORTS\n    AlphaBlend=gdi32.GdiAlphaBlend\n    TransparentBlt=gdi32.GdiTransparentBlt\n' > target/forwarders/msimg32.def
next_base
"$LLVM/lld-link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /BASE:$BASE \
    /DEF:target/forwarders/msimg32.def target/forwarders/empty.obj /OUT:target/forwarders/msimg32.dll
cp target/forwarders/msimg32.dll ../storage/system/msimg32.dll

# urlmon.dll, propsys.dll, winspool.drv: the few functions programs reach
# for, kept in kernel32.
fwd() {
    out=$1; shift
    { printf 'LIBRARY %s
EXPORTS
' "$out"; for f in "$@"; do printf '    %s=kernel32.%s
' "$f" "$f"; done; printf '%s' "$EXTRA"; } > "target/forwarders/$out.def"
    next_base
    "$LLVM/lld-link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /BASE:$BASE /DEF:"target/forwarders/$out.def" target/forwarders/empty.obj /OUT:"target/forwarders/$out"
    cp "target/forwarders/$out" "../storage/system/$out"
   }
# Lines for a .def: each of the names forwarded to one kernel32 function
# (VeilCryptUnsupported for FALSE/NULL calls, VeilErrorNotSupported for those
# answering an error number, VeilCngUnsupported for an NTSTATUS or HRESULT,
# VeilNothingToFree for a 0). Given to fwd as EXTRA.
unsup() {
    target=$1; shift
    for f in "$@"; do printf '    %s=kernel32.%s
' "$f" "$target"; done
}
# advapi32.dll: the registry, tokens, ETW and the rest kernel32 implements.
# Not kept: ACL editing, restricted tokens, services, LSA (claude.exe's sandbox).
EXTRA="$(unsup VeilCryptUnsupported AddAccessAllowedAce AddAccessAllowedAceEx AddAccessDeniedAceEx AddAce     ConvertSecurityDescriptorToStringSecurityDescriptorW ConvertStringSecurityDescriptorToSecurityDescriptorW     ConvertStringSidToSidW CreateProcessWithLogonW CreateRestrictedToken DuplicateTokenEx GetAce GetAclInformation     GetKernelObjectSecurity ImpersonateAnonymousToken LookupAccountNameW SetKernelObjectSecurity     SetSecurityDescriptorControl SetThreadToken SetTokenInformation QueryServiceConfigW QueryServiceStatus     CloseServiceHandle SaferiIsExecutableFileType OpenSCManagerW OpenServiceW)
$(unsup VeilNothingToFree GetSecurityDescriptorLength)
$(unsup VeilErrorNotSupported SetEntriesInAclA)
$(unsup VeilCngUnsupported LsaAddAccountRights LsaRemoveAccountRights)
    LsaNtStatusToWinError=kernel32.LsaNtStatusToWinError
    LsaOpenPolicy=kernel32.LsaOpenPolicy
    LsaClose=kernel32.LsaClose
    LsaQueryInformationPolicy=kernel32.LsaQueryInformationPolicy
    LsaFreeMemory=kernel32.LsaFreeMemory
" fwd advapi32.dll CryptImportKey CryptEncrypt CryptDestroyKey IsValidSid GetLengthSid EqualSid CopySid AllocateAndInitializeSid FreeSid IsWellKnownSid CheckTokenMembership ConvertSidToStringSidA ConvertSidToStringSidW SystemFunction036 CryptAcquireContextA CryptAcquireContextW CryptReleaseContext CryptGenRandom \
    CryptCreateHash CryptHashData CryptGetHashParam CryptDestroyHash CreateProcessAsUserW DecryptFileW DuplicateEncryptionInfoFile GetFileSecurityW     GetSecurityDescriptorOwner GetTokenInformation GetUserNameA GetUserNameW IsTextUnicode OpenProcessToken     OpenThreadToken RevertToSelf AdjustTokenPrivileges LookupPrivilegeValueW LookupAccountSidW InitializeAcl \
    InitializeSecurityDescriptor IsValidSecurityDescriptor GetSecurityDescriptorControl GetSecurityDescriptorDacl \
    GetSecurityDescriptorGroup GetSecurityDescriptorSacl SetSecurityDescriptorDacl SetSecurityDescriptorGroup \
    SetSecurityDescriptorOwner SetSecurityDescriptorSacl GetSidSubAuthority GetSidSubAuthorityCount MapGenericMask \
    GetNamedSecurityInfoW SetNamedSecurityInfoW GetSecurityInfo SetSecurityInfo RegFlushKey RegSetValueExA \
    RegSetValueW RegDeleteKeyW RegEnumKeyW RegRenameKey RegConnectRegistryW RegLoadKeyW RegUnLoadKeyW RegSaveKeyW \
    RegOpenKeyA RegOpenCurrentUser RegDeleteKeyA RegDeleteKeyExA RegDeleteTreeW RegDeleteTreeA RegGetValueA RegQueryValueW \
    RegDeleteValueA RegEnumKeyExA RegEnumValueA RegQueryInfoKeyA \
    RegRestoreKeyW RegSetKeySecurity RegNotifyChangeKeyValue RegCloseKey RegCreateKeyA RegCreateKeyExA RegCreateKeyExW RegCreateKeyW     RegDeleteKeyExW RegDeleteValueW RegEnumKeyExW RegEnumValueW RegGetValueW RegOpenKeyExA RegOpenKeyExW     RegOpenKeyW RegQueryInfoKeyW RegQueryValueExA RegQueryValueExW RegSetKeyValueA RegSetKeyValueW     RegSetValueExW EventActivityIdControl EventEnabled EventProviderEnabled EventRegister     EventSetInformation EventUnregister EventWrite EventWriteEx EventWriteTransfer \
    RegisterEventSourceW RegisterEventSourceA \
    DeregisterEventSource ReportEventW ReportEventA
fwd urlmon.dll FindMimeFromData
# What the Rust toolchain loads besides.
fwd bcryptprimitives.dll ProcessPrng
fwd bcrypt.dll BCryptGenRandom
# A forwarder DLL from its .def: what it doesn't offer yet points at kernel32
# functions that fail plainly (VeilCngUnsupported and friends, toolchain.rs).
fwd_link() {
    next_base
    "$LLVM/lld-link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /BASE:$BASE /DEF:"target/forwarders/$1.def" target/forwarders/empty.obj /OUT:"target/forwarders/$1"
    cp "target/forwarders/$1" "../storage/system/$1"
}
# bcrypt.dll: random numbers; no algorithms yet.
printf 'LIBRARY bcrypt.dll\nEXPORTS\n    BCryptGenRandom=kernel32.BCryptGenRandom\n' > target/forwarders/bcrypt.dll.def
for f in BCryptCloseAlgorithmProvider BCryptCreateHash BCryptDecrypt BCryptDeriveKey BCryptDestroyHash BCryptDestroyKey BCryptDestroySecret BCryptEncrypt BCryptExportKey BCryptFinalizeKeyPair BCryptFinishHash BCryptGenerateKeyPair BCryptGetProperty BCryptHashData BCryptImportKey BCryptImportKeyPair BCryptOpenAlgorithmProvider BCryptSecretAgreement BCryptSetProperty BCryptSignHash BCryptVerifySignature BCryptGenerateSymmetricKey BCryptDuplicateHash BCryptHash BCryptKeyDerivation BCryptDeriveKeyPBKDF2; do printf '    %s=kernel32.VeilCngUnsupported\n' "$f" >> target/forwarders/bcrypt.dll.def; done
fwd_link bcrypt.dll
# crypt32.dll: the server certificates Schannel hands out (secur32 keeps them);
# no certificate stores of its own yet.
printf 'LIBRARY crypt32.dll\nEXPORTS\n' > target/forwarders/crypt32.dll.def
for f in CertCloseStore CertEnumCertificatesInStore CertFreeCertificateContext CertDuplicateCertificateContext; do printf '    %s=secur32.%s\n' "$f" "$f" >> target/forwarders/crypt32.dll.def; done
for f in CertGetEnhancedKeyUsage CertSerializeCertificateStoreElement CryptHashCertificate2 CertAddCertificateContextToStore CertCreateCertificateChainEngine CertFindCertificateInStore CertFindExtension CertFreeCRLContext CertFreeCTLContext CertFreeCertificateChain CertFreeCertificateChainEngine CertGetCertificateChain CertGetNameStringA CertGetNameStringW CertOpenStore CertOpenSystemStoreA CertOpenSystemStoreW CryptDecodeObjectEx CryptQueryObject CryptStringToBinaryA CryptStringToBinaryW CryptBinaryToStringA CryptBinaryToStringW PFXImportCertStore CertCreateCertificateContext CertGetCertificateContextProperty CertVerifyCertificateChainPolicy CryptProtectData CryptUnprotectData; do printf '    %s=kernel32.VeilCryptUnsupported\n' "$f" >> target/forwarders/crypt32.dll.def; done
fwd_link crypt32.dll
# wldap32.dll: no LDAP.
printf 'LIBRARY wldap32.dll\nEXPORTS\n' > target/forwarders/wldap32.dll.def
for f in ldap_bind_s ldap_search_s ldap_set_option ldap_simple_bind_s ldap_unbind_s ldap_msgfree ldap_value_free_len ldap_memfree ber_free; do printf '    %s=kernel32.VeilLdapUnsupported\n' "$f" >> target/forwarders/wldap32.dll.def; done
for f in ldap_err2string ldap_first_attribute ldap_first_entry ldap_get_dn ldap_get_values_len ldap_next_attribute ldap_next_entry ldap_sslinit ldap_init; do printf '    %s=kernel32.VeilCryptUnsupported\n' "$f" >> target/forwarders/wldap32.dll.def; done
fwd_link wldap32.dll
# iphlpapi.dll: interface names have no numbers here (0 is "not found").
printf 'LIBRARY iphlpapi.dll\nEXPORTS\n    if_nametoindex=kernel32.VeilCryptUnsupported\n    if_indextoname=kernel32.VeilCryptUnsupported\n    FreeMibTable=kernel32.VeilNothingToFree\n' > target/forwarders/iphlpapi.dll.def
# No adapter or route tables yet (os.networkInterfaces()).
unsup VeilErrorNotSupported CancelMibChangeNotify2 ConvertInterfaceIndexToLuid ConvertInterfaceLuidToNameW GetBestRoute2 GetUnicastIpAddressTable NotifyIpInterfaceChange GetAdaptersAddresses GetIfEntry GetIpAddrTable GetIpForwardTable GetTcpTable GetTcp6Table GetUdpTable >> target/forwarders/iphlpapi.dll.def
printf '    GetNetworkParams=kernel32.GetNetworkParams
' >> target/forwarders/iphlpapi.dll.def
fwd_link iphlpapi.dll
# msvcp140.dll: Microsoft C++ runtime compatibility.
printf 'LIBRARY msvcp140.dll
EXPORTS
    "?uncaught_exceptions@std@@YAHXZ"=ucrtbase.__uncaught_exceptions
    _Query_perf_counter=kernel32.VeilQueryPerfCounter
    _Query_perf_frequency=kernel32.VeilQueryPerfFrequency
' > target/forwarders/msvcp140.dll.def
fwd_link msvcp140.dll
# fwpuclnt.dll (the firewall), netapi32.dll (local users and groups),
# wtsapi32.dll (sessions): claude.exe imports them for its sandbox; none of
# that exists here, and each call says so.
printf 'LIBRARY fwpuclnt.dll\nEXPORTS\n    FwpmFreeMemory0=kernel32.VeilNothingToFree\n' > target/forwarders/fwpuclnt.dll.def
for f in FwpmEngineClose0 FwpmEngineOpen0 FwpmFilterAdd0 FwpmFilterCreateEnumHandle0 FwpmFilterDeleteByKey0 FwpmFilterDestroyEnumHandle0 FwpmFilterEnum0 FwpmSubLayerAdd0 FwpmSubLayerDeleteByKey0 FwpmTransactionAbort0 FwpmTransactionBegin0 FwpmTransactionCommit0; do printf '    %s=kernel32.VeilErrorNotSupported\n' "$f" >> target/forwarders/fwpuclnt.dll.def; done
fwd_link fwpuclnt.dll
printf 'LIBRARY netapi32.dll\nEXPORTS\n    NetApiBufferFree=kernel32.VeilNothingToFree\n' > target/forwarders/netapi32.dll.def
for f in NetLocalGroupAdd NetLocalGroupAddMembers NetLocalGroupDel NetLocalGroupGetMembers NetUserAdd NetUserDel NetUserGetInfo NetUserModalsGet NetUserSetInfo; do printf '    %s=kernel32.VeilErrorNotSupported\n' "$f" >> target/forwarders/netapi32.dll.def; done
fwd_link netapi32.dll
printf 'LIBRARY wtsapi32.dll\nEXPORTS\n    WTSFreeMemory=kernel32.VeilNothingToFree\n    WTSQuerySessionInformationW=kernel32.VeilCryptUnsupported\n' > target/forwarders/wtsapi32.dll.def
fwd_link wtsapi32.dll
EXTRA="$(unsup VeilCryptUnsupported DeleteProfileW)
" fwd userenv.dll GetUserProfileDirectoryW
# A DLL of one-jump thunks, for exports that must keep Windows' ordinals
# (lld numbers forwarded exports itself): thunk_dll OUT IMPORT_LIB name:ordinal...
thunk_dll() {
    out=$1; lib=$2; shift 2
    c=target/forwarders/$out.c
    printf 'LIBRARY %s
EXPORTS
' "$out" > "target/forwarders/$out.def"
    : > "$c"
    for e in "$@"; do
        n=${e%%:*}
        printf '__attribute__((naked)) void v_%s(void) { __asm__("jmp *__imp_%s(%%rip)"); }
' "$n" "$n" >> "$c"
        printf '    %s=v_%s @%s
' "$n" "$n" "${e#*:}" >> "target/forwarders/$out.def"
    done
    "$LLVM/clang-cl.exe" /nologo /c /O2 "$c" /Fo"target/forwarders/$out.obj"
    next_base
    "$LLVM/lld-link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /BASE:$BASE /DEF:"target/forwarders/$out.def"         "target/forwarders/$out.obj" "$OUT/$lib" /OUT:"target/forwarders/$out"
    cp "target/forwarders/$out" "../storage/system/$out"
}
# oleaut32.dll: imported by number.
thunk_dll oleaut32.dll kernel32.dll.lib SysAllocStringLen:4 SysFreeString:6 SysStringLen:7 VariantInit:8 VariantClear:9 GetErrorInfo:200 SetErrorInfo:201
EXTRA="$(unsup VeilCngUnsupported CreateStreamOnHGlobal GetHGlobalFromStream)
" fwd ole32.dll CoCreateGuid CoCreateInstance CoInitializeEx CoUninitialize CoTaskMemFree CoCreateFreeThreadedMarshaler
fwd authz.dll AuthzInitializeResourceManager AuthzFreeResourceManager AuthzInitializeContextFromSid AuthzFreeContext AuthzAccessCheck
fwd version.dll GetFileVersionInfoSizeW GetFileVersionInfoSizeA GetFileVersionInfoW GetFileVersionInfoA VerQueryValueW VerQueryValueA
fwd propsys.dll PSGetPropertyDescriptionListFromString PropVariantToStringVectorAlloc
fwd winspool.drv OpenPrinterW OpenPrinterA ClosePrinter GetPrinterDriverW EnumPrintersW GetDefaultPrinterW DocumentPropertiesW
fwd shlwapi.dll PathAppendW
 EXTRA=
# wsock32.dll: Winsock 1, by number, which ws2_32 carries under the same numbers.
thunk_dll wsock32.dll ws2_32.dll.lib accept:1 bind:2 closesocket:3 connect:4 getpeername:5 getsockname:6 getsockopt:7 htonl:8 htons:9 ioctlsocket:10 inet_addr:11 inet_ntoa:12 listen:13 ntohl:14 ntohs:15 recv:16 recvfrom:17 select:18 send:19 sendto:20 setsockopt:21 shutdown:22 socket:23 gethostbyaddr:51 gethostbyname:52 getprotobyname:53 getprotobynumber:54 getservbyname:55 getservbyport:56 gethostname:57 WSAGetLastError:111 WSASetLastError:112 WSAStartup:115 WSACleanup:116 __WSAFDIsSet:151
# KernelBase.dll: on Windows most of kernel32 lives there; here it's the
# other way round, every kernel32 export forwarded (Cygwin loads it by name).
{ printf 'LIBRARY KernelBase.dll\nEXPORTS\n'
  "$LLVM/llvm-objdump.exe" -p "$OUT/kernel32.dll" | awk '/^ *[0-9]+ +0x[0-9a-f]+ +[A-Za-z_]/ { print "    " $3 "=kernel32." $3 }'
} > target/forwarders/KernelBase.dll.def
fwd_link KernelBase.dll
# dbghelp.dll (symbols, minidumps) and winmm.dll (sound): not here.
{ printf 'LIBRARY dbghelp.dll
EXPORTS
'; unsup VeilNothingToFree SymGetOptions SymSetOptions; unsup VeilCryptUnsupported MiniDumpWriteDump; } > target/forwarders/dbghelp.dll.def
fwd_link dbghelp.dll
{ printf 'LIBRARY winmm.dll
EXPORTS
'; unsup VeilErrorNotSupported waveInAddBuffer waveInClose waveInOpen waveInPrepareHeader waveInReset waveInStart waveInStop waveInUnprepareHeader waveOutClose waveOutOpen waveOutPrepareHeader waveOutReset waveOutUnprepareHeader waveOutWrite; } > target/forwarders/winmm.dll.def
fwd_link winmm.dll
echo "installed: $(ls ../storage/system | tr '\n' ' ')"

# secur32.dll: Schannel over rustls. It uses the standard library (and crates
# from crates.io), so it's built on its own, outside this folder: the kernel's
# .cargo/config.toml (build-std) would apply to anything below the repository.
SECUR32_WORK="${TEMP:-/tmp}/veilos-secur32"
rm -rf "$SECUR32_WORK/src"
mkdir -p "$SECUR32_WORK"
cp -r secur32/Cargo.toml secur32/src "$SECUR32_WORK/"
(cd "$SECUR32_WORK" && RUSTFLAGS="-C link-arg=/BASE:0x7e000a000000" cargo build --release --target x86_64-pc-windows-msvc)
cp "$SECUR32_WORK/target/x86_64-pc-windows-msvc/release/secur32.dll" ../storage/system/secur32.dll
