#ifndef WINCOMPAT_H
#define WINCOMPAT_H

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#ifndef __attribute__
#define __attribute__(x)
#endif

#ifndef __restrict
#define __restrict
#endif

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#define WINAPI __stdcall
#define WINAPIV __cdecl
#define WSAAPI __stdcall
#define NTAPI __stdcall

#define WINBASEAPI DECLSPEC_IMPORT
#define WINADVAPI DECLSPEC_IMPORT

#define CONST const

#define _In_
#define _Out_
#define _In_opt_
#define _Out_opt_
#define _Out_writes_bytes_(x)
#define IN
#define OUT

typedef void VOID;
typedef int BOOL;
typedef unsigned char BOOLEAN;
typedef char CHAR;
typedef short SHORT;
typedef unsigned char BYTE;
typedef unsigned char UCHAR;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef int INT;
typedef long LONG;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG_PTR;
typedef long long LONG_PTR;
typedef unsigned long long ULONG64;
#if defined(__GNUC__)
typedef unsigned long long DWORD64;
#else
typedef unsigned __int64 DWORD64;
#endif
typedef long NTSTATUS;
typedef long SECURITY_STATUS;
typedef ULONG_PTR SIZE_T;
typedef ULONG_PTR DWORD_PTR;
typedef ULONG_PTR UINT_PTR;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char *PCHAR;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef const char *LPCCH;
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR;
typedef WCHAR *PWSTR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef const WCHAR *PCWSTR;
typedef const WCHAR *LPCWCH;
typedef BOOL *LPBOOL;
typedef BYTE *PBYTE;
typedef BYTE *PUCHAR;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef ULONG *PULONG;
typedef LONG *PLONG;
typedef LONG *PNTSTATUS;
typedef ULONG_PTR size_t;
typedef DWORD ALG_ID;
typedef PVOID HCRYPTHASH;
typedef PVOID HANDLE;
typedef HANDLE *PHANDLE;
typedef PVOID HMODULE;
typedef PVOID HCRYPTPROV;
typedef PVOID HCRYPTKEY;
typedef PVOID HCERTSTORE;
typedef PVOID HCRYPTMSG;
typedef PVOID HCRYPTPROV_LEGACY;
typedef PVOID HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HANDLE;
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_SECRET_HANDLE;
typedef PVOID PSID;
typedef char *va_list;
typedef unsigned int UINT32;

#define va_start(v,l) (v = (va_list)_ADDRESSOF(l) + _INTSIZEOF(l))
#define va_end(v) (v = (va_list)0)
#define va_arg(v,l) (*(l *)((v += _INTSIZEOF(l)) - _INTSIZEOF(l)))
#define _INTSIZEOF(n) ((sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1))
#define _ADDRESSOF(v) (&(v))

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef LONG_MAX
#define LONG_MAX 2147483647L
#endif
#ifndef LONG_MIN
#define LONG_MIN (-2147483647L - 1)
#endif
#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

typedef struct _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    };
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;

typedef struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _TOKEN_SOURCE {
    CHAR SourceName[8];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID_AND_ATTRIBUTES {
    PSID Sid;
    DWORD Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_STATISTICS {
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    DWORD TokenType;
    DWORD ImpersonationLevel;
    DWORD DynamicCharged;
    DWORD DynamicAvailable;
    DWORD GroupCount;
    DWORD PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS, *PTOKEN_STATISTICS;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenStatistics = 10
} TOKEN_INFORMATION_CLASS;

typedef struct _STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    char *Buffer;
} STRING, ANSI_STRING, LSA_STRING, *PSTRING, *PANSI_STRING, *PLSA_STRING;

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, *PSECURITY_STRING;

typedef ULONG LSA_OPERATIONAL_MODE;
typedef ULONG *PLSA_OPERATIONAL_MODE;

typedef enum _SECURITY_LOGON_TYPE {
    Interactive = 2
} SECURITY_LOGON_TYPE;

typedef struct _QUOTA_LIMITS {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
} QUOTA_LIMITS, *PQUOTA_LIMITS;

typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
} SecHandle, CredHandle, CtxtHandle, *PCredHandle, *PCtxtHandle;

typedef struct _TimeStamp {
    ULONG LowPart;
    LONG HighPart;
} TimeStamp, *PTimeStamp;

typedef struct _SecBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PSecBuffer pBuffers;
} SecBufferDesc, *PSecBufferDesc;

typedef char SEC_CHAR;
typedef PVOID SEC_GET_KEY_FN;

typedef struct _SECURITY_LOGON_SESSION_DATA {
    ULONG Size;
} SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA;

typedef struct _GROUPS {
    ULONG GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *LPFILETIME;

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *LPSYSTEMTIME;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION;

typedef struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFOA;

typedef struct _GUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} GUID;

typedef struct _WSADATA {
    WORD wVersion;
    WORD wHighVersion;
    CHAR szDescription[257];
    CHAR szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA, *LPWSADATA;

typedef UINT_PTR SOCKET;
typedef struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
} SOCKADDR, *PSOCKADDR, *LPSOCKADDR;

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
};

typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
} CRYPT_DATA_BLOB, CRYPT_INTEGER_BLOB, CRYPT_OBJID_BLOB, CERT_NAME_BLOB, CERT_BLOB,
  *PCRYPT_DATA_BLOB, *PCERT_NAME_BLOB, *PCERT_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CRYPT_BIT_BLOB {
    DWORD cbData;
    BYTE *pbData;
    DWORD cUnusedBits;
} CRYPT_BIT_BLOB;

typedef struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_INFO {
    DWORD dwVersion;
    CRYPT_INTEGER_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CERT_NAME_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
} CERT_INFO, *PCERT_INFO;

typedef struct _CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;
typedef const CERT_CONTEXT *PCCERT_CONTEXT;

typedef struct _CMSG_STREAM_INFO {
    DWORD cbContent;
    BOOL fFinal;
    PVOID pvArg;
    PVOID pfnStreamOutput;
} CMSG_STREAM_INFO, *PCMSG_STREAM_INFO;

typedef struct _CMSG_SIGNER_ENCODE_INFO {
    DWORD cbSize;
    PCERT_INFO pCertInfo;
    HCRYPTPROV hCryptProv;
    DWORD dwKeySpec;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
    DWORD cAuthAttr;
    void *rgAuthAttr;
    DWORD cUnauthAttr;
    void *rgUnauthAttr;
} CMSG_SIGNER_ENCODE_INFO, *PCMSG_SIGNER_ENCODE_INFO;

typedef struct _CMSG_SIGNED_ENCODE_INFO {
    DWORD cbSize;
    DWORD cSigners;
    PCMSG_SIGNER_ENCODE_INFO rgSigners;
    DWORD cCertEncoded;
    PCERT_BLOB rgCertEncoded;
    DWORD cCrlEncoded;
    void *rgCrlEncoded;
    DWORD cAttrCertEncoded;
    void *rgAttrCertEncoded;
} CMSG_SIGNED_ENCODE_INFO, *PCMSG_SIGNED_ENCODE_INFO;

typedef struct _BCRYPT_DH_KEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
} BCRYPT_DH_KEY_BLOB, *PBCRYPT_DH_KEY_BLOB;

typedef struct _BCRYPT_DH_PARAMETER_HEADER {
    ULONG cbLength;
    ULONG dwMagic;
    ULONG cbKeyLength;
} BCRYPT_DH_PARAMETER_HEADER, *PBCRYPT_DH_PARAMETER_HEADER;

typedef struct _BCryptBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
} BCryptBuffer, *PBCryptBuffer;

typedef struct _BCryptBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PBCryptBuffer pBuffers;
} BCryptBufferDesc, *PBCryptBufferDesc;

typedef struct _DOMAIN_CONTROLLER_INFOA {
    LPSTR DomainControllerName;
    LPSTR DomainControllerAddress;
    ULONG DomainControllerAddressType;
    GUID DomainGuid;
    LPSTR DomainName;
    LPSTR DnsForestName;
    ULONG Flags;
    LPSTR DcSiteName;
    LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

typedef enum _KERB_PROTOCOL_MESSAGE_TYPE {
    KerbSubmitTicketMessage = 21
} KERB_PROTOCOL_MESSAGE_TYPE;

typedef struct _KERB_CRYPTO_KEY32 {
    LONG KeyType;
    ULONG Length;
    ULONG Offset;
} KERB_CRYPTO_KEY32, *PKERB_CRYPTO_KEY32;

typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY32 Key;
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;

#define HEAP_ZERO_MEMORY 0x00000008
#define MEM_COMMIT 0x00001000
#define MEM_RELEASE 0x00008000
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_READWRITE 0x04

#define CP_UTF8 65001
#define CP_ACP 0

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define INVALID_SOCKET ((SOCKET)(~0ULL))
#define SOCKET_ERROR (-1)
#define MAKEWORD(a,b) ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))

#define X509_ASN_ENCODING 0x00000001
#define PKCS_7_ASN_ENCODING 0x00010000
#define ASN_OBJECT_IDENTIFIER 0x06
#define CMSG_SIGNED 2
#define CMSG_CONTENT_PARAM 2

#define PROV_RSA_FULL 1
#define PROV_RSA_AES 24
#define CRYPT_VERIFYCONTEXT 0xF0000000
#define CRYPT_EXPORTABLE 0x00000001
#define CRYPT_USER_KEYSET 0x00001000
#define CRYPT_ACQUIRE_SILENT_FLAG 0x00000040
#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF
#define CALG_SHA1 0x00008004
#define HP_HASHVAL 0x0002

#define BCRYPT_DH_PARAMETERS_MAGIC 0x4d504844
#define BCRYPT_DH_PUBLIC_MAGIC 0x42504844
#define BCRYPT_DH_PUBLIC_BLOB L"DHPUBLICBLOB"
#define BCRYPT_DH_ALGORITHM L"DH"
#define BCRYPT_DH_PARAMETERS L"DHParameters"
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"

#define DS_DIRECTORY_SERVICE_REQUIRED 0x00000010
#define ERROR_SUCCESS 0
#define ERROR_NO_TOKEN 1008
#define MAX_COMPUTERNAME_LENGTH 15

#define TOKEN_QUERY 0x0008
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#define SE_PRIVILEGE_ENABLED 0x00000002
#define SID_MAX_SUB_AUTHORITIES 15
#define SECURITY_LOCAL_SYSTEM_RID 18
#define SECURITY_NT_AUTHORITY {0,0,0,0,0,5}

#define SE_TCB_NAME "SeTcbPrivilege"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT PVOID WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

#define GetModuleHandleA KERNEL32$GetModuleHandleA
#define LoadLibraryA KERNEL32$LoadLibraryA
#define GetProcAddress KERNEL32$GetProcAddress

#endif
