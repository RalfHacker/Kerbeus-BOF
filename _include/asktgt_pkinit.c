#pragma once

// Helpers for the certificate-based AS-REQ path. This file builds the PKINIT
// AuthPack, performs ephemeral Diffie-Hellman with the KDC, and derives the
// reply key used to decrypt the returned AS-REP.

WCHAR* CharToWide(char* value, int* wideChars) {
    if (wideChars)
        *wideChars = 0;

    if (!value)
        return NULL;

    int valueLength = my_strlen(value);
    int converted = KERNEL32$MultiByteToWideChar(CP_ACP, 0, value, valueLength, NULL, 0);
    if (converted <= 0)
        return NULL;

    WCHAR* wideValue = MemAlloc((converted + 1) * sizeof(WCHAR));
    if (!wideValue)
        return NULL;

    if (KERNEL32$MultiByteToWideChar(CP_ACP, 0, value, valueLength, wideValue, converted) != converted)
        return NULL;

    wideValue[converted] = 0;
    if (wideChars)
        *wideChars = converted;
    return wideValue;
}

#define PKINIT_AUTHDATA_OID "1.3.6.1.5.2.3.1"
#define OID_SHA1 "1.3.14.3.2.26"

// RFC 3526 / MODP Group 14 parameters used by this PKINIT implementation.
// These values are public domain parameters, not secrets:
//   p: 2048-bit safe-prime modulus used for the DH group.
//   q: subgroup order, equal to (p - 1) / 2 for this safe-prime group.
//   g: generator 2, encoded where the DH key pair is created/imported.
// Windows CNG expects p and g in BCRYPT_DH_PARAMETERS, while the PKINIT
// SubjectPublicKeyInfo domain parameters sent to the KDC include p, g, and q.
char DH_GROUP14_P_HEX[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

char DH_GROUP14_Q_HEX[] =
    "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD91"
    "28A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F63"
    "7A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E"
    "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DC"
    "F6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301C"
    "D93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880"
    "AB9472D455655347FFFFFFFFFFFFFFF";

BOOL HexCharToByte(char c, byte* value) {
    if (c >= '0' && c <= '9') {
        *value = (byte)(c - '0');
        return FALSE;
    }
    if (c >= 'a' && c <= 'f') {
        *value = (byte)(c - 'a' + 10);
        return FALSE;
    }
    if (c >= 'A' && c <= 'F') {
        *value = (byte)(c - 'A' + 10);
        return FALSE;
    }
    return TRUE;
}

BOOL HexStringToBytes(char* hex, byte** bytes, DWORD* length) {
    int hexLength = my_strlen(hex);
    if ((hexLength & 1) != 0)
        return TRUE;

    *length = (DWORD)(hexLength / 2);
    *bytes = MemAlloc(*length);
    if (!*bytes)
        return TRUE;

    for (DWORD i = 0; i < *length; i++) {
        byte high = 0;
        byte low = 0;
        if (HexCharToByte(hex[i * 2], &high) || HexCharToByte(hex[i * 2 + 1], &low))
            return TRUE;
        (*bytes)[i] = (byte)((high << 4) | low);
    }

    return FALSE;
}

BOOL HexStringToFixedBytes(char* hex, DWORD fixedLength, byte** bytes) {
    DWORD rawLength = 0;
    byte* rawBytes = NULL;
    if (HexStringToBytes(hex, &rawBytes, &rawLength))
        return TRUE;
    if (rawLength > fixedLength)
        return TRUE;

    *bytes = MemAlloc(fixedLength);
    if (!*bytes)
        return TRUE;

    for (DWORD i = 0; i < fixedLength; i++)
        (*bytes)[i] = 0;

    MemCpy(*bytes + (fixedLength - rawLength), rawBytes, rawLength);
    return FALSE;
}

BOOL MakeIntegerFromBytes(byte* value, DWORD length, AsnElt* asn) {
    // DER INTEGER values must be positive; prepend a zero byte when the high
    // bit would otherwise make the value look negative.
    while (length > 1 && *value == 0) {
        value++;
        length--;
    }

    BOOL addPadding = (value[0] & 0x80) ? TRUE : FALSE;
    DWORD encodedLength = length + (addPadding ? 1 : 0);
    byte* encoded = MemAlloc(encodedLength);
    if (!encoded)
        return TRUE;

    if (addPadding) {
        encoded[0] = 0;
        MemCpy(encoded + 1, value, length);
    }
    else {
        MemCpy(encoded, value, length);
    }

    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_INTEGER, encoded, 0, encodedLength, asn);
}

BOOL MakeIntegerFromHex(char* hex, AsnElt* asn) {
    DWORD rawLength = 0;
    byte* rawBytes = NULL;
    if (HexStringToBytes(hex, &rawBytes, &rawLength))
        return TRUE;
    return MakeIntegerFromBytes(rawBytes, rawLength, asn);
}

BOOL MakeOID(byte* value, DWORD length, AsnElt* asn) {
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_OBJECT_IDENTIFIER, value, 0, length, asn);
}

BOOL Sha1Buffer(byte* data, DWORD dataLength, byte* digest) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD digestLength = 20;

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            return TRUE;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        return TRUE;
    if (!ADVAPI32$CryptHashData(hHash, data, dataLength, 0))
        return TRUE;
    if (!ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLength, 0))
        return TRUE;

    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptReleaseContext(hProv, 0);
    return FALSE;
}

BOOL BuildPkAuthenticator(KDCReqBody* reqBody, DWORD pkNonce, AsnElt* pkAuthenticator) {
    // The PKAuthenticator binds the signed PKINIT payload to the exact KDC-REQ
    // body by including a SHA1 checksum of that body plus time and nonce fields.
    AsnElt reqBodyAsn = { 0 };
    if (AsnKDCReqBodyEncode(reqBody, &reqBodyAsn))
        return TRUE;

    int reqBodyBytesSize = 0;
    byte* reqBodyBytes = NULL;
    if (AsnToBytesEncode(&reqBodyAsn, &reqBodyBytesSize, &reqBodyBytes))
        return TRUE;

    byte reqBodyChecksum[20] = { 0 };
    if (Sha1Buffer(reqBodyBytes, reqBodyBytesSize, reqBodyChecksum))
        return TRUE;

    SYSTEMTIME systemTime;
    KERNEL32$GetSystemTime(&systemTime);
    char currentTime[18];
    MSVCRT$sprintf(currentTime, "%04d%02d%02d%02d%02d%02dZ",
        systemTime.wYear, systemTime.wMonth, systemTime.wDay,
        systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

    AsnElt cusecAsn = { 0 };
    AsnElt ctimeAsn = { 0 };
    AsnElt nonceAsn = { 0 };
    AsnElt checksumAsn = { 0 };

    if (PackIntegerLong(0, systemTime.wMilliseconds * 1000, &cusecAsn))
        return TRUE;
    if (PackString(1, ASN_GeneralizedTime, currentTime, &ctimeAsn))
        return TRUE;
    if (PackIntegerLong(2, (LONG)pkNonce, &nonceAsn))
        return TRUE;
    if (PackBlock(3, reqBodyChecksum, sizeof(reqBodyChecksum), &checksumAsn))
        return TRUE;

    AsnElt pkAuthFields[] = { cusecAsn, ctimeAsn, nonceAsn, checksumAsn };
    if (Make3(ASN_SEQUENCE, pkAuthFields, 4, pkAuthenticator))
        return TRUE;

    return FALSE;
}

BOOL BuildDhClientPublicValue(BCRYPT_KEY_HANDLE dhKey, AsnElt* subjectPublicKeyInfo) {
    // Export the ephemeral CNG DH public key and wrap it as a SubjectPublicKeyInfo:
    // algorithm = dhpublicnumber with domain parameters { p, g, q },
    // subjectPublicKey = DER INTEGER containing the client's public DH value.
    ULONG publicBlobSize = 0;
    if (BCrypt$ExportKey(dhKey, 0, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &publicBlobSize, 0) != 0)
        return TRUE;

    byte* publicBlob = MemAlloc(publicBlobSize);
    if (!publicBlob)
        return TRUE;
    if (BCrypt$ExportKey(dhKey, 0, BCRYPT_DH_PUBLIC_BLOB, publicBlob, publicBlobSize, &publicBlobSize, 0) != 0)
        return TRUE;

    BCRYPT_DH_KEY_BLOB* blobHeader = (BCRYPT_DH_KEY_BLOB*)publicBlob;
    byte* modulus = publicBlob + sizeof(BCRYPT_DH_KEY_BLOB);
    byte* generator = modulus + blobHeader->cbKey;
    byte* publicValue = generator + blobHeader->cbKey;

    byte dhPublicNumberOid[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };
    AsnElt oidAsn = { 0 };
    AsnElt pAsn = { 0 };
    AsnElt gAsn = { 0 };
    AsnElt qAsn = { 0 };
    AsnElt domainParams = { 0 };
    AsnElt algorithmIdentifier = { 0 };
    AsnElt publicInteger = { 0 };
    AsnElt publicBitString = { 0 };

    if (MakeOID(dhPublicNumberOid, sizeof(dhPublicNumberOid), &oidAsn))
        return TRUE;
    if (MakeIntegerFromBytes(modulus, blobHeader->cbKey, &pAsn))
        return TRUE;
    if (MakeIntegerFromBytes(generator, blobHeader->cbKey, &gAsn))
        return TRUE;
    if (MakeIntegerFromHex(DH_GROUP14_Q_HEX, &qAsn))
        return TRUE;

    AsnElt domainFields[] = { pAsn, gAsn, qAsn };
    if (Make3(ASN_SEQUENCE, domainFields, 3, &domainParams))
        return TRUE;

    AsnElt algorithmFields[] = { oidAsn, domainParams };
    if (Make3(ASN_SEQUENCE, algorithmFields, 2, &algorithmIdentifier))
        return TRUE;

    if (MakeIntegerFromBytes(publicValue, blobHeader->cbKey, &publicInteger))
        return TRUE;

    int publicIntegerBytesSize = 0;
    byte* publicIntegerBytes = NULL;
    if (AsnToBytesEncode(&publicInteger, &publicIntegerBytesSize, &publicIntegerBytes))
        return TRUE;
    if (MakeBitString(publicIntegerBytes, 0, publicIntegerBytesSize, &publicBitString))
        return TRUE;

    AsnElt spkiFields[] = { algorithmIdentifier, publicBitString };
    if (Make3(ASN_SEQUENCE, spkiFields, 2, subjectPublicKeyInfo))
        return TRUE;

    return FALSE;
}

BOOL BuildAuthPack(KDCReqBody* reqBody, BCRYPT_KEY_HANDLE dhKey, DWORD pkNonce, byte** authPackBytes, DWORD* authPackSize) {
    // AuthPack ::= SEQUENCE { pkAuthenticator, clientPublicValue, clientDHNonce }.
    // The empty clientDHNonce keeps the field present while reply-key derivation
    // below uses only the KDC nonce if one is returned.
    AsnElt pkAuthenticator = { 0 };
    AsnElt pkAuthenticatorContext = { 0 };
    AsnElt clientPublicValue = { 0 };
    AsnElt clientPublicValueContext = { 0 };
    AsnElt clientDhNonce = { 0 };
    AsnElt clientDhNonceContext = { 0 };
    AsnElt authPack = { 0 };

    if (BuildPkAuthenticator(reqBody, pkNonce, &pkAuthenticator))
        return TRUE;
    if (MakeExplicit(ASN_CONTEXT, 0, &pkAuthenticator, 1, &pkAuthenticatorContext))
        return TRUE;

    if (BuildDhClientPublicValue(dhKey, &clientPublicValue))
        return TRUE;
    if (MakeExplicit(ASN_CONTEXT, 1, &clientPublicValue, 1, &clientPublicValueContext))
        return TRUE;

    if (MakeBlob((byte*)"", 0, 0, &clientDhNonce))
        return TRUE;
    if (MakeExplicit(ASN_CONTEXT, 3, &clientDhNonce, 1, &clientDhNonceContext))
        return TRUE;

    AsnElt authPackFields[] = { pkAuthenticatorContext, clientPublicValueContext, clientDhNonceContext };
    if (Make3(ASN_SEQUENCE, authPackFields, 3, &authPack))
        return TRUE;

    int encodedAuthPackSize = 0;
    byte* encodedAuthPack = NULL;
    if (AsnToBytesEncode(&authPack, &encodedAuthPackSize, &encodedAuthPack))
        return TRUE;

    *authPackBytes = encodedAuthPack;
    *authPackSize = encodedAuthPackSize;
    return FALSE;
}

BOOL SignAuthPackCms(PCCERT_CONTEXT signingCert, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE certProvider, DWORD keySpec, CERT_BLOB* certBlobs, DWORD certCount, byte* authPackBytes, DWORD authPackSize, char* digestOid, byte** signedCmsBytes, DWORD* signedCmsSize) {
    // PKINIT sends the AuthPack as CMS SignedData. The certificate private key
    // proves possession to the KDC; the inner content type is id-pkinit-authData.
    CMSG_SIGNER_ENCODE_INFO signer = { 0 };
    signer.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    signer.pCertInfo = signingCert->pCertInfo;
    signer.hCryptProv = (HCRYPTPROV)certProvider;
    signer.dwKeySpec = keySpec;
    signer.HashAlgorithm.pszObjId = digestOid;

    CMSG_SIGNED_ENCODE_INFO signedInfo = { 0 };
    signedInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    signedInfo.cSigners = 1;
    signedInfo.rgSigners = &signer;
    signedInfo.cCertEncoded = certCount;
    signedInfo.rgCertEncoded = certBlobs;

    HCRYPTMSG hMsg = CRYPT32$CryptMsgOpenToEncode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CMSG_SIGNED,
        &signedInfo,
        PKINIT_AUTHDATA_OID,
        NULL
    );
    if (!hMsg)
        return TRUE;

    if (!CRYPT32$CryptMsgUpdate(hMsg, authPackBytes, authPackSize, TRUE))
        return TRUE;

    DWORD cmsSize = 0;
    if (!CRYPT32$CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &cmsSize))
        return TRUE;

    byte* cmsBytes = MemAlloc(cmsSize);
    if (!cmsBytes)
        return TRUE;
    if (!CRYPT32$CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, cmsBytes, &cmsSize))
        return TRUE;

    CRYPT32$CryptMsgClose(hMsg);
    *signedCmsBytes = cmsBytes;
    *signedCmsSize = cmsSize;
    return FALSE;
}

BOOL SignAuthPack(PCCERT_CONTEXT signingCert, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE certProvider, DWORD keySpec, HCERTSTORE certStore, byte* authPackBytes, DWORD authPackSize, byte** signedCmsBytes, DWORD* signedCmsSize) {
    DWORD certCount = 0;
    PCCERT_CONTEXT current = NULL;

    while ((current = CRYPT32$CertEnumCertificatesInStore(certStore, current)) != NULL)
        certCount++;

    CERT_BLOB* certBlobs = NULL;
    if (certCount) {
        certBlobs = MemAlloc(sizeof(CERT_BLOB) * certCount);
        if (!certBlobs)
            return TRUE;

        current = NULL;
        DWORD certIndex = 0;
        while ((current = CRYPT32$CertEnumCertificatesInStore(certStore, current)) != NULL) {
            certBlobs[certIndex].cbData = current->cbCertEncoded;
            certBlobs[certIndex].pbData = (byte*)current->pbCertEncoded;
            certIndex++;
        }
    }

    if (!SignAuthPackCms(signingCert, certProvider, keySpec, certBlobs, certCount, authPackBytes, authPackSize, NULL, signedCmsBytes, signedCmsSize))
        return FALSE;

    if (!SignAuthPackCms(signingCert, certProvider, keySpec, certBlobs, certCount, authPackBytes, authPackSize, OID_SHA1, signedCmsBytes, signedCmsSize))
        return FALSE;

    PRINT_OUT("[X] CryptMsg signing failed with GetLastError=%lu\n", KERNEL32$GetLastError());
    return TRUE;
}

BOOL BuildPaPkAsReqBlob(byte* signedCmsBytes, DWORD signedCmsSize, byte** paPkAsReqBytes, DWORD* paPkAsReqSize) {
    // PA-PK-AS-REQ wraps the signed AuthPack in context [0] signedAuthPack.
    AsnElt signedAuthPack = { 0 };
    AsnElt signedAuthPackContext = { 0 };
    AsnElt paPkAsReq = { 0 };

    if (MakeBlob(signedCmsBytes, 0, signedCmsSize, &signedAuthPack))
        return TRUE;
    if (MakeImplicit(ASN_CONTEXT, 0, &signedAuthPack, &signedAuthPackContext))
        return TRUE;
    if (Make3(ASN_SEQUENCE, &signedAuthPackContext, 1, &paPkAsReq))
        return TRUE;

    int encodedPaPkAsReqSize = 0;
    byte* encodedPaPkAsReq = NULL;
    if (AsnToBytesEncode(&paPkAsReq, &encodedPaPkAsReqSize, &encodedPaPkAsReq))
        return TRUE;

    *paPkAsReqBytes = encodedPaPkAsReq;
    *paPkAsReqSize = encodedPaPkAsReqSize;
    return FALSE;
}

void PrintKirbiOutput(byte* ticket, BOOL show, BOOL nowrap) {
    if (!show || !ticket)
        return;

    if (nowrap)
        PRINT_OUT("%s\n", ticket);
    else
        PRINT_OUT("[*] base64(ticket.kirbi): \n\n%s\n\n", ticket);
}

BOOL GenerateDhKeyPair(BCRYPT_ALG_HANDLE* dhAlgorithm, BCRYPT_KEY_HANDLE* dhKey) {
    // Generate an ephemeral 2048-bit DH key pair using Group 14 p and g = 2.
    // The private value stays inside CNG; only the public value is exported into
    // the PKINIT AuthPack.
    byte* modulus = NULL;
    byte* generator = NULL;
    if (HexStringToFixedBytes(DH_GROUP14_P_HEX, 256, &modulus))
        return TRUE;
    if (HexStringToFixedBytes("02", 256, &generator))
        return TRUE;

    if (BCrypt$OpenAlgorithmProvider(dhAlgorithm, BCRYPT_DH_ALGORITHM, NULL, 0) != 0)
        return TRUE;
    if (BCrypt$GenerateKeyPair(*dhAlgorithm, dhKey, 2048, 0) != 0)
        return TRUE;

    ULONG parameterBlobSize = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 512;
    byte* parameterBlob = MemAlloc(parameterBlobSize);
    if (!parameterBlob)
        return TRUE;

    BCRYPT_DH_PARAMETER_HEADER* parameterHeader = (BCRYPT_DH_PARAMETER_HEADER*)parameterBlob;
    parameterHeader->cbLength = parameterBlobSize;
    parameterHeader->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    parameterHeader->cbKeyLength = 256;

    MemCpy(parameterBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER), modulus, 256);
    MemCpy(parameterBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER) + 256, generator, 256);

    if (BCrypt$SetProperty(*dhKey, BCRYPT_DH_PARAMETERS, parameterBlob, parameterBlobSize, 0) != 0)
        return TRUE;
    if (BCrypt$FinalizeKeyPair(*dhKey, 0) != 0)
        return TRUE;

    return FALSE;
}

BOOL CmsDecodeContent(byte* cmsBytes, DWORD cmsSize, byte** contentBytes, DWORD* contentSize) {
    // PA-PK-AS-REP returns the KDC's DH key info as CMS SignedData. We only need
    // the signed content here; certificate chain validation is not performed.
    HCRYPTMSG hMsg = CRYPT32$CryptMsgOpenToDecode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        0,
        0,
        NULL,
        NULL
    );
    if (!hMsg)
        return TRUE;
    if (!CRYPT32$CryptMsgUpdate(hMsg, cmsBytes, cmsSize, TRUE))
        return TRUE;
    if (!CRYPT32$CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, contentSize))
        return TRUE;

    *contentBytes = MemAlloc(*contentSize);
    if (!*contentBytes)
        return TRUE;
    if (!CRYPT32$CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, *contentBytes, contentSize))
        return TRUE;

    CRYPT32$CryptMsgClose(hMsg);
    return FALSE;
}

BOOL ExtractAsnIntegerBytes(AsnElt* integerAsn, byte** integerBytes, DWORD* integerSize) {
    // Strip DER INTEGER sign padding before importing the public number into CNG.
    int rawSize = ValueLength(integerAsn);
    byte* rawBytes = MemAlloc(rawSize);
    if (!rawBytes)
        return TRUE;
    EncodeValue(integerAsn, 0, rawSize, rawBytes, 0);

    int offset = 0;
    while ((offset + 1) < rawSize && rawBytes[offset] == 0)
        offset++;

    *integerSize = rawSize - offset;
    *integerBytes = MemAlloc(*integerSize);
    if (!*integerBytes)
        return TRUE;
    MemCpy(*integerBytes, rawBytes + offset, *integerSize);
    return FALSE;
}

BOOL ExtractKdcDhPublicKey(RAW_DATA* pkAsRepData, byte** kdcPublicKey, DWORD* kdcPublicKeySize, byte** serverDhNonce, DWORD* serverDhNonceSize) {
    // Parse PA-PK-AS-REP dhSignedData, unwrap KDC-DHKeyInfo, and extract the
    // KDC's public DH integer plus the optional serverDHNonce.
    AsnElt pkAsRep = { 0 };
    if (BytesToAsnDecode(pkAsRepData->data, pkAsRepData->size, &pkAsRep))
        return TRUE;

    AsnElt* dhInfo = &pkAsRep;
    if (dhInfo->tagClass == ASN_CONTEXT && dhInfo->tagValue == 0 && dhInfo->subCount == 1)
        dhInfo = &(dhInfo->sub[0]);

    byte* dhSignedData = NULL;
    int dhSignedDataSize = 0;
    BOOL found = FALSE;
    if (serverDhNonce)
        *serverDhNonce = NULL;
    if (serverDhNonceSize)
        *serverDhNonceSize = 0;

    for (int i = 0; i < dhInfo->subCount; i++) {
        if (dhInfo->sub[i].tagValue == 0) {
            AsnElt* value = dhInfo->sub[i].subCount ? &(dhInfo->sub[i].sub[0]) : &(dhInfo->sub[i]);
            if (AsnGetOctetString(value, &dhSignedData, &dhSignedDataSize))
                return TRUE;
            found = TRUE;
        }
        else if (dhInfo->sub[i].tagValue == 1 && serverDhNonce && serverDhNonceSize) {
            AsnElt* value = dhInfo->sub[i].subCount ? &(dhInfo->sub[i].sub[0]) : &(dhInfo->sub[i]);
            if (AsnGetOctetString(value, serverDhNonce, (int*)serverDhNonceSize))
                return TRUE;
        }
    }

    if (!found)
        return TRUE;

    byte* kdcDhKeyInfo = NULL;
    DWORD kdcDhKeyInfoSize = 0;
    if (CmsDecodeContent(dhSignedData, dhSignedDataSize, &kdcDhKeyInfo, &kdcDhKeyInfoSize))
        return TRUE;

    AsnElt dhKeyInfoAsn = { 0 };
    if (BytesToAsnDecode(kdcDhKeyInfo, kdcDhKeyInfoSize, &dhKeyInfoAsn))
        return TRUE;
    if (dhKeyInfoAsn.tagValue != ASN_SEQUENCE)
        return TRUE;

    AsnElt* subjectPublicKeyNode = NULL;
    for (int i = 0; i < dhKeyInfoAsn.subCount; i++) {
        if (dhKeyInfoAsn.sub[i].tagValue == 0) {
            subjectPublicKeyNode = &(dhKeyInfoAsn.sub[i]);
            break;
        }
    }
    if (!subjectPublicKeyNode)
        return TRUE;

    AsnElt* bitStringNode = subjectPublicKeyNode->subCount ? &(subjectPublicKeyNode->sub[0]) : subjectPublicKeyNode;
    int bitStringSize = ValueLength(bitStringNode);
    byte* bitStringBytes = MemAlloc(bitStringSize);
    if (!bitStringBytes)
        return TRUE;
    EncodeValue(bitStringNode, 0, bitStringSize, bitStringBytes, 0);
    if (bitStringSize < 2)
        return TRUE;

    AsnElt publicKeyInteger = { 0 };
    if (BytesToAsnDecode(bitStringBytes + 1, bitStringSize - 1, &publicKeyInteger))
        return TRUE;
    if (publicKeyInteger.tagValue != ASN_INTEGER)
        return TRUE;

    return ExtractAsnIntegerBytes(&publicKeyInteger, kdcPublicKey, kdcPublicKeySize);
}

BOOL DerivePkinitReplyKey(BCRYPT_ALG_HANDLE dhAlgorithm, BCRYPT_KEY_HANDLE dhKey, byte* kdcPublicKey, DWORD kdcPublicKeySize, byte* clientDhNonce, DWORD clientDhNonceSize, byte* serverDhNonce, DWORD serverDhNonceSize, int asRepEtype, EncryptionKey* replyKey) {
    if (asRepEtype != aes256_cts_hmac_sha1 && asRepEtype != aes128_cts_hmac_sha1) {
        PRINT_OUT("[X] /certificate currently supports AES128/AES256 AS-REP keys only.\n");
        return TRUE;
    }

    byte* modulus = NULL;
    byte* generator = NULL;
    byte* publicValue = NULL;
    if (HexStringToFixedBytes(DH_GROUP14_P_HEX, 256, &modulus))
        return TRUE;
    if (HexStringToFixedBytes("02", 256, &generator))
        return TRUE;
    if (kdcPublicKeySize > 256)
        return TRUE;

    // CNG imports DH public blobs as fixed-width { p, g, publicValue } fields.
    // Left-pad the KDC's DER integer to the 256-byte Group 14 modulus size.
    publicValue = MemAlloc(256);
    if (!publicValue)
        return TRUE;
    for (int i = 0; i < 256; i++)
        publicValue[i] = 0;
    MemCpy(publicValue + (256 - kdcPublicKeySize), kdcPublicKey, kdcPublicKeySize);

    DWORD publicBlobSize = sizeof(BCRYPT_DH_KEY_BLOB) + 768;
    byte* publicBlob = MemAlloc(publicBlobSize);
    if (!publicBlob)
        return TRUE;

    BCRYPT_DH_KEY_BLOB* publicBlobHeader = (BCRYPT_DH_KEY_BLOB*)publicBlob;
    publicBlobHeader->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
    publicBlobHeader->cbKey = 256;
    MemCpy(publicBlob + sizeof(BCRYPT_DH_KEY_BLOB), modulus, 256);
    MemCpy(publicBlob + sizeof(BCRYPT_DH_KEY_BLOB) + 256, generator, 256);
    MemCpy(publicBlob + sizeof(BCRYPT_DH_KEY_BLOB) + 512, publicValue, 256);

    BCRYPT_KEY_HANDLE kdcKey = 0;
    if (BCrypt$ImportKeyPair(dhAlgorithm, 0, BCRYPT_DH_PUBLIC_BLOB, &kdcKey, publicBlob, publicBlobSize, 0) != 0)
        return TRUE;

    BCRYPT_SECRET_HANDLE sharedSecret = 0;
    if (BCrypt$SecretAgreement(dhKey, kdcKey, &sharedSecret, 0) != 0)
        return TRUE;

    ULONG sharedSecretSize = 0;
    if (BCrypt$DeriveKey(sharedSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &sharedSecretSize, 0) != 0)
        return TRUE;

    byte* sharedSecretBytes = MemAlloc(sharedSecretSize);
    if (!sharedSecretBytes)
        return TRUE;
    if (BCrypt$DeriveKey(sharedSecret, BCRYPT_KDF_RAW_SECRET, NULL, sharedSecretBytes, sharedSecretSize, &sharedSecretSize, 0) != 0)
        return TRUE;

    // BCrypt returns the raw secret little-endian for this path. PKINIT's reply
    // key KDF expects the DH shared secret in network byte order.
    ReverseBytes(sharedSecretBytes, sharedSecretSize);

    DWORD kdfInputSize = sharedSecretSize + clientDhNonceSize + serverDhNonceSize;
    byte* kdfInput = MemAlloc(kdfInputSize);
    if (!kdfInput)
        return TRUE;
    MemCpy(kdfInput, sharedSecretBytes, sharedSecretSize);
    if (clientDhNonce && clientDhNonceSize)
        MemCpy(kdfInput + sharedSecretSize, clientDhNonce, clientDhNonceSize);
    if (serverDhNonce && serverDhNonceSize)
        MemCpy(kdfInput + sharedSecretSize + clientDhNonceSize, serverDhNonce, serverDhNonceSize);

    DWORD replyKeyLength = (asRepEtype == aes256_cts_hmac_sha1) ? 32 : 16;
    byte* kdfMaterial = MemAlloc(40);
    if (!kdfMaterial)
        return TRUE;

    // PKINIT reply-key material is SHA1(counter || sharedSecret || nonces).
    // Two SHA1 blocks are enough for AES256; AES128 takes the first 16 bytes.
    for (DWORD counter = 0; counter < 2; counter++) {
        byte* hashInput = MemAlloc(kdfInputSize + 1);
        byte hashOutput[20] = { 0 };
        if (!hashInput)
            return TRUE;
        hashInput[0] = (byte)counter;
        MemCpy(hashInput + 1, kdfInput, kdfInputSize);
        if (Sha1Buffer(hashInput, kdfInputSize + 1, hashOutput))
            return TRUE;
        MemCpy(kdfMaterial + (counter * 20), hashOutput, 20);
    }

    replyKey->key_type = asRepEtype;
    replyKey->key_size = replyKeyLength;
    replyKey->key_value = MemAlloc(replyKeyLength);
    if (!replyKey->key_value)
        return TRUE;
    MemCpy(replyKey->key_value, kdfMaterial, replyKeyLength);

    BCrypt$DestroySecret(sharedSecret);
    BCrypt$DestroyKey(kdcKey);
    return FALSE;
}

RAW_DATA* FindRawPaData(AS_REP* asRep, DWORD type) {
    for (int i = 0; i < asRep->pa_data_count; i++) {
        if (asRep->pa_data[i].type == type)
            return (RAW_DATA*)asRep->pa_data[i].value;
    }
    return NULL;
}

BOOL NewAS_REQ_cert(char* pcUsername, char* pcDomain, BOOL bPac, AS_REQ* as_req) {
    // Certificate PKINIT negotiates AES reply keys; RC4 is intentionally omitted.
    as_req->pvno = 5;
    as_req->msg_type = KERB_AS_REQ;

    as_req->req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK | CANONICALIZE;
    as_req->req_body.till = 1 * 3600;
    as_req->req_body.rtime = 1 * 3600;
    ADVAPI32$SystemFunction036(&(as_req->req_body.nonce), 4);
    if (my_copybuf(&as_req->req_body.realm, pcDomain, my_strlen(pcDomain) + 1))
        return TRUE;

    as_req->req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    as_req->req_body.cname.name_count = 1;
    as_req->req_body.cname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
    if (!as_req->req_body.cname.name_string)
        return TRUE;
    if (my_copybuf(&(as_req->req_body.cname.name_string[0]), pcUsername, my_strlen(pcUsername) + 1))
        return TRUE;

    as_req->req_body.sname.name_count = 2;
    as_req->req_body.sname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.sname.name_count);
    if (!as_req->req_body.sname.name_string)
        return TRUE;
    as_req->req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
    if (my_copybuf(&(as_req->req_body.sname.name_string[0]), "krbtgt", 7))
        return TRUE;
    if (my_copybuf(&(as_req->req_body.sname.name_string[1]), pcDomain, my_strlen(pcDomain) + 1))
        return TRUE;

    as_req->req_body.etypes_count = 2;
    as_req->req_body.etypes = MemAlloc(sizeof(int) * as_req->req_body.etypes_count);
    if (!as_req->req_body.etypes)
        return TRUE;
    as_req->req_body.etypes[0] = aes256_cts_hmac_sha1;
    as_req->req_body.etypes[1] = aes128_cts_hmac_sha1;

    as_req->pa_data_count = 2;
    as_req->pa_data = MemAlloc(sizeof(PA_DATA) * as_req->pa_data_count);
    if (!as_req->pa_data)
        return TRUE;

    as_req->pa_data[1].type = PADATA_PA_PAC_REQUEST;
    as_req->pa_data[1].value = MemAlloc(sizeof(KERB_PA_PAC_REQUEST));
    if (!as_req->pa_data[1].value)
        return TRUE;
    ((KERB_PA_PAC_REQUEST*)as_req->pa_data[1].value)->include_pac = bPac;

    return FALSE;
}

BOOL AskTGT_cert(char* user, char* domain, char* certificate, char* certificatePassword, BOOL pac, BOOL show, BOOL nowrap, BOOL ptt, char* dc, byte** kirbiBytes) {
    // High-level PKINIT flow:
    // 1. Import the supplied PFX and find its private key.
    // 2. Generate an ephemeral DH key pair and signed AuthPack.
    // 3. Send PA-PK-AS-REQ, parse PA-PK-AS-REP, derive the reply key.
    // 4. Decrypt the AS-REP and optionally submit the resulting TGT.
    int certBlobSize = 0;
    byte* certBlob = base64_decode((byte*)certificate, &certBlobSize);
    if (!certBlob || certBlobSize == 0) {
        PRINT_OUT("[X] Failed to decode /certificate data.\n");
        return TRUE;
    }

    int passwordChars = 0;
    WCHAR* passwordWide = CharToWide(certificatePassword, &passwordChars);

    CRYPT_DATA_BLOB pfx = { 0 };
    pfx.cbData = certBlobSize;
    pfx.pbData = certBlob;

    HCERTSTORE certStore = CRYPT32$PFXImportCertStore(&pfx, passwordWide, CRYPT_USER_KEYSET | CRYPT_EXPORTABLE);
    if (!certStore && !certificatePassword) {
        WCHAR emptyPassword[] = { 0 };
        certStore = CRYPT32$PFXImportCertStore(&pfx, emptyPassword, CRYPT_USER_KEYSET | CRYPT_EXPORTABLE);
    }
    if (!certStore) {
        PRINT_OUT("[X] Failed to import the supplied certificate.\n");
        return TRUE;
    }

    PCCERT_CONTEXT certContext = NULL;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE certProvider = 0;
    DWORD keySpec = 0;
    BOOL callerFreeProvider = FALSE;
    while ((certContext = CRYPT32$CertEnumCertificatesInStore(certStore, certContext)) != NULL) {
        if (CRYPT32$CryptAcquireCertificatePrivateKey(certContext, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &certProvider, &keySpec, &callerFreeProvider))
            break;
    }

    if (!certContext) {
        PRINT_OUT("[X] The supplied certificate does not contain an accessible private key.\n");
        return TRUE;
    }
    if (keySpec == CERT_NCRYPT_KEY_SPEC) {
        PRINT_OUT("[X] /certificate currently requires a CryptoAPI-backed PFX key.\n");
        return TRUE;
    }

    BCRYPT_ALG_HANDLE dhAlgorithm = 0;
    BCRYPT_KEY_HANDLE dhKey = 0;
    if (GenerateDhKeyPair(&dhAlgorithm, &dhKey)) {
        PRINT_OUT("[X] Failed to generate the PKINIT DH key pair.\n");
        return TRUE;
    }

    AS_REQ certAsReq = { 0 };
    if (NewAS_REQ_cert(user, domain, pac, &certAsReq)) {
        PRINT_OUT("[X] Failed to build the PKINIT AS-REQ.\n");
        return TRUE;
    }

    DWORD pkNonce = 0;
    ADVAPI32$SystemFunction036(&pkNonce, sizeof(pkNonce));

    byte* authPackBytes = NULL;
    DWORD authPackSize = 0;
    if (BuildAuthPack(&(certAsReq.req_body), dhKey, pkNonce, &authPackBytes, &authPackSize)) {
        PRINT_OUT("[X] Failed to build the PKINIT AuthPack.\n");
        return TRUE;
    }

    byte* signedCmsBytes = NULL;
    DWORD signedCmsSize = 0;
    if (SignAuthPack(certContext, certProvider, keySpec, certStore, authPackBytes, authPackSize, &signedCmsBytes, &signedCmsSize)) {
        PRINT_OUT("[X] Failed to sign the PKINIT AuthPack.\n");
        return TRUE;
    }

    byte* paPkAsReqBytes = NULL;
    DWORD paPkAsReqSize = 0;
    if (BuildPaPkAsReqBlob(signedCmsBytes, signedCmsSize, &paPkAsReqBytes, &paPkAsReqSize)) {
        PRINT_OUT("[X] Failed to wrap PA-PK-AS-REQ.\n");
        return TRUE;
    }

    certAsReq.pa_data[0].type = PADATA_PK_AS_REQ;
    certAsReq.pa_data[0].value = MemAlloc(sizeof(RAW_DATA));
    if (!certAsReq.pa_data[0].value)
        return TRUE;
    ((RAW_DATA*)certAsReq.pa_data[0].value)->size = paPkAsReqSize;
    ((RAW_DATA*)certAsReq.pa_data[0].value)->data = paPkAsReqBytes;

    PRINT_OUT("[*] Building AS-REQ (PKINIT) for: '%s\\%s'\n", domain, user);

    AsnElt requestAsn = { 0 };
    if (ReqToAsnEncode(certAsReq, 10, &requestAsn)) {
        PRINT_OUT("[X] Failed to ASN.1 encode the PKINIT AS-REQ.\n");
        return TRUE;
    }

    int requestBytesSize = 0;
    byte* requestBytes = NULL;
    if (AsnToBytesEncode(&requestAsn, &requestBytesSize, &requestBytes)) {
        PRINT_OUT("[X] Failed to serialize the PKINIT AS-REQ.\n");
        return TRUE;
    }

    byte* response = NULL;
    int responseSize = 0;
    sendBytes(dc ? dc : domain, "88", requestBytes, requestBytesSize, &response, &responseSize);
    if (responseSize == 0) {
        PRINT_OUT("[X] The KDC did not return a PKINIT response.\n");
        return TRUE;
    }

    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response, responseSize, &responseAsn)) {
        PRINT_OUT("[X] Failed to parse the PKINIT response.\n");
        return TRUE;
    }
    if (responseAsn.tagValue == KERB_ERROR) {
        uint errorCode = 0;
        if (!AsnGetErrorCode(&(responseAsn.sub[0]), &errorCode))
            PRINT_OUT("[X] PKINIT failed: %s\n", lookupKrbErrorCode(errorCode));
        return TRUE;
    }
    if (responseAsn.tagValue != KERB_AS_REP) {
        PRINT_OUT("[X] Unexpected PKINIT response tag: %d\n", responseAsn.tagValue);
        return TRUE;
    }

    AS_REP asRep = { 0 };
    if (NewAS_REP(responseAsn, &asRep)) {
        PRINT_OUT("[X] Failed to parse the AS-REP returned by the KDC.\n");
        return TRUE;
    }

    RAW_DATA* pkAsRepData = FindRawPaData(&asRep, PADATA_PK_AS_REP);
    if (!pkAsRepData) {
        PRINT_OUT("[X] The KDC did not return PA-PK-AS-REP data.\n");
        return TRUE;
    }

    byte* kdcPublicKey = NULL;
    DWORD kdcPublicKeySize = 0;
    byte* serverDhNonce = NULL;
    DWORD serverDhNonceSize = 0;
    if (ExtractKdcDhPublicKey(pkAsRepData, &kdcPublicKey, &kdcPublicKeySize, &serverDhNonce, &serverDhNonceSize)) {
        PRINT_OUT("[X] Failed to extract the KDC DH public key from PA-PK-AS-REP.\n");
        return TRUE;
    }

    EncryptionKey replyKey = { 0 };
    if (DerivePkinitReplyKey(dhAlgorithm, dhKey, kdcPublicKey, kdcPublicKeySize, NULL, 0, serverDhNonce, serverDhNonceSize, asRep.enc_part.etype, &replyKey)) {
        PRINT_OUT("[X] Failed to derive the PKINIT reply key.\n");
        return TRUE;
    }

    if (HandleASREP(responseAsn, replyKey, NULL, FALSE, dc ? dc : domain, kirbiBytes)) {
        PRINT_OUT("[X] Failed to decrypt the AS-REP using the derived PKINIT reply key.\n");
        return TRUE;
    }

    PRINT_OUT("[+] TGT request successful!\n");
    PrintKirbiOutput(*kirbiBytes, show, nowrap);

    if (callerFreeProvider && certProvider)
        ADVAPI32$CryptReleaseContext((HCRYPTPROV)certProvider, 0);
    if (dhKey)
        BCrypt$DestroyKey(dhKey);
    if (dhAlgorithm)
        BCrypt$CloseAlgorithmProvider(dhAlgorithm, 0);
    CRYPT32$CertCloseStore(certStore, 0);

    if (ptt)
        PTT(NULL, *kirbiBytes);

    return FALSE;
}
