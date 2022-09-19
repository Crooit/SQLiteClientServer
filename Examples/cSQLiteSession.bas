#Include "cSQLiteCS\cSQLiteSession.bi"
#Include Once "win\wincrypt.bi"
#Inclib "crypt32"
SUB Bin2Hex(BYREF sBinary AS STRING, _
            BYREF sHex AS STRING)
' Convert binary string to hex representation
dim nHexLength    AS LONG
    sHex = ""
    nHexLength = LEN(sBinary) * 2
    IF LEN(nHexLength) > 0 THEN
        nHexLength = nHexLength + 1
        sHex = SPACE$(nHexLength)
        CryptBinaryToStringA(STRPTR(sBinary), _
                            LEN(sBinary), _
                            CRYPT_STRING_HEXRAW + CRYPT_STRING_NOCRLF, _
                            STRPTR(sHex), _
                            varptr(nHexLength))
         sHex = LEFT$(sHex,nHexLength)
    END IF
END SUB

Dim oClientSession          AS cSQLiteSession
Dim oServerSession          AS cSQLiteSession
dim sClientPublicKey        as string
dim sServerPublicKey        as string
dim sClientSessionKey       as string
dim sServerSessionKey       as string
dim sHex                    as string
Dim sRandom                 as string
dim sClearText              as string
dim sCipherText             as string
dim sAny                    as string

Print "Client Startup Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Print "Server Startup Status " + oServerSession.WindowsErrorDescription(oServerSession.Status)
sClientPublicKey = oClientSession.PublicKey
Print "Client Public Key Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Bin2Hex(sClientPublicKey,sHex)
print "Client Public Key"
print sHex
sServerPublicKey = oServerSession.PublicKey
Print "Server Public Key Status " + oServerSession.WindowsErrorDescription(oServerSession.Status)
Bin2Hex(sServerPublicKey,sHex)
print "Server Public Key"
print sHex
Print "Client and Server exchange public keys"
oClientSession.GenerateSessionKey(sServerPublicKey)
sClientSessionKey = oClientSession.SessionKey
Print "Client Session Key Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Bin2Hex(sClientSessionKey,sHex)
print "Client Session Key"
print sHex
oServerSession.GenerateSessionKey(sClientPublicKey)
sServerSessionKey = oServerSession.SessionKey
Print "Server Session Key Status " + oServerSession.WindowsErrorDescription(oServerSession.Status)
Bin2Hex(sServerSessionKey,sHex)
print "Server Session Key"
print sHex
sClearText = "Default IV..."
oClientSession.EncryptText (sClearText, sCipherText)
Print "Client Encrypt Default IV Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Bin2Hex(sCipherText,sHex)
print "Client Encrypted String Default IV"
print sHex
oServerSession.DecryptText (sCipherText,sClearText)
Print "Server Decrypt Default IV Status " + oServerSession.WindowsErrorDescription(oServerSession.Status)
print "Server Decrypted String Default IV"
print sClearText
sRandom = oClientSession.RandomString (16)
Print "Client Creates Random IV Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
oClientSession.IV(sRandom)
Print "Client Random IV Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Bin2Hex(sRandom,sHex)
Print "Client Random IV"
print sHex
oServerSession.IV(sRandom)
Print "Client Random IV sent to Server using Default IV"
oClientSession.EncryptText (sRandom, sCipherText)
Print "Client Random IV Encrypted Status " + oClientSession.WindowsErrorDescription(oClientSession.Status)
Bin2Hex(sCipherText,sHex)
print "Client Encrypted Random IV"
print sHex
oServerSession.DecryptText (sCipherText,sClearText)
print "Server Decrypted String Random IV"
Print "Server Decrypt Random IV Status " + oServerSession.WindowsErrorDescription(oServerSession.Status)
Bin2Hex(sClearText,sHex)
print "Server Decrypted Random IV"
print sHex
Print "Press any key..."
Sleep




