' ########################################################################################
' File: cSQLiteSession.bi
' Contents: FreeBasic Windows Sqlite Client Server Session Support.
' Version: 1.00
' Compiler: FreeBasic 32 & 64-bit Windows
' Copyright (c) 2022 Rick Kelly
' Released into the public domain for private and public use without restriction
' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
' EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
' MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
' ########################################################################################
#pragma once
#Include Once "windows.bi"
#Include Once "win\bcrypt.bi"
#Inclib "bcrypt"
#Include Once "win/winsock2.bi"
#Include Once "win/ws2tcpip.bi"
'Namespace cSQLiteSessionClass
' ########################################################################################
' cSQLiteSession Class
' ########################################################################################
Type cSQLiteSession Extends Object
    Private:
    
dim hKeyExchangeAlgorithm   as BCRYPT_ALG_HANDLE
dim hKeyExchange            as BCRYPT_KEY_HANDLE
Dim hRandomAlgorithm        as BCRYPT_ALG_HANDLE
Dim hHashAlgorithm          as BCRYPT_ALG_HANDLE
dim hCryptoAlgorithm        as BCRYPT_ALG_HANDLE
dim sPublicKey              as string
dim sSessionKey             as string
dim sIV                     as string = "Temporary AES256"                  'Must be 16 bytes AES is a 128 bit block cipher. Will be replaced with an exchanged value during client/server handshake.
dim lCurrentStatus          as NTSTATUS = S_OK
Dim WSAD                    as WSADATA
Dim iTimeout                as Long = 20000
Dim iWaitTimeout            as Long = 10

    Declare Sub GeneratePublicKey ()
    Declare Function EncryptOneBlock (ByVal hKey as BCRYPT_KEY_HANDLE, ByRef sPlainText as String, ByRef sCipherText as String, ByVal lFinal as BOOLEAN) As NTSTATUS
    Declare Function DecryptOneBlock (ByVal hKey as BCRYPT_KEY_HANDLE, ByRef sCipherText as String, ByRef sPlainText as String, ByVal lFinal as BOOLEAN) as NTSTATUS
    Declare Function ZStringPointer(ByRef sAny as String) as ZString Ptr
  
    Public:

    Declare Constructor
    Declare Destructor
    Declare Sub GenerateSessionKey (byref sOtherPublicKey as string)
    Declare sub HashString (ByRef sAny as String, ByRef sHash as String)
    Declare Function RandomString (ByVal iLength as uLong) AS String
    Declare Sub EncryptText (ByRef sPlainText as String, ByRef sCipherText as String)
    Declare Sub DecryptText (ByRef sCipherText as String, ByRef sPlainText as String)
    Declare Property PublicKey () AS string
    declare property SessionKey () as string                                    'When caller wants the shared encryption key
    declare property Status () as NTSTATUS
    Declare Property Timeout(ByVal iTimeout as Long)
    Declare Property WaitTimeout(ByVal iTimeout as Long)
    declare Sub IV (Byref sIVRandom as string)
    Declare Function TCPConnect (ByRef hSocket as SOCKET, ByRef sIPAddress as String, ByVal wPort as WORD) as BOOLEAN
    Declare Function UDPBroadcast (ByVal sMessage as String, ByRef sResponse as String, ByVal wPort as WORD, ByVal nMessageSize as Long) as BOOLEAN
    Declare Function UDPSendTo (ByVal hSocket as SOCKET, ByRef sMessage as String, ByVal wPort as WORD, ByVal nIPAddress as ulong) as BOOLEAN
    Declare Function UDPReceiveFrom (ByVal hSocket as DWORD, ByRef sResponse as String, ByRef SockAddress as SOCKADDR_IN, ByVal nMessageSize as Long) as BOOLEAN
    Declare Function SendAndReceiveSocket (ByVal hSocket as SOCKET, ByVal iBufferSize as Long, ByRef sMessage as String, ByRef sResponse as String) as BOOLEAN
    Declare Function SendSocket (ByVal hSocket as SOCKET, ByRef sData as String) as BOOLEAN
    Declare Function ReceiveSocket (ByVal hSocket as Long, ByVal iBufferSize as Long, ByRef sReceived as String) as BOOLEAN                               
    Declare Function SocketReceiveReady (ByVal hSocket as SOCKET) as BOOLEAN
    Declare Function HostNameFromIP (ByRef sIPAddress as String, ByRef sHostName as String) as BOOLEAN
    Declare Function IPFromHostName (ByRef sHostName as String, ByRef sIPAddress as String) as BOOLEAN
    Declare Function HostByAddress (ByRef sHostName as String, ByRef lpHostEntry as HOSTENT Ptr) as BOOLEAN
    Declare Function HostByName (ByRef sHostName as String, ByRef lpHostEntry as HOSTENT Ptr) as BOOLEAN
    Declare Function OpenListenerSocket (ByRef hSocket as SOCKET, ByVal HWnd as HWnd, ByVal nMessageID as uLong, ByVal nEvents as Long, ByVal lDefaultIP as BOOLEAN, ByVal nType as Long, ByVal wPort as WORD, ByRef sIPAddress as String) as BOOLEAN
    Declare Function PreferredAddress (ByRef sLocalHostName as String, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
    Declare Function StringToIP (ByRef sIPAddress as String) as ulong
    Declare Function LocalHostName (ByRef sLocalHostName as String) as BOOLEAN 
    Declare Sub IPToString (ByVal nIPAddress as ulong, ByRef sIPAddress as String)
    Declare Function BindSocket (ByVal hSocket as SOCKET, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
    Declare Function AsyncSelectSocket (ByVal hSocket as SOCKET, ByVal HWnd as HWND, ByVal iMessageID as u_int, ByVal iEvents as Long) as BOOLEAN
    Declare Function ListenSocket (ByVal hSocket as SOCKET) as BOOLEAN
    Declare Function AcceptSocket (ByVal hListeningSocket as SOCKET, ByRef hAcceptSocket as SOCKET, ByRef AcceptSockAddress as SOCKADDR_IN) as BOOLEAN
    Declare Function BlockingSocket (ByVal hSocket as SOCKET, ByVal nMode as Long) as BOOLEAN 
    Declare Function GetSocket (ByVal nFamily as Long, ByVal nType as Long, ByVal nProtocol as Long, ByRef hSocket as SOCKET) as BOOLEAN
    Declare Function TimeoutSocket (ByVal hSocket as SOCKET) as BOOLEAN
    Declare Function ConnectSocket (ByVal hSocket as SOCKET, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
    Declare Function Disconnect (ByRef hSocket as SOCKET) as BOOLEAN
    Declare Function SocketShutdown (ByVal hSocket as SOCKET) as BOOLEAN
    Declare Sub SocketClose (ByVal hSocket as SOCKET)
    Declare Function WindowsErrorDescription (ByVal iErrorCode as Long) as String
 
End Type 
PRIVATE Constructor cSQLiteSession
    This.lCurrentStatus = BCryptOpenAlgorithmProvider(varptr(This.hKeyExchangeAlgorithm), CAST(LPCWSTR,strptr(BCRYPT_ECDH_P384_ALGORITHM)), 0, 0)
    if This.lCurrentStatus = S_OK Then
        This.lCurrentStatus = BCryptOpenAlgorithmProvider(VarPtr(This.hRandomAlgorithm),CAST(LPCWSTR,strptr(BCRYPT_RNG_ALGORITHM)), 0, 0)
    end if
    if This.lCurrentStatus = S_OK Then
        This.lCurrentStatus = BCryptOpenAlgorithmProvider(VarPtr(This.hHashAlgorithm),CAST(LPCWSTR,strptr(BCRYPT_SHA256_ALGORITHM)), 0, 0)
    end if
    if This.lCurrentStatus = S_OK then
        This.lCurrentStatus = BCryptOpenAlgorithmProvider(VarPtr(This.hCryptoAlgorithm), CAST(LPCWSTR,strptr(BCRYPT_AES_ALGORITHM)), 0, 0)
    end if
    if This.lCurrentStatus = S_OK then
        This.lCurrentStatus = BCryptSetProperty(This.hCryptoAlgorithm, CAST(LPCWSTR,StrPtr(BCRYPT_CHAINING_MODE)), Cast(PUCHAR,strptr(BCRYPT_CHAIN_MODE_CBC)), Len(BCRYPT_CHAIN_MODE_CBC) , 0)
    end if
    If This.lCurrentStatus = S_OK then
' Major version 2, minor version 2 minimum required
         This.lCurrentStatus = WSAStartup (makeword(2,2), @This.WSAD)
    end if
end constructor
private Destructor cSQLiteSession
    BCryptCloseAlgorithmProvider(This.hKeyExchangeAlgorithm, 0)
    BCryptCloseAlgorithmProvider(This.hHashAlgorithm, 0)
    BCryptCloseAlgorithmProvider(This.hRandomAlgorithm, 0)
    BCryptCloseAlgorithmProvider(This.hCryptoAlgorithm, 0)
    BCryptDestroyKey(hKeyExchange)
    WSACleanup()
end destructor
' ========================================================================================
' Gets the Public Key
' ========================================================================================
Private Property cSQLiteSession.PublicKey () as string
    GeneratePublicKey ()
    Property = sPublicKey
end property
' ========================================================================================
' Gets the Session Key
' ========================================================================================
Private Property cSQLiteSession.SessionKey () as string
    Property = sSessionKey
end property
' ========================================================================================
' Gets the class status
' ========================================================================================
Private Property cSQLiteSession.Status () as NTSTATUS
    Property = lCurrentStatus
end property
' =====================================================================================
' Socket Timeout
' =====================================================================================
Private Property cSQLiteSession.Timeout (ByVal iTimeout as Long)
    This.iTimeout = iTimeout
End Property
' =====================================================================================
' Socket Receive Ready Wait Timeout
' =====================================================================================
Private Property cSQLiteSession.WaitTimeout (ByVal iTimeout as Long)
    This.iWaitTimeout = iTimeout
End Property
' ========================================================================================
' Sets the session IV
' ========================================================================================
Private Sub cSQLiteSession.IV (Byref sIVRandom as string)
    This.sIV = sIVRandom
end Sub
' ========================================================================================
' Generate Public Key
' ========================================================================================
Private Sub cSQLiteSession.GeneratePublicKey ()
 ' Open Algorithm Provider
dim lStatus                 as NTSTATUS
dim iKeySize                as ulong
 
' Generate Key Pair
        lStatus = BCryptGenerateKeyPair(This.hKeyExchangeAlgorithm, varptr(This.hKeyExchange), 384, 0)
 '   end if
    If lStatus = S_OK then
' Finalize Key Pair
        lStatus = BCryptFinalizeKeyPair(This.hKeyExchange,0)
    end if
' Save the generated public key
    If lStatus = S_OK then
' Get the size of the key
        lStatus = BCryptExportKey(This.hKeyExchange, Null, Cast(LPCWSTR,strptr(BCRYPT_ECCPUBLIC_BLOB)), Null, 0, varptr(iKeySize), 0)
    end if
    If lStatus = S_OK then
' Initialize Public Key to required size
        This.sPublicKey = space(iKeySize)
     ' Retrieve Public Key
        lStatus = BCryptExportKey(This.hKeyExchange, Null, Cast(LPCWSTR,strptr(BCRYPT_ECCPUBLIC_BLOB)), Cast(PUCHAR,strptr(This.sPublicKey)), iKeySize, varptr(iKeySize), 0)
    end if
    if lStatus <> S_OK then
        This.sPublicKey = ""
        BCryptDestroyKey(hKeyExchange)
    end if
    ' Reset default IV
    This.sIV = "Temporary AES256"
     lCurrentStatus = lStatus
end Sub
' =====================================================================================
' Generate a string of random values
' =====================================================================================
Private Function cSQLiteSession.RandomString (ByVal iLength as uLong) as string
' Return a string of random bytes
Dim sRandom                     as string

    sRandom = ""
    If iLength > 0 Then
       sRandom = Space(iLength)
' Get a random stream of bytes
       This.lCurrentStatus = BCryptGenRandom(This.hRandomAlgorithm, Cast(PUCHAR,StrPtr(sRandom)), iLength, 0)
    End If
    Return sRandom
End Function
' ========================================================================================
' Generate Session Key
' ========================================================================================
private sub cSQLiteSession.GenerateSessionKey (byref sOtherPublicKey as string)
' Import Public key by Other Party 
dim hKeyImport              as BCRYPT_KEY_HANDLE
dim hSecret                 as BCRYPT_SECRET_HANDLE
dim lStatus                 as NTSTATUS
dim iDerivedKeySize         as ulong
dim sDerivedKey             as string 

    sSessionKey = ""
    lStatus = lCurrentStatus
    if lStatus = S_OK then
        lStatus = BCryptImportKeyPair(hKeyExchangeAlgorithm, Null, Cast(LPCWSTR,strptr(BCRYPT_ECCPUBLIC_BLOB)), varptr(hKeyImport), Cast(PUCHAR,strptr(sOtherPublicKey)), Len(sOtherPublicKey), 0)
    end if
' Create the secret
    if lStatus = S_OK then
        lStatus = BCryptSecretAgreement(hKeyExchange, hKeyImport, varptr(hSecret), 0)
    end if
' Once the secret handle has been generated, a symmetric key can be derived.
' Get Derived Key Size
    if lStatus = S_OK then
        lStatus = BCryptDeriveKey(hSecret, Cast(LPCWSTR,strptr(BCRYPT_KDF_HASH)), Null, Null, 0, varptr(iDerivedKeySize), 0)
    end if
' Initialize Derived Key to required size
    sDerivedKey = space(iDerivedKeySize)
      if lStatus = S_OK then
        lStatus = BCryptDeriveKey(hSecret, Cast(LPCWSTR,strptr(BCRYPT_KDF_HASH)), Null, Cast(PUCHAR,strptr(sDerivedKey)), iDerivedKeySize, varptr(iDerivedKeySize), 0)
    end if
    If lStatus = S_OK then
        HashString(sDerivedKey,This.sSessionKey)
    end if
    BCryptDestroyKey(hKeyImport)
    BCryptDestroyKey(hKeyExchange)
    BCryptDestroySecret(hSecret)
    This.lCurrentStatus = lStatus  
end sub
' =====================================================================================
' Hash a string
' =====================================================================================
private sub cSQLiteSession.HashString (ByRef sAny as String, ByRef sHash as String)
' Hash a string set number of times
Dim hHashHandle             as BCRYPT_HASH_HANDLE
Dim iHashSize               as ULong
dim lStatus                 as NTSTATUS

    sHash = ""
    lStatus = BCryptCreateHash(This.hHashAlgorithm, VarPtr(hHashHandle), 0, 0, 0, 0, 0)
    If lStatus = S_OK then
        BCryptHashData (hHashHandle, Cast(PUCHAR,StrPtr(sAny)), Len(sAny), 0)
    end if
    iHashSize = 32
    sHash = Space(iHashSize)
    lStatus = BCryptFinishHash (hHashHandle, Cast(PUCHAR,StrPtr(sHash)), iHashSize, 0)
    If lStatus <> S_OK then
        sHash = ""
    End If
    This.lCurrentStatus = lStatus
    BCryptDestroyHash (hHashHandle)  
end sub
' =====================================================================================
' Encrypt a single plain text string
' =====================================================================================
Private Sub cSQLiteSession.EncryptText (ByRef sPlainText as String, ByRef sCipherText as String)
' Encrypt a single plain text string
Dim lStatus           as NTSTATUS
Dim hKey              as BCRYPT_KEY_HANDLE

' Generate the AES key schedule and Encrypt
    lStatus = BCryptGenerateSymmetricKey(This.hCryptoAlgorithm, VarPtr(hKey), 0, 0, Cast(PUCHAR,StrPtr(This.sSessionKey)), Len(This.sSessionKey), 0)
    If lStatus = S_OK Then
        lStatus = EncryptOneBlock(hKey, sPlainText, sCipherText, True)
    End If
' Release key handle
    BCryptDestroyKey(hKey)
    This.lCurrentStatus = lStatus
End Sub
' =====================================================================================
' Encrypt one block
' =====================================================================================
Private Function cSQLiteSession.EncryptOneBlock (ByVal hKey as BCRYPT_KEY_HANDLE, ByRef sPlainText as String, ByRef sCipherText as String, ByVal lFinal as BOOLEAN) As NTSTATUS
' lFinal = TRUE, then this is last block of the encryption run
' and padding is then added as needed
Dim iCipherTextSize     as Long
Dim iResult             as uLong
Dim lStatus             as NTSTATUS
dim sIVStart            as string
    sIVStart = This.sIV                 'Copy IV since it gets updated during encrypt
    sCipherText = ""
' Get the Cipher text size before encryption
lStatus = BCryptEnCrypt (hKey, Cast(PUCHAR,StrPtr(sPlainText)), Len(sPlainText), ByVal 0, Cast(PUCHAR,StrPtr(sIVStart)), Len(sIVStart), _
                        ByVal 0, ByVal 0, ByVal VarPtr(iCipherTextSize), IIf(lFinal=True,BCRYPT_BLOCK_PADDING,0)) 
    If lStatus = S_OK Then
' Allocate the output cipher text buffer and encrypt
       sCipherText = Space(iCipherTextSize)
       lStatus =  BCryptEnCrypt(hKey, Cast(PUCHAR,StrPtr(sPlainText)) ,Len(sPlainText), ByVal 0, Cast(PUCHAR,StrPtr(sIVStart)), Len(sIVStart), _
                                Cast(PUCHAR,StrPtr(sCipherText)),iCipherTextSize,ByVal VarPtr(iResult),IIf(lFinal=True,BCRYPT_BLOCK_PADDING,0))
    End If
    Return lStatus
End Function
' =====================================================================================
' Decrypt a single plain text string
' =====================================================================================
Private Sub cSQLiteSession.DecryptText (ByRef sCipherText as String, ByRef sPlainText as String)
Dim lStatus             as NTSTATUS
Dim hKey                as BCRYPT_KEY_HANDLE

' Generate the AES key schedule and Decrypt
    lStatus = BCryptGenerateSymmetricKey(This.hCryptoAlgorithm, VarPtr(hKey), 0, 0, Cast(PUCHAR,StrPtr(This.sSessionKey)), Len(This.sSessionKey), 0)
    If lStatus = S_OK then
        lStatus = DecryptOneBlock(hKey, sCipherText, sPlainText, True)
    End If
' Release key handle
    BCryptDestroyKey(hKey)
    lCurrentStatus = lStatus
End Sub
' =====================================================================================
' Decrypt one block
' =====================================================================================
Private Function cSQLiteSession.DecryptOneBlock (ByVal hKey as BCRYPT_KEY_HANDLE, ByRef sCipherText as String, ByRef sPlainText as String, ByVal lFinal as BOOLEAN) as NTSTATUS
' Decrypt one block
' lFinal = TRUE, then this is last block of the decryption run and padding is stripped as needed
Dim iPlainTextSize    as Long
Dim iResult           as ULong
Dim lStatus           as NTSTATUS
dim sIVStart            as string

    sIVStart = This.sIV
    sPlainText = ""
' Get the Clear text size before decryption
    lStatus = BCryptDeCrypt(hKey,Cast(PUCHAR,StrPtr(sCipherText)),Len(sCipherText),ByVal 0,Cast(PUCHAR,StrPtr(sIVStart)),Len(sIVStart), _
                            ByVal 0,ByVal 0,ByVal VarPtr(iPlainTextSize),IIf(lFinal=True,BCRYPT_BLOCK_PADDING,0))
    If lStatus = S_OK then
' Allocate the output plain text buffer and decrypt
       sPlainText = Space(iPlainTextSize)
       lStatus = BCryptDeCrypt(hKey,Cast(PUCHAR,StrPtr(sCipherText)),Len(sCipherText),ByVal 0,Cast(PUCHAR,StrPtr(sIVStart)),Len(sIVStart), _
                               Cast(PUCHAR,StrPtr(sPlainText)),iPlainTextSize,ByVal VarPtr(iResult),IIf(lFinal=True,BCRYPT_BLOCK_PADDING,0))
    End If
' If final block, iResult will have the final size
    If lFinal = True Then
       sPlainText = Left(sPlainText,iResult)
    End If
    Function = lStatus
End Function
' =====================================================================================
' Connect to TCP host
' =====================================================================================
Private Function cSQLiteSession.TCPConnect (ByRef hSocket as SOCKET, ByRef sIPAddress as String, ByVal wPort as WORD) as BOOLEAN

Dim lReturn       as BOOLEAN
Dim nIPAddress    as IN_ADDR
Dim SockAddress   as SOCKADDR_IN

    lReturn = False
    nIPAddress.s_addr = StringToIP(sIPAddress)
    lReturn = GetSocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,hSocket)
    Select Case lReturn
        Case True
            lReturn = TimeoutSocket(hSocket)
            If lReturn = True Then
               SockAddress.sin_family = AF_INET
               SockAddress.sin_port = htons(wPort)
               SockAddress.sin_addr.s_addr = nIPAddress.s_addr
               lReturn = ConnectSocket(hSocket,SockAddress)
            End If
            If lReturn = False Then
               Disconnect(hSocket)
            End If
    End Select
    Function = lReturn
End Function
' =====================================================================================
' UDP Broadcast
' =====================================================================================
Private Function cSQLiteSession.UDPBroadcast (ByVal sMessage as String, ByRef sResponse as String, ByVal wPort as WORD, ByVal nMessageSize as Long) as BOOLEAN
Dim SockAddress       as SOCKADDR_IN
Dim hSocket           as SOCKET
Dim lReturn           as BOOLEAN
Dim iReturn           as Long
Dim iBroadcast        as Long
Dim iBroadcastLen     as Long
    If GetSocket (AF_INET,SOCK_DGRAM,IPPROTO_UDP,hSocket) = False Then
       Function = False
       Exit Function
    End If
    iBroadcast = 1
    iBroadcastLen = Len(iBroadcast)
' Turn on the broadcast option    
    iReturn = setsockopt(hsocket,SOL_SOCKET,SO_BROADCAST,ByVal Cast(zstring ptr,VarPtr(iBroadcast)),iBroadcastLen)
    This.lCurrentStatus = WSAGetLastError
    lReturn = IIf(iReturn = SOCKET_ERROR,False,True)
    If lReturn = True Then
       lReturn = UDPSendTo (hSocket,sMessage,wPort,INADDR_BROADCAST)
       If lReturn = True Then
          lReturn = SocketReceiveReady (hSocket)
          If lReturn = True Then
             lReturn = UDPReceiveFrom (hSocket,sResponse,SockAddress,nMessageSize)
          End If
       End If
    End If
    Disconnect(hSocket)
    Function = lReturn
End Function
' =====================================================================================
' Send a UDP message
' =====================================================================================
Private Function cSQLiteSession.UDPSendTo (ByVal hSocket as SOCKET, ByRef sMessage as String, ByVal wPort as WORD, ByVal nIPAddress as ulong) as BOOLEAN
Dim SockAddress       as SOCKADDR_IN
Dim SockAddressSize   as Long
Dim iReturn           as Long

    SockAddress.sin_family = AF_INET
    SockAddress.sin_port = htons(wPort)
    SockAddress.sin_addr.s_addr = htonl(nIPAddress)
    SockAddressSize = Len(SockAddress)
    iReturn = sendto(hSocket,ByVal StrPtr(sMessage),Len(sMessage),0,ByVal Cast(SOCKADDR ptr,VarPtr(SockAddress)),SockAddressSize)
    This.lCurrentStatus = WSAGetLastError
    Function = IIf(iReturn = SOCKET_ERROR,False,True)
End Function
' =====================================================================================
' Receive a UDP message
' =====================================================================================
Private Function cSQLiteSession.UDPReceiveFrom (ByVal hSocket as DWORD, ByRef sResponse as String, ByRef SockAddress as SOCKADDR_IN, ByVal nMessageSize as Long) as BOOLEAN
Dim SockAddressSize   as Long
Dim nResponseSize     as Long
Dim lReturn           as BOOLEAN

    sResponse = Space(nMessageSize)
    SockAddressSize = Len(SockAddress)
    nResponseSize = recvfrom(hSocket,ByVal StrPtr(sResponse),nMessageSize,0,ByVal Cast(SOCKADDR ptr,VarPtr(SockAddress)),ByVal VarPtr(SockAddressSize))
    This.lCurrentStatus = WSAGetLastError
    Select Case nResponseSize
        Case SOCKET_ERROR
            lReturn = False
        Case Is > 0
            sResponse = Left(sResponse,nResponseSize)
            lReturn = True
        Case Else
            sResponse = ""
            lReturn = True
    End Select
    Function = lReturn
End Function
' =====================================================================================
' Send a message and retrieve the response
' =====================================================================================
Private Function cSQLiteSession.SendAndReceiveSocket (ByVal hSocket as SOCKET, ByVal iBufferSize as Long, ByRef sMessage as String, ByRef sResponse as String) as BOOLEAN
Dim lReturn       as BOOLEAN 
    lReturn = SendSocket (hSocket,sMessage)
    If lReturn = True Then
        lReturn = ReceiveSocket (hSocket,iBufferSize,sResponse)
    End If
    Function = lReturn
End Function
' =====================================================================================
' Send a message to a socket
' =====================================================================================
Private Function cSQLiteSession.SendSocket (ByVal hSocket as SOCKET, ByRef sData as String) as BOOLEAN
Dim nDataSent         as Long
Dim nDataRemaining    as Long
Dim pData             as ZString Ptr
Dim lReturn           as BOOLEAN

    nDataRemaining = Len(sData)
    This.lCurrentStatus = S_OK
    lReturn = True
    If nDataRemaining = 0 Then
       Function = True
       Exit Function
    End If
    pData = Cast(ZString ptr,StrPtr(sData))
    Do
        nDataSent = send (hSocket,ByVal pData,nDataRemaining,0)
        This.lCurrentStatus = WSAGetLastError()
        Select Case nDataSent
            Case SOCKET_ERROR
                lReturn = False
                Exit Do
            Case Else
                pData = pData + nDataSent
                nDataRemaining = nDataRemaining - nDataSent
                If nDataRemaining < 1 Then
                   This.lCurrentStatus = S_OK
                   Exit Do
                End If
        End Select
    Loop
    Function = lReturn
End Function
' =====================================================================================
' Receive a message from a socket
' =====================================================================================
Private Function cSQLiteSession.ReceiveSocket(ByVal hSocket as Long, ByVal iBufferSize as Long, ByRef sReceived as String) as BOOLEAN
Dim lpBuffers         as WSABUF
Dim sBuffer           as String
Dim nFlags            as Long
Dim nBytesReceived    as Long
Dim iReturn           as Long

    sReceived = ""
    nFlags = 0
    Do
        sBuffer = Space(iBufferSize)
        lpBuffers.Len = iBufferSize
        lpBuffers.buf = StrPtr(sBuffer)
        nBytesReceived = 0
        iReturn = WSARecv (hSocket,ByVal VarPtr(lpBuffers),1,ByVal VarPtr(nBytesReceived),ByVal VarPtr(nFlags),ByVal(0),ByVal(0))
        This.lCurrentStatus = WSAGetLastError
        If iReturn = SOCKET_ERROR Then
           Function = False
           Exit Function
        End If
        Select Case nBytesReceived
            Case Is > 0
                sReceived = sReceived + Left(sBuffer,nBytesReceived)
                If SocketReceiveReady(hSocket) = False Then
                   Exit Do
                End If
            Case Else
                Exit Do
        End Select
    Loop
    Function = True
End Function
' =====================================================================================
' Check if any socket message is available to receive
' =====================================================================================
Private Function cSQLiteSession.SocketReceiveReady (ByVal hSocket as SOCKET) as BOOLEAN
Dim FDSet         as FD_SET
Dim FDTime        as timeval
Dim lReturn       as BOOLEAN
Dim hSocketsReady as Long

    lReturn = False
    FDSet.fd_count = 1
    FDSet.fd_array(0) = hSocket
    FDTime.tv_sec = Int(iTimeOut / 1000)
    FDTime.tv_usec = This.iWaitTimeout - FDTime.tv_sec * 1000
    hSocketsReady = select_(0,ByVal VarPtr(FDSet),ByVal(0),ByVal(0),ByVal VarPtr(FDTime))
    This.lCurrentStatus = WSAGetLastError()
' If return value = number of sockets, socket is ready
    Select Case hSocketsReady
        Case 1
            lReturn = True
        Case SOCKET_ERROR
        Case Else
            This.lCurrentStatus = WSAETIMEDOUT
    End Select
    Function = lReturn
End Function
' =====================================================================================
' Open a Listener Socket
' =====================================================================================
Private Function cSQLiteSession.OpenListenerSocket (ByRef hSocket as SOCKET, ByVal HWnd as HWnd, ByVal nMessageID as uLong, ByVal nEvents as Long, ByVal lDefaultIP as BOOLEAN, ByVal nType as Long, ByVal wPort as WORD, ByRef sIPAddress as String) as BOOLEAN
' if lDefaultIP = TRUE, preferred IP returned in sIPAddress
Dim SockAddress           as SOCKADDR_IN
Dim sLocalHostName        as String
Dim nIPProto              as Long
Dim lReturn               as BOOLEAN

    lReturn = True
    nIPProto = IIf(nType = SOCK_STREAM,IPPROTO_TCP,IPPROTO_UDP)
' Get preferred IP address if requested
    If lDefaultIP = True Then
       lReturn = PreferredAddress(sLocalHostName,SockAddress)
       If lReturn = True Then
          IPToString(SockAddress.sin_addr.s_addr,sIPAddress)
       End If
    Else
       SockAddress.sin_addr.s_addr = StringToIP(sIPAddress)
    End If
    If lReturn = False Then
       Function = False
       Exit Function
    End If
' Open Socket
    If GetSocket(AF_INET,nType,nIPProto,hSocket) = False Then
       Function = False
       Exit Function
    End If
    SockAddress.sin_family = AF_INET
    SockAddress.sin_port = htons(wPort)
' Open, Bind, Listen Socket
    If GetSocket(AF_INET,nType,nIPProto,hSocket) = True Then
       If BindSocket(hSocket,SockAddress) = True Then
          lReturn = AsyncSelectSocket(hSocket,HWnd,nMessageID,nEvents)
          If lReturn = True Then
             If nIPProto = IPPROTO_TCP Then
                lReturn = ListenSocket(hSocket)
             End If
          End If
       End If
    End If
    If lReturn = False Then
       Disconnect(hSocket)
    End If
    Function = lReturn
End Function
' =====================================================================================
' Bind Socket
' =====================================================================================
Private Function cSQLiteSession.BindSocket (ByVal hSocket as SOCKET, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
Dim iReturn           as Long
    iReturn = bind(hSocket,ByVal Cast(SOCKADDR ptr,VarPtr(SockAddress)),Len(SockAddress))
    This.lCurrentStatus = WSAGetLastError
    Function = IIf(iReturn = SOCKET_ERROR,False,True)
End Function
' =====================================================================================
' Listen Socket
' =====================================================================================
Private Function cSQLiteSession.ListenSocket (ByVal hSocket as SOCKET) as BOOLEAN
Dim iReturn           as BOOLEAN
    iReturn = listen(hSocket,SOMAXCONN)
    This.lCurrentStatus = WSAGetLastError
    Function = IIf(iReturn = SOCKET_ERROR,False,True)
End Function
' =====================================================================================
' Request Windows message-based notification of network events for a socket
' =====================================================================================
Private Function cSQLiteSession.AsyncSelectSocket (ByVal hSocket as SOCKET, ByVal HWnd as HWND, ByVal iMessageID as u_int, ByVal iEvents as Long) as BOOLEAN
Dim iReturn        as Long
    iReturn = WSAAsyncSelect (hSocket,HWnd,iMessageID,iEvents)
    This.lCurrentStatus = WSAGetLastError
    Function = IIf(iReturn = SOCKET_ERROR,False,True)
End Function
' =====================================================================================
' Get Preferred IPv4 address for TCP/UDP
' =====================================================================================
Private Function cSQLiteSession.PreferredAddress (ByRef sLocalHostName as String, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
Dim lReturn           as BOOLEAN
Dim iError            as Long
Dim pAddrInfo         as ADDRINFOA Ptr
Dim pFreeAddrInfo     as ADDRINFOA Ptr
Dim hints             as ADDRINFOA
    lReturn = LocalHostName(sLocalHostName)
    If lReturn = True Then
       hints.ai_family = AF_INET
       iError = getaddrinfo(ByVal ZStringPointer(sLocalHostName),ByVal Null,@hints,@pAddrInfo)
       This.lCurrentStatus = WSAGetLastError
       If iError = 0 Then
          This.lCurrentStatus = WSAEAFNOSUPPORT
          lReturn = False
          pFreeAddrInfo = pAddrInfo
          Do While pAddrInfo <> Null
             Select Case pAddrInfo->ai_protocol
                Case 0,IPPROTO_UDP,IPPROTO_TCP
                   SockAddress = *Cast(SOCKADDR_IN Ptr, pAddrInfo->ai_addr)
                   This.lCurrentStatus = S_OK
                   lReturn = True
                   pAddrInfo = Null
                Case Else
                   pAddrInfo = pAddrInfo->ai_next
             End Select
          Loop
          freeaddrinfo(ByVal pFreeAddrInfo)
       Else
          lReturn = False
       End If
    End If
    Function = lReturn
End Function
' =====================================================================================
' Given an IP string, lookup the host name
' =====================================================================================
Private Function cSQLiteSession.HostNameFromIP (ByRef sIPAddress as String, ByRef sHostName as String) as BOOLEAN
Dim lReturn           as BOOLEAN
Dim lpHost            as HOSTENT Ptr
Dim nIPAddress        as IN_ADDR

    lReturn = False
    sHostName = ""
    nIPAddress.s_addr = StringToIP (sIPAddress)
    If nIPAddress.s_addr = INADDR_NONE Then
        This.lCurrentStatus = WSAHOST_NOT_FOUND
        Function = False
        Exit Function
    End If
    lReturn = HostByAddress (sIPAddress,lpHost)
    If lReturn = True Then
       sHostName = *Cast(ZString Ptr, lpHost->h_name)
    End If
    Function = lReturn
End Function
' =====================================================================================
' Given a host name, return to IP Address
' =====================================================================================
Private Function cSQLiteSession.IPFromHostName (ByRef sHostName as String, ByRef sIPAddress as String) as BOOLEAN
Dim lReturn           as BOOLEAN
Dim lpHost            as HOSTENT Ptr
Dim HOST_ADDR_LIST    as IN_ADDR

    sIPAddress = ""
    lReturn = HostByName (sHostName,lpHost)
    If lReturn = True Then
       HOST_ADDR_LIST = *Cast(IN_ADDR Ptr, lpHost->h_addr_list[0])
       If HOST_ADDR_LIST.s_addr = INADDR_NONE Then
          This.lCurrentStatus = WSAHOST_NOT_FOUND
          lReturn = False
       Else 
          IPToString (HOST_ADDR_LIST.s_addr, sIPAddress)
       End If
    End If
    Function = lReturn
End Function
' =====================================================================================
' DNS lookup of host IP
' =====================================================================================
Private Function cSQLiteSession.HostByAddress (ByRef sIPAddress as String, ByRef lpHostEntry as HOSTENT Ptr) as BOOLEAN
Dim uIN_ADDR    as in_addr

    uIN_ADDR.s_addr = StringToIP (sIPAddress)
    lpHostEntry = gethostbyaddr (ByVal Cast(ZString ptr,VarPtr(uIN_ADDR.s_addr)),Len(uIN_ADDR.s_Addr),AF_INET)
    This.lCurrentStatus = WSAGetLastError()
    Function = IIf(lpHostEntry <> 0,True,False)
End Function
' =====================================================================================
' DNS lookup of host name
' =====================================================================================
Private Function cSQLiteSession.HostByName (ByRef sHostName as String, ByRef lpHostEntry as HOSTENT Ptr) as BOOLEAN
    lpHostEntry = gethostbyname (ByVal ZStringPointer(sHostName))
    This.lCurrentStatus = WSAGetLastError()
    Function = IIf(lpHostEntry <> 0,True,False)
End Function
' =====================================================================================
' Connect Socket
' =====================================================================================
Private Function cSQLiteSession.ConnectSocket (ByVal hSocket as SOCKET, ByRef SockAddress as SOCKADDR_IN) as BOOLEAN
Dim lReturn   as BOOLEAN

    lReturn = WSAConnect (hSocket, Cast(SOCKADDR ptr,VarPtr(SockAddress)), SizeOf(SockAddress), ByVal(0), ByVal(0), ByVal(0), ByVal(0))
    This.lCurrentStatus = WSAGetLastError()
    Function = IIf(lReturn <> SOCKET_ERROR,True,False)
End Function
' =====================================================================================
' Shutdown socket
' =====================================================================================
Private Function cSQLiteSession.SocketShutdown (ByVal hSocket as SOCKET) as BOOLEAN
Dim iReturn   as Long

     iReturn =  shutdown(hSocket,SD_BOTH)
     Function = IIf(iReturn = 0,True,False)
End Function
' =====================================================================================
' Close Socket
' =====================================================================================
Private Sub cSQLiteSession.SocketClose (ByVal hSocket as SOCKET)
    If hSocket <> INVALID_SOCKET Then    
          closesocket(hSocket)
    End If
End Sub
' =====================================================================================
' Set Socket Timeout
' =====================================================================================
Private Function cSQLiteSession.TimeoutSocket (ByVal hSocket as SOCKET) as BOOLEAN
Dim lReturn     as Long

    lReturn = True
    If iTimeOut > 0 Then
       lReturn = setsockopt(hSocket,SOL_SOCKET,SO_SNDTIMEO,ByVal Cast(zstring ptr,VarPtr(This.iTimeOut)),Len(This.iTimeOut))
       This.lCurrentStatus = WSAGetLastError
       lReturn = IIf(lReturn = SOCKET_ERROR,False,True)
       If lReturn = True Then
          lReturn = setsockopt(hSocket,SOL_SOCKET,SO_RCVTIMEO,ByVal Cast(zstring ptr,VarPtr(This.iTimeOut)),Len(This.iTimeOut))
          This.lCurrentStatus = WSAGetLastError
          lReturn = IIf(lReturn = SOCKET_ERROR,False,True)
       End If
    End If
    Function = lReturn
End Function
' =====================================================================================
' Initialize a socket
' =====================================================================================
Private Function cSQLiteSession.GetSocket (ByVal nFamily as Long, ByVal nType as Long, ByVal nProtocol as Long, ByRef hSocket as SOCKET) as BOOLEAN
    hSocket = WSASocket(nFamily,nType,nProtocol,ByVal(0),ByVal(0),ByVal(0))
    This.lCurrentStatus = WSAGetLastError()
    Function = IIf(hSocket <> INVALID_SOCKET,True,False)
End Function
' =====================================================================================
' Convert dot notated IP address string
' =====================================================================================
Private Function cSQLiteSession.StringToIP (ByRef sIPAddress as String) as ulong
    Function = inet_addr (ByVal ZStringPointer(sIPAddress))
End Function
' =====================================================================================
' Take an IP address and convert to string dot notation
' =====================================================================================
Private Sub cSQLiteSession.IPToString (ByVal nIPAddress as ulong, ByRef sIPAddress as String)
Dim lpszIPAddress as ZString Ptr
Dim uIN_ADDR      as in_addr

    uIN_ADDR.s_addr = nIPAddress
    lpszIPAddress = inet_ntoa (uIN_ADDR)
    sIPAddress = *lpszIPAddress
End Sub
' =====================================================================================
' Get Computer Name
' =====================================================================================
Private Function cSQLiteSession.LocalHostName (ByRef sLocalHostName as String) as BOOLEAN
Dim szLocalHostName   as ZString * MAX_COMPUTERNAME_LENGTH + 1
Dim lReturn           as BOOLEAN
Dim iReturn           as Long
Dim nSize             as Long

    sLocalHostName = ""
    This.lCurrentStatus = 0
    nSize = MAX_COMPUTERNAME_LENGTH + 1
    iReturn = GetComputerName(ByVal StrPtr(szLocalHostName),ByVal VarPtr(nSize))
    If iReturn <> 0 Then
       sLocalHostName = szLocalHostName
       lReturn = True
    Else
       This.lCurrentStatus = GetLastError()
       lReturn = False
    End If
    Function = lReturn
End Function
' =====================================================================================
' Get ZString Pointer from a STRING type
' =====================================================================================
Function cSQLiteSession.ZStringPointer (ByRef sAny as String) as ZString Ptr
    If StrPtr(sAny) = 0 Then
       Function = @""
    Else
       Function = StrPtr(sAny)
    End If
End Function
' =====================================================================================
' Get Windows error description
' =====================================================================================
Private Function cSQLiteSession.WindowsErrorDescription (ByVal iErrorCode as NTSTATUS) as String
Dim sErrorDescription   as String * 255
dim hNT                 as LPCVOID
    hNT = DyLibLoad("NTDLL.dll")
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM + FORMAT_MESSAGE_FROM_HMODULE, hNT, iErrorCode, 0, sErrorDescription, SizeOf(sErrorDescription), ByVal 0)
    DyLibFree (Cast(Any Ptr,hNT))
    Function = sErrorDescription
End Function
'END NAMESPACE