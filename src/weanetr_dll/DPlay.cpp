//
// Created by DiaLight on 09.01.2025.
//

#include "DPlay.h"

#include <patches/logging.h>
#include <tools/last_error.h>

#include "logging.h"
#include "messages.h"

using namespace net;

#define print_notDecompiled(prefix) printf(prefix "function %s is not decompiled\n", __FUNCTION__)
#define assert_notDecompiled() do { print_notDecompiled("[FATAL] "); exit(1); } while(false)

void __stdcall log_HRESULT(HRESULT hresult) {
    _log("ERROR %x AUT %x\n", hresult, 0x887707D0);
    switch ( hresult ) {
    case 0x887707DA:
        _log(
          "\t\tNo credentials were supplied and the software security packa"
          "ge (SSPI) that will prompt for credentials cannot be loaded. \n");
        break;
    case 0x887707E4:
        _log(
          "\t\tThe requested information could not be digitally encrypted. "
          "Encryption is used for message privacy. This error is only relev"
          "ant in a secure session. \n");
        break;
    case 0x887707EE:
        _log(
          "\t\tThe requested information could not be digitally signed. Dig"
          "ital signatures are used to establish the authenticity of messages. \n");
        break;
    case 0x887707F8:
        _log("\t\tThe software security package cannot be loaded. \n");
        break;
    case 0x88770802:
        _log("\t\tThe Encryption is not supported\n");
        break;
    case 0x8877080C:
        _log(
          "\t\tNo credentials were supplied and the CryptoAPI package (CAPI"
          ") to use for cryptography services cannot be loaded. \n");
        break;
    case 0x88770816:
        _log(
          "\t\tAn action cannot be performed because a player or client app"
          "lication is not logged in. Returned by the IDirectPlay3::Send me"
          "thod when the client application tries to send a secure message "
          "without being logged in. \n");
        break;
    case 0x88770820:
        _log(
          "\t\tThe session could not be opened because credentials are requ"
          "ired and either no credentials were supplied or the credentials "
          "were invalid. \n");
        break;
    case 0x887707D0:
        _log("\t\tThe password or credentials supplied could not be authenticated. \n");
        break;
    case 0x8877044C:
        _log("\t\tNot Registered\n");
        break;
    case 0x88770442:
        _log("\t\tALready Registered\n");
        break;
    case 0x88770438:
        _log("\t\tService Provider Loaded\n");
        break;
    case 0x8877042E:
        _log(
          "\t\tReturned by the IDirectPlayLobby2::Connect method if the application"
          " was not started by using the IDirectPlayLobby2::RunApplication method o"
          "r if there is no DPLCONNECTION structure currently initialized for this "
          "DirectPlayLobby object. \n");
        break;
    case 0x8877041A:
        _log("\t\tAn unknown application was specified. \n");
        break;
    case 0x88770406:
        _log("\t\tThe interface parameter is invalid. \n");
        break;
    case 0x887703FC:
        _log("\t\tThe application has not been started yet. \n");
        break;
    case 0x887703F2:
        _log("\t\tCannot start the application. \n");
        break;
    case 0x887703E8:
        _log("\t\tThe data buffer is too large to store. \n");
        break;
    case 0x8877015E:
        _log(
          "\t\tThe method is in the process of connecting to the network. The application"
          " should keep calling the method until it returns DP_OK, indicating successful "
          "completion, or it returns a different error. \n");
        break;
    case 0x88770154:
        _log(
          "\t\tAn invalid password was supplied when attempting to join a session that re"
          "quires a password. \n");
        break;
    case 0x8877014A:
        _log("\t\tThe session is not accepting any new players. \n");
        break;
    case 0x88770140:
        _log("\t\tThe requested object has not been initialized. \n");
        break;
    case 0x88770136:
        _log("\t\tThe connection to the session has been lost. \n");
        break;
    case 0x8877012C:
        _log("\t\tA player has lost the connection to the session. \n");
        break;
    case 0x88770122:
        _log("\t\tA Server cannot be created\n");
        break;
    case 0x88770118:
        _log("\t\tUser Cancel\n");
        break;
    case 0x8877010E:
        _log("\t\tA message cannot be sent because the transmission medium is busy. \n");
        break;
    case 0x887700FA:
        _log("\t\tThe requested function is not available at this time. \n");
        break;
    case 0x887700F0:
        _log("\t\tThe operation could not be completed in the specified time. \n");
        break;
    case 0x887700E6:
        _log("\t\tThe message being sent by the IDirectPlay3::Send method is too large. \n");
        break;
    case 0x887700DC:
        _log("\t\tThere are no existing sessions for this game. \n");
        break;
    case 0x887700D2:
        _log("\t\tThere are no active players in the session. \n");
        break;
    case 0x887700C8:
        _log("\t\tNo name server (host) could be found or created. A host must exist to create a player. \n");
        break;
    case 0x887700BE:
        _log("\t\tThere are no messages in the receive queue. \n");
        break;
    case 0x887700AA:
        _log("\t\tNo communication link was established. \n");
        break;
    case 0x887700A0:
        _log("\t\tThe communication link that DirectPlay is attempting to use is not capable of this function. \n");
        break;
    case 0x8877009B:
        _log("\t\tThe group ID is not recognized as a valid group ID for this game session. \n");
        break;
    case 0x88770096:
        _log("\t\tThe player ID is not recognized as a valid player ID for this game session. \n");
        break;
    case 0x88770082:
        _log("\t\tThe DirectPlay object pointer is invalid. \n");
        break;
    case 0x88770078:
        _log("\t\tThe flags passed to this method are invalid. \n");
        break;
    case 0x8877005A:
        _log("\t\tAn exception occurred when processing the request. \n");
        break;
    case 0x88770050:
        _log(
          "\t\tThe capabilities of the DirectPlay object have not been determined yet. This error will occur if"
          " the DirectPlay object is implemented on a connectivity solution that requires polling to determine "
          "available bandwidth and latency. \n");
        break;
    case 0x88770046:
        _log("\t\tA new session cannot be created. \n");
        break;
    case 0x8877003C:
        _log("\t\tA new player cannot be created. \n");
        break;
    case 0x88770032:
        _log("\t\tA new group cannot be created. \n");
        break;
    case 0x88770028:
        _log("\t\tThe player cannot be added to the session. \n");
        break;
    case DPERR_BUFFERTOOSMALL:
        _log("\t\tThe supplied buffer is not large enough to contain the requested data. \n");
        break;
    case 0x88770014:
        _log("\t\tThe requested operation cannot be performed because there are existing active players. \n");
        break;
    case 0x8877000A:
        _log("\t\tThe session is full or an incorrect password was supplied. \n");
        break;
    case 0x88770005:
        _log("\t\tThis object is already initialized. \n");
        break;
    case E_INVALIDARG:
        _log("\t\tOne or more of the parameters passed to the method are invalid. \n");
        break;
    case E_OUTOFMEMORY:
        _log("\t\tThere is insufficient memory to perform the requested operation. \n");
        break;
    case E_FAIL:
        _log("\t\tAn undefined error condition occurred. \n");
        break;
    case E_NOINTERFACE:
        _log("\t\tThe interface is not supported. \n");
        break;
    case E_NOTIMPL:
        _log(
          "\t\tThe function is not available in this implementation. Returned from IDirectPlay3::GetGroupConnectionSettings a"
          "nd IDirectPlay3::SetGroupConnectionSettings if they are called from a session that is not a lobby session. \n");
        break;
    case E_PENDING:
        _log("\t\tPending Operation\n");
        break;
    default: {  // patch
        std::string errStr = FormatLastError(hresult);
        _log("[err] %X %s\n", hresult, errStr.c_str());
    } return;
    }
}


int DPlay::createIDirectPlayLobby3(IDirectPlayLobby3 **a2_out) {
    IDirectPlayLobby3 *ppv;
    if (CoCreateInstance(
        CLSID_DirectPlayLobby, NULL, 1u,
        IID_IDirectPlayLobby3, (LPVOID *)&ppv
    )) return 0;
    *a2_out = ppv;
    return 1;
}

int DPlay::createIDirectPlay4(IDirectPlay4 **a1_out) {
    IDirectPlay4 *ppv = NULL;
    if (CoCreateInstance(
        CLSID_DirectPlay, NULL, 1u,
        IID_IDirectPlay4, (LPVOID *) &ppv
    )) return 0;
    *a1_out = ppv;
    return 1;
}

int DPlay::releaseIDirectPlay4(IDirectPlay4 *obj) {
    if (!obj) return 0x80004005;
    return obj->Release();
}

int DPlay::Startup(MessageHandlerType handler) {
    this->f565_hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if ( this->f5C1_ptr_eos ) {
        free(this->f5C1_ptr_eos);
        this->f5C1_ptr_eos = NULL;
    }
    if ( !this->f565_hEvent )
        return 0;

    int result = 0;
    if ( this->createIDirectPlayLobby3(&this->f56d_pIDirectPlayLobby3) ) {
        if ( createIDirectPlay4(&this->f569_pIDirectPlay4) ) {
            result = 1;
            memset(&this->f571_desc, 0, sizeof(this->f571_desc));
            this->f20_isServiceProviderInitialized = 1;
            NetworkServiceProvider::Startup(handler);
        } else {
            this->f56d_pIDirectPlayLobby3->Release();
            this->f56d_pIDirectPlayLobby3 = NULL;
        }
    }
    if ( result || !this->f565_hEvent )
        return result;
    CloseHandle(this->f565_hEvent);
    this->f565_hEvent = NULL;
    return result;
}

int DPlay::ShutDown() {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::ShutDown Error Shutdowning DPlay system when not Initialised\n");
        return 0;
    }
    int result = 0;
    NetworkServiceProvider::Destroy();
    if (this->f565_hEvent) {
        CloseHandle(this->f565_hEvent);
        this->f565_hEvent = NULL;
    }
    releaseIDirectPlay4(this->f569_pIDirectPlay4);
    this->f56d_pIDirectPlayLobby3->Release();
    this->f56d_pIDirectPlayLobby3 = NULL;
    this->f569_pIDirectPlay4 = NULL;
    this->f20_isServiceProviderInitialized = 0;
    memset(&this->f571_desc, 0, sizeof(this->f571_desc));
    NetworkServiceProvider::ShutDown();
    result = 1;
    if (this->f5C1_ptr_eos) {
        free(this->f5C1_ptr_eos);
        this->f5C1_ptr_eos = NULL;
        return 1;
    }
    return result;
}

int DPlay::SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::SetupConnection Error:- ServiceProvider Not Initialised\n");
        return 0;
    }
    _log("\tDPlay::SetupConnection\n");
    if (this->f569_pIDirectPlay4->InitializeConnection(a2_dplayAddr, 0)) return 0;
    memset(&this->f571_desc, 0, sizeof(this->f571_desc));
    this->f4_arg = a4_arg;
    this->f44_guidApplication = *a3_guid;
    return 1;
}

#pragma pack(push, 1)
struct EnumAddressTypesCtx {
    char f0_readGuids;
    DWORD f1_count;
    GUID *f5_pGuids;
};
#pragma pack(pop)
BOOL FAR PASCAL IDirectPlayLobby2_EnumAddressTypes_callback(
    REFGUID         guidDataType,
    LPVOID          lpContext,
    DWORD           dwFlags
) {
    auto *ctx = (EnumAddressTypesCtx *) lpContext;
    bool found = false;
    if (guidDataType == DPAID_PhoneW || guidDataType == DPAID_Phone) {
        found = true;
    } else if (guidDataType == DPAID_INet || guidDataType == DPAID_INetW) {
        found = true;
    } else if (guidDataType == DPAID_ComPort) {
        found = true;
    } else if (guidDataType == DPAID_Modem) {
        found = true;
    } else if (guidDataType == DPAID_ModemW) {
        found = true;
    }
    if (found) {
        if (!ctx->f0_readGuids) {
            ++ctx->f1_count;
        } else {
            *ctx->f5_pGuids++ = guidDataType;
        }
    }
    return 1;
}

struct EnumConnectionsCtx {
    DPlay *f0_pDPlay;
    IDirectPlay3 *f4_IDirectPlay3;
    IDirectPlayLobby2 *f8_pIDirectPlayLobby2;
    NetworkServiceProvider::ServiceEnumCallback fC_callback;
    void *f10_context;
};

const GUID GUID_BFUnk1 {0xD8D29744, 0x208A, 0x11D0, {0xBC, 0x9D, 0x00, 0xA0, 0x24, 0x29, 0x67, 0xB6}};
const GUID GUID_BFUnk2 {0xD1714F40, 0x5989, 0x11D0, {0x9A, 0x84, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
const GUID GUID_BFUnk3 {0x25462BA0, 0xCE8D, 0x11CF, {0x83, 0x9B, 0x00, 0xAA, 0x00, 0xB9, 0x30, 0x48}};

BOOL FAR PASCAL IDirectPlay3_EnumConnections_callback(
    LPCGUID     lpguidSP,
    LPVOID		lpConnection,
    DWORD		dwConnectionSize,
    LPCDPNAME   lpName,
    DWORD 		dwFlags,
    LPVOID 		lpContext
) {
    auto *ctx = (EnumConnectionsCtx *) lpContext;

    if (*lpguidSP == GUID_BFUnk1) return 1;
    if (*lpguidSP == GUID_BFUnk3) return 1;
    if (*lpguidSP == DPSPGUID_TCPIP) return 1;
    if (*lpguidSP == DPSPGUID_MODEM) return 1;
    if (*lpguidSP != DPSPGUID_IPX) return 1;
    EnumAddressTypesCtx lpContext2;
    lpContext2.f0_readGuids = 0;
    lpContext2.f1_count = 0;
    IDirectPlayLobby2 *f8_pIDirectPlayLobby2 = ctx->f8_pIDirectPlayLobby2;
    void *f10_context = ctx->f10_context;
    f8_pIDirectPlayLobby2->EnumAddressTypes(IDirectPlayLobby2_EnumAddressTypes_callback, *lpguidSP, &lpContext2, 0);
    size_t nameLen = wcslen(lpName->lpszShortName);
    MyLocalService *v8_localService = (MyLocalService *)malloc(
        sizeof(MyLocalService)
        + sizeof(WCHAR) * (nameLen + 1)  // name
        + dwConnectionSize  // addr
        + 16 * lpContext2.f1_count  // guilds
    );
    if (!v8_localService) return 1;
    memset(v8_localService, 0, sizeof(MyLocalService));
    v8_localService->f0_guid = *lpguidSP;
    v8_localService->f10_count = lpContext2.f1_count;
    v8_localService->f14_addr_size = dwConnectionSize;
    v8_localService->f18_pName = v8_localService->f28_name;
    v8_localService->f1C_next = NULL;
    wcscpy(v8_localService->f28_name, lpName->lpszShortName);

    MyLocalServiceAddr *pAddr = (MyLocalServiceAddr *)&v8_localService->f28_name[wcslen(v8_localService->f28_name) + 1];
    v8_localService->f20_addr = pAddr;
    memcpy(pAddr, lpConnection, dwConnectionSize);

    GUID *pGuids = (GUID *)&pAddr->f0_signature[dwConnectionSize];
    v8_localService->f24_pGuid = pGuids;
    lpContext2.f0_readGuids = 1;
    lpContext2.f5_pGuids = pGuids;

    f8_pIDirectPlayLobby2->EnumAddressTypes(IDirectPlayLobby2_EnumAddressTypes_callback, *lpguidSP, &lpContext2, 0);
    if (ctx->fC_callback) ctx->fC_callback(
        v8_localService,
        v8_localService->f18_pName,
        v8_localService->f24_pGuid,
        v8_localService->f10_count,
        f10_context
    );

    free(v8_localService);
    return 1;
}

int DPlay::EnumerateLocalServices(ServiceEnumCallback a2_fun, void *a3_arg) {
    IDirectPlay3 *dplay3;
    if (CoCreateInstance(CLSID_DirectPlay, NULL, 1u, IID_IDirectPlay3, (LPVOID *)&dplay3) ) return 0;
    IDirectPlayLobby *dlobby;
    HRESULT hresult;
    {  // dynamic link
        auto dplayx = LoadLibraryA("dplayx.dll");
        typedef HRESULT(WINAPI * DirectPlayLobbyCreateA_t)(LPGUID, LPDIRECTPLAYLOBBYA*, IUnknown*, LPVOID, DWORD);
        auto DirectPlayLobbyCreateA = (DirectPlayLobbyCreateA_t) GetProcAddress(dplayx, "DirectPlayLobbyCreateA");
        hresult = DirectPlayLobbyCreateA(NULL, &dlobby, NULL, NULL, 0);
        FreeLibrary(dplayx);
    }
    if (hresult) {
        _log("\t\tDPlay::EnumerateLocalServices failed:-Couldn't Create IDirectPlayLobby Interface\n");
        dplay3->Release();
        return 0;
    }
    IDirectPlayLobby2 *dlobby2;
    hresult = dlobby->QueryInterface(IID_IDirectPlayLobby2, (LPVOID *) &dlobby2);
    dlobby->Release();
    if (hresult != S_OK) {
        _log("\t\tDPlay::EnumerateLocalServices failed:-Couldn't Create IDirectPlayLobby2 Interface\n");
        dplay3->Release();
        return 0;
    }
    EnumConnectionsCtx lpContext;
    lpContext.f8_pIDirectPlayLobby2 = dlobby2;
    lpContext.f10_context = a3_arg;
    lpContext.f0_pDPlay = this;
    lpContext.f4_IDirectPlay3 = dplay3;
    lpContext.fC_callback = a2_fun;
    bool isServiceProviderInitialized = this->f20_isServiceProviderInitialized;
    if (!isServiceProviderInitialized) {
        hresult = dplay3->EnumConnections(NULL, IDirectPlay3_EnumConnections_callback, &lpContext, 1);
    }
    if (!isServiceProviderInitialized) dplay3->Release();
    dlobby2->Release();
    DPSPGUID_TCPIP;
    return hresult ? 0 : 1;
}

int DPlay::BuildSession(MessageHandlerType handler, GUID *guid, char *a4_outNGLD, DWORD *a5_outPlayers,
                        wchar_t *a6_outGameName, wchar_t *a7_outPlayerName, int a8_totalMaxPlayers, int a9_ignore) {
    int result = 32;
    HANDLE EventA = CreateEventA(NULL, FALSE, FALSE, NULL);
    this->f162_DestroySPSession_hEvent = EventA;
    if (EventA) {
        if (this->createIDirectPlayLobby3(&this->f56d_pIDirectPlayLobby3)) {
            DWORD Size = 0;
            static_assert(DPERR_BUFFERTOOSMALL == 0x8877001E);
            if (this->f56d_pIDirectPlayLobby3->GetConnectionSettings(0, NULL, &Size) == DPERR_BUFFERTOOSMALL) {
                auto *v13_connection = (DPLCONNECTION *) malloc(Size);
                if (v13_connection) {
                    if ( !this->f56d_pIDirectPlayLobby3->GetConnectionSettings(0, v13_connection, &Size) ) {
                        // #define DPSESSION_MIGRATEHOST 0x00000004
                        v13_connection->lpSessionDesc->dwFlags = 4;
                        v13_connection->lpSessionDesc->dwMaxPlayers = a8_totalMaxPlayers;
                        if (!this->f56d_pIDirectPlayLobby3->SetConnectionSettings(0, 0, v13_connection)) {
                            if ((v13_connection->dwFlags & DPLCONNECTION_CREATESESSION) == 0) {
                                Sleep(3000u);
                            }
                            if (!this->f56d_pIDirectPlayLobby3->ConnectEx(0, IID_IDirectPlay4, (LPVOID *) &this->f569_pIDirectPlay4, 0)) {
                                memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
                                this->f186_sessionDesc.flags = 4;
                                this->f186_sessionDesc.guidApplication = this->f44_guidApplication;
                                int dwMaxPlayers = v13_connection->lpSessionDesc->dwMaxPlayers;
                                this->f186_sessionDesc.currentPlayers = 1;
                                this->f186_sessionDesc.totalMaxPlayers = dwMaxPlayers;
                                if ( v13_connection->lpSessionDesc->lpszSessionName )
                                    wcscpy(this->f186_sessionDesc.gameName, v13_connection->lpSessionDesc->lpszSessionName);
                                if ( a4_outNGLD )
                                    memset(a4_outNGLD, 0, 0xD0u);
                                if ( (v13_connection->dwFlags & DPLCONNECTION_CREATESESSION) != 0 ) {
                                    if ( !this->f569_pIDirectPlay4->CreatePlayer((DPID *) &this->f226_curPlayer.playerId, v13_connection->lpPlayerName, this->f565_hEvent, 0, 0, 0) ) {
                                        this->f226_curPlayer.flags |= 3u;
                                        this->f226_curPlayer.playersSlot = 0;
                                        this->f24_playerList->f20_playerId_slot = this->f226_curPlayer.playerId;
                                        this->f24_playerList->flags = this->f24_playerList->flags & 0xF0 | 1;// joined
                                        this->f24_playerList->flags = this->f24_playerList->flags & 0xF | 0x10;// host
                                        this->f24_playerList->field_24 = 0;
                                        wcscpy(this->f24_playerList->f0_playername, v13_connection->lpPlayerName->lpszShortName);
                                        result = 0x1000;
                                        Sleep(10000u);
                                    }
                                } else if ( !this->f569_pIDirectPlay4->CreatePlayer((DPID *) &this->f226_curPlayer.playerId, v13_connection->lpPlayerName, this->f565_hEvent, 0, 0, 0)) {
                                    result = 0x2000;
                                    *a5_outPlayers = 0;
                                    this->f186_sessionDesc.currentPlayers = v13_connection->lpSessionDesc->dwCurrentPlayers;
                                    this->f226_curPlayer.flags = (this->f226_curPlayer.flags & ~1u) | 2;
                                    this->f226_curPlayer.playersSlot = 0;
                                    this->f24_playerList->flags &= 0xFu;       // joined | not host
                                    this->f24_playerList->field_24 = 0;
                                }
                            }
                        }
                    }
                    if (result != 32) {
                        if (a7_outPlayerName) {
                            DPNAME *lpPlayerName = v13_connection->lpPlayerName;
                            if ( lpPlayerName->lpszShortName )
                                wcscpy(a7_outPlayerName, lpPlayerName->lpszShortName);
                        }
                        if ( a6_outGameName && v13_connection->lpSessionDesc->lpszSessionName )
                            wcscpy(a6_outGameName, v13_connection->lpSessionDesc->lpszSessionName);
                    }
                    free(v13_connection);
                }
            }
        }
    }
    if (result != 0x20 || !this->f162_DestroySPSession_hEvent)
        return result;
    CloseHandle(this->f162_DestroySPSession_hEvent);
    this->f162_DestroySPSession_hEvent = NULL;
    return result;
}
BOOL FAR PASCAL IDirectPlayLobby3_EnumLocalApplications_callback(
    LPCDPLAPPINFO   lpAppInfo,
    LPVOID          lpContext,
    DWORD           dwFlags) {
    return TRUE;
}
int DPlay::enumLocalApplications(int a2, int a3) {
    int f20_isServiceProviderInitialized; // edi

    f20_isServiceProviderInitialized = this->f20_isServiceProviderInitialized;
    if(!f20_isServiceProviderInitialized)
        f20_isServiceProviderInitialized = this->Startup(NULL) == 0;
    if(this->f20_isServiceProviderInitialized)
        this->f56d_pIDirectPlayLobby3->EnumLocalApplications(IDirectPlayLobby3_EnumLocalApplications_callback, NULL, 0);
    if(!f20_isServiceProviderInitialized)
        this->ShutDown();
    return 0;
}

int DPlay::connectLobby(int a2_flags, WCHAR *a3_sessionName, WCHAR *a4_playerName, GUID *a5_guidApplication,
                        wchar_t *a6_address, int a7, int a8_maxPlayers) {
    int result = 32;
    int f20_isServiceProviderInitialized = this->f20_isServiceProviderInitialized;
    if ( !f20_isServiceProviderInitialized )
        f20_isServiceProviderInitialized = this->Startup(NULL) == 0;
    if ( this->f20_isServiceProviderInitialized ) {
        DPSESSIONDESC2 v36_sessionDesc;
        memset(&v36_sessionDesc, 0, sizeof(v36_sessionDesc));
        v36_sessionDesc.dwMaxPlayers = a8_maxPlayers;
        v36_sessionDesc.dwSize = 0x50;
        v36_sessionDesc.guidApplication = *a5_guidApplication;
        v36_sessionDesc.guidInstance = *a5_guidApplication;
        v36_sessionDesc.lpszSessionName = a3_sessionName;

        DPNAME v32_playerName;
        memset(&v32_playerName, 0, sizeof(v32_playerName));
        v32_playerName.lpszShortName = a4_playerName;
        v32_playerName.dwSize = 0x10;

        GUID elem0Guid = DPSPGUID_TCPIP;

        DPCOMPOUNDADDRESSELEMENT v35_elements[] {
            {DPAID_ServiceProvider, sizeof(GUID), &elem0Guid},
            {DPAID_INetW, sizeof(WCHAR) * (wcslen(a6_address) + 1), a6_address}
        };

        uint8_t compoundAddressBuf[4096];
        DWORD compoundAddressSize = sizeof(compoundAddressBuf);
        this->f56d_pIDirectPlayLobby3->CreateCompoundAddress(
            v35_elements, ARRAYSIZE(v35_elements),
            compoundAddressBuf, &compoundAddressSize
        );

        DPLCONNECTION v35_connection;
        memset(&v35_connection, 0, sizeof(v35_connection));
        v35_connection.lpPlayerName = &v32_playerName;
        v35_connection.guidSP = elem0Guid;
        v35_connection.dwFlags = (a2_flags != 0) + 1;
        v35_connection.lpSessionDesc = &v36_sessionDesc;
        v35_connection.dwSize = 40;
        v35_connection.dwAddressSize = compoundAddressSize;
        v35_connection.lpAddress = compoundAddressBuf;

        DWORD v31_dwAppID;
        if (!this->f56d_pIDirectPlayLobby3->RunApplication(0, &v31_dwAppID, &v35_connection, this->f565_hEvent)) {
            DWORD messageFlags = 0;
            DWORD v27_size = 0x800;
            int *v18_buf = (int *) malloc(0x800u);
            if (v18_buf) {
                int isConnected = 0;
                while (true) {
                    if (WaitForSingleObject(this->f565_hEvent, 60000u) == WAIT_OBJECT_0) {
                        messageFlags = 1;
                        int hresult = this->f56d_pIDirectPlayLobby3->ReceiveLobbyMessage(0, v31_dwAppID, &messageFlags, v18_buf, &v27_size);
                        if (hresult != 0) {
                            log_HRESULT(hresult);
                            continue;
                        }
                        if ((messageFlags & 1) == 0)
                            continue;

                        _log("GOT A LOBBY MESSAGE\n");
                        int v21 = *v18_buf;
                        if (*v18_buf == 4 || v21 == 2) {
                            _log(" NOT CONNECTED\n");
                            break; // root
                        }
                        if (v21 == 3) {
                            _log("CONNECTED\n");
                            isConnected = 1;
                        }
                        continue;
                    }
                    if (!isConnected) break;
                }
                free(v18_buf);
            }
            result = 2;
        }
    }
    if ( !f20_isServiceProviderInitialized )
        this->ShutDown();
    return result;
}

int DPlay::CreateSPSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
                           MySessionCredentials *a5_cred, int a6_flags) {
    int result_ = 32;
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tDPlay::CreateSPSession Error:-Network Service Provider Not Initialised\n");
        return result_;
    }

    if ( !a5_cred ) {
        _log("\tDPlay::CreateSPSession Error:-No Credentials specified\n");
        return result_;
    }

    if ( a5_cred->f0_credentialParameterSize < 0x30u ) {
        _log("\tDPlay::CreateSPSession Error:-Invalid Credentials specified\n");
        return result_;
    }
    unsigned int f10_totalMaxPlayers = a5_cred->f10_totalMaxPlayers;
    if ( !f10_totalMaxPlayers ) {
        _log("\tDPlay::CreateSPSession Error:-Must specify a number of max players allowed to log in\n");
        return 32;
    }
    if ( f10_totalMaxPlayers > 0x10 ) {
        _log("\tMAX PLAYERS > %d\n", 16);
        return 0x80004005;
    }
    int v10_flags = a6_flags;
    this->f571_desc.dwSize = 80;
    if ( (a6_flags & 8) != 0 ) {
        this->f571_desc.dwFlags = 4096;
        if ( (a6_flags & 0x80u) != 0 )
            this->f571_desc.dwFlags = 4352;
    } else if ( (a6_flags & 4) != 0 ) {
        this->f571_desc.dwFlags = 4;
    } else {
        this->f571_desc.dwFlags = 0;
    }
    int dwFlags = this->f571_desc.dwFlags;
    dwFlags |= 0x2000;
    this->f571_desc.dwFlags = dwFlags;
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    this->f571_desc.dwUser1 = a5_cred->f4_dk2Version;
    *(dk2::SessionMapInfo *) &this->f571_desc.dwUser2 = a5_cred->f20_mapInfo;
    this->f571_desc.dwUser4 = a5_cred->f28_fileHashsum;
    this->f571_desc.guidApplication = this->f44_guidApplication;
    this->f571_desc.dwMaxPlayers = a5_cred->f10_totalMaxPlayers;
    this->f571_desc.lpszSessionName = a3_gameName;

    {
        int hresult;
        if ( (a6_flags & 0x88) != 0 ) {
            hresult = 0x80004005;
        } else {
            WCHAR *f1C_password = (WCHAR *) a5_cred->f1C_password;
            if ( f1C_password ) {
                v10_flags |= 0x200;
                this->f571_desc.lpszPassword = f1C_password;
                a6_flags = v10_flags;
            }
            hresult = this->f569_pIDirectPlay4->Open(&this->f571_desc, 0x82);
        }
        if ( hresult ) {
            if ( hresult != 0x8877015E ) {
                log_HRESULT(hresult);
                return 32;
            }
            result_ = 1;
            _log("CONNECTING\n");
            return result_;
        }
    }

    DPNAME v27_playerName;
    v27_playerName.dwFlags = 0;
    v27_playerName.dwSize = 16;
    v27_playerName.lpszShortName = a4_playerName;
    v27_playerName.lpszLongName = NULL;
    IDirectPlay4 *f569_pIDirectPlay4 = this->f569_pIDirectPlay4;
    bool v15 = (v10_flags & 8) == 0;
    PlayerId *p_f4_playerId = &this->f226_curPlayer.playerId;

    {
        int hresult;
        if ( v15 ) {
            hresult = f569_pIDirectPlay4->CreatePlayer(
                        (DPID *) &this->f226_curPlayer.playerId,
                        &v27_playerName, this->f565_hEvent, 0, 0, 0);
        } else {
            hresult = f569_pIDirectPlay4->CreatePlayer(
                        (DPID *) &this->f226_curPlayer.playerId,
                        &v27_playerName, this->f565_hEvent, 0, 0, 256);
        }
        if (hresult) {
            _log("DPlay::CreateSPSession Error:-Couldnot create player dplay code %x\n", hresult);
            log_HRESULT(hresult);
            this->f569_pIDirectPlay4->Close();
            return 32;
        }
    }
    this->f226_curPlayer.playersSlot = 0;
    this->f226_curPlayer.flags |= 1u;
    this->f186_sessionDesc.dk2Version = a5_cred->f4_dk2Version;
    this->f186_sessionDesc.flags = a6_flags;
    this->f186_sessionDesc.guidApplication = this->f44_guidApplication;
    this->f186_sessionDesc.totalMaxPlayers = a5_cred->f10_totalMaxPlayers;
    this->f186_sessionDesc.currentPlayers = 1;
    this->f186_sessionDesc.mapInfo = a5_cred->f20_mapInfo;
    this->f186_sessionDesc.fileHashsum = a5_cred->f28_fileHashsum;
    this->f186_sessionDesc.cred_2C = a5_cred->field_2C;
    wcscpy(this->f186_sessionDesc.gameName, a3_gameName);
    this->f24_playerList->f20_playerId_slot = *p_f4_playerId;
    this->f24_playerList->flags = this->f24_playerList->flags & 0xF0 | 1;
    this->f24_playerList->flags = this->f24_playerList->flags & 0xF | 0x10;
    wcscpy(this->f24_playerList->f0_playername, a4_playerName);
    HANDLE EventA = CreateEventA(NULL, FALSE, FALSE, NULL);
    this->f162_DestroySPSession_hEvent = EventA;
    int result;
    if (EventA) {
        this->f226_curPlayer.flags |= 2u;
        result = 2;
        *a2_outPlayers = 0;
    } else {
        _log("\tDPlay::CreateSPSession Error:-Could not create KillMessage Event\n");
        static_assert(sizeof(DPID) == sizeof(PlayerId));
        this->f569_pIDirectPlay4->DestroyPlayer(*(DPID *) p_f4_playerId);
        IDirectPlay4 *v24 = this->f569_pIDirectPlay4;
        *p_f4_playerId = {.value=0};
        v24->Close();
        return 32;
    }
    return result;
}

int DPlay::JoinSPSession(MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName,
                         MySessionCredentials *a5_cred) {
    MLDPLAY_SESSIONDESC *v5_desc = a2_desc;
    HRESULT hresult = 0x80004005;
    int v30_dk2Version = 0;
    DPSESSIONDESC2 *p_f571_desc = &this->f571_desc;
    p_f571_desc->dwSize = 80;

    this->f571_desc.guidInstance = a2_desc->guidInstance;
    MySessionCredentials *v10_cred = a5_cred;
    bool v11 = a5_cred == 0;
    if ( !v11 && v10_cred->f0_credentialParameterSize >= 0x30u ) {
        int f4_dk2Version = v10_cred->f4_dk2Version;
        this->f571_desc.dwUser1 = f4_dk2Version;
        v30_dk2Version = f4_dk2Version;
    }
    if ( (v5_desc->flags & 8) != 0 ) {
        this->f571_desc.dwFlags = 0x1000;
        if (v5_desc->flags & 0x80 != 0)
            this->f571_desc.dwFlags = 0x1100;
    } else {
        this->f571_desc.dwFlags = 0;
    }
    int dwFlags = this->f571_desc.dwFlags;
    dwFlags |= 0x2000;
    this->f571_desc.dwFlags = dwFlags;

    int v16_isOpened = 0;
    if ((v5_desc->flags & 8) != 0) {
        if (v10_cred) {
            if (v10_cred->f0_credentialParameterSize < 0x30u) {
                _log("\tDPlay::JoinSPSession Error:-Invalid Credential parameter passed\n");
                return 32;
            }
            if ((v5_desc->flags & 0x200) != 0) {
                WCHAR* f1C_password = (WCHAR*) v10_cred->f1C_password;
                if (!f1C_password)
                    return 0x800;
                this->f571_desc.lpszPassword = f1C_password;
            }
        }
        if (v5_desc->flags & 0x80 != 0) {
            hresult = this->f569_pIDirectPlay4->SecureOpen(p_f571_desc, 129, 0, 0);
            v16_isOpened = 1;
        }
    }
    int v17_flags = v5_desc->flags;
    if ( (v17_flags & 0x80u) == 0 && !v16_isOpened ) {
        if ( (v17_flags & 0x200) != 0 && v10_cred && v10_cred->f0_credentialParameterSize >= 0x30u ) {
            WCHAR* v18_password = (WCHAR*) v10_cred->f1C_password;
            if (!v18_password) return 0x800;
            this->f571_desc.lpszPassword = v18_password;
        }
        hresult = this->f569_pIDirectPlay4->Open(p_f571_desc, 129);
    }
    switch ( hresult ) {
    case 0x88770820:
        _log("\tDPlay::JoinSPSession Error:-Credentials must be specified\n");
        return 0x200;
    case 0x8877000A:
        _log("\tDPlay::JoinSPSession Error:-Access Denied\n");
        return 0x400;
    case 0x88770154:
        _log("\tDPlay::JoinSPSession Error:-Invalid Password\n");
        return 0x800;
    }
    if (hresult) {
        static_assert(DPERR_CONNECTING == 0x8877015E);
        if (hresult == DPERR_CONNECTING) {
            return 1;
        }
        log_HRESULT(hresult);
        return 32;
    }
    DWORD a2_size = 0;
    if (this->f569_pIDirectPlay4->GetSessionDesc(NULL, &a2_size) != DPERR_BUFFERTOOSMALL) {
        _log("\tDPlay::JoinSPSession Error:-Couldnot get session description\n");
        this->f569_pIDirectPlay4->Close();
        return 32;
    }
    DPSESSIONDESC2* v20_sessionDesc = (DPSESSIONDESC2 *) malloc(a2_size);
    if (!v20_sessionDesc) {
        _log("\tDPlay::JoinSPSession Error:-Couldnot allocate for session description\n");
        this->f569_pIDirectPlay4->Close();
        return 32;
    }
    int hresult_ = this->f569_pIDirectPlay4->GetSessionDesc(v20_sessionDesc, &a2_size);
    if (hresult_) {
        _log("\tDPlay::JoinSPSession Error:-GetSessionDesc returned error %x\n", hresult_);
        this->f569_pIDirectPlay4->Close();
        free(v20_sessionDesc);
        return 32;
    }
    if (v20_sessionDesc->dwMaxPlayers > v5_desc->totalMaxPlayers) {
        if (this->f24_playerList)
            free(this->f24_playerList);
        MyPlayerDesc* v22 = (MyPlayerDesc *) malloc(sizeof(MyPlayerDesc) * v20_sessionDesc->dwMaxPlayers);
        this->f24_playerList = v22;
        if (!v22) {
            _log("\tDPlay::JoinSPSession Error:-Couldnot re-allocate player list\n");
            this->f569_pIDirectPlay4->Close();
            free(v20_sessionDesc);
            return 32;
        }
        memset(v22, 0, sizeof(MyPlayerDesc) * v20_sessionDesc->dwMaxPlayers);
    }
    this->f186_sessionDesc.totalMaxPlayers = v20_sessionDesc->dwMaxPlayers;
    this->f186_sessionDesc.currentPlayers = v20_sessionDesc->dwCurrentPlayers;
    free(v20_sessionDesc);
    PlayerId* p_f4_playerId = &this->f226_curPlayer.playerId;
    DPNAME v31_playerName;
    v31_playerName.dwFlags = 0;
    v31_playerName.dwSize = 16;
    v31_playerName.lpszShortName = a4_playerName;
    v31_playerName.lpszLongName = 0;
    if (this->f569_pIDirectPlay4->CreatePlayer((DPID*) &this->f226_curPlayer.playerId, &v31_playerName, this->f565_hEvent, 0, 0, 0)) {
        this->f569_pIDirectPlay4->Close();
        return 32;
    }
    this->f226_curPlayer.flags &= ~1u;
    HANDLE EventA = CreateEventA(NULL, FALSE, FALSE, NULL);
    this->f162_DestroySPSession_hEvent = EventA;
    if (!EventA) {
        _log("\tDPlay::JoinSPSession Error:-Could not create KillMessage Event\n");
        this->f569_pIDirectPlay4->DestroyPlayer(*(DPID*) p_f4_playerId);
        *p_f4_playerId = {.value = 0};
        this->f569_pIDirectPlay4->Close();
        return 32;
    }
    this->f186_sessionDesc.dk2Version = v30_dk2Version;
    MLDPLAY_SESSIONDESC* f1E6_desc = v5_desc;
    this->f186_sessionDesc.guidApplication = this->f44_guidApplication;
    this->f186_sessionDesc.totalMaxPlayers = f1E6_desc->totalMaxPlayers;
    this->f186_sessionDesc.currentPlayers = 1;
    this->f186_sessionDesc.flags = f1E6_desc->flags;
    wcscpy(this->f186_sessionDesc.gameName, f1E6_desc->gameName);
    if (this->f569_pIDirectPlay4->GetSessionDesc(NULL, &a2_size) == DPERR_BUFFERTOOSMALL) {
        DPSESSIONDESC2* v27 = (DPSESSIONDESC2*) malloc(a2_size);
        if (v27) {
            if (!this->f569_pIDirectPlay4->GetSessionDesc(v27, &a2_size)) {
                this->f186_sessionDesc.totalMaxPlayers = v27->dwMaxPlayers;
                this->f186_sessionDesc.currentPlayers = v27->dwCurrentPlayers;
            }
            free(v27);
        }
    }
    this->f226_curPlayer.flags |= 2u;
    *a3_outPlayerCount = 0;
    return 2;
}

int DPlay::DestroySPSession() {
    if ( this->f20_isServiceProviderInitialized ) {
        if ( (this->f226_curPlayer.flags & 2) != 0 ) {
            _log("\tDPlay::DestroySPSession\n");
            EnterCriticalSection(&this->dataLock);
            this->f226_curPlayer.flags &= ~2;
            this->f569_pIDirectPlay4->DestroyPlayer(*(DPID *) &this->f226_curPlayer.playerId);
            this->f226_curPlayer.playerId = {.value=0};
            this->f569_pIDirectPlay4->Close();
            LeaveCriticalSection(&this->dataLock);
            SetEvent(this->f162_DestroySPSession_hEvent);
            _log("DES m_kill %x\n", this->f162_DestroySPSession_hEvent);
            CloseHandle(this->f162_DestroySPSession_hEvent);
            this->f162_DestroySPSession_hEvent = NULL;
        }
    } else {
        _log("\tDPlay::DestroySPSession:-Service Provider Not Initialised\n");
    }
    if ( !this->f5C1_ptr_eos )
        return 0;
    free(this->f5C1_ptr_eos);
    this->f5C1_ptr_eos = NULL;
    return 0;
}
BOOL FAR PASCAL IDirectPlay4_EnumSessions_callback(LPCDPSESSIONDESC2 lpThisSD, LPDWORD lpdwTimeOut, DWORD dwFlags, LPVOID lpContext) {
    if (dwFlags == 1) return 0;
    int sdFlags = lpThisSD->dwFlags;

    MLDPLAY_SESSIONDESC v13_desc;
    if ((sdFlags & 0x1000) != 0) {
        v13_desc.flags = 8;
    } else if ((sdFlags & 4) != 0) {
        v13_desc.flags = 4;
    }
    if ((sdFlags & 0x100) != 0) {
        v13_desc.flags |= 0x80;
    }
    if ((sdFlags & 0x400) != 0) {
        v13_desc.flags |= 0x200;
    }
    v13_desc.dk2Version = lpThisSD->dwUser1;
    v13_desc.mapInfo = *(dk2::SessionMapInfo *) &lpThisSD->dwUser2;
    v13_desc.fileHashsum = lpThisSD->dwUser4;
    v13_desc.guidInstance = lpThisSD->guidInstance;
    v13_desc.guidApplication = lpThisSD->guidApplication;
    v13_desc.currentPlayers = lpThisSD->dwCurrentPlayers;
    v13_desc.totalMaxPlayers = lpThisSD->dwMaxPlayers;
    wcscpy(v13_desc.gameName, lpThisSD->lpszSessionName);
    if (!lpContext) return TRUE;
    EnumerateSessionsCallback a3_callback = (EnumerateSessionsCallback) ((void **)lpContext)[0];
    void *a5_arg = ((void **)lpContext)[1];
    if (a3_callback)
        a3_callback(&v13_desc, a5_arg);
    return TRUE;
}
int DPlay::EnumerateSessions(DWORD a2_timeout, EnumerateSessionsCallback a3_callback, int a4_flags, void *a5_arg) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::EnumerateSessions Error:- Not Initialised\n");
        return 32;
    }
    this->f571_desc.dwSize = 80;
    this->f571_desc.guidApplication = this->f44_guidApplication;
    int flags = DPENUMSESSIONS_RETURNSTATUS | DPENUMSESSIONS_PASSWORDREQUIRED | DPENUMSESSIONS_AVAILABLE;
    if ((a4_flags & 2) != 0) {
        flags |= DPENUMSESSIONS_ASYNC;
    } else if ((a4_flags & 4) != 0) {
        flags |= DPENUMSESSIONS_STOPASYNC;
    }
    void *v10_context[] {
        a3_callback,
        a5_arg
    };
    HRESULT hresult = this->f569_pIDirectPlay4->EnumSessions(
        &this->f571_desc,
        a2_timeout,
        IDirectPlay4_EnumSessions_callback,
        v10_context,
        flags);
    if (hresult) {
        if (hresult == 0x8877015E) {
            _log("STILL CONNECTING %x\n", hresult);
            return 1;
        }
        _log("*********%x error\n", hresult);
        log_HRESULT(hresult);
        return 32;
    }
    return 2;
}

int DPlay::getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) {
    int f20__isConnectionSetupComplete = this->f20_isServiceProviderInitialized;
    int result = 32;
    DWORD Size = 0;
    if (!f20__isConnectionSetupComplete || (this->f226_curPlayer.flags & 2) == 0) return result;
    if (!a2_pDesc) {
        *a3_pSize = sizeof(MLDPLAY_SESSIONDESC);
        return 2;
    }
    if (*a3_pSize < sizeof(MLDPLAY_SESSIONDESC) || this->f569_pIDirectPlay4->GetSessionDesc(NULL, &Size) != 0x8877001E) {
        return result;
    }
    DPSESSIONDESC2 *v7_descBuf = (DPSESSIONDESC2 *)malloc(Size);
    if (!v7_descBuf) return result;
    if (!this->f569_pIDirectPlay4->GetSessionDesc(v7_descBuf, &Size)) {
        EnterCriticalSection(&this->dataLock);
        int dwFlags = v7_descBuf->dwFlags;
        if ((dwFlags & 0x1000) != 0) {
            this->f186_sessionDesc.flags = 8;
        } else if ((dwFlags & 4) != 0) {
            this->f186_sessionDesc.flags = 4;
        } if ((v7_descBuf->dwFlags & 0x100) != 0) {
            this->f186_sessionDesc.flags |= 0x80;
        }
        if ((v7_descBuf->dwFlags & 0x400) != 0) {
            this->f186_sessionDesc.flags |= 0x200;
        }
        this->f186_sessionDesc.dk2Version = v7_descBuf->dwUser1;
        this->f186_sessionDesc.mapInfo = *(dk2::SessionMapInfo *) &v7_descBuf->dwUser2;
        this->f186_sessionDesc.fileHashsum = v7_descBuf->dwUser4;
        this->f186_sessionDesc.guidInstance = v7_descBuf->guidInstance;
        this->f186_sessionDesc.guidApplication = v7_descBuf->guidApplication;
        this->f186_sessionDesc.currentPlayers = v7_descBuf->dwCurrentPlayers;
        this->f186_sessionDesc.totalMaxPlayers = v7_descBuf->dwMaxPlayers;
        wcscpy(this->f186_sessionDesc.gameName, v7_descBuf->lpszSessionName);
        *a2_pDesc = this->f186_sessionDesc;
        LeaveCriticalSection(&this->dataLock);
        result = 2;
    }
    free(v7_descBuf);
    return result;
}

int DPlay::setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) {
    int f20__isConnectionSetupComplete = this->f20_isServiceProviderInitialized;
    if (!f20__isConnectionSetupComplete) return 0;

    DWORD Size = 0;
    if ((this->f226_curPlayer.flags & 2) == 0
      || a3_size < 0xA4
      || this->f569_pIDirectPlay4->GetSessionDesc(0, &Size) != 0x8877001E) {
        return 0;
    }
    DPSESSIONDESC2 *pDesc2 = (DPSESSIONDESC2 *) malloc(Size);
    if (!pDesc2) return 0;

    int result = 0;
    if (!this->f569_pIDirectPlay4->GetSessionDesc(pDesc2, &Size)) {
        EnterCriticalSection(&this->dataLock);

        *(dk2::SessionMapInfo *) &pDesc2->dwUser2 = this->f186_sessionDesc.mapInfo = a2_desc->mapInfo;
        pDesc2->dwUser4 = this->f186_sessionDesc.fileHashsum = a2_desc->fileHashsum;
        this->f186_sessionDesc.cred_2C = a2_desc->cred_2C;
        pDesc2->dwMaxPlayers = this->f186_sessionDesc.totalMaxPlayers = a2_desc->totalMaxPlayers;

        int hresult = this->f569_pIDirectPlay4->SetSessionDesc(pDesc2, 0);
        LeaveCriticalSection(&this->dataLock);

        if ( hresult ) {
            log_HRESULT(hresult);
        } else {
            Size = 0xA4;
            MLDPLAY_SESSIONDESC desc;
            this->getSessionDesc(&desc, &Size);
            result = 1;
        }
    }
    free(pDesc2);
    return result;
}

int DPlay::DestroySession(unsigned int a2_slot) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tNetworkServiceProvider::DestroySession Error::ServiceProvider Not Initialised\n");
        return 32;
    }
    if ((this->f226_curPlayer.flags & 2) == 0) {
        _log("\tNetworkServiceProvider::DestroySession Error::Not connected to session\n");
        return 32;
    }
    if ((this->f226_curPlayer.flags & 1) == 0) {
        _log("\tNetworkServiceProvider::DestroySession Error::Not host\n");
        return 0x80000;
    }
    EnterCriticalSection(&this->dataLock);
    if (a2_slot < this->f186_sessionDesc.totalMaxPlayers) {
        MyPlayerDesc* f24_playerList = this->f24_playerList;
        if (f24_playerList) {
            MyPlayerDesc* v5 = &f24_playerList[a2_slot];
            if ((v5->flags & 0xF) != 0) {
                _log("\tDPlay::DESTROYING PLAYER Index %d, using DPlay\n", v5->f20_playerId_slot);
                this->f569_pIDirectPlay4->DestroyPlayer(*(DPID*) &v5->f20_playerId_slot);
            }
        }
    }
    LeaveCriticalSection(&this->dataLock);
    return 32;
}

void DPlay::EnableNewPlayers(int a2_enabled) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::EnableNewPlayers Error:Not Initialised\n");
        return;
    }
    if ((this->f226_curPlayer.flags & 2) == 0) {
        _log("\tDPlay::EnableNewPlayers Error:Not Connected To Session\n");
        return;
    }
    _log("CALLING ENABLENEWPLAYERS\n");
    if ((this->f226_curPlayer.flags & 1) == 0) return;

    EnterCriticalSection(&this->dataLock);
    DWORD Size = 0;
    if (this->f569_pIDirectPlay4->GetSessionDesc(NULL, &Size) == 0x8877001E) {
        DPSESSIONDESC2* desc = (DPSESSIONDESC2*) malloc(Size);
        if (desc) {
            HRESULT hresult = this->f569_pIDirectPlay4->GetSessionDesc(desc, &Size);
            if (hresult == 0) {
                int dwFlags = desc->dwFlags;
                int f3C_flags;
                if (a2_enabled) {
                    desc->dwFlags = dwFlags & 0xFFFFFFDF;
                    this->f186_sessionDesc.flags &= ~0x10;
                } else {
                    desc->dwFlags = dwFlags | 0x20;
                    this->f186_sessionDesc.flags |= 0x10;
                }
                this->f186_sessionDesc.flags = f3C_flags;
                hresult = this->f569_pIDirectPlay4->SetSessionDesc(desc, 0);
                if (hresult != 0) {
                    log_HRESULT(hresult);
                }
            } else {
                log_HRESULT(hresult);
            }
            free(desc);
        }
    }
    LeaveCriticalSection(&this->dataLock);
}

BOOL FAR PASCAL IDirectPlay4_EnumPlayers_callback(
    DPID            dpId,
    DWORD           dwPlayerType,
    LPCDPNAME       lpName,
    DWORD           dwFlags,
    LPVOID          lpContext) {
    if (!lpContext) return TRUE;

    auto a3_callback = (MyPlayerEnumCb) ((void **) lpContext)[0];
    auto a5_arg = ((void **) lpContext)[1];
    if ( !a3_callback ) return TRUE;

    MyPlayerCbData cbData;
    cbData.f0_flags = 1;
    cbData.field_1 = 0;
    cbData.f5_slotNo = 0;
    cbData.f26_playerId_slot = *(PlayerId *) &dpId;
    wcscpy(cbData.f6_shortName, lpName->lpszShortName);
    a3_callback(&cbData, (DWORD) a5_arg);
    return TRUE;
}

int DPlay::EnumPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg) {
    if (!this->f20_isServiceProviderInitialized) return 32;

    void *v7_ctx[] {a3_callback, a5_arg};
    int hresult = this->f569_pIDirectPlay4->EnumPlayers(
        a2_guidInstance, IDirectPlay4_EnumPlayers_callback, v7_ctx, 0x80
    );
    if (hresult) {
        _log("ENUMPLAYERS FAILED\n");
        log_HRESULT(hresult);
        return 2;
    }
    _log("ENUMPLAYERS CALLED\n");
    return 2;
}

BOOL DPlay::SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) {
    // printf("DPlay::SendMessage ty=%X sz=%X pl=%X\n", (int) (*(uint8_t *) a3_buf), a4_size, a2_playerId_slot);
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::SendMessage Error:-Not Initialised\n");
        return 32;
    }
    if ((this->f226_curPlayer.flags & 2) == 0) {
        _log("\tDPlay::SendMessage Error:-Not Connected To Session\n");
        return 32;
    }
    PlayerId f28_playerId = {.value = a2_playerId_slot};
    if (a2_playerId_slot == 0xFFFF) {
        f28_playerId = {.value = 0};
    } else if (a2_playerId_slot == 0xFFFE) {
        f28_playerId = {.value = 1};
        if ((this->f186_sessionDesc.flags & 8) == 0) {
            f28_playerId = this->f28_host_playerId;
        }
    }
    HRESULT hresult = this->f569_pIDirectPlay4->Send(
        *(DPID*) &this->f226_curPlayer.playerId,
        *(DPID*) &f28_playerId, 0, a3_buf, a4_size);
    if (hresult) {
        if (hresult != 0x8000000A && hresult != 0x8877010E) {
            log_HRESULT(hresult);
            return 32;
        }
    }
    return 2;
}

int DPlay::SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) {
    // patch::log::dbg("DPlay::SendMessageTo ty=%X sz=%X sock=%X", (int) (*(uint8_t *) a3_buf), a4_size, a2_dstSock);
    PlayerId f28_playerId = *(PlayerId *) a2_dstSock;
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::SendMessageTo Error:-Not Initialised\n");
        return 32;
    }
    if ((this->f226_curPlayer.flags & 2) == 0) {
        _log("\tDPlay::SendMessageTo Error:-Not Connected To Session\n");
        return 32;
    }
    if (f28_playerId == 0xFFFF) {
        f28_playerId = {.value = 0};
    } else if (f28_playerId == 0xFFFE) {
        f28_playerId = {.value = 1};
        if ((this->f186_sessionDesc.flags & 8) == 0) {
            f28_playerId = this->f28_host_playerId;
        }
    }
    HRESULT hresult = this->f569_pIDirectPlay4->Send(
        *(DPID*) &this->f226_curPlayer.playerId,
        *(DPID*) &f28_playerId, 0, a3_buf, a4_size);
    if (hresult) {
        if (hresult != 0x8000000A && hresult != 0x8877010E) {
            log_HRESULT(hresult);
            return 32;
        }
    }
    return 2;
}

void DPlay::ProcessDPlaySystemMessage(DPMSG_GENERIC *a2_packet) {
    // patch::log::dbg("DPlay::ProcessDPlaySystemMessage ty=%X", a2_packet->dwType);
    int v22_handleMessage = 0;
    switch (a2_packet->dwType) {
    case DPSYS_SESSIONLOST:
        if ((this->f226_curPlayer.flags & 2) != 0) {
            _log("SESSION HAS BEEN LOST, MUST EXIT GRACEFULLY\n");
        }
        break;
    case DPSYS_HOST:
        _log("DPSYS_HOST\n");
        if ( (this->f226_curPlayer.flags & 2) != 0 ) {
            EnterCriticalSection(&this->dataLock);
            for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
                MyPlayerDesc &pl = this->f24_playerList[i];
                if ((pl.flags & 0xF) != 0 && (pl.flags & 0xF0) != 0) {
                    pl.flags &= 0xFu;
                }
            }
            this->f226_curPlayer.flags |= 1;
            BYTE *v19_pFlags = &this->f24_playerList[this->f226_curPlayer.playersSlot].flags;
            *v19_pFlags = *v19_pFlags & 0xF | 0x10;
            DWORD Size;
            if (this->f569_pIDirectPlay4->GetSessionDesc(NULL, &Size) == 0x8877001E) {
                DPSESSIONDESC2 *sessionDesc = (DPSESSIONDESC2 *)malloc(Size);
                if ( sessionDesc ) {
                    Size = 0;
                    if (!this->f569_pIDirectPlay4->GetSessionDesc(sessionDesc, &Size)) {
                        this->f186_sessionDesc.totalMaxPlayers = sessionDesc->dwMaxPlayers;
                        this->f186_sessionDesc.currentPlayers = sessionDesc->dwCurrentPlayers;
                    }
                    free(sessionDesc);
                }
            }
            this->schedulePlayersChangePacket(
              14,
              this->f226_curPlayer.playerId,
              this->f226_curPlayer.playersSlot,
              this->f24_playerList[this->f226_curPlayer.playersSlot].f0_playername,
              this->f226_curPlayer.flags);
            LeaveCriticalSection(&this->dataLock);
            this->messageHandler(0xFFFE, NULL, 0, 0xA, this->f4_arg);
        }
        break;
    case DPSYS_SETPLAYERORGROUPDATA:
        _log("DPSYS_SETPLAYERORGROUPDATA\n");
        break;
    case DPSYS_SETPLAYERORGROUPNAME:
        _log("DPSYS_SETPLAYERORGROUPNAME\n");
        break;
    case DPSYS_SETSESSIONDESC:
        _log("DPSYS_SETSESSIONDESC\n");
        break;
    case DPSYS_ADDGROUPTOGROUP:
    case DPSYS_CHAT:
      return;
    case DPSYS_DELETEGROUPFROMGROUP:
        _log("DPSYS_DELETEGROUPFROMGROUP\n");
        break;
    case DPSYS_SECUREMESSAGE:
        _log("DPSYS_SECUREMESSAGE\n");
        break;
    case DPSYS_STARTSESSION:
        _log("DPSYS_STARTSESSION\n");
        break;
    case DPSYS_DELETEPLAYERFROMGROUP:
        _log("DPSYS_DELETEPLAYERFROMGROUP\n");
        break;
    case DPSYS_CREATEPLAYERORGROUP: {
        DPMSG_CREATEPLAYERORGROUP *v2_packet = (DPMSG_CREATEPLAYERORGROUP *) a2_packet;
        if (v2_packet->dwPlayerType == 1 && (this->f226_curPlayer.flags & 1) != 0) {
            EnterCriticalSection(&this->dataLock);
            MyMessage_1_AddedPlayer v24_message;
            for (int slotNo = 0; slotNo < this->f186_sessionDesc.totalMaxPlayers; ++slotNo) {
                MyPlayerDesc *v11_playerDesc = &this->f24_playerList[slotNo];
                if ((v11_playerDesc->flags & 0xF) != 0) continue;
                ++this->f186_sessionDesc.currentPlayers;
                v11_playerDesc->f20_playerId_slot = *(PlayerId*) &v2_packet->dpId;
                v11_playerDesc->f35_slotNo = slotNo;
                if ((v2_packet->dwFlags & DPENUMPLAYERS_SPECTATOR) != 0)
                    v11_playerDesc->field_24 = 4;
                else
                    v11_playerDesc->field_24 = 0;
                wcscpy(v11_playerDesc->f0_playername, v2_packet->dpnName.lpszShortName);
                this->schedulePlayersChangePacket(
                    1,
                    v11_playerDesc->f20_playerId_slot,
                    v11_playerDesc->f35_slotNo,
                    v11_playerDesc->f0_playername,
                    v11_playerDesc->field_24);
                v11_playerDesc->flags = 1;
                v11_playerDesc->f2C_packet_D_Guaranteed_sendScheduled_count = 0;
                v11_playerDesc->f30_receivedScheduled_count = 0;
                if ((v2_packet->dwFlags & DPENUMPLAYERS_SPECTATOR) != 0) {
                    _log("ADDED NEW SPECTATOR %s %d %d\n", v11_playerDesc, slotNo, v2_packet->dpId);
                } else {
                    _log("ADDED NEW PLAYER %s %d %d\n", v11_playerDesc, slotNo, v2_packet->dpId);
                }
                this->send_B_PlayerList(slotNo);
                SetEvent(this->f16A_playerCountChange_hEvent);

                v24_message.f5_slotNo = slotNo;
                v24_message.f0_message = 1;
                v24_message.f26_playerId_slot = v11_playerDesc->f20_playerId_slot;
                if ((v2_packet->dwFlags & DPENUMPLAYERS_SPECTATOR) != 0) {
                    v24_message.f1_flags = 4;
                } else {
                    v24_message.f1_flags = 0;
                }
                wcscpy(v24_message.f6_playerName, this->f24_playerList[slotNo].f0_playername);
                v22_handleMessage = 1;
                break;
            }
            LeaveCriticalSection(&this->dataLock);
            if (v22_handleMessage) {
                this->messageHandler(0xFFFE, &v24_message, sizeof(MyMessage_1_AddedPlayer), 1, this->f4_arg);
            }
        }
    } break;
    case DPSYS_DESTROYPLAYERORGROUP: {
        _log("DPSYS_DESTROYPLAYERORGROUP\n");
        DPMSG_DESTROYPLAYERORGROUP *v2_packet = (DPMSG_DESTROYPLAYERORGROUP *) a2_packet;
        if ( v2_packet->dwPlayerType == 1 && this->f24_playerList ) {
            EnterCriticalSection(&this->dataLock);
            for (int slotNo = 0; slotNo < this->f186_sessionDesc.totalMaxPlayers; ++slotNo) {
                MyPlayerDesc *v7_playerList = &this->f24_playerList[slotNo];
                if ((v7_playerList->flags & 0xF) == 0) continue;
                if (*(DPID*) &v7_playerList->f20_playerId_slot != v2_packet->dpId) continue;
                _log("DELETED PLAYER %s %d\n", (const char*) v7_playerList, slotNo);
                v22_handleMessage = 1;
                this->fDA_unused1_perPlayerSlot[v7_playerList->f35_slotNo] = 0;
                this->f5A_ackPacketCount_perPlayerSlot[v7_playerList->f35_slotNo] = 0;
                memset(v7_playerList, 0, sizeof(MyPlayerDesc));
                char flags = this->f226_curPlayer.flags;
                --this->f186_sessionDesc.currentPlayers;
                if ((flags & 1) != 0) {
                    this->releasePacketSendArr_forPlayer(slotNo);
                    if ((this->f186_sessionDesc.flags & 8) != 0)
                        this->schedulePlayersChangePacket(9, v7_playerList->f20_playerId_slot, 0, NULL, 0);
                }
                break;
            }
            LeaveCriticalSection(&this->dataLock);
            if (v22_handleMessage) {
                this->messageHandler(0xFFFE, &a2_packet, 4, 2, this->f4_arg);
            }
        }
    } break;
    case DPSYS_ADDPLAYERTOGROUP:
        _log("ADD PLAYER TO GROUP MESSAGE \n");
        break;
    default:
        LABEL_57:
        _log("  WARNING network: NLDPlay::ProcessDPlaySystemMessage() dwType out of range: %08X\n", a2_packet->dwType);
        break;
    }
}

PacketHeader *DPlay::ReadSPMessage() {
    void *f5C1_ptr_eos = this->f5C1_ptr_eos;
    if ( !f5C1_ptr_eos ) {
        this->f5C1_ptr_eos = malloc(0x1000u);
    }

    BOOL exitLoop = 0;
    PacketHeader *result = NULL;
    while (true) {
        if ((this->f226_curPlayer.flags & 1) == 0) {
            EnterCriticalSection(&this->dataLock);
            if ( this->f5C1_ptr_eos && this->popReceivedPacketToHandle((PacketHeader*) this->f5C1_ptr_eos)) {
                result = (PacketHeader*) this->f5C1_ptr_eos;
                LeaveCriticalSection(&this->dataLock);
                return result;
            }
            LeaveCriticalSection(&this->dataLock);
        }
        DWORD count = 0;
        DWORD waitResult = 0;
        this->f569_pIDirectPlay4->GetMessageQueue(0, 0, 2, &count, NULL);
        if ( !count ) {
            HANDLE Handles[2];
            Handles[0] = this->f565_hEvent;
            Handles[1] = this->f162_DestroySPSession_hEvent;
            waitResult = WaitForMultipleObjects(2u, Handles, 0, 0xFFFFFFFF);
        }
        switch (waitResult) {
            case WAIT_OBJECT_0: {  // this->f565_hEvent
                void *lpData = this->f5C1_ptr_eos;
                DWORD Size = 4096;
                int hresult = 0x80004005;
                DPID lpidFrom;
                DPID lpidTo;
                if ( lpData ) {
                    hresult = this->f569_pIDirectPlay4->Receive(&lpidFrom, &lpidTo, 1, lpData, &Size);
                    if ( hresult == 0x8877001E ) {
                        free(this->f5C1_ptr_eos);
                        void *v9_buf = malloc(Size);
                        this->f5C1_ptr_eos = v9_buf;
                        if ( v9_buf )
                            hresult = this->f569_pIDirectPlay4->Receive(&lpidFrom, &lpidTo, 1, v9_buf, &Size);
                    }
                }
                if ( hresult ) {
                    _log("DPlay::ReadSPMessage: Dplay returned non DP_OK\n");
                    break;
                }
                if (lpidFrom == 0) {
                    this->ProcessDPlaySystemMessage((DPMSG_GENERIC*) this->f5C1_ptr_eos);
                    break;
                }
                auto* packet = (PacketHeader*) this->f5C1_ptr_eos;
                if (Size < 0xC) {
                    _log("INVALID LENGTH\n");
                    break;
                }
                if (packet->signature != 0xBF) {
                    _log("INVALID HEADER ID\n");
                    break;
                }
                int packetHandled = 0;
                if ((this->f226_curPlayer.flags & 1) == 0) {
                    EnterCriticalSection(&this->dataLock);
                    packetHandled = this->handlePacket_1_2_9_B_E((PacketHeader*) this->f5C1_ptr_eos, Size, (MySocket*) &lpidFrom);
                    LeaveCriticalSection(&this->dataLock);
                }
                if (!packetHandled) {
                    switch (packet->packetTy) {
                    case 3:
                    case 4:
                    case 0xD:
                    case 0x10:
                        exitLoop = 1;
                        result = packet;
                        break;
                    case 0xC:
                        EnterCriticalSection(&this->dataLock);
                        if (Size >= 0xD8)
                            this->handlePacket_C((MyPacket_C_HandledPackets*) packet);
                        LeaveCriticalSection(&this->dataLock);
                        break;
                    default:
                        _log("UNKNOWN MESSAGE\n");
                        break;
                    }
                }
            } break;
            case WAIT_OBJECT_0 + 1:  // this->f162_DestroySPSession_hEvent
                _log("\tDPlay Application killing of Message handling\n");
            default:
                exitLoop = 1;
                result = NULL;
                break;
        }
        if (exitLoop) return result;
    }
}

void DPlay::setNewHost(MyPacket_E_NewHost *a2_packet) {

}

int DPlay::SendMSResults(const char *a2_message) {
    return 32;
}

unsigned int DPlay::EnumerateNetworkMediums(NetworkServiceProvider::EnumerateNetworkMediumsCallback a2, void *a3) {
    return 32;
}

struct MyEnumAddressCtx {
    DPlay *f0_dplay;
    void *f4_dataBuf;
    DWORD f8_size;
    int fC_return;
};
BOOL FAR PASCAL IDirectPlayLobby3_EnumAddress_callback(
    REFGUID         guidDataType,
    DWORD           dwDataSize,
    LPCVOID         lpData,
    LPVOID          lpContext
) {
    if (guidDataType != DPAID_ModemW) return TRUE;
    if (!lpContext) return TRUE;
    auto *ctx = (MyEnumAddressCtx *) lpContext;
    ctx->fC_return = 16;
    if (ctx->f4_dataBuf && ctx->f8_size >= dwDataSize + 2) {
        memset(ctx->f4_dataBuf, 0, dwDataSize + 2);
        memcpy(ctx->f4_dataBuf, lpData, dwDataSize);
        ctx->fC_return = 2;
    }
    ctx->f8_size = dwDataSize + 2;
    return TRUE;
}
int DPlay::EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) {
    DWORD Size = 0;
    int fC_flags = 0x20;
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tDPlay::EnumerateNetworkMediums Error:Not Initialised\n");
        return 0x20;
    }
    DWORD *v6 = a4_pSize;
    MyEnumAddressCtx v11_ctx;
    v11_ctx.f0_dplay = this;
    int v7_size = *a4_pSize;
    v11_ctx.f4_dataBuf = a3_dataBuf;
    v11_ctx.f8_size = v7_size;
    v11_ctx.fC_return = 0x20;
    IDirectPlay4 *dplay4;
    if ( !a2 || !this->createIDirectPlay4(&dplay4) )
        return 0x20;
    if (
        !dplay4->InitializeConnection(*(LPVOID *)((char *) a2 + 32), 0)
        && dplay4->GetPlayerAddress(0, NULL, &Size) == 0x8877001E
    ) {
        void *v8_buf = malloc(Size);
        if ( v8_buf ) {
            if ( !dplay4->GetPlayerAddress(0, v8_buf, &Size) ) {
                this->f56d_pIDirectPlayLobby3->EnumAddress(
                    IDirectPlayLobby3_EnumAddress_callback, v8_buf, Size, &v11_ctx
                );
            }
            free(v8_buf);
            fC_flags = v11_ctx.fC_return;
            *v6 = v11_ctx.f8_size;
        }
      }
    this->releaseIDirectPlay4(dplay4);
    return fC_flags;
}

int DPlay::CreateCompoundAddress(
    DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
    MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) {
    if (!this->f20_isServiceProviderInitialized) return 32;
    int hresult = this->f56d_pIDirectPlayLobby3->CreateCompoundAddress(
        a2_elements, a3_elementCount, a4_outAddr, (LPDWORD) a5_outSize
    );
    if (hresult == 0x8877001E) return 16;
    if (!hresult) return 2;
    return 32;
}

unsigned int DPlay::__getHiWord(PlayerId playerId) {
    return playerId.slotIdx;
}

PacketHeader *DPlay::_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) {
    uint16_t slot = a2_packet->playerListIdx_m1_m2;
    if (slot != 0xFFFF
      && slot != this->f226_curPlayer.playersSlot
      && (slot != 0xFFFE || (this->f226_curPlayer.flags & 1) == 0)
    ) {
        patch::log::dbg("DPlay::_handleMessage DONT_HANDLE");
        return NULL;
    }
    this->messageHandler(
        a2_packet->playersSlot, &a2_packet[1], a2_packet->f8_messageSize,
        a3_handlerTy, this->f4_arg
    );
    if ((this->f226_curPlayer.flags & 1) != 0 && a2_packet->playerListIdx_m1_m2 == net_AllPlayers) {
        EnterCriticalSection(&this->dataLock);
        this->SendMessage(0xFFFF, a2_packet, a2_packet->f8_messageSize + sizeof(PacketHeader), 0);
        LeaveCriticalSection(&this->dataLock);
    } else {
        patch::log::dbg("DPlay::_handleMessage DONT_SEND");
    }
    *a4_outSize = a2_packet->f8_messageSize;
    return a2_packet;
}
