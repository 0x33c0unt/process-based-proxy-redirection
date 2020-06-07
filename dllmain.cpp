#include <windows.h>
#include <fstream>
#pragma comment(lib, "ws2_32.lib")
using namespace std;
DWORD connectAdr;
bool auth;
BYTE IPArr[7]; // scanning %d puts exact 4 bytes  
int port;
string username;
string password;
void proxyInitialization(bool auth, string IP, int port, string username = "", string password = "")
{
    ::auth = auth;
    sscanf(IP.c_str(), "%d.%d.%d.%d", &IPArr[0], &IPArr[1], &IPArr[2], &IPArr[3]);
    ::port = port;
    ::username = username;
    ::password = password;
}
void MainConsole()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    SetConsoleTitle("0x33c0unt");
}
__declspec(naked) int hasConnect(SOCKET s, const sockaddr* name, int namelen)
{
    __asm
    {
        push ebp
        mov ebp, esp
        mov edx, connectAdr
        add edx, 5
        jmp edx
    }
}
int WINAPI FakeConnect(SOCKET s, const sockaddr* name, int namelen) // FakeConnect
{
    SHORT PORT;
    BYTE IP[4];
    u_long iMode = 0, iResult;

    memcpy(IP, name->sa_data + 2, 4); // read the ip

    memcpy((void*)(name->sa_data + 2), IPArr, 4); // change the ip

    *(BYTE*)&PORT = *(BYTE*)(name->sa_data + 1); // read...
    *(BYTE*)((DWORD)&PORT + 1) = *(BYTE*)name->sa_data;// the port

    *(BYTE*)(name->sa_data + 1) = *(BYTE*)&port; // change
    *(BYTE*)(name->sa_data) = *(BYTE*)((DWORD)&port + 1); // the port

    printf("Connection to %d.%d.*.*:%hu will be redirected to %d.%d.*.*:%hu\n", IP[0], IP[1], PORT, IPArr[0], IPArr[1], port);
    //printf("Connection to %d.%d.%d.%d:%hu will be redirected to %d.%d.%d.%d:%hu\n", IP[0], IP[1], IP[2], IP[3], PORT, IPArr[0], IPArr[1], IPArr[2], IPArr[3], port);

    int r = hasConnect(s, name, namelen);
    /*if (r == SOCKET_ERROR)
    {
        puts("An error occurred while connecting");
        return r;
    }*/
    char authMethodsPacket[] = { 0x5,0x1,0x0 };
    if (auth)
        authMethodsPacket[2] = 0x2; // username/password
    do
        r = send(s, authMethodsPacket, sizeof(authMethodsPacket), 0);
    while (r == SOCKET_ERROR);
    char buff[1024];
    int len;
    do
    {
        len = recv(s, buff, 1024, 0);
        if (len > 0)
        {
            if (buff[0] == 0x5 && buff[1] == 0x0 && len == 2 && !auth or buff[0] == 0x1 && buff[1] == 0x0 && auth)
            {
                BYTE* connectionPacket = (BYTE*)malloc(10);
                connectionPacket[0] = 0x5;
                connectionPacket[1] = 1;
                connectionPacket[2] = 0;
                connectionPacket[3] = 1;
                memcpy(connectionPacket + 4, IP, 4);
                *(BYTE*)(connectionPacket + 9) = *(BYTE*)&PORT;
                *(BYTE*)(connectionPacket + 8) = *(BYTE*)((DWORD)&PORT + 1);
                send(s, (const char*)connectionPacket, 10, 0);
            }
            else if (buff[0] == 0x5 && buff[1] == 0x2 && auth)
            {
                BYTE* authenticationPacket = (BYTE*)malloc(3 + username.length() + password.length());
                authenticationPacket[0] = 0x1;
                authenticationPacket[1] = username.length();
                memcpy(authenticationPacket + 2, username.c_str(), username.length());
                authenticationPacket[username.length() + 2] = password.length();
                memcpy(authenticationPacket + 3 + username.length(), password.c_str(), password.length());
                send(s, (const char*)authenticationPacket, 3 + username.length() + password.length(), 0);
            }
            else if (buff[0] == 0x5 && buff[1] == 0x0)
            {
                break;
            }

            for (int i = 0; i < len; i++)
                printf("%02x", buff[i]);
            printf("\n");
        }
    } while (true);
    printf("Connected\n");
    return r;
}
__declspec(naked) void connectWrapper(SOCKET s, const sockaddr* name, int namelen)
{
    __asm
    {
        push ebp
        mov ebp, esp

        pushad

        push namelen
        push name
        push s
        call FakeConnect

        popad

        pop ebp
        ret 0xC
    }
}
DWORD GetCallDiff(DWORD Src, DWORD Dest)
{
    DWORD Diff = 0;
    if (Src > Dest)
    {
        Diff = Src - Dest;
        return (0xFFFFFFFB - Diff);
    }
    return (Dest - Src - 5);
}
void Hook()
{
    MainConsole();
    proxyInitialization(false,"1.2.3.4", 1024); // socks5 IP & PORT here
    connectAdr = (DWORD)GetProcAddress(GetModuleHandle("WS2_32.dll"), "connect");
    DWORD Old;
    VirtualProtect((LPVOID)connectAdr, 1024, PAGE_EXECUTE_READWRITE, &Old);
    *(BYTE*)connectAdr = 0xE9;
    *(DWORD*)(connectAdr + 1) = GetCallDiff(connectAdr, (DWORD)&connectWrapper);
    VirtualProtect(connect, 5, Old, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Hook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

