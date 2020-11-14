# process-based-proxy-redirection
Process-based proxy redirection for WinSock connections (x86), supports blocking and non-blocking sockets, authenticated and none-authenticated connections for SOCKS5 protocol

<h4>Usage;</h4>

Compile and inject the dll to the target process.

<h4>Compilation;</h4>

1)Create an empty C++ project in Visual Studio,  

2)Project->Add Existing Item-> Choose dllmain.cpp

3)Project->Properties->General->Configuration Type, Change it to .dll

4)Project->Properties->Advanced->Character set, Change to "Use Multi-Byte Character Set"

5)Project->Properties->C/C++->Preprocessor->Preprocessor Definitions, add ";_CRT_SECURE_NO_WARNINGS" to end of existing definitions or simply add "#define _CRT_SECURE_NO_WARNINGS" on the top of dllmain.cpp

6)Build
