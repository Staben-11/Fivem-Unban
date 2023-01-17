#include <Windows.h>
#include "auth.hpp"
#include <string>
#include <direct.h>
#include "skStr.h"
#include <u202E.h>
#include <antidbg.h>
#include <wininet.h>
#pragma comment(lib,"Wininet.lib")

using namespace KeyAuth;

std::string name = ""; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = ""; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = ""; // app secret, the blurred text on licenses tab and other tabs
std::string version = ""; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.2/"; // change if you're self-hosting

/*
	Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg

	Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

	Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url);

DWORD AntiDebug1_Loop(LPVOID in) {

	while (1) 
	{
		if (GetAsyncKeyState(NULL) & 1) {

		}

		else
		{
			is_present();
			Sleep(300);
			debug_string();
			Sleep(300);
			hide_thread();
			remote_is_present();
			Sleep(300);
			driverdetect();
		}
	}
}

DWORD AntiDebug2_Loop(LPVOID in) 
{

	while (1) 
	{
		if (GetAsyncKeyState(NULL) & 1) 
		{

		}

		else
		{
			Sleep(300);
			checkfordbg();
			Sleep(300);
			thread_context();
		}
	}
}

int main()
{
	CreateThread(NULL, NULL, AntiDebug1_Loop, NULL, NULL, NULL);
	CreateThread(NULL, NULL, AntiDebug2_Loop, NULL, NULL, NULL);

	system(skCrypt("mode 60,20"));
	SetConsoleTitleA(skCrypt(""));
	
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoading   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLOading   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoAding   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoaDing   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoadIng   ") << std::flush;
	Sleep(100);

	// Checkando conexão com a internet.
	char url[128];
	strcat(url, "https://www.google.com/");
	bool bConnect = InternetCheckConnection(url, FLAG_ICC_FORCE_CONNECTION, 0);

	if (bConnect)
	{
		// Próxima etapa.
	}
	else
	{
		system(skCrypt("cls"));
		std::cout << skCrypt("\n No internet connection.");
		Sleep(2500);
		abort();
	}

	KeyAuthApp.init();

	if (KeyAuthApp.checkblack()) {
		system(skCrypt("cls"));
		std::cout << skCrypt("\n Blacklist Detected.");
		Sleep(2500);
		abort();
	}

	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoadiNg   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoadinG   ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoading.  ") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoading..") << std::flush;
	Sleep(100);
	std::cout << skCrypt("\b\b\b\b\b\b\b\b\b\bLoading...") << std::flush;
	Sleep(100);

	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	system(skCrypt("cls"));
	system(skCrypt("mode 60,20"));
	std::cout << "\n\n" << R"(
	 ,_     _
	 |\\_,-~/
	/ _  _ |    ,--.
	(  @  @ )   / ,-'          1. Login
	 \  _T_/-._( (
	 /         `. \            2. Register
	|         _  \ |
	\ \ ,  /      |            3. Upgrade
	 || |-_\__   /
	((_/`(____,-'
	)" << '\n';

	std::cout << skCrypt("\n	?: ");
	
	int option;
	std::string username;
	std::string password;
	std::string key;
	
	std::cin >> option;
	switch (option)
	{
	case 1:
		system(skCrypt("cls"));
		system(skCrypt("mode 60,20"));
		std::cout << "\n" << R"(
                     .-.         .--''-.
                   .'   '.     /'       `.
                   '.     '. ,'          |
                o    '.o   ,'        _.-'
                 \.--./'. /.:. :._:.'
                .'    '._-': ': ': ': ':
               :(#) (#) :  ': ': ': ': ':>-
                ' ____ .'_.:' :' :' :' :'
                 '\__/'/ | | :' :' :'
                       \  \ \
                       '  ' '             
	)" << '\n';
		std::cout << skCrypt("                    username: ");
		std::cin >> username;
		std::cout << skCrypt("\n                    password: ");
		std::cin >> password;
		system(skCrypt("cls"));
		KeyAuthApp.login(username, password);
		KeyAuthApp.log("Login");
		break;
	case 2:
		system(skCrypt("cls"));
		system(skCrypt("mode 60,20"));
		std::cout << "\n" << R"(
                     .-.         .--''-.
                   .'   '.     /'       `.
                   '.     '. ,'          |
                o    '.o   ,'        _.-'
                 \.--./'. /.:. :._:.'
                .\   /'._-':#0: ':#0: ':
               :(#) (#) :  ':#0: ':#0: ':>#=-
                ' ____ .'_.:J0:' :J0:' :'
                 'V  V'/ | |":' :'":'
                       \  \ \
                       '  ' '           
	)" << '\n';
		std::cout << skCrypt("                    username: ");
		std::cin >> username;
		std::cout << skCrypt("\n                    password: ");
		std::cin >> password;
		std::cout << skCrypt("\n                    license: ");
		std::cin >> key;
		system(skCrypt("cls"));
		KeyAuthApp.regstr(username, password, key);
		KeyAuthApp.log("Register");
		break;
	case 3:
		system(skCrypt("cls"));
		system(skCrypt("mode 60,20"));
		std::cout << R"(
                          /)  (\
                     .-._((,~~.))_.-,
                      `=.   99   ,='
                        / ,o~~o. \
                       { { .__. } }
                        ) `~~~\' (
                       /`-._  _\.-\
                     /         )  \
                    ,-X        #   X-.
                  /   \          /   \
                 (     )| |  | |(     )
                   \   / | |  | | \   /
                    \_(.-( )--( )-.)_/
                    /_,\ ) /  \ ( /._\
                        /_,\  /._\          
	)" << '\n';
		std::cout << skCrypt("                    username: ");
		std::cin >> username;
		std::cout << skCrypt("\n                    license: ");
		std::cin >> key;
		system(skCrypt("cls"));
		KeyAuthApp.upgrade(username, key);
		KeyAuthApp.log("Upgrade");
		break;
	default:
		std::cout << skCrypt("\n\n Invalid Selection");
		Sleep(3000);
		exit(0);
	}
	
	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}
	
	// Checkando conexão com a internet.
	char url2[128];
	strcat(url2, "https://www.google.com/");
	bool cConnect = InternetCheckConnection(url2, FLAG_ICC_FORCE_CONNECTION, 0);

	if (cConnect)
	{
		// Próxima etapa.
	}
	else
	{
		system(skCrypt("cls"));
		std::cout << skCrypt("\n No internet connection.");
		Sleep(2500);
		abort();
	}

	// Logado com sucesso.
	system(skCrypt("mode 60,20"));
	std::cout << "\n" << R"(
	   	   /\                 /\
		  / \'._   (\_/)   _.'/ \
		  |.''._'--(o.o)--'_.''.|
		   \_ / `;=/ " \=;` \ _/
		     `\__| \___/ |__/`
		          \(_|_)/
		           " ` "                
	)" << '\n';
	std::cout << skCrypt("\n	    	  Welcome back ") << KeyAuthApp.data.username;
	Sleep(2500);

	XKRJNTPMDGQD(); // Download de todos arquivos e criação de uma pasta "isolada".
	OICXSXOPZFAK(); // Processo inteiro de spoofing.
	VLNNKUUVKTUP(); // Exclusão da pasta, limpeza de "rastros" e termino do programa.

	exit(0);
}
