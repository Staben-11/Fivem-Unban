#include <iostream>
#include <urlmon.h>
#include <direct.h>
#include <skStr.h>
#include <random>
#include <wininet.h>
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "urlmon.lib")

namespace {
	std::string const default_chars =
		"abcdefghijklmnaoqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
}

std::string random_string(size_t len = 15, std::string const& allowed_chars = default_chars) {
	std::mt19937_64 gen{ std::random_device()() };

	std::uniform_int_distribution<size_t> dist{ 0, allowed_chars.length() - 1 };

	std::string ret;

	std::generate_n(std::back_inserter(ret), len, [&] { return allowed_chars[dist(gen)]; });
	return ret;
}

void Downloads()
{
	system(skCrypt("cls"));
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
	std::cout << skCrypt("\n	Please wait, your system will be spoofed.");
	Sleep(2500);

	// Verificando se há conexão com a internet.
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

	// Download de todos arquivos

	if (_mkdir("C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c") == -1)
	Sleep(1500);

	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022933364121712/kdmapper.exe", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\kdmapper.exe", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022933687095416/Spoofer.sys", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\Spoofer.sys", 0, NULL);

	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022933984870470/AMIDEWINx64.EXE", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\AMIDEWINx64.EXE", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022934328811630/amifldrv64.sys", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\amifldrv64.sys", 0, NULL);

	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022933032763493/HWID.cmd", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\RVCGMYUFXFEW.cmd", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073034453363998720/beta.bat", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\YSWQBBEJWGPF.bat", 0, NULL);

	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022932424597605/C.cmd", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\KNNDGEWJOSLA.cmd", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022932709822575/D.cmd", "C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\USYZYONQWMUM.cmd", 0, NULL);

	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022934697922560/Volumeid.exe", "C:\\Volumeid.exe", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1073022570783326212/1073022935025057793/Volumeid64.exe", "C:\\Volumeid64.exe", 0, NULL);
}

void Cleaner()
{
	// Finalizando tarefas relacionadas ao FiveM
	system(skCrypt("taskkill /f /im FiveM_b2372_GTAProcess.exe.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM_SteamChild.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM_b2699_GTAProcess.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im wallpaper32.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im steam.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im EpicGamesLauncher.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im Launcher.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im LauncherPatcher.exe >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Deletando arquivos de configuração do FiveM & deslogando conta ativa.
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\data\\cache >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\data\\nui-storage >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\data\\server-cache-priv >nul 2>nul"));

	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\crashes >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\logs >nul 2>nul"));

	system(skCrypt("del /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\CitizenFX.ini >nul 2>nul"));
	system(skCrypt("del /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\cef_console.txt >nul 2>nul"));
	system(skCrypt("del /s /q \"C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\favorites.json >nul 2>nul"));

	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Roaming\\CitizenFX >nul 2>nul"));
	system(skCrypt("/C rmdir /s /q \"C:\\Users\\%username%\\AppData\\Local\\DigitalEntitlements >nul 2>nul"));
	system(skCrypt("/C cd C:\\Users\\%username%\\Saved Games\\ && rmdir /s /q .\\CitizenFX >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Deletando arquivos temporários
	system(skCrypt("del /s /f /q %temp%\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\temp\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Prefetch\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %LOCALAPPDATA%\Microsoft\Windows\Caches\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\SoftwareDistribution\Download\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %programdata%\Microsoft\Windows\WER\Temp\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %HomePath%\AppData\LocalLow\Temp\*.* >nul 2>nul"));
	system(skCrypt("rd /s /f /q %windir%\history >nul 2>nul"));
	system(skCrypt("rd /s /f /q %windir%\cookies >nul 2>nul"));
	system(skCrypt("rd /q /s %systemdrive%\$Recycle.Bin >nul 2>nul"));
	system(skCrypt("rd /q /s d:\$Recycle.Bin >nul 2>nul"));

	// Deletando arquivos de Log
	system(skCrypt("del /s /f /q %windir%\Logs\CBS\CbsPersist*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Logs\MoSetup\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Panther\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\logs\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %localappdata%\Microsoft\Windows\WebCache\*.log >nul 2>nul"));
	system(skCrypt("rd /s /f /q %localappdata%\Microsoft\Windows\INetCache\*.log >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);
}

void Spoofer()
{
	system(skCrypt("cd C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c & start kdmapper Spoofer.sys >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(2500);

	system(skCrypt("start C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\RVCGMYUFXFEW.cmd >nul 2>nul"));

	Sleep(2500);

	system(skCrypt("start C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\YSWQBBEJWGPF.bat >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(2500);

	system(skCrypt("start C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\KNNDGEWJOSLA.cmd >nul 2>nul"));
	system(skCrypt("start C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c\\USYZYONQWMUM.cmd >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(4000);

	system(skCrypt("taskkill /f /im cmd.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im cmd.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im cmd.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im cmd.exe >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	std::string HwGuildRandom = random_string(12, "abcdefghijklmnopqrstuvwxyz123456789");
	std::string FunctionCmd = "/C REG ADD \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001\" /f /v HwProfileGuid /t REG_SZ /d {1b7803eb-da69-11ea-a112-";
	std::string LesDeux = FunctionCmd + HwGuildRandom + "}";
	ShellExecuteA(0, "open", "cmd.exe", LesDeux.c_str(), 0, SW_HIDE);
	//----------------------//
	//	    Fonction2   	//
	//----------------------//
	std::string MachineRandom = random_string(12, "abcdefghijklmnopqrstuvwxyz123456789");
	std::string MachineFonction = "/C REG ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /f /v MachineGuid /t REG_SZ /d ValeurTest"; // Maybe it's work with 16 bit idk
	std::string FonctionContribue = MachineFonction + MachineRandom;
	ShellExecuteA(0, "open", "cmd.exe", FonctionContribue.c_str(), 0, SW_HIDE); // Execute fonction invalid and it's work
	//----------------------//
	//	    Fonction3   	//
	//----------------------//
	std::string macrandom = random_string(12, "abcdefghijklmnopqrstuvwxyz123456789");
	std::string macfonction = "/C REG ADD HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001 /f /v MachineGuid /t REG_SZ /d ValeurTest"; // Maybe it's work with 16 bit idk
	std::string DoubleFonction = MachineFonction + MachineRandom;
	ShellExecuteA(0, "open", "cmd.exe", FonctionContribue.c_str(), 0, SW_HIDE); // Execute fonction for change mac but i dont if work with 16 byte bcs on 16 byte mac change evertime

	system(skCrypt("cls"));
	Sleep(1500);

	// Clean DNS Resolver Cache (Restart May Be Required)
	system(skCrypt("ipconfig /release >nul 2>nul"));
	system(skCrypt("ipconfig /renew >nul 2>nul"));
	system(skCrypt("ipconfig /flushdns >nul 2>nul"));
	system(skCrypt("netsh int ip reset >nul 2>nul"));
	system(skCrypt("netsh winsock reset >nul 2>nul"));
	system(skCrypt("netsh winsock reset catalog >nul 2>nul"));
	system(skCrypt("netsh interface ipv4 reset >nul 2>nul"));
	system(skCrypt("netsh interface ipv6 reset >nul 2>nul"));
	system(skCrypt("netsh int ipv4 reset reset.log >nul 2>nul"));
	system(skCrypt("netsh int ipv6 reset reset.log >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(2500);
}

void Final()
{
	system(skCrypt("mode 60,20"));
	system(skCrypt("rmdir /s /q C:\\ProgramData\\Packages\\Microsoft.StoreApp_kzf8qxf38zg5c"));
	system(skCrypt("del /s /q C:\\Volumeid.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im Volumeid64.exe >nul 2>nul")); // Anti-Bug
	system(skCrypt("del /s /q C:\\Volumeid64.exe >nul 2>nul"));
	system(skCrypt("fsutil usn deletejournal /d /c:"));
	system(skCrypt("fsutil usn deletejournal /d /d:"));
	system(skCrypt("cls"));
    std::cout << R"(
            .-"-.            .-"-.          .-"-.
          _/_-.-_\_        _/.-.-.\_      _/.-.-.\_
         / __} {__ \      /|( o o )|\    ( ( o o ) )
        / //  "  \\ \    | //  "  \\ |    |/  "  \|
       / / \'---'/ \ \  / / \'---'/ \ \    \ .-. /
       \ \_/`"""`\_/ /  \ \_/`"""`\_/ /    /`"""`\
        \           /    \           /    /       \
		)" << '\n';
	std::cout << skCrypt("\n		 System spoofed successfully.");
	Sleep(3500);
	exit(0);
}
