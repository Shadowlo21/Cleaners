#pragma once
#include "smth.h"
void FNClean() {

	 killer();
	 system("reg delete \"HKLM\\SYSTEM\\ControlSet001\\Services\\EpicOnlineServices\" /f > nul 2>&1");
	 system("reg delete \"HKCU\\SOFTWARE\\Epic Games\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\Classes\\com.epicgames.launcher\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\ControlSet001\\Services\\BEService\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\ControlSet001\\Services\\BEDaisy\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BEService\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BEDaisy\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\WOW6432Node\\EasyAntiCheat\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\WOW6432Node\\Epic Games\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\""NonPackaged\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications\" /f > nul 2>&1");
	 system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.epicgames.launcher\" /f > nul 2>&1");
	 system("reg delete \"HKCR\\com.epicgames.eos\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications\" /f > nul 2>&1");
	 system("reg delete \"HKLM\\SOFTWARE\\EpicGames\" /f > nul 2>&1");
	 system("reg delete \"HKEY_USERS\\S-1-5-18\\Software\\Epic Games\" /f > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\Epic Games\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\All Users\\Epic\\EpicGamesLauncher\\Data\\EMS\\current\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngine\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngineLauncher\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\ProgramData\\Epic\\EpicOnlineServices\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\ProgramData\\Epic\\EpicGamesLauncher\\Data\\EMS\\current\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Program Files (x86)\\Epic Games\\Epic Online Services\\service\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64""\\Shared Files\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Program Files (x86)\\Common Files\\BattlEye\" > nul 2>&1");
	 system("RMDIR /S /Q \"%systemdrive%\\Program Files (x86)\\EasyAntiCheat\" > nul 2>&1");
	 system("RMDIR /s /Q \"%systemdrive%\\$Recycle.bin\" > nul 2>&1");
	 system("el /q \"%systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\Temp\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\Temp\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Windows\\Temp\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Windows\\Temp\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Windows\\TEMP\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Windows\\TEMP\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Windows\\temp\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Windows\\temp\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Program Files (x86)\\Temp\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Program Files (x86)\\Temp\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Windows\\Logs\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Windows\\Logs\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache\\*\") do @rd /s /q ""\"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient\\*\") do @r""d /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Windows\\Prefetch\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Windows\\Prefetch\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\Recent\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\Recent\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\*\") do @rd /s /q \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\AMD_Common\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\AMD_Common\\*\") do @rd /s /q"" \"%x\" > nul 2>&1");
	 system("del /q \"%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds\\*\" > nul 2>&1");
	 system("for /d %x in (\"%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds\\*\") do @rd"" /s /q \"%x\" > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Windows\\Temp\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Windows\\Prefetch\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\Temp\\ > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.etl > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.log > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.tmp > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.old > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.bak > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.bac > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.bup > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.chk > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.dmp > nul 2>&1");
	 system("del /f /s /q %systemdrive%\\*.temp > nul 2>&1");
	 system("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\BEService /f");
	 system("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BEService /f");
	 system("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat /f");
	 system("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat /f");
	 system("del /f /s /q \"C:\\Program Files (x86)\\Common Files\\BattlEye\\BEService.exe\"");
	 system("del /f /s /q \"C:\\Program Files (x86)\\Common Files\\BattlEye\\BEService_fn.exe\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\CN\\GameReport\\FortniteClient-Win64-Shipping.exe\\gpa.bin\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache\\92b1da15789e5451b49097cdafa85ec0f45214d6b0df9e8d.bin\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache\\92b1da15789e5451e900a9bc20b57cd2f45214d6b0df9e8d.bin\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\cl.cache\\x64\\Version 2.1 AMD-APP (3380.6).Ellesmere.cache\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\D3DSCache\\e4548a4577c56a84\\52264C4C-172F-41B9-91B8-7F0C3B1E9021_VEN_1002&DEV_67DF&SUBSYS_C580&REV_E7.idx\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\D3DSCache\\e4548a4577c56a84\\52264C4C-172F-41B9-91B8-7F0C3B1E9021_VEN_1002&DEV_67DF&SUBSYS_C580&REV_E7.lock\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\D3DSCache\\e4548a4577c56a84\\52264C4C-172F-41B9-91B8-7F0C3B1E9021_VEN_1002&DEV_67DF&SUBSYS_C580&REV_E7.val\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation\\GfeSDK\\FortniteClient-Win64-Shipping_12856.log\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History\\\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\Temp\\\"");
	 system("del /f /s /q \"C:\\Windows\\Temp\"");
	 system("del /f /s /q \"C:\\Windows\\Prefetch\"");
	 system("del /f /s /q \"C:\\Temp\\\"");
	 system("del /f /s /q %systemdrive%\\*.etl");
	 system("del /f /s /q %systemdrive%\\*.log");
	 system("del /f /s /q %systemdrive%\\*.tmp");
	 system("del /f /s /q %systemdrive%\\*.old");
	 system("del /f /s /q %systemdrive%\\*.bak");
	 system("del /f /s /q %systemdrive%\\*.bac");
	 system("del /f /s /q %systemdrive%\\*.bup");
	 system("del /f /s /q %systemdrive%\\*.chk");

	 system("/q %systemdrive%\\*.dmp");
	 system("del /f /s /q %systemdrive%\\*.temp");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\Temp\"");
	 system("del /f /s /q \"C:\\Windows\\Prefetch\"");
	 system("del /f /s /q \"C:\\Program Files (x86)\\EasyAntiCheat\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\"");
	 system("del /f /s /q \"C:\\Program Files (x86)\\Common Files\\BattlEye\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\CN\\GameReport\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\CN\\GameReport\\FortniteClient-Win64-Shipping.exe\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\cl.cache\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\AMD\\cl.cache\\x64\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\D3DSCache\\e4548a4577c56a84\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation\\GfeSDK\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\UnrealEngine\\5.0\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\CrashReportClient\"");
	 system("del /f /s /q \"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\"");
	 system("reg delete \"HKLM\\SOFTWARE\\WOW6432Node\\EasyAntiCheat\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-2532382528-581214834-2534474248-1001\\Device\\HarddiskVolume3\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping_EAC.exe:  B1 8A B0 E9 8D 13 D5 01 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-2532382528-581214834-2534474248-1001\\Device\\HarddiskVolume3\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\EasyAntiCheat\\EasyAntiCheat_Setup.exe:  73 D5 4B 11 8D 13 D5 01 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-2532382528-581214834-2534474248-1001\\Device\\HarddiskVolume3\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe:  E7 CB 84 E9 8D 13 D5 01 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\Type: 0x00000010\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\Start: 0x00000003\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\ErrorControl: 0x00000001\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\ImagePath: \"%systemdrive%\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.exe\"\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\DisplayName: \"EasyAntiCheat\"\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\WOW64: 0x0000014C\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\ObjectName: \"LocalSystem\"\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\Description: \"Provides integrated security and services for online multiplayer games.\" /f");
	 system("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat\\Security\\Security:  01 00 14 80 A0 00 00 00 AC 00 00 00 14 00 00 00 30 00 00 00 02 00 1C 00 01 00 00 00 02 80 14 00 FF 01 0F 00 01 01 00 00 00 00 00 01 00 00 00 00 02 00 70 00 05 00 00 00 00 00 14 00 30 00 02 00 01 01 00 00 00 00 00 01 00 00 00 00 00 00 14 00 FD 01 02 00 01 01 00 00 00 00 00 05 12 00 00 00 00 00 18 00 FF 01 0F 00 01 02 00 00 00 00 00 05 20 00 00 00 20 02 00 00 00 00 14 00 8D 01 02 00 01 01 00 00 00 00 00 05 04 00 00 00 00 00 14 00 8D 01 02 00 01 01 00 00 00 00 00 05 06 00 00 00 01 01 00 00 00 00 00 05 12 00 00 00 01 01 00 00 00 00 00 05 12 00 00 00\" /f\"");

	system("netsh advfirewall reset > nul 2>&1");
	MessageBoxA(0, "Clean Done", "Shadow", 0);


}


const char* commanders[] = {
	"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\flags: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\installedlocation: \"c:\\program files\\windowsapps\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\packagefamily: 0x0000004e\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\packagefullname: \"microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\packagetype: 0x00000004\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\volume: 0x00000001\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\182\\_indexkeys:  50 61 63 6b 61 67 65 46 61 6d 69 6c 79 5c 34 65 5c 31 38 32 00 50 61 63 6b 61 67 65 46 75 6c 6c 4e 61 6d 65 5c 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 6e 65 75 74 72 61 6c 5f 73 70 6c 69 74 2e 73 63 61 6c 65 2d 31 30 30 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefamily\\4e\\180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefamily\\4e\\181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefamily\\4e\\182\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\\182\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\package\"\\fullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale - 100_8wekyb3d8bbwe\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\\182\\flags: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\\182\\flags: 0x00000080\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\index\\packagefullname\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\\182\\state: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\flags: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\installedlocation: \"c:\\program files\\windowsapps\\microsoft.xboxgameoverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\packagefamily: 0x0000004e\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\packagefullname: \"microsoft.xboxgameoverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\packagetype: 0x00000008\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\volume: 0x00000001\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\180\\_indexkeys:  50 61 63 6b 61 67 65 46 61 6d 69 6c 79 5c 34 65 5c 31 38 30 00 50 61 63 6b 61 67 65 46 75 6c 6c 4e 61 6d 65 5c 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 6e 65 75 74 72 61 6c 5f 7e 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\flags: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\installedlocation: \"c:\\program files\\windowsapps\\microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\packagefamily: 0x0000004e\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\packagefullname: \"microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\packagetype: 0x00000001\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\volume: 0x00000001\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  50 61 63 6b 61 67 65 46 61 6d 69 6c 79 5c 34 65 5c 31 38 31 00 50 61 63 6b 61 67 65 46 75 6c 6c 4e 61 6d 65 5c 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 78 36 34 5f 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  50 61 63 6b 61 67 65 46 75 6c 6c 4e 61 6d 65 5c 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 78 36 34 5f 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 78 36 34 5f 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 5c 34 65 5c 31 38 31 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 31 2e 34 31 2e 32 34 30 30 31 2e 30 5f 78 36 34 5f 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\package\\data\\181\\_indexkeys:  00 00\" /f"
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a83\" /f",
"reg delete \"hklm\\software\\microsoft\\securitymanager\\capauthz\\applicationsex\\microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\\apppackagetype: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\securitymanager\\capauthz\\applicationsex\\microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\\capsids:  0a 00 00 00 01 02 00 00 00 00 00 0f 03 00 00 00 01 00 00 00 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 e8 41 fe 65 15 cb 86 8e 43 2c e1 30 42 2a b3 51 4e 9c 0e 17 b4 1b 89 09 98 da 44 8d 13 6a 0c b3 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 e4 29 72 ae 52 a9 2e 19 c4 fb 6c 51 9e 00 25 50 5b 64 a6 6f a4 d2 d0 57 d2 db d7 37 f2 b0 85 ac 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 0b 44 35 cf 44 6c 30 b5 4c 90 da 15 db 4c 09 94 5a 08 a5 69 f0 dc c5 65 02 4a 7b b9 a8 2c da c2 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 3c da 35 57 2a 15 fa c8 02 c1 bc 52 65 2b d8 ec c8 8e 72 9b 62 79 a8 20 65 1e 06 07 af 02 70 0c 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 ce 22 45 27 27 b8 ea 12 11 8a 20 ef 09 19 fd 6b b8 b4 a0 d6 03 10 5b dd d6 cf 74 85 60 22 d2 cd 01 0a 00 00 00 00 00 0f 03 00 00 00 00 04 00 00 0a d5 ca 1a 96 05 1c f5 5e 2c 0c ce 2a e\" /f",
"reg delete \"hklm\\software\\microsoft\\securitymanager\\capauthz\\applicationsex\\microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\\enterpriseid: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\securitymanager\\capauthz\\applicationsex\\microsoft.xboxgameoverlay_1.41.24001.0_x64__8wekyb3d8bbwe\\packagesid: \"s-1-15-2-1823635404-1364722122-2170562666-1762391777-2399050872-3465541734-3732476201\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ac\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ac\\application: 0x00000093\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ac\\applicationusermodelid: \"microsoft.xboxgameoverlay_8wekyb3d8bbwe!app\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ac\\user: 0x00000003\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ac\\_indexkeys:  55 73 65 72 41 6e 64 41 70 70 6c 69 63 61 74 69 6f 6e 5c 33 5e 39 33 00 55 73 65 72 41 6e 64 41 70 70 6c 69 63 61 74 69 6f 6e 55 73 65 72 4d 6f 64 65 6c 49 64 5c 33 5e 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 21 41 70 70 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ad\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ad\\application: 0x00000093\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ad\\applicationusermodelid: \"microsoft.xboxgameoverlay_8wekyb3d8bbwe!app\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ad\\user: 0x00000004\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\data\\ad\\_indexkeys:  55 73 65 72 41 6e 64 41 70 70 6c 69 63 61 74 69 6f 6e 5c 34 5e 39 33 00 55 73 65 72 41 6e 64 41 70 70 6c 69 63 61 74 69 6f 6e 55 73 65 72 4d 6f 64 65 6c 49 64 5c 34 5e 4d 69 63 72 6f 73 6f 66 74 2e 58 62 6f 78 47 61 6d 65 4f 76 65 72 6c 61 79 5f 38 77 65 6b 79 62 33 64 38 62 62 77 65 21 41 70 70 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\index\\userandapplication\\3^93\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\index\\userandapplication\\3^93\\ac\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\index\\userandapplication\\4^93\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\applicationuser\\index\\userandapplication\\4^93\\ad\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\applicationusermodelid: \"microsoft.xboxgameoverlay_8wekyb3d8bbwe!app\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\entrypoint: \"gamebar.app\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\executable: \"gamebar.exe\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\flags: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\index: 0x00000000\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\package: 0x00000181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\packagerelativeapplicationid: \"app\"\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\startpage: (null!)\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\data\\93\\_indexkeys:  50 61 63 6b 61 67 65 5c 31 38 31 5c 39 33 00 50 61 63 6b 61 67 65 41 6e 64 50 61 63 6b 61 67 65 52 65 6c 61 74 69 76 65 41 70 70 6c 69 63 61 74 69 6f 6e 49 64 5c 31 38 31 5e 41 70 70 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\index\\packageandpackagerelativeapplicationid\\181^app\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\index\\packageandpackagerelativeapplicationid\\181^app\\93\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\index\\package\\181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\application\\index\\package\\181\\93\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a80\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a80\\package: 0x00000180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a80\\user: 0x00000003\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a81\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a81\\package: 0x00000181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a81\\user: 0x00000003\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a81\\_indexkeys:  55 73 65 72 5c 33 5c 31 61 38 31 00 55 73 65 72 41 6e 64 50 61 63 6b 61 67 65 5c 33 5e 31 38 31 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a82\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a82\\package: 0x00000182\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a82\\user: 0x00000003\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a83\\package: 0x00000180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a83\\user: 0x00000004\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a83\\_indexkeys:  55 73 65 72 5c 34 5c 31 61 38 33 00 55 73 65 72 41 6e 64 50 61 63 6b 61 67 65 5c 34 5e 31 38 30 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a84\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a84\\package: 0x00000181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a84\\user: 0x00000004\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\data\\1a84\\_indexkeys:  55 73 65 72 5c 34 5c 31 61 38 34 00 55 73 65 72 41 6e 64 50 61 63 6b 61 67 65 5c 34 5e 31 38 31 00 00\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^180\\1a80\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^181\\1a81\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^182\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\3^182\\1a82\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\4^180\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\4^180\\1a83\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\4^181\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\userandpackage\\4^181\\1a84\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\user\\3\\1a80\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\user\\3\\1a81\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\user\\3\\1a82\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\user\\4\\1a83\" /f",
"reg delete \"hklm\\software\\microsoft\\windows\\currentversion\\appmodel\\staterepository\\cache\\packageuser\\index\\user\\4\\1a84\" /f",
"reg delete \"hkey_local_machine\software\epicgames\" /f",
"reg delete \"hklm\\system\\controlset001\\services\\beservice\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\sessioninfo\\1\\virtualdesktops\\currentvirtualdesktop\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\streammru\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\streammru\\0\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\streammru\\mrulistex\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\streams\\0\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\userassist\\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\\count\\{6q809377-6ns0-444o-8957-n3773s02200r}\\rcvp tnzrf\\sbegavgr\\sbegavgrtnzr\\ovanevrf\\jva64\\rnflnagvpurng\\rnflnagvpurng_frghc.rkr\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\userassist\\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\\count\\{6q809377-6ns0-444o-8957-n3773s02200r}\\rcvp tnzrf\\sbegavgr\\sbegavgrtnzr\\ovanevrf\\jva64\\sbegavgrpyvrag-jva64-fuvccvat.rkr\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\software\\microsoft\\windows\\currentversion\\explorer\\userassist\\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\\count\\{6q809377-6ns0-444o-8957-n3773s02200r}\\rcvp tnzrf\\sbegavgr\\sbegavgrtnzr\\ovanevrf\\jva64\\sbegavgrpyvrag-jva64-fuvccvat_rnp.rkr\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\system\\gameconfigstore\\children\\03ce6902-ff58-41de-ab92-36fcaf27a580\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001\\system\\gameconfigstore\\parents\\fd13f746e7d2d69760b017363f621255c9b49ac8\" /f",
"reg delete \"hku\\s-1-5-21-2532382528-581214834-2534474248-1001_classes\\local settings\\mrtcache\\c:%5cprogram files%5cwindowsapps%5cmicrosoft.xboxgamingoverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5cmicrosoft.system.package.metadata%5cs-1-5-21-2532382528-581214834-2534474248-1001-mergedresources-2.pri\" /f",
"reg delete \"hklm\\system\\currentcontrolset\\services\\beservice\" /f"
};

void hardclean() {
	 killer();
	 system("del \"%localappdata%\\microsoft\\feeds\" /s /f /q");
	 system("del \"%systemdrive%\\users\\%username%\\appdata\\local\\epicgameslauncher\\saved\\webcache\\cookies\"");
	 system("del \"%temp%\\getadmin.vbs\"");
	 system("del \"c:\\programdata\\microsoft\\search\\data\\applications\\windows\\edb.jcp\"");
	 system("del \"c:\\recovery\\ntuser.sys\"");
	 system("del \"c:\\system volume information\\indexervolumeguid\"");
	 system("del \"c:\\system volume information\\tracking.log\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\content\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\content\\77ec63bda74bd0d0e0426dc8f8008506\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\content\\fb0d848f74f70bb2eaa93746d24d9749\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\metadata\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\metadata\\77ec63bda74bd0d0e0426dc8f8008506\"");
	 system("del \"c:\\users\\%username%\\appdata\\locallow\\microsoft\\cryptneturlcache\\metadata\\fb0d848f74f70bb2eaa93746d24d9749\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\crashdumps\\backgr~2.dmp\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\epicgameslauncher\\saved\\webcache\\cookies\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\feeds cache\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\feeds\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\windows\\webcache\\v01.chk\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\windows\\webcache\\v0100024.log\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\windows\\webcache\\webcac~1.dat\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\microsoft\\windows\\webcache\\webcac~1.jfm\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\nordvpn\\logs\\app-2019-12-09.nwl\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\nvidia corporation\\gfesdk\\fortni~1.log\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\packages\\microsoft.windows.cortana_cw5n1h2txyewy\\appdata\\cachestorage\\caches~1.jfm\"");
	 system("del \"c:\\users\\%username%\\appdata\\local\\temp\\ecache.bin\"");
	// Continuing with the rest of the commands...
	 system("del \"c:\\users\\all users\\microsoft\\search\\data\\applications\\windows\\edb.jcp\"");
	 system("del \"c:\\users\\all users\\microsoft\\search\\data\\applications\\windows\\projects\\systemindex\\propmap\\cipt0000.000\"");
	 system("del \"c:\\users\\all users\\microsoft\\windows\\wer\\temp\\wer5cc2.tmp.xml\"");
	 system("del \"c:\\users\\all users\\microsoft\\windows\\wer\\temp\\wer95df.tmp.mdmp\"");
	 system("del \"c:\\users\\public\\shared files\"");
	 system("del \"c:\\windows\\cbstemp\\30780525_1668355464\"");
	 system("del \"c:\\windows\\inf\\bthpan.pnf\"");
	 system("del \"c:\\windows\\inf\\e2xw10x64.pnf\"");
	 system("del \"c:\\windows\\inf\\e2xw10~1.pnf\"");
	 system("del \"c:\\windows\\inf\\ialpss2i_gpio2_skl.pnf\"");
	 system("del \"c:\\windows\\inf\\intelpep.pnf\"");
	 system("del \"c:\\windows\\inf\\monitor.pnf\"");
	 system("del \"c:\\windows\\inf\\msports.pnf\"");
	 system("del \"c:\\windows\\inf\\ndisvirtualbus.pnf\"");
	 system("del \"c:\\windows\\inf\\netathr10x.pnf\"");
	 system("del \"c:\\windows\\inf\\netavpna.pnf\"");
	 system("del \"c:\\windows\\inf\\netrasa.pnf\"");
	 system("del \"c:\\windows\\inf\\netsstpa.pnf\"");
	 system("del \"c:\\windows\\inf\\netvwifimp.pnf\"");
	 system("del \"c:\\windows\\inf\\rdpbus.pnf\"");
	 system("del \"c:\\windows\\inf\\usbxhci.pnf\"");
	 system("del \"c:\\windows\\inf\\wmiacpi.pnf\"");
	 system("del \"c:\\windows\\logs\\cbs\\cbs.log\"");
	 system("del \"c:\\windows\\system32\\wbem\\repository\\mapping1.map\"");
	 system("del \"c:\\windows\\system32\\wbem\\repository\\writable.tst\"");
	 system("del \"c:\\windows\\temp\\206f3fdc-b1a8-4fd6-bdb8-6cfe76122873\"");
	 system("del \"c:\\windows\\temp\\6e04ef32-0387-48b1-b812-ac2bba90a8d0\"");
	 system("del /q /f %windir%\\kb*.log");
	 system("del /q /f /a /s \"c:\\users\\%username%\\appdata\\local\\iconcache.db\"");
	 system("del /q /f /a /s \"c:\\users\\%username%\\appdata\\local\\updater.log\"");
	 system("del /f \"c:\\programdata\\microsoft\\windows\\devicemetadatacache\\dmrc.idx\"");
	 system("del /f \"c:\\system volume information\\tracking.log\"");
	 system("del /f \"c:\\users\\%username%\\appdata\\local\\ac\\inetcookies\\ese\\container.dat\"");
	 system("del /f \"c:\\users\\%username%\\appdata\\local\\microsoft\\onedrive\\logs\\common\\devicehealthsummaryconfiguration.ini\"");
	 system("del /f \"c:\\users\\%username%\\appdata\\local\\microsoft\\vault\\userprofileroaming\\latest.dat\"");
	 system("del /f \"c:\\users\\%username%\\appdata\\local\\microsoft\\windows\\inetcache\\ie\\container.dat\"");
	 system("del /f \"c:\\users\\%username%\\appdata\\local\\unrealengine\\4.23\\saved\\config\\windowsclient\\manifest.ini\"");
	 system("del /f \"c:\\users\\%username%\\ntuser.ini\"");
	 system("del /f \"c:\\windows\\win.ini\"");
	 system("del /f /q \"%userprofile%\\recent\\*.*\"");
	 system("del /f /s /q \"%appdata%\\roaming\\easyanticheat\\*.*\"");
	 system("del /f /s /q \"%systemdrive%paint\\users\\%username%\\appdata\\roaming\\vstelemetry\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\desktop.ini\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\intel\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\msocache\\{71230000-00e2-0000-1000-00000000}\\setup.dat\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\msocache\\{71230000-00e2-0000-1000-00000000}\\setup.dat\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\program files (x86)\\easyanticheat\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\program files (x86)\\easyanticheat\\easyanticheat.sys\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\electronic arts\\*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\electronic arts\\ea services\\license\\*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\electronic arts\\ea services\\license\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\datamart\\paidwifi\\networkscache\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\datamart\\paidwifi\\networkscache\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\datamart\\paidwifi\\rules\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\datamart\\paidwifi\\rules\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\windows\\wer\\temp\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\programdata\\microsoft\\windows\\wer\\temp\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\recovery\\ntuser.sys\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\system volume information\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\temp\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\users\\%%username%%\\appdata\\local\\unrealengine\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\users\\%username%\\appdata\\local\\microsoft\\feeds\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\users\\%username%\\appdata\\local\\microsoft\\windows\\history\\history.ie5\\*.*\"");
	 system("del /f /s /q \"%systemdrive%\\users\\%username%\\appdata\\local\\microsoft\\windows\\history\\history.ie5\\*.*\"");


	for (const char* command : commanders) {
		system(command);
	}

	MessageBoxA(0, "Clean Done", "Shadow", 0);
}
