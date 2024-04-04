#pragma once
#include "smth.h"

void CODClean() {



		killer();
		
        system(skCrypt("rmdir /s /q \"%localappdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%localappdata%\\Blizzard Entertainment\"").decrypt());
        system(skCrypt("rmdir /s /q \"%appdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%programdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%programdata%\\Blizzard Entertainment\"").decrypt());
        system(skCrypt("rmdir /s /q \"%programdata%\\Activision\"").decrypt());
        system(skCrypt("rmdir /s /q \"%USERPROFILE%\\Documents\\Call Of Duty Black Ops Cold War\"").decrypt());
        system(skCrypt("rmdir /s /q \"%USERPROFILE%\\Documents\\Call of Duty Modern Warfare\"").decrypt());

        // Delete specific files related to Call of Duty Modern Warfare
        system(skCrypt("del \"%codmw%\\Data\\data\\shmem\" /s /q").decrypt());
        system(skCrypt("del \"%codmw%\\main\\recipes\\cmr_hist\" /s /q").decrypt());

        // Delete additional directories
        system(skCrypt("rmdir /s /q \"%localappdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%localappdata%\\Blizzard Entertainment\"").decrypt());
        system(skCrypt("rmdir /s /q \"%appdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%programdata%\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"%programdata%\\Blizzard Entertainment\"").decrypt());
        system(skCrypt("rmdir /s /q \"%USERPROFILE%\\Documents\\Call of Duty Modern Warfare\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Battle.net\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\12On7\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\BlizzardBrowser\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\main\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\telescopeCache\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\xpak_cache\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\Data\\indices\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\Program Files (x86)\\Call of Duty Modern Warfare\\Data\\config\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\ProgramData\\NVIDIA Corporation\\NV_Cache\"").decrypt());
        system(skCrypt("rmdir /s /q \"c:\\ProgramData\\NVIDIA Corporation\\NV_Cache\"").decrypt());

        // Delete registry entries
        system(skCrypt("reg delete HKCU\\Software\\Blizzard Entertainment\\Battle.net /f").decrypt());
        system(skCrypt("reg delete HKLM\\Software\\WOW6432Node\\Blizzard Entertainment /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Blizzard Entertainment\\Battle.net\\Identity /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\DirectInput /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f").decrypt());
        system(skCrypt("reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ActivityDataModel /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\battlenet /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\blizzard /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Blizzard.URI.Battlenet /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Blizzard.URI.Blizzard /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Blizzard.URI.Heroes /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Blizzard.URI.SC2 /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\heroes /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\starcraft /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\battlenet /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001 /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName /f").decrypt());
        system(skCrypt("reg delete HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\VIDEO /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\battlenet /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\blizzard /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\Blizzard.URI.Battlenet /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\Blizzard.URI.Blizzard /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\Blizzard.URI.Heroes /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\Blizzard.URI.SC2 /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\heroes /f").decrypt());
        system(skCrypt("reg delete HKEY_CLASSES_ROOT\\starcraft /f").decrypt());

        // Delete additional directories and temporary files
        system(skCrypt("del C:\\ProgramData\\Battle.net /s /q").decrypt());
        system(skCrypt("del C:\\ProgramData\\Blizzard Entertainment /s /q").decrypt());
        system(skCrypt("del C:\\Users\\%USERNAME%\\AppData\\Local\\Temp /s /q").decrypt());
        system(skCrypt("del C:\\Windows\\Temp /s /q").decrypt());


		MessageBoxA(0, skCrypt("Clean Done").decrypt(), skCrypt("Shadow").decrypt(), 0);

}