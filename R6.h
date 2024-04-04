#pragma once
#include "smth.h"
void R6Clean() {
	killer();
	cmd(skCrypt("del C:\\\"Program Files (x86)\"\\Ubisoft\\\"Ubisoft Game Launcher\"\\cache /f /Q > NUL 2 > NUL").decrypt());
	cmd(skCrypt("del C:\\\"Program Files (x86)\"\\Ubisoft\\\"Ubisoft Game Launcher\"\\savegames /f /Q > NUL 2 > NUL").decrypt());
	cmd(skCrypt("del C:\\Users\\%USERNAME%\\AppData\\Local\\\"Ubisoft Game Launcher\"\\spool /f /Q > NUL 2 > NUL").decrypt());
	cmd(skCrypt("del C:\\Users\\%USERNAME%\\AppData\\Local\\Temp /f /Q > NUL 2 > NUL").decrypt());
	cmd(skCrypt("del C:\\Windows\\Temp /f /Q > NUL 2 > NUL").decrypt());
	MessageBoxA(0, skCrypt("Clean Done").decrypt(), skCrypt("Shadow").decrypt(), 0);

}