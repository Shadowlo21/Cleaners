#pragma once
#include "smth.h"
void R6Clean() {
	killer();
	cmd("del C:\\\"Program Files (x86)\"\\Ubisoft\\\"Ubisoft Game Launcher\"\\cache /f /Q > NUL 2 > NUL");
	cmd("del C:\\\"Program Files (x86)\"\\Ubisoft\\\"Ubisoft Game Launcher\"\\savegames /f /Q > NUL 2 > NUL");
	cmd("del C:\\Users\\%USERNAME%\\AppData\\Local\\\"Ubisoft Game Launcher\"\\spool /f /Q > NUL 2 > NUL");
	cmd("del C:\\Users\\%USERNAME%\\AppData\\Local\\Temp /f /Q > NUL 2 > NUL");
	cmd("del C:\\Windows\\Temp /f /Q > NUL 2 > NUL");
	MessageBoxA(0, "Clean Done", "Shadow", 0);

}
