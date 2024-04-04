#pragma once
#include "iostream"
#include "Windows.h"
#include "Encryption/skStr.h"
#include "Encryption/lazy.h"
using namespace std;
#define cmd(x) LI_FN(system)(x);
#define Out(x) printf(x);
const char* TaskKills[]{

	"epicgameslauncher.exe",
	"EpicWebHelper.exe",
	"FortniteClient-Win64-Shipping_EAC.exe",
	"FortniteClient-Win64-Shipping_BE.exe",
	"FortniteLauncher.exe",
	"FortniteClient-Win64-Shipping.exe",
	"EpicGamesLauncher.exe",
	"EasyAntiCheat.exe",
	"BEService.exe",
	"BEServices.exe",
	"RainbowSix.exe",
	"cod.exe",
	"Battle.net.exe",
	"Agent.exe",
	"FiveM.exe",
	"vgtray.exe",
	"BattleEye.exe"
};

void killer() {
	for (const auto& command : TaskKills) {
		// Construct the TaskKill command string
		std::string taskKillCommand = "TaskKill /F /IM " + std::string(command);
		// Execute the command
		if (system(taskKillCommand.c_str()) != 0) {
			// Handle failure to kill process if needed
		}
	}
}