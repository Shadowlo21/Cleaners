#pragma once
#include "iostream"
#include "Windows.h"
using namespace std;
#define cmd(x) system(x);
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
		std::string taskKillCommand = "TaskKill /F /IM " + std::string(command);
		if (system(taskKillCommand.c_str()) != 0) {
		}
	}
}
