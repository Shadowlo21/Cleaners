#include "R6.h"
#include "Valorant.h"
#include "Fortnite.h"
#include "Fivem.h"
#include "COD.h"
int option;
int Fnoption;
void chooseer() {
	system("cls");
	Out(skCrypt("[1] Deep Clean Fn\n").decrypt());
	Out(skCrypt("[2] Normal Clean Fn\n").decrypt());
	Out(skCrypt("\n Clean -> ").decrypt());
	std::cin >> Fnoption;
	switch (Fnoption)
	{
	case 1:
		hardclean();
		break;
	case 2:
		FNClean();
		break;
	default:
		break;
	}
}
int main() {
	Out(skCrypt("[1] Clean Fivem\n").decrypt());
	Out(skCrypt("[2] Clean Fortnite\n").decrypt());
	Out(skCrypt("[3] Clean R6\n").decrypt());
	Out(skCrypt("[4] Clean Valorant\n").decrypt());
	Out(skCrypt("[5] Clean Cod\n").decrypt());
	Out(skCrypt("\n Clean -> ").decrypt());
	std::cin >> option;
	switch (option)
	{
	case 1:
		FivemClean();
		break;
	case 2:
		chooseer();
		break;
	case 3:
		R6Clean();
		break;
	case 4:
		ValoClean();
		break;
	case 5:
		CODClean();
		break;
	default:
		exit(0);
	}

	return 0;

}