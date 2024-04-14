#include "R6.h"
#include "Valorant.h"
#include "Fortnite.h"
#include "Fivem.h"
#include "COD.h"
int option;
int Fnoption;
void chooseer() {
	system("cls");
	Out("[1] Deep Clean Fn\n");
	Out("[2] Normal Clean Fn\n");
	Out("\n Clean -> ");
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
	Out("[1] Clean Fivem\n");
	Out("[2] Clean Fortnite\n");
	Out("[3] Clean R6\n");
	Out("[4] Clean Valorant\n");
	Out("[5] Clean Cod\n");
	Out("\n Clean -> ");
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
