#include <ultra64.h>
#include "constants.h"
#include "game/chr/chraction.h"
#include "game/debug.h"
#include "lib/vi.h"
#include "lib/vm.h"
#include "bss.h"
#include "data.h"
#include "types.h"

#define DEBUGMENU_MAIN     0
#define DEBUGMENU_CUTSCENE 1

#define DEBUGOPT_PROPS         32
#define DEBUGOPT_PADS          40
#define DEBUGOPT_44            44
#define DEBUGOPT_ALLTRAINING   29
#define DEBUGOPT_TILES         39
#define DEBUGOPT_ALLLEVELS     13
#define DEBUGOPT_CHRSTATS      65
#define DEBUGOPT_ALLCHALLENGES 67
#define DEBUGOPT_VMSTATS       69
#define DEBUGOPT_MEMINFO       70
#define DEBUGOPT_ALLBUDDIES    94
#define DEBUGOPT_MANPOS        101

s32 var80078150nb[] = {
	15,
	30,
	45,
	59,
	72,
	84,
	95,
	108,
	-1,
};

s32 g_DebugMenuPositions[][2] = {
	{ 8, 2  },
	{ 8, 3  },
	{ 8, 4  },
	{ 8, 5  },
	{ 8, 6  },
	{ 8, 7  },
	{ 8, 8  },
	{ 8, 9  },
	{ 8, 10 },
	{ 8, 11 },
	{ 8, 12 },
	{ 8, 13 },
	{ 8, 14 },
	{ 8, 15 },
	{ 8, 16 },

	{ 25, 2  },
	{ 25, 3  },
	{ 25, 4  },
	{ 25, 5  },
	{ 25, 6  },
	{ 25, 7  },
	{ 25, 8  },
	{ 25, 9  },
	{ 25, 10 },
	{ 25, 11 },
	{ 25, 12 },
	{ 25, 13 },
	{ 25, 14 },
	{ 25, 15 },
	{ 25, 16 },

	{ 40, 2  },
	{ 40, 3  },
	{ 40, 4  },
	{ 40, 5  },
	{ 40, 6  },
	{ 40, 7  },
	{ 40, 8  },
	{ 40, 9  },
	{ 40, 10 },
	{ 40, 11 },
	{ 40, 12 },
	{ 40, 13 },
	{ 40, 14 },
	{ 40, 15 },
	{ 40, 16 },

	{ 57, 2  },
	{ 57, 3  },
	{ 57, 4  },
	{ 57, 5  },
	{ 57, 6  },
	{ 57, 7  },
	{ 57, 8  },
	{ 57, 9  },
	{ 57, 10 },
	{ 57, 11 },
	{ 57, 12 },
	{ 57, 13 },
	{ 57, 14 },
	{ 57, 15 },

	{ 8, 18 },
	{ 8, 19 },
	{ 8, 20 },
	{ 8, 21 },
	{ 8, 22 },
	{ 8, 23 },
	{ 8, 24 },
	{ 8, 25 },
	{ 8, 26 },
	{ 8, 27 },
	{ 8, 28 },
	{ 8, 29 },
	{ 8, 30 },

	{ 25, 18 },
	{ 25, 19 },
	{ 25, 20 },
	{ 25, 21 },
	{ 25, 22 },
	{ 25, 23 },
	{ 25, 24 },
	{ 25, 25 },
	{ 25, 26 },
	{ 25, 27 },
	{ 25, 28 },
	{ 25, 29 },

	{ 40, 18 },
	{ 40, 19 },
	{ 40, 20 },
	{ 40, 21 },
	{ 40, 22 },
	{ 40, 23 },
	{ 40, 24 },
	{ 40, 25 },
	{ 40, 26 },
	{ 40, 27 },
	{ 40, 28 },

	{ 57, 18 },
	{ 57, 19 },
	{ 57, 20 },
	{ 57, 21 },
	{ 57, 22 },
	{ 57, 23 },
	{ 57, 24 },
	{ 57, 25 },
	{ 57, 26 },
	{ 57, 27 },
	{ 57, 28 },
	{ 57, 29 },
	{ 57, 30 },
};

// ntsc-beta rodata at 7f1af170
char *g_DebugMenuLabels[] = {
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"All Levels",
	"-",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"All Training",

	"-",
	"-",
	"props",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"tiles",
	"pads",
	"-",
	"-",
	"-",
	"-",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"chr stats",
	"-",
	"all challenges",
	"-",
	"VM Stats",
	"Mem Info",
	"-",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"all buddies",

	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
	"testing man pos",
	"-",
	"-",
	"-",
	"-",
	"-",
	"-",
};

s32 var80078684nb[] = {
	0, -1,
};

u32 var8007868cnb[] = {
	8, 2,
	8, 3,
	8, 4,
	8, 5,
	8, 6,
	8, 7,
	8, 8,
	8, 9,
	8, 10,
	8, 11,
};

s32 g_DebugCurMenu = DEBUGMENU_MAIN;
s32 var800786e0nb = 0;
s32 var800786e4nb = 0;
s32 var80075d60 = 2;
s32 var80075d64 = 2;
s32 var80075d68 = 2;
s32 var800786f4nb = 2;
s32 var800786f8nb = 0;
bool g_DebugRenderBg = true;
bool g_DebugRenderProps = true;
s32 var80078704nb = 1;
s32 var80078708nb = 0;
bool g_DebugRoomState = false;
s32 var80078710nb = 0;
s32 var80078714nb = 0;
s32 var80078718nb = 0;
s32 var8007871cnb = 0;
bool g_DebugLineMode = false;
s32 var80078724nb = 0;
s32 var80078728nb = 0;
s32 var8007872cnb = 0;
bool g_DebugManPos = false;
bool g_DebugTurboMode = false;
bool g_DebugObjectives = false;
bool g_DebugZBufferDisabled = false;
s32 var80078740nb = 0;
s32 var80078744nb = 0;
s32 var80078748nb = 0;
s32 var8007874cnb = 0;
s32 var80078750nb = 0;
s32 var80078754nb = 0;
s32 var80078758nb = 0;
s32 var8007875cnb = 0;
s32 var80078760nb = 0;
s32 g_DebugSlowMotion = SLOWMOTION_OFF;
s32 var80078768nb = 0;
s32 g_DebugTiles = 0;
s32 g_DebugPads = 0;
s32 var80078774nb = 0;
s32 var80078778nb = 0;
s32 var8007877cnb = 0;
s32 var80078780nb = 0;
s32 var80078784nb = 0;
s32 var80078788nb = 0;
s32 var8007878cnb = 0;
s32 var80078790nb = 0;
bool g_DebugFootsteps = true;
bool g_DebugAllChallenges = false;
bool g_DebugAllBuddies = false;
bool g_DebugAllTraining = false;
s32 var800787a4nb = 0;
s32 var800787a8nb = 0;
bool g_DebugMemInfo = false;
s32 var800787b0nb = 0;
s32 var800787b4nb = 0;
s32 var800787b8nb = 0;
s32 var800787bcnb = 0;
s32 var800787c0nb = 0;
s32 var800787c4nb = 1;
s32 var800787c8nb = 0;
s32 var800787ccnb = 0;
s32 var800787d0nb = 0;
s32 var800787d4nb = 0;
s32 var800787d8nb = 0;
s32 var800787dcnb = 0;
s32 var800787e0nb = 0;
bool g_DebugChrStats = false;
s32 var800787e8nb = 0;
s32 var800787ecnb = 0;
s32 var800787f0nb = 0;
u32 var800787f4nb = 0x80500000;
u32 var800787f8nb = 0x00040000;
u32 var800787fcnb = 0x7f000000;
u32 var80078800nb = 0x7f100000;
u32 var80078804nb = 0x80600000;
u32 var80078808nb = 0x00040000;
u32 var8007880cnb = 0x70000000;
u32 var80078810nb = 0x70100000;
s32 g_DebugScreenshotRgb = 0;
s32 g_DebugScreenshotJpg = 0;
bool g_DebugIsMenuOpen = false;

u32 var80078820nb = 0;
u32 var80078824nb = 0;
u32 var80078828nb = 0;
u32 var8007882cnb = 0;
u32 var80078830nb = 0;
u32 var80078834nb = 0xbf800000;
u32 var80078838nb = 0;
u32 var8007883cnb = 0x3f800000;
u32 var80078840nb = 0;
u32 var80078844nb = 0;
u32 var80078848nb = 0x3f800000;
u32 var8007884cnb = 0;
u32 var80078850nb = 0;
u32 var80078854nb = 0x3f800000;
u32 var80078858nb = 0;
u32 var8007885cnb = 0;
u32 var80078860nb = 0;
u32 var80078864nb = 0;
u32 var80078868nb = 0;
u32 var8007886cnb = 0;
u32 var80078870nb = 0;
u32 var80078874nb = 0;
u32 var80078878nb = 0x3f800000;

const char var7f1af378nb[] = "main";
const char var7f1af380nb[] = "scene %d";

GLOBAL_ASM(
glabel debugUpdateMenu
/*  f119270:	27bdffd8 */ 	addiu	$sp,$sp,-40
/*  f119274:	3c028008 */ 	lui	$v0,0x8008
/*  f119278:	8c4286dc */ 	lw	$v0,-0x7924($v0)
/*  f11927c:	afbf0024 */ 	sw	$ra,0x24($sp)
/*  f119280:	afb30020 */ 	sw	$s3,0x20($sp)
/*  f119284:	afb2001c */ 	sw	$s2,0x1c($sp)
/*  f119288:	afb10018 */ 	sw	$s1,0x18($sp)
/*  f11928c:	1440000b */ 	bnez	$v0,.NB0f1192bc
/*  f119290:	afb00014 */ 	sw	$s0,0x14($sp)
/*  f119294:	3c048008 */ 	lui	$a0,0x8008
/*  f119298:	3c058008 */ 	lui	$a1,0x8008
/*  f11929c:	3c068008 */ 	lui	$a2,0x8008
/*  f1192a0:	24c68150 */ 	addiu	$a2,$a2,-32432
/*  f1192a4:	24a58174 */ 	addiu	$a1,$a1,-32396
/*  f1192a8:	0fc46325 */ 	jal	dmenuSetMenu
/*  f1192ac:	248484d4 */ 	addiu	$a0,$a0,-31532
/*  f1192b0:	3c028008 */ 	lui	$v0,0x8008
/*  f1192b4:	10000032 */ 	beqz	$zero,.NB0f119380
/*  f1192b8:	8c4286dc */ 	lw	$v0,-0x7924($v0)
.NB0f1192bc:
/*  f1192bc:	24010001 */ 	addiu	$at,$zero,0x1
/*  f1192c0:	1441002f */ 	bne	$v0,$at,.NB0f119380
/*  f1192c4:	3c03800a */ 	lui	$v1,0x800a
/*  f1192c8:	3c02800a */ 	lui	$v0,0x800a
/*  f1192cc:	3c04800a */ 	lui	$a0,0x800a
/*  f1192d0:	24847950 */ 	addiu	$a0,$a0,0x7950
/*  f1192d4:	24427888 */ 	addiu	$v0,$v0,0x7888
/*  f1192d8:	24637860 */ 	addiu	$v1,$v1,0x7860
.NB0f1192dc:
/*  f1192dc:	ac620000 */ 	sw	$v0,0x0($v1)
/*  f1192e0:	24420014 */ 	addiu	$v0,$v0,0x14
/*  f1192e4:	0044082b */ 	sltu	$at,$v0,$a0
/*  f1192e8:	1420fffc */ 	bnez	$at,.NB0f1192dc
/*  f1192ec:	24630004 */ 	addiu	$v1,$v1,0x4
/*  f1192f0:	3c118008 */ 	lui	$s1,0x8008
/*  f1192f4:	3c13800a */ 	lui	$s3,0x800a
/*  f1192f8:	26737860 */ 	addiu	$s3,$s3,0x7860
/*  f1192fc:	26318684 */ 	addiu	$s1,$s1,-31100
/*  f119300:	3c057f1b */ 	lui	$a1,0x7f1b
/*  f119304:	ae200000 */ 	sw	$zero,0x0($s1)
/*  f119308:	24a5f378 */ 	addiu	$a1,$a1,-3208
/*  f11930c:	0c004e60 */ 	jal	strcpy
/*  f119310:	8e640000 */ 	lw	$a0,0x0($s3)
/*  f119314:	8e2e0000 */ 	lw	$t6,0x0($s1)
/*  f119318:	3c127f1b */ 	lui	$s2,0x7f1b
/*  f11931c:	2652f380 */ 	addiu	$s2,$s2,-3200
/*  f119320:	25cf0001 */ 	addiu	$t7,$t6,0x1
/*  f119324:	ae2f0000 */ 	sw	$t7,0x0($s1)
/*  f119328:	00008025 */ 	or	$s0,$zero,$zero
.NB0f11932c:
/*  f11932c:	0c006568 */ 	jal	ailistFindById
/*  f119330:	26040c00 */ 	addiu	$a0,$s0,0xc00
/*  f119334:	1040000b */ 	beqz	$v0,.NB0f119364
/*  f119338:	0010c080 */ 	sll	$t8,$s0,0x2
/*  f11933c:	0278c821 */ 	addu	$t9,$s3,$t8
/*  f119340:	8f240004 */ 	lw	$a0,0x4($t9)
/*  f119344:	02402825 */ 	or	$a1,$s2,$zero
/*  f119348:	0c004fc1 */ 	jal	sprintf
/*  f11934c:	02003025 */ 	or	$a2,$s0,$zero
/*  f119350:	8e280000 */ 	lw	$t0,0x0($s1)
/*  f119354:	26100001 */ 	addiu	$s0,$s0,0x1
/*  f119358:	25090001 */ 	addiu	$t1,$t0,0x1
/*  f11935c:	1000fff3 */ 	beqz	$zero,.NB0f11932c
/*  f119360:	ae290000 */ 	sw	$t1,0x0($s1)
.NB0f119364:
/*  f119364:	3c058008 */ 	lui	$a1,0x8008
/*  f119368:	24a5868c */ 	addiu	$a1,$a1,-31092
/*  f11936c:	02602025 */ 	or	$a0,$s3,$zero
/*  f119370:	0fc46325 */ 	jal	dmenuSetMenu
/*  f119374:	02203025 */ 	or	$a2,$s1,$zero
/*  f119378:	3c028008 */ 	lui	$v0,0x8008
/*  f11937c:	8c4286dc */ 	lw	$v0,-0x7924($v0)
.NB0f119380:
/*  f119380:	00025080 */ 	sll	$t2,$v0,0x2
/*  f119384:	3c048008 */ 	lui	$a0,0x8008
/*  f119388:	008a2021 */ 	addu	$a0,$a0,$t2
/*  f11938c:	0fc463df */ 	jal	dmenuSetSelectedOption
/*  f119390:	8c8486e0 */ 	lw	$a0,-0x7920($a0)
/*  f119394:	8fbf0024 */ 	lw	$ra,0x24($sp)
/*  f119398:	8fb00014 */ 	lw	$s0,0x14($sp)
/*  f11939c:	8fb10018 */ 	lw	$s1,0x18($sp)
/*  f1193a0:	8fb2001c */ 	lw	$s2,0x1c($sp)
/*  f1193a4:	8fb30020 */ 	lw	$s3,0x20($sp)
/*  f1193a8:	03e00008 */ 	jr	$ra
/*  f1193ac:	27bd0028 */ 	addiu	$sp,$sp,0x28
);

GLOBAL_ASM(
glabel debug0f1193b0nb
/*  f1193b0:	27bdffe8 */ 	addiu	$sp,$sp,-24
/*  f1193b4:	afbf0014 */ 	sw	$ra,0x14($sp)
/*  f1193b8:	0fc463dc */ 	jal	dmenuGetSelectedOption
/*  f1193bc:	00000000 */ 	sll	$zero,$zero,0x0
/*  f1193c0:	3c0e8008 */ 	lui	$t6,0x8008
/*  f1193c4:	8dce86dc */ 	lw	$t6,-0x7924($t6)
/*  f1193c8:	8fbf0014 */ 	lw	$ra,0x14($sp)
/*  f1193cc:	3c018008 */ 	lui	$at,0x8008
/*  f1193d0:	000e7880 */ 	sll	$t7,$t6,0x2
/*  f1193d4:	002f0821 */ 	addu	$at,$at,$t7
/*  f1193d8:	ac2286e0 */ 	sw	$v0,-0x7920($at)
/*  f1193dc:	03e00008 */ 	jr	$ra
/*  f1193e0:	27bd0018 */ 	addiu	$sp,$sp,0x18
);

void debug0f1193e4nb(void)
{
	// empty
}

void debug0f1193ecnb(void)
{
	// empty
}

GLOBAL_ASM(
glabel debug0f1193f4nb
/*  f1193f4:	3c028008 */ 	lui	$v0,0x8008
/*  f1193f8:	3c038008 */ 	lui	$v1,0x8008
/*  f1193fc:	240e0002 */ 	addiu	$t6,$zero,0x2
/*  f119400:	246386ec */ 	addiu	$v1,$v1,-30996
/*  f119404:	244286f4 */ 	addiu	$v0,$v0,-30988
/*  f119408:	ac4e0000 */ 	sw	$t6,0x0($v0)
/*  f11940c:	ac6e0000 */ 	sw	$t6,0x0($v1)
/*  f119410:	3c018008 */ 	lui	$at,0x8008
/*  f119414:	03e00008 */ 	jr	$ra
/*  f119418:	ac2e86e8 */ 	sw	$t6,-0x7918($at)
);

GLOBAL_ASM(
glabel debug0f11941cnb
/*  f11941c:	27bdffe8 */ 	addiu	$sp,$sp,-24
/*  f119420:	afbf0014 */ 	sw	$ra,0x14($sp)
/*  f119424:	3c048008 */ 	lui	$a0,0x8008
/*  f119428:	248487f4 */ 	addiu	$a0,$a0,-30732
/*  f11942c:	0c00c460 */ 	jal	rmon0002fa30
/*  f119430:	24050002 */ 	addiu	$a1,$zero,0x2
/*  f119434:	0c00c462 */ 	jal	rmon0002fa38
/*  f119438:	240400fa */ 	addiu	$a0,$zero,0xfa
/*  f11943c:	8fbf0014 */ 	lw	$ra,0x14($sp)
/*  f119440:	27bd0018 */ 	addiu	$sp,$sp,0x18
/*  f119444:	03e00008 */ 	jr	$ra
/*  f119448:	00000000 */ 	sll	$zero,$zero,0x0
);

GLOBAL_ASM(
glabel debug0f11944cnb
/*  f11944c:	27bdffe8 */ 	addiu	$sp,$sp,-24
/*  f119450:	afbf0014 */ 	sw	$ra,0x14($sp)
/*  f119454:	0c00c464 */ 	jal	rmon0002fa40
/*  f119458:	00000000 */ 	sll	$zero,$zero,0x0
/*  f11945c:	8fbf0014 */ 	lw	$ra,0x14($sp)
/*  f119460:	27bd0018 */ 	addiu	$sp,$sp,0x18
/*  f119464:	03e00008 */ 	jr	$ra
/*  f119468:	00000000 */ 	sll	$zero,$zero,0x0
);

bool debugProcessInput(s8 stickx, s8 sticky, u16 buttons, u16 buttonsthisframe)
{
	s32 i;
	s32 prev;
	s32 tmp = 3;

	debugUpdateMenu();

	if (g_DebugScreenshotRgb) {
		prev = g_DebugScreenshotRgb++;

		if (tmp == prev) {
			viGrabRgb32();
			g_DebugScreenshotRgb = 0;
			viSet16Bit();
			osViBlack(false);
		}
	}

	if (g_DebugScreenshotJpg) {
		prev = g_DebugScreenshotJpg++;

		if (tmp == prev) {
			viGrabJpg32();
			g_DebugScreenshotJpg = 0;
			viSet16Bit();
			osViBlack(false);
		}
	}

	if (!g_DebugIsMenuOpen) {
		tmp = (buttons & U_CBUTTONS) && (buttons & D_CBUTTONS);
		g_DebugIsMenuOpen = tmp;
		return tmp;
	}

	if (var80075d68 != -2) {
		var800786f4nb = var80075d68;
		var80075d68 = -2;
	}

	if (buttonsthisframe & L_JPAD) {
		dmenuNavigateLeft();
		var80075d68 = -2;
	}

	if (buttonsthisframe & R_JPAD) {
		dmenuNavigateRight();
		var80075d68 = -2;
	}

	if (buttonsthisframe & U_JPAD) {
		dmenuNavigateUp();
		var80075d68 = -2;
	}

	if (buttonsthisframe & D_JPAD) {
		dmenuNavigateDown();
		var80075d68 = -2;
	}

	if (buttonsthisframe & (A_BUTTON | START_BUTTON)) {
		if (g_DebugCurMenu == DEBUGMENU_CUTSCENE) {
			if (dmenuGetSelectedOption() == 0) {
				// Selected "main" from cutscene menu
				g_DebugCurMenu = DEBUGMENU_MAIN;
				func000142d4nb();
				debugUpdateMenu();
			} else {
				cutsceneStart(0xc00 + dmenuGetSelectedOption() - 1);
			}
		} else if (g_DebugCurMenu == DEBUGMENU_MAIN) {
			switch (dmenuGetSelectedOption()) {
			case DEBUGOPT_MANPOS:
				g_DebugManPos ^= 1;
				break;
			case DEBUGOPT_PADS:
				g_DebugPads = (g_DebugPads + 1) % 4;
				break;
			case DEBUGOPT_TILES:
				g_DebugTiles = (g_DebugTiles + 1) % 4;
				break;
			case DEBUGOPT_ALLLEVELS:
				for (i = 0; i < 21; i++) {
					for (tmp = 0; tmp < 3; tmp++) {
						g_GameFile.besttimes[i][tmp] = 7;
					}
				}

				g_AltTitleUnlocked = true;
				break;
			case DEBUGOPT_ALLCHALLENGES:
				g_DebugAllChallenges ^= 1;
				mpDetermineUnlockedFeatures();
				break;
			case DEBUGOPT_ALLBUDDIES:
				g_DebugAllBuddies ^= 1;
				break;
			case DEBUGOPT_ALLTRAINING:
				g_DebugAllTraining ^= 1;

				for (i = 0; i < ARRAYCOUNT(g_GameFile.firingrangescores); i++) {
					g_GameFile.firingrangescores[i] = 0xff;
				}

				gamefileSetFlag(GAMEFILEFLAG_CI_CLOAK_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_DISGUISE_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_XRAY_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_IR_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_RTRACKER_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_DOORDECODER_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_NIGHTVISION_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_CAMSPY_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_ECMMINE_DONE);
				gamefileSetFlag(GAMEFILEFLAG_CI_UPLINK_DONE);
				break;
			case DEBUGOPT_44:
				// This is one of the "-" labels. The value is returned in a
				// getter function but the getter function is never called.
				var800787a4nb ^= 1;
				break;
			case DEBUGOPT_CHRSTATS:
				g_DebugChrStats ^= 1;
				break;
			case DEBUGOPT_PROPS:
				g_DebugRenderProps ^= 1;
				break;
			case DEBUGOPT_VMSTATS:
				g_VmShowStats ^= 1;
				break;
			case DEBUGOPT_MEMINFO:
				g_DebugMemInfo ^= 1;
				break;
			}
		}
	}

	if (buttonsthisframe & START_BUTTON) {
		if (g_DebugIsMenuOpen == true) {
			func000142d4nb();
		}

		g_DebugIsMenuOpen = false;
	}

	debug0f1193b0nb();

	return g_DebugIsMenuOpen;
}

bool debug0f11ed70(void)
{
	return var800786f8nb;
}

bool debugIsBgRenderingEnabled(void)
{
	return g_DebugRenderBg;
}

bool debugIsPropRenderingEnabled(void)
{
	return g_DebugRenderProps;
}

bool debug0f11990cnb(void)
{
	return var80078708nb;
}

bool debugIsManPosEnabled(void)
{
	return g_DebugManPos;
}

void debugSetManPos(bool enabled)
{
	g_DebugManPos = enabled;
}

bool debug0f119930nb(void)
{
	return var80078710nb;
}

bool debug0f11993cnb(void)
{
	return var80078714nb;
}

bool debug0f119948nb(void)
{
	return var80078718nb;
}

bool debug0f119954nb(void)
{
	return var8007871cnb;
}

bool debugIsRoomStateDebugEnabled(void)
{
	return g_DebugRoomState;
}

bool debugIsLineModeEnabled(void)
{
	return g_DebugLineMode;
}

void debugSetLineModeEnabled(bool enabled)
{
	g_DebugLineMode = enabled;
}

bool debugIsTurboModeEnabled(void)
{
	return g_DebugTurboMode;
}

void debugSetTurboMode(bool enabled)
{
	g_DebugTurboMode = enabled;
}

bool debugForceAllObjectivesComplete(void)
{
	return g_DebugObjectives;
}

bool debugIsZBufferDisabled(void)
{
	return g_DebugZBufferDisabled;
}

bool debug0f11ee30(void)
{
	return var80078744nb;
}

bool debug0f11ee38(void)
{
	return var80078750nb;
}

bool debug0f11ee40(void)
{
	return var80078754nb;
}

bool debug0f1199d8nb(void)
{
	return var80078758nb;
}

bool debug0f1199e4nb(void)
{
	return var80078740nb;
}

bool debug0f1199f0nb(void)
{
	return var80078724nb;
}

bool debug0f1199fcnb(void)
{
	return var80078728nb;
}

bool debug0f119a08nb(void)
{
	return var8007872cnb;
}

bool debug0f119a14nb(void)
{
	return var80078748nb;
}

bool debug0f119a20nb(void)
{
	return var8007874cnb;
}

bool debug0f119a2cnb(void)
{
	return var8007875cnb;
}

s32 debugGetSlowMotion(void)
{
	return g_DebugSlowMotion;
}

bool debug0f119a44nb(void)
{
	return var80078768nb;
}

bool debug0f119a50nb(void)
{
	return var80078760nb;
}

s32 debugGetTilesDebugMode(void)
{
	return g_DebugTiles;
}

s32 debugGetPadsDebugMode(void)
{
	return g_DebugPads;
}

bool debug0f119a74nb(void)
{
	return var80078774nb;
}

void debug0f119a80nb(void)
{
	var80078774nb = 0;
}

bool debug0f119a8cnb(void)
{
	return var80078778nb;
}

bool debug0f11eea8(void)
{
	return var80078780nb;
}

bool debug0f119aa4nb(void)
{
	return false;
}

bool debugDangerousProps(void)
{
	return var800787ecnb;
}

bool debug0f119ab8nb(void)
{
	return var800787d8nb;
}

bool debug0f119ac4nb(void)
{
	return var800787dcnb;
}

bool debug0f119ad0nb(void)
{
	return var8007877cnb;
}

bool debugGetMotionBlur(void)
{
	return var80078784nb;
}

bool debug0f119ae8nb(void)
{
	return var80078790nb;
}

u32 dprint()
{
	return var800787b8nb;
}

bool debug0f119b00nb(void)
{
	return var800787c0nb;
}

bool debugAllowEndLevel(void)
{
	return var800787c4nb;
}

bool debug0f119b18nb(void)
{
	return var800787c8nb;
}

bool debug0f119b24nb(void)
{
	return var800787ccnb;
}

bool debug0f119b30nb(void)
{
	return var800787d0nb;
}

bool debug0f119b3cnb(void)
{
	return var800787d4nb;
}

bool debugIsFootstepsEnabled(void)
{
	return g_DebugFootsteps;
}

bool debugIsAllChallengesEnabled(void)
{
	return g_DebugAllChallenges;
}

bool debugIsAllBuddiesEnabled(void)
{
	return g_DebugAllBuddies;
}

bool debugIsAllTrainingEnabled(void)
{
	return g_DebugAllTraining;
}

bool debug0f119b78nb(void)
{
	return var800787a4nb;
}

bool debug0f119b84nb(void)
{
	return var800787a8nb;
}

bool debugIsMemInfoEnabled(void)
{
	return g_DebugMemInfo;
}

bool debug0f119b9cnb(void)
{
	return var800787b0nb;
}

bool debug0f119ba8nb(void)
{
	return var800787bcnb;
}

bool debugIsChrStatsEnabled(void)
{
	return g_DebugChrStats;
}

bool debug0f11ef80(void)
{
	return var800787e8nb;
}

bool debug0f119bccnb(void)
{
	return var800787e0nb;
}

bool debug0f119bd8nb(void)
{
	return var800787f0nb;
}
