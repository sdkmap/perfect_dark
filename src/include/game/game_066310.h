#ifndef IN_GAME_GAME_066310_H
#define IN_GAME_GAME_066310_H
#include <ultra64.h>
#include "types.h"

void alarmActivate(void);
void alarmDeactivate(void);
bool alarmIsActive(void);
bool audioPlayFromWorldPosition(s8 channel_id, s16 audio_id, s32 volumemaybe, struct position *pos, s32 arg4, s32 arg5);
float countdownTimerGetValue(void);
bool countdownTimerIsHidden(void);
bool countdownTimerIsRunning(void);
void countdownTimerSetRunning(bool running);
void countdownTimerSetValue(float frames);
void countdownTimerSetVisible(u32 flag, bool show);
void countdownTimerTick(void);
u32 func0f066310(struct position *pos, u32 arg1);
u32 func0f0665ac(void);
u32 func0f066640(void);
u32 func0f0666cc(void);
u32 func0f0667ac(void);
u32 func0f0667b4(void);
u32 func0f0667bc(void);
u32 func0f0667c4(void);
u32 func0f0667cc(void);
u32 func0f0667d4(void);
u32 func0f0667dc(void);
u32 func0f06680c(void);
u32 func0f06683c(void);
u32 func0f06686c(void);
u32 func0f06689c(void);
u32 func0f0668cc(void);
u32 func0f0668fc(void);
u32 func0f06692c(void);
u32 func0f06695c(void);
u32 func0f06698c(void);
u32 func0f0669bc(void);
u32 func0f0669ec(void);
u32 func0f066a1c(void);
u32 func0f066abc(void);
u32 func0f066b5c(void);
u32 func0f067424(void);
u32 func0f0674bc(void);
u32 func0f0675c8(void);
u32 func0f0677ac(void);
u32 func0f0678f8(void);
u32 func0f06797c(void);
u32 func0f0679ac(void);
u32 func0f067bc4(void);
u32 func0f067d88(void);
u32 func0f067dc4(void);
u32 func0f068018(void);
u32 func0f06803c(void);
u32 func0f0681c0(void);
u32 func0f068218(void);
u32 func0f0682dc(void);
u32 func0f0682fc(void);
u32 func0f068368(void);
u32 func0f06843c(void);
u32 func0f0685e4(void);
u32 func0f068694(void);
u32 func0f0686e0(void);
u32 func0f0686f0(void);
u32 func0f068760(void);
s32 func0f0687b8(struct defaultobj *obj);
u32 func0f0687e4(void);
u32 func0f0688f4(void);
u32 func0f06896c(void);
u32 func0f068998(void);
u32 func0f068aa8(void);
u32 func0f068ad4(void);
u32 func0f068af4(void);
u32 func0f068b14(void);
u32 func0f068c04(void);
u32 func0f068fc8(void);
u32 func0f069144(void);
u32 func0f069630(void);
u32 func0f069710(void);
u32 func0f069750(void);
u32 func0f069850(void);
u32 func0f069b4c(void);
u32 func0f069c1c(void);
u32 func0f069c70(void);
u32 func0f069cd8(void);
u32 func0f069d38(void);
u32 func0f06a170(void);
u32 func0f06a1ec(void);
u32 func0f06a52c(void);
u32 func0f06a550(void);
u32 func0f06a580(void);
u32 func0f06a620(void);
u32 func0f06a730(void);
u32 func0f06ab60(void);
u32 func0f06ac40(void);
void func0f06ac90(struct position *pos);
void setupParseObject(u32 *ptr, bool arg1, bool arg2);
void setupParseObjectWithArg2False(u32 *ptr, bool arg1);
u32 func0f06b36c(void);
u32 func0f06b39c(void);
u32 func0f06b488(void);
u32 func0f06b610(void);
u32 func0f06be44(void);
u32 func0f06bea0(void);
u32 func0f06c28c(void);
u32 func0f06c8ac(void);
u32 func0f06cd00(void);
u32 func0f06d37c(void);
u32 func0f06d90c(void);
u32 func0f06db00(void);
u32 func0f06dbd8(void);
u32 func0f06e87c(void);
u32 func0f06e9cc(void);
u32 func0f06eb4c(void);
u32 func0f06ec20(void);
u32 func0f06ed64(void);
u32 func0f06ef44(void);
u32 func0f06f0a0(void);
u32 func0f06f314(void);
u32 func0f06f504(void);
u32 func0f06f54c(void);
u32 func0f07063c(void);
u32 func0f070698(void);
u32 func0f0706f8(void);
u32 func0f07079c(void);
u32 func0f07092c(void);
u32 func0f070a1c(void);
u32 func0f070bd0(void);
u32 func0f070ca0(void);
void func0f070e2c(struct position *pos, u32 arg1);
u32 func0f070e58(void);
u32 func0f070eac(void);
u32 func0f070f08(void);
void func0f0710ec(struct defaultobj *obj, u32 arg1);
u32 func0f071360(void);
u32 func0f0713e4(void);
u32 func0f0714b8(void);
u32 func0f0720b4(void);
u32 func0f0720d8(void);
u32 func0f072110(void);
u32 func0f072144(void);
u32 func0f072650(void);
u32 func0f0726ec(void);
u32 func0f072774(void);
u32 func0f0727d4(void);
u32 func0f072adc(void);
u32 func0f0732d4(void);
u32 func0f073478(void);
u32 func0f073ae8(void);
u32 func0f073c6c(void);
u32 func0f076f30(void);
u32 func0f07731c(void);
u32 func0f077448(void);
u32 func0f07766c(void);
u32 func0f077c10(void);
u32 func0f078094(void);
u32 func0f0782ac(void);
u32 func0f078930(void);
u32 func0f078a2c(void);
u32 func0f078be0(void);
u32 func0f078c78(void);
u32 func0f079ca4(void);
u32 func0f079f1c(void);
u32 func0f07accc(void);
struct heliobj *func0f07adf4(struct defaultobj *obj);
u32 func0f07ae18(struct heliobj *heli, u32 arg1);
u32 func0f07af34(struct heliobj *heli);
u32 func0f07afd0(void);
u32 func0f07b038(struct heliobj *heli);
void func0f07b078(struct heliobj *heli);
u32 func0f07b0bc(struct heliobj *heli, u32 arg1);
u32 func0f07b0f4(struct heliobj *heli);
float heliGetTimer(struct heliobj *heli);
u32 func0f07b158(void);
u32 func0f07b164(void);
u32 func0f07b290(struct heliobj *heli, u32 arg1);
u32 func0f07b3f0(void);
u32 func0f07ba38(void);
u32 func0f07c12c(void);
u32 func0f07c7b0(void);
u32 func0f07c830(void);
u32 func0f07cacc(void);
u32 func0f07d1e4(void);
u32 func0f07df74(void);
u32 func0f07dfd0(void);
u32 func0f07e058(void);
u32 func0f07e0b8(void);
u32 func0f07e184(void);
u32 func0f07e1fc(void);
u32 func0f07e2cc(void);
u32 func0f07e468(void);
u32 func0f07e474(void);
u32 func0f07e758(void);
u32 func0f07f6d0(void);
u32 func0f07f918(void);
u32 func0f07f924(struct image *image, u32 arg1, struct defaultobj *obj);
u32 func0f07fbf0(void);
u32 func0f07fbf8(void);
u32 func0f0809c4(void);
u32 func0f080f8c(void);
u32 func0f081220(void);
u32 func0f081310(void);
u32 func0f081c18(void);
u32 func0f081ccc(void);
u32 func0f0826cc(void);
void func0f082964(struct attachment *attachment, s32 arg1);
u32 func0f082a1c(void);
u32 func0f082d74(void);
u32 func0f082e84(void);
u32 func0f082f88(struct position *pos);
u32 func0f08307c(void);
u32 func0f083db0(void);
u32 func0f0840ac(void);
u32 func0f0841dc(void);
u32 func0f084594(void);
u32 func0f0849dc(void);
u32 func0f084ce0(void);
u32 func0f084cf0(void);
u32 func0f084e58(void);
u32 func0f084f64(void);
u32 func0f085050(void);
u32 func0f085194(void);
u32 func0f0851ec(void);
u32 func0f085270(void);
void func0f0852ac(struct defaultobj *obj, float damage, struct coord *coord, s32 arg3, s32 arg4);
u32 func0f0859a0(void);
u32 func0f085e00(void);
u32 func0f085eac(void);
u32 func0f086918(void);
u32 func0f0869a8(struct defaultobj *obj);
u32 func0f0869cc(void);
u32 func0f086d60(void);
void func0f086f40(struct position *pos);
u32 func0f087420(void);
u32 func0f087458(void);
u32 func0f08756c(void);
u32 func0f087638(void);
u32 func0f087668(void);
u32 func0f08791c(void);
u32 func0f087b0c(void);
u32 func0f087c0c(void);
u32 func0f087d10(void);
u32 func0f087e40(void);
u32 func0f087fb0(void);
u32 func0f088028(void);
u32 func0f08819c(void);
u32 func0f088254(void);
u32 func0f08841c(void);
u32 func0f0887c8(void);
u32 func0f088840(struct position *pos, s32 arg1);
u32 func0f089014(void);
u32 func0f0899dc(void);
u32 func0f089a94(void);
u32 func0f089c70(void);
u32 func0f089d64(void);
u32 func0f089db8(void);
u32 func0f089dd8(struct chrdata *chr, u32 thing, u32 flags);
u32 func0f089f8c(void);
u32 func0f08a38c(void);
u32 func0f08a724(void);
u32 func0f08a88c(void);
u32 func0f08a9f4(void);
u32 func0f08aa70(void);
u32 func0f08aaf4(u8 arg0);
u32 func0f08ab64(void);
u32 func0f08ab9c(void);
u32 func0f08abd4(void);
u32 func0f08acb0(void);
u32 func0f08adac(void);
u32 func0f08adc8(void);
u32 func0f08ae0c(void);
u32 func0f08ae54(struct defaultobj *obj, struct chrdata *chr);
u32 func0f08b108(void);
u32 func0f08b208(void);
u32 func0f08b25c(void);
u32 func0f08b27c(void);
u32 func0f08b658(void);
u32 func0f08b880(void);
void func0f08b8b8(struct chrdata *chr, u32 arg1);
u32 func0f08b8e8(void);
u32 func0f08bad0(void);
u32 func0f08bb3c(void);
u32 func0f08bb5c(void);
u32 func0f08bc5c(void);
u32 func0f08bcf4(void);
u32 func0f08bd00(void);
u32 func0f08bdd4(void);
u32 func0f08be80(void);
u32 func0f08bf78(void);
u32 func0f08c040(void);
u32 func0f08c190(void);
u32 func0f08c424(void);
u32 func0f08c484(void);
u32 func0f08c54c(struct doorobj *door);
u32 func0f08cb20(void);
u32 func0f08d3dc(void);
u32 func0f08d460(void);
u32 func0f08d4e8(struct doorobj *door);
u32 func0f08d514(void);
u32 func0f08d540(void);
u32 func0f08d784(void);
u32 func0f08daa8(void);
u32 func0f08dd44(void);
u32 func0f08df10(void);
u32 func0f08e0c4(void);
u32 func0f08e1a0(void);
u32 func0f08e214(void);
u32 func0f08e224(void);
u32 func0f08e2ac(void);
u32 func0f08e3a4(void);
u32 func0f08e488(struct defaultobj *obj, u32 arg1);
u32 func0f08e520(void);
u32 func0f08e564(void);
u32 func0f08e5a8(void);
u32 func0f08e6bc(void);
u32 func0f08e794(void);
u32 func0f08e8ac(void);
u32 func0f08e9e4(void);
u32 func0f08ea50(void);
u32 func0f08ed74(void);
u32 func0f08f11c(void);
u32 func0f08f538(void);
u32 func0f08f604(void);
u32 func0f08f968(void);
u32 func0f08fcb8(void);
void func0f08fee8(struct position *pos, s32 arg1);
u32 func0f08fffc(void);
u32 func0f0900c0(void);
u32 func0f09018c(void);
u32 func0f0903d4(void);
u32 func0f09044c(void);
u32 func0f0904e0(void);
u32 func0f090520(void);
u32 func0f09054c(void);
u32 func0f0908b8(void);
u32 func0f090d34(void);
u32 func0f090db4(void);
u32 func0f091030(void);
u32 func0f0910ac(void);
u32 func0f091250(void);
u32 func0f0912dc(void);
u32 func0f091d84(struct defaultobj *obj, u32 arg1, u32 arg2);
s32 setupGetCommandLength(u32 *ptr);
u32 func0f092004(u32 arg0);
u32 func0f092098(struct tag *tag);
u32 func0f092124(void);
u32 func0f0921b4(void);
u32 func0f09220c(void);
u32 func0f092304(void);
u32 func0f09233c(void);
u32 func0f0923d4(void);
u32 func0f092420(void);
u32 func0f092484(void);
u32 func0f092610(void);
u32 func0f0926bc(struct position *pos, u32 arg1, u32 arg2);
s32 func0f0927d4(float arg0, float arg1, float arg2, float arg3, s16 arg4);
u32 func0f092914(void);
u32 func0f09294c(void);
u32 func0f092a98(void);
u32 func0f092b50(void);
u32 func0f092b7c(void);
u32 func0f092c04(void);
u32 func0f093508(void);
u32 func0f093630(void);
u32 func0f093790(void);
u32 func0f0938ec(void);
void func0f0939f8(s32 arg0, struct position *pos, s32 arg2, s32 arg3, s32 arg4, s32 arg5, s32 arg6, s32 arg7, s32 arg8, float arg9, s32 arg10, s32 arg11, float arg12, float arg13, float arg14);
void func0f0942d0(s32 channel);
u32 func0f0943bc(s32 channel);
bool audioPlayFromWorldPosition2(s8 channel_id, s32 audio_id, s32 volumemaybe, struct position *pos, u32 arg4, s32 arg5, s32 arg6, s32 arg7);
u32 func0f0946b0(void);
u32 func0f094940(void);
u32 func0f094b1c(void);
u32 func0f094d78(void);
u32 func0f094ef4(void);
u32 func0f09505c(void);
u32 func0f095200(void);
u32 func0f095278(void);
u32 func0f095320(void);
u32 func0f095330(void);
u32 func0f095340(void);
u32 func0f0953cc(void);
u32 func0f095560(void);
s32 func0f0955f4(void);
u32 func0f095650(u32 arg0);
u32 func0f095684(u32 arg0);
u32 func0f095b64(void);
u32 func0f095bf4(void);
u32 func0f095c04(void);
u32 func0f095d64(void);
u32 func0f095f60(void);
u32 func0f095fd8(void);
u32 func0f096088(void);
u32 func0f096360(void);
u32 func0f0964b4(void);
u32 func0f0965e4(void);
u32 func0f096698(void);
u32 func0f096700(void);
struct position *heliGetTargetPosition(struct heliobj *heli);
struct defaultobj *objFindByTagId(s32 tag_id);
struct tag *tagFindById(s32 tag_id);

#endif
