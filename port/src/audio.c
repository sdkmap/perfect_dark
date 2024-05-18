#include <PR/ultratypes.h>
#include <stdio.h>
#include <SDL.h>
#include "platform.h"
#include "config.h"
#include "audio.h"
#include "system.h"

static SDL_AudioDeviceID dev;

static s32 bufferSize = 512;
static s32 queueLimit = 8192;

static f32 offsetFrames = 0.5f;
static u32 offsetBytes;

s32 audioInit(void)
{
	if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) {
		sysLogPrintf(LOG_ERROR, "SDL audio init error: %s", SDL_GetError());
		return -1;
	}

	SDL_AudioSpec want, have;
	SDL_zero(want);
	want.freq = 22020; // TODO: this might cause trouble for some platforms
	want.format = AUDIO_S16SYS;
	want.channels = 2;
	want.samples = bufferSize;
	want.callback = NULL;

	const f32 spf = (f32)want.freq / (PAL ? 50.f : 60.f);
	offsetBytes = offsetFrames * spf * (f32)sizeof(int16_t);

	dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
	if (dev == 0) {
		sysLogPrintf(LOG_ERROR, "SDL_OpenAudio error: %s", SDL_GetError());
		return -1;
	}

	SDL_PauseAudioDevice(dev, 0);

	return 0;
}

s32 audioGetBytesBuffered(void)
{
	u32 count = SDL_GetQueuedAudioSize(dev);

	// pd's audio code decides how many samples of audio to produce based on the amount of audio
	// currently buffered, so we adjust the reported count to be some number of frames in the future
	// to counteract lag; idea shamelessly stolen from mm recomp
	if (offsetBytes) {
		if (count > offsetBytes) {
			count -= offsetBytes;
		} else {
			count = 0;
		}
	}

	return count;
}

s32 audioGetSamplesBuffered(void)
{
	return audioGetBytesBuffered() / (2 * sizeof(s16));
}

void audioSubmitBuffer(const s16 *buf, u32 size)
{
	if (buf && size) {
		if (audioGetSamplesBuffered() < queueLimit) {
			SDL_QueueAudio(dev, buf, size);
		}
	}
}

PD_CONSTRUCTOR static void audioConfigInit(void)
{
	configRegisterInt("Audio.BufferSize", &bufferSize, 0, 1 * 1024 * 1024);
	configRegisterFloat("Audio.OffsetFrames", &offsetFrames, 0.f, 5.f);
	configRegisterInt("Audio.QueueLimit", &queueLimit, 0, 1 * 1024 * 1024);
}
