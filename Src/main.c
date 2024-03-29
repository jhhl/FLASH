

#include "stm32l4xx_hal.h"
#include "stm32l4xx_ll_usart.h"
#include "math.h"
#include "string.h"

#define PI 3.14159265358979323846


// one of 32, 48, 64, 80
#define CPU_FREQ 64

#define DAC_TIMER_PERIOD ((CPU_FREQ*1000000)/(44100))

#include "lookupTables.h"
#include "defaultPatches.h"

DAC_HandleTypeDef    DacHandle;
UART_HandleTypeDef   huart1;
static DAC_ChannelConfTypeDef sConfig;

void SystemClock_Config(void);
static void TIM6_Config(void);
static void USART1_Init(void);
static void Error_Handler(void);


#define BUFFERSIZE 256
#define POLYPHONY 16

#define DEFAULT_PB_RANGE 2

#define ARPEG_SIZE 32
#define ARPEG_RELEASE_CATCH 10

uint16_t buffer[BUFFERSIZE*2] = {0};
uint16_t buffer2[BUFFERSIZE*2] = {0};

float fm_freq;
float fm_depth;
float fm_decay;
float lfo_freq;
float pwm_freq;
float pwm_depth;
float detuneUp;
float detuneDown;

float releaseRate = -0.0025;
float attackRate = 0.25;
float fm_attack = 2.0;

float outputGain = 1.0;

uint8_t waveParam =0x0F;

struct channel {
  int32_t bend;
  uint8_t volume;
  uint8_t RPNstack[4];
  uint8_t pbSensitivity;
  uint8_t mod;
  float lfo_depth;
  const float* tuning;
  unsigned sustain:1;
} channels[16];

struct oscillator {
  uint8_t channel;
  uint8_t notenumber;

  uint8_t stolen;
  uint8_t stolenChannel;

  float phase;
  float amplitude;
  float fm_phase;
  float fm_amplitude;
  float fm_depth_cache;
  float lfo_phase;
  uint32_t starttime;

  uint16_t velocity;
  unsigned alive:1;
  unsigned released:1;
  unsigned sustained:1;
  unsigned intAttack:1;
} oscillators[POLYPHONY];

// TODO: unionize this with oscillator memory (if we get short of ram)
uint8_t monoNoteStack[ARPEG_SIZE*2];
uint8_t monoNoteEnd=0;
uint8_t monoNoteReleaseStack[ARPEG_SIZE*2];
uint8_t monoNoteReleaseEnd=0;
uint8_t monoNoteNow=0;
uint8_t monoNoteTimer=0;
uint8_t monoNoteReleaseTimer=0;
uint8_t arpegSpeed=10;
float portamento = 1.0;

uint32_t timestamp = 0;
uint8_t targetWave = 0;
uint8_t squareSawSwitch = 0;

float mainLut[8192]={0};

typedef void doOsc_t(struct oscillator* osc, uint16_t* buf);
doOsc_t oscAlgo1;
doOsc_t oscAlgo2;
doOsc_t oscAlgo3_square;
doOsc_t oscAlgo3_saw;
doOsc_t *doOscillator = &oscAlgo1;

typedef void doOscStereo_t(struct oscillator* osc, struct oscillator* osc2, uint16_t* buf, uint16_t* buf2);
doOscStereo_t oscAlgo1Stereo;
doOscStereo_t oscAlgo2Stereo;
doOscStereo_t oscAlgo1Quad;
doOscStereo_t oscAlgo2Quad;
doOscStereo_t *doOscillatorStereo = &oscAlgo1Stereo;

typedef void monophonicAlgo_t(float f, uint16_t* buf, uint16_t* buf2);
monophonicAlgo_t algoMonophonic1;
monophonicAlgo_t algoMonophonic2;
monophonicAlgo_t algoMonophonic3_square;
monophonicAlgo_t algoMonophonic3_saw;
monophonicAlgo_t *monophonicAlgo = &algoMonophonic2;

typedef void doOscPoly4_t(struct oscillator* osc, struct oscillator* osc2, struct oscillator* osc3, struct oscillator* osc4, uint16_t* buf, uint16_t* buf2);
doOscPoly4_t oscAlgo1Poly4;
doOscPoly4_t *doOscillatorPoly4 = &oscAlgo1Poly4;

typedef void generateIntoBuffer_t(uint16_t* buf, uint16_t* buf2);
generateIntoBuffer_t generateIntoBufferFullPoly;
generateIntoBuffer_t generateIntoBufferDualOsc;
generateIntoBuffer_t generateIntoBufferPoly4;
generateIntoBuffer_t generateIntoBufferMonophonic;
generateIntoBuffer_t *generateIntoBuffer = &generateIntoBufferFullPoly;

typedef void noteOn_t(uint8_t n, uint8_t vel, uint8_t chan);
noteOn_t noteOnFullPoly;
noteOn_t noteOnDualOsc;
noteOn_t noteOnPoly4;
noteOn_t noteOnMonophonic;
noteOn_t *noteOn = &noteOnDualOsc;

typedef void noteOff_t(uint8_t n, uint8_t chan);
noteOff_t noteOffFullPoly;
noteOff_t noteOffDualOsc;
noteOff_t noteOffPoly4;
noteOff_t noteOffMonophonic;
noteOff_t *noteOff = &noteOffDualOsc;

// For ease of re-ordering:
enum {
  wave_Sine = 0,
  wave_Hammondish,
  wave_Hammondish2,
  wave_SineCubed,
  wave_HalfSine,
  wave_AbsSine,
  wave_HardSquare,
  wave_SoftSquare,
  wave_FifthSquare,
  wave_OctaveSquare,
  wave_FifthSaw,
  wave_HardSaw,
  wave_SoftSaw,
  wave_VarySaw,
  wave_SineEven,
  wave_AbsSineEven,
  wave_HardPulse,
  wave_SoftPulse,
  wave_HardSyncSine,
  wave_HardSyncSaw
};

enum {
  algo_1_poly = 0,
  algo_1_stereo,
  algo_1_mono,
  algo_1_quad,
  algo_2_poly,
  algo_2_stereo,
  algo_2_mono,
  algo_2_quad,
  algo_3_poly,
  algo_3_mono
  //algo_1_poly4
};

enum {
  cc_modulation = 1,
  cc_portamento = 5,
  cc_sustain = 64,
  cc_lfo_freq = 76,      // MMA Vibrato Rate
  cc_attack_rate = 73,   // MMA Attack Time
  cc_release_rate = 72,  // MMA Release Time
  cc_detune = 15,        //  Undefined
  cc_fm_freq = 20,       //  Undefined
  cc_fm_freq_fine = 21,  //  Undefined
  cc_fm_depth = 22,      //  Undefined
  cc_fm_attack_rate = 75,// MMA Decay Time
  cc_fm_decay_rate = 23, //  Undefined
  cc_algo = 24,          //  Undefined
  cc_waveform = 25,      //  Undefined
  cc_wave_param = 26,    //  Undefined
  cc_arpeg_speed = 27,   //  Undefined
  cc_pwm_depth = 28,     //  Undefined

  cc_output_gain = 88,

  cc_all_sound_off = 120,
  cc_all_notes_off = 123,

  cc_per_channel_tuning = 3,
  cc_all_channels_tuning = 9
  // 6, 38, 100, 101 RPN stuff
};

#define phase_incr(x, y) \
  x += y; \
  if (x >8192.0f) x-=8192.0f;

#define phase_incr_safe(x, y) \
  x += y; \
  while (x >8192.0f) x-=8192.0f;

#define phase_wrap(x) \
  while ( x<0.0f ) x+=8192.0f; \
  while ( x>=8192.0f ) x-=8192.0f;

void setStereo(int stereo){

  // static bool previousState=0;
  // if (stereo == previousState) return;
  // previousState = stereo;

  // Completely stop and reinit the timer, otherwise there is a risk of 
  // desyncing and missing the first/last sample in each buffer
  TIM6_Config(); 

  if (HAL_DAC_Stop_DMA(&DacHandle, DAC_CHANNEL_1) != HAL_OK)
    Error_Handler();
  if (HAL_DAC_Stop_DMA(&DacHandle, DAC_CHANNEL_2) != HAL_OK)
    Error_Handler();

  if (HAL_DAC_ConfigChannel(&DacHandle, &sConfig, DAC_CHANNEL_1) != HAL_OK)
    Error_Handler();
  if (HAL_DAC_Start_DMA(&DacHandle, DAC_CHANNEL_1, (uint32_t *)buffer, BUFFERSIZE*2, DAC_ALIGN_12B_R) != HAL_OK)
    Error_Handler();
  if (HAL_DAC_ConfigChannel(&DacHandle, &sConfig, DAC_CHANNEL_2) != HAL_OK)
    Error_Handler();
  if (HAL_DAC_Start_DMA(&DacHandle, DAC_CHANNEL_2, 
        stereo ? ((uint32_t *)buffer2) : ((uint32_t *)buffer), 
        BUFFERSIZE*2, DAC_ALIGN_12B_R) != HAL_OK)
    Error_Handler();

}

void antialias(unsigned int radius){
// Must be symmetric

  float sum = 0;
  float scale = 1.0/((float)radius);

  for (int i=0; i<radius;i++) {
    sum+=mainLut[i];
  }

  for (int i=0;i<8192;i++) {
    float t = sum*scale;
    sum-=mainLut[i];
    sum+=mainLut[ (i+radius)%8192 ];
    mainLut[i] = t;
  }

}

void setWaveform(uint8_t id, uint8_t param) {
  if (id&0x80) return;

  // %8192 == &8191
  #define waveCheck() if (id!=targetWave || param!=waveParam) return;

  switch (id) {
  default:
  case wave_Sine:
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i];
    }
    goto skipAntiAliasing;

  case wave_Hammondish:

    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i]*0.5;
    }
    #define addSine(m, n) for (uint16_t i=0;i<8192;i++) { mainLut[i]+= sinLut[(i*m)&8191] *n; } \
    waveCheck()

    if (param&(1<<0)) addSine(2, 0.25)
    if (param&(1<<1)) addSine(3, 0.25)
    if (param&(1<<2)) addSine(4, 0.25)
    if (param&(1<<3)) addSine(6, 0.25)
    if (param&(1<<4)) addSine(8, 0.25)
    if (param&(1<<5)) addSine(10, 0.25)
    if (param&(1<<6)) addSine(12, 0.25)

    goto skipAntiAliasing;

  case wave_Hammondish2:

    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i]*0.5;
    }

    if (param&(1<<0)) addSine(2, 0.25)
    if (param&(1<<1)) addSine(3, 0.25)
    if (param&(1<<2)) addSine(4, 0.2)
    if (param&(1<<3)) addSine(6, 0.15)
    if (param&(1<<4)) addSine(8, 0.15)
    if (param&(1<<5)) addSine(10, 0.1)
    if (param&(1<<6)) addSine(12, 0.1)

    goto skipAntiAliasing;

  case wave_SineCubed:
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i]*sinLut[i]*sinLut[i];
    }
    break;

  case wave_HalfSine:
    {
      float normalize = -0.3183098705884235; //2/2pi
      for (uint16_t i=0;i<4096;i++) {
        mainLut[i]=normalize + sinLut[i];
      }
      waveCheck()
      for (uint16_t i=4096;i<8192;i++) {
        mainLut[i]=normalize;
      }
      break;
    }
  case wave_AbsSine:
    {
      float normalize = -0.6366197723675814; //4/2pi
      for (uint16_t i=0;i<8192;i++) {
        mainLut[i]= (sinLut[i] > 0 ? sinLut[i] : -sinLut[i]) +normalize;
      }
      break;
    }
  case wave_HardSquare:
    for (uint16_t i=0;i<4096;i++) {
      mainLut[i]=0.5;
    }
    waveCheck()
    for (uint16_t i=4096;i<8192;i++) {
      mainLut[i]=-0.5;
    }
    break;
  case wave_SoftSquare:
    { 
      uint16_t i=0;
      while (i<512) {
        mainLut[i]= (i/512.0) -0.5;
        i++;
      }
      waveCheck()
      while (i<4096) {
        mainLut[i]=0.5;
        i++;
      }
      waveCheck()
      while (i<4096+512) {
        mainLut[i]= ((512-i+4096)/512.0) -0.5;
        i++;
      }
      waveCheck()
      while (i<8192) {
        mainLut[i]=-0.5;
        i++;
      }
    }
    break;
  case wave_FifthSquare:
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]= (((i*2)&8191) >4192? 0.25:-0.25) + (((i*3)&8191) >4192? 0.25:-0.25);
    }
    break;
  case wave_OctaveSquare:
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]= (((i)&8191) >4192? 0.25:-0.25) + (((i*2)&8191) >4192? 0.25:-0.25);
    }
    break;
  case wave_FifthSaw:
    {
      uint16_t i; float j;
      for (j=-0.25, i=0;   i<4096;i++) { mainLut[i]= j+=1.0/8192.0; }
      for (j=-0.25, i=4096;i<8192;i++) { mainLut[i]= j+=1.0/8192.0; }
      for (j=-0.25, i=0;   i<2730;i++) { mainLut[i]+=j+=0.5/2730.6; }
      for (j=-0.25, i=2730;i<5461;i++) { mainLut[i]+=j+=0.5/2730.6; }
      for (j=-0.25, i=5461;i<8192;i++) { mainLut[i]+=j+=0.5/2730.6; }
    }
    break;
  case wave_HardSaw:
    {
      float j=-0.5;
      for (uint16_t i=0;i<8192;i++) {
        mainLut[i]= j+=1.0/8192.0;
      }
    }
    break;
  case wave_SoftSaw:
    {
      float j=0.5;
      for (uint16_t i=0;i<512;i++) {
        mainLut[i]= j-=1.0/512.0;
      }
      waveCheck()
      for (uint16_t i=512;i<8192;i++) {
        mainLut[i]= j+=1.0/(8192.0-512);
      }
    }
    break;
  case wave_VarySaw:
    {
      float j=0.5, duty=param*32, downslope=1.0/duty, upslope=1.0/(8192.0-duty);
      for (uint16_t i=0;i<duty;i++) {
        mainLut[i]= j-=downslope;
      }
      waveCheck()
      for (uint16_t i=duty;i<8192;i++) {
        mainLut[i]= j+=upslope;
      }
    }
    break;
  case wave_SineEven:
    for (uint16_t i=0;i<4096;i++) {
      mainLut[i]= sinLut[i*2];
    }
    waveCheck()
    for (uint16_t i=4096;i<8192;i++) {
      mainLut[i]= 0.0;
    }
    break;
  case wave_AbsSineEven:
    {
      float normalize = -0.3183098705884235; //2/2pi
      for (uint16_t i=0;i<2048;i++) {
        mainLut[i]= sinLut[i*2] +normalize;
      }
      waveCheck()
      for (uint16_t i=2048;i<4096;i++) {
        mainLut[i]= sinLut[i*2-4096] +normalize;
      }
      waveCheck()
      for (uint16_t i=4096;i<8192;i++) {
        mainLut[i]= normalize;
      }
      break;
    }
  case wave_HardPulse:
    {
      float normalize = -(param+1)/256.0 + 0.5;
      for (uint16_t i=0;i<(param+1)*32;i++) {
        mainLut[i]=normalize + 0.5;
      }
      waveCheck()
      for (uint16_t i=(param+1)*32;i<8192;i++) {
        mainLut[i]=normalize - 0.5;
      }
      break;
    }
  case wave_SoftPulse:
    {
      float normalize = -(param+1)/256.0 + 0.5; //assumption
      uint16_t i=0, duty=(param+1)*28 +512;
      while (i<512) {
        mainLut[i]= (i/512.0) -0.5 +normalize;
        i++;
      }
      waveCheck()
      while (i<duty) {
        mainLut[i]=0.5 +normalize;
        i++;
      }
      waveCheck()
      while (i<duty+512) {
        mainLut[i]= ((512-i+duty)/512.0) -0.5 +normalize;
        i++;
      }
      waveCheck()
      while (i<8192) {
        mainLut[i]=-0.5 +normalize;
        i++;
      }
    }
    break;
  case wave_HardSyncSine:
    {
      float step = (float)param*(1.0/16), j=0.0;

      for (uint16_t i=0;i<8192;i++) {
        mainLut[i]=sinLut[ (uint16_t)j ];
        j+=step;
        if (j>=8192.0) j-=8192.0;
      }
    }
    break;
  case wave_HardSyncSaw:
    {
      float step = (float)param*(1.0/16/8192.0);
      float j=-0.5;
      for (uint16_t i=0;i<8192;i++) {
        mainLut[i]= j;
        j+=step;
        if (j>=0.5) j-=1.0;
      }
    }
    waveCheck()
    antialias(512);
    antialias(512);
    break;
  }
  waveCheck()
  antialias(136);
  waveCheck()
  antialias(136);

skipAntiAliasing:

  if (id==targetWave && param==waveParam) targetWave|=0x80;
}

uint8_t fm_freq_cc[] = {0,0}, attackrate_cc=0, releaserate_cc=0, fm_attack_cc=0;
void parameterChange(uint8_t chan, uint8_t cc, uint8_t i){

  #define set_fm_freq() fm_freq=(float)((fm_freq_cc[0]<<7) + fm_freq_cc[1])/1024;
  #define set_fm_attack() fm_attack = (fm_depth * 0.001/((float)fm_attack_cc+0.5));
  #define set_attack_rate() attackRate = (0.128/(float)(attackrate_cc+1)) * outputGain;
  #define set_release_rate() releaseRate = -(0.128/(float)(releaserate_cc+1)) * outputGain;

  switch (cc) {
    case cc_modulation:
      channels[chan].mod = i;
      channels[chan].lfo_depth = (float)(i*8);
      break;
    case cc_portamento:
      portamento = (float)(128-i) /128.0;
      break;

    case cc_lfo_freq:
      lfo_freq = i==127? 0.0: 204.8 + (float)(i*4);
      pwm_freq = (float)(i*i)*0.04419368838737677; //[0..712.8]
      break;

    case cc_attack_rate:
      attackrate_cc=i;
      set_attack_rate()
      break;
    case cc_release_rate:
      releaserate_cc=i;
      set_release_rate()
      break;

    case cc_output_gain:
      outputGain = i==0 ? 1.0 : i*0.125;
      set_attack_rate()
      set_release_rate()
      break;

    case cc_detune:{
        float detune= ((float)(i)/10160.0);
        detuneUp = 1.0 + detune;
        detuneDown = 1.0 - detune;
      }
      break;

    case cc_fm_freq:
      fm_freq_cc[0] = i;
      set_fm_freq()
      break;
    case cc_fm_freq_fine:
      fm_freq_cc[1] = i;
      set_fm_freq()
      break;
    case cc_fm_depth:
      fm_depth=(float)(i*25)/127;
      set_fm_attack()
      break;
    case cc_fm_attack_rate:
      fm_attack_cc=i;
      set_fm_attack()
      break;
    case cc_pwm_depth:
      pwm_depth=(float)(i*1795)/127;
      break;

    case cc_fm_decay_rate:
      fm_decay=1.0 - ((float)(i*i)/25400000);
      break;
    case cc_algo:
      {
        for (int i=POLYPHONY;i--;) oscillators[i].alive=0;
        oscillators[0].released=1;
        oscillators[0].amplitude=0;
        monoNoteNow=monoNoteEnd=monoNoteReleaseEnd=0;
        monoNoteTimer=254;
        squareSawSwitch=0;
        switch (i){
          case algo_1_poly: default:
            doOscillator = &oscAlgo1;
            generateIntoBuffer = &generateIntoBufferFullPoly;
            noteOn = &noteOnFullPoly;
            noteOff = &noteOffFullPoly;
            setStereo(0);
            break;

          case algo_1_stereo:
            doOscillatorStereo = &oscAlgo1Stereo;
            generateIntoBuffer = &generateIntoBufferDualOsc;
            noteOn = &noteOnDualOsc;
            noteOff = &noteOffDualOsc;
            setStereo(1);
            break;
          case algo_2_poly:
            doOscillator = &oscAlgo2;
            generateIntoBuffer = &generateIntoBufferFullPoly;
            noteOn = &noteOnFullPoly;
            noteOff = &noteOffFullPoly;
            setStereo(0);
            break;

          case algo_2_stereo:
            doOscillatorStereo = &oscAlgo2Stereo;
            generateIntoBuffer = &generateIntoBufferDualOsc;
            noteOn = &noteOnDualOsc;
            noteOff = &noteOffDualOsc;
            setStereo(1);
            break;

          case algo_1_mono:
            monophonicAlgo = &algoMonophonic1;
            generateIntoBuffer = &generateIntoBufferMonophonic;
            noteOn = &noteOnMonophonic;
            noteOff = &noteOffMonophonic;
            setStereo(1);
            break;

          case algo_2_mono:
            monophonicAlgo = &algoMonophonic2;
            generateIntoBuffer = &generateIntoBufferMonophonic;
            noteOn = &noteOnMonophonic;
            noteOff = &noteOffMonophonic;
            setStereo(1);
            break;

          case algo_3_mono:
            oscillators[0].phase=8192.0;
            squareSawSwitch = 1;
            monophonicAlgo = (waveParam==0) ? &algoMonophonic3_saw : &algoMonophonic3_square;
            generateIntoBuffer = &generateIntoBufferMonophonic;
            noteOn = &noteOnMonophonic;
            noteOff = &noteOffMonophonic;
            setStereo(1);
            break;
          case algo_3_poly:
            for (int i=POLYPHONY;i--;) {oscillators[i].phase=8192.0;}
            squareSawSwitch = 1;
            doOscillator = (waveParam==0) ? &oscAlgo3_saw : &oscAlgo3_square;
            generateIntoBuffer = &generateIntoBufferFullPoly;
            noteOn = &noteOnFullPoly;
            noteOff = &noteOffFullPoly;
            setStereo(0);
            break;
          // case algo_1_poly:
            // doOscillatorPoly4 = &oscAlgo1Poly4;
            // generateIntoBuffer = &generateIntoBufferPoly4;
            // noteOn = &noteOnPoly4;
            // noteOff = &noteOffPoly4;
            // setStereo(1);
            // break;

          case algo_1_quad:
            doOscillatorStereo = &oscAlgo1Quad;
            generateIntoBuffer = &generateIntoBufferDualOsc;
            noteOn = &noteOnDualOsc;
            noteOff = &noteOffDualOsc;
            setStereo(1);
            break;
          case algo_2_quad:
            doOscillatorStereo = &oscAlgo2Quad;
            generateIntoBuffer = &generateIntoBufferDualOsc;
            noteOn = &noteOnDualOsc;
            noteOff = &noteOffDualOsc;
            setStereo(1);
            break;

        }
      }
      break;

    case cc_waveform:
      targetWave = i;
      break;
    case cc_wave_param:
      waveParam = i;
        if (squareSawSwitch) {
          doOscillator = (waveParam==0) ? &oscAlgo3_saw : &oscAlgo3_square;
          monophonicAlgo = (waveParam==0) ? &algoMonophonic3_saw : &algoMonophonic3_square;
        } else targetWave&=0x7F;
      break;
    case cc_arpeg_speed:
      arpegSpeed=(i>>2);
      break;




    case cc_sustain: 
      channels[chan].sustain = (i>63);
      if (channels[chan].sustain == 0) {//pedal released
        if (noteOff == &noteOffMonophonic) {
          if (oscillators[0].released) break;

          for (int i=monoNoteEnd-2;i>=0;i-=2) {
            if (monoNoteStack[i]&0x80 && monoNoteStack[i+1]==chan) {
              for (int j=i; j<monoNoteEnd;j++) {
                monoNoteStack[j]=monoNoteStack[j+2];
              }
              monoNoteEnd-=2;
            }
          }

          if (monoNoteEnd) {
            monoNoteReleaseTimer=ARPEG_RELEASE_CATCH;
            if (monoNoteNow>=monoNoteEnd) monoNoteNow=monoNoteEnd-2;
            oscillators[0].notenumber=monoNoteStack[monoNoteNow]&0x7f;
          } else {
            oscillators[0].released=1;
            memcpy(monoNoteStack, monoNoteReleaseStack, monoNoteReleaseEnd);
            monoNoteEnd=monoNoteReleaseEnd;
          }

        } else {
          //loop through oscillators and release any with sustained=true
          for (uint8_t i=POLYPHONY; i--;) {
            if (oscillators[i].sustained && oscillators[i].alive && !oscillators[i].released && oscillators[i].channel==chan) {
              oscillators[i].released=1;
              oscillators[i].sustained=0;
            }
          }
        }
      }
      break;


    case cc_all_sound_off:
    case cc_all_notes_off: {
      for (int i=POLYPHONY;i--;) oscillators[i].alive=0;
      oscillators[0].released=1;
      oscillators[0].amplitude=0;
      monoNoteNow=monoNoteEnd=monoNoteReleaseEnd=0;
      monoNoteTimer=254;
    } break;

    case 101: channels[chan].RPNstack[0]=i; break;
    case 100: channels[chan].RPNstack[1]=i; break;
    case 38:  channels[chan].RPNstack[3]=i; break; //not used yet
    case 6:   channels[chan].RPNstack[2]=i; 
      if (channels[chan].RPNstack[0]==0 && channels[chan].RPNstack[1]==0) {//Pitch bend sensitivity

        // For now, only allow changing bend range in 12ET mode
        if (channels[chan].tuning==&fEqualLookup[0]) {
          channels[chan].pbSensitivity = i; // should this be limited to 24 ?
        }
      }
      break;

    case cc_per_channel_tuning:
      if (i == 0) {
          channels[chan].pbSensitivity=DEFAULT_PB_RANGE;
          channels[chan].tuning = &fEqualLookup[0];
      } else if (i<=16) {
          channels[chan].pbSensitivity=1;
          channels[chan].tuning = &fTuningTables[i-1][0];
      }
      break;

    case cc_all_channels_tuning:
      if (i == 0) {
        for (int j=0;j<16;j++) {
          channels[j].pbSensitivity=DEFAULT_PB_RANGE;
          channels[j].tuning = &fEqualLookup[0];
        }
      } else if (i<=16){
        for (int j=0;j<16;j++) {
          channels[j].pbSensitivity=1;
          channels[j].tuning = &fTuningTables[i-1][0];
        }
      } else {
        for (int j=0;j<16;j++) {
          channels[j].pbSensitivity=1;
          channels[j].tuning = &fTuningTables[j][0];
        }
      }
      break;
  }
}

void loadPatch(uint8_t p){
  // Link between byte position in the patch file and CC number
  const uint8_t paramMap[64] = {
    cc_modulation, // Must be first as it's loaded per-channel
    cc_algo,
    cc_fm_freq,
    cc_fm_freq_fine,
    cc_fm_depth,
    cc_fm_attack_rate,
    cc_fm_decay_rate,
    cc_attack_rate,
    cc_release_rate,
    cc_waveform,
    cc_wave_param,
    cc_lfo_freq,
    cc_detune, 
    cc_arpeg_speed,
    cc_portamento,
    cc_output_gain,
    cc_pwm_depth
  };
  for (uint8_t i=0;i<16;i++)
    parameterChange(i, cc_modulation, bPatches[p][0]);

  for (uint8_t i=1;i<64;i++)
    parameterChange(0, paramMap[i], bPatches[p][i]);
}

inline void trigger_int_envelope(struct oscillator* osc, uint8_t vel, uint8_t n){

  osc->intAttack=1;
  osc->fm_amplitude=0;
  osc->fm_depth_cache = (vel/127.0)*fm_depth;// * fEqualLookup[ n ];

}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
void noteOnFullPoly(uint8_t n, uint8_t vel, uint8_t chan) {

// find a free oscillator
// set it up
  uint8_t i, oldest, similar = 255;
  uint32_t mintime=0xffffffff;

  for (i=POLYPHONY; i--;) {
    if (0==oscillators[i].alive) break;
    if (oscillators[i].notenumber == n) {
      similar = i;
    }
    if (oscillators[i].starttime < mintime) {
      oldest = i;
      mintime = oscillators[i].starttime;
    }
  }


  if (oscillators[i].alive!=0) {
    i = (similar==255)?oldest:similar;
    oscillators[i].stolen=n;
    oscillators[i].stolenChannel=chan;
  } else {
    oscillators[i].notenumber=n;
    oscillators[i].channel=chan;

    trigger_int_envelope(&oscillators[i], vel, n);
  }

  oscillators[i].alive = 1;
  oscillators[i].starttime = timestamp++;
  oscillators[i].released = 0;
  oscillators[i].sustained = 0;
  oscillators[i].velocity=vel * outputGain;

  

}
#pragma GCC diagnostic pop

void noteOffFullPoly(uint8_t n, uint8_t chan) {
// find oscillator with same channel and note number
// kill it

  for (uint8_t i=POLYPHONY; i--;) {
    if (oscillators[i].alive && !oscillators[i].released && oscillators[i].notenumber==n && oscillators[i].channel==chan && !oscillators[i].sustained) {
      if (channels[chan].sustain) {
        oscillators[i].sustained=1;
      } else {
        oscillators[i].released=1;
      }
      break;
    }
  }

}

void noteOnDualOsc(uint8_t n, uint8_t vel, uint8_t chan) {

// find a free oscillator
// set it up
  uint8_t i, oldest, similar=255;
  uint32_t mintime=0xffffffff;

  for (i=0; i<POLYPHONY; i+=2) {
    if (0==oscillators[i].alive) break;
    if (oscillators[i].notenumber == n) {
      similar = i;
    }
    if (oscillators[i].starttime < mintime) {
      oldest = i;
      mintime = oscillators[i].starttime;
    }
  }

  if (i==POLYPHONY) {
    i = (similar==255)?oldest:similar;
    oscillators[i].stolen=n;
    oscillators[i].stolenChannel=chan;
  } else {
    oscillators[i].notenumber=n;
    oscillators[i].channel=chan;

    oscillators[i].stolen=0;

    trigger_int_envelope(&oscillators[i], vel, n);

  }

  oscillators[i].alive = 1;
  oscillators[i].starttime = timestamp++;
  oscillators[i].released = 0;
  oscillators[i].sustained = 0;
  oscillators[i].velocity=vel * outputGain;



}

void noteOffDualOsc(uint8_t n, uint8_t chan) {
// find oscillator with same channel and note number
// kill it

  for (uint8_t i=0; i<POLYPHONY; i+=2) {
    if ( oscillators[i].alive 
     && !oscillators[i].released 
     && oscillators[i].notenumber==n 
     && oscillators[i].channel==chan 
     && !oscillators[i].sustained
     ){
      if (channels[chan].sustain) {
        oscillators[i].sustained=1;
      } else {
        oscillators[i].released=1;
      }
      break;
    }
  }

}

void noteOnMonophonic(uint8_t n, uint8_t vel, uint8_t chan) {

  if (oscillators[0].released) {
    monoNoteEnd=0;
    //oscillators[0].fm_amplitude = (vel/127.0)*fm_depth * fEqualLookup[ n ];
    trigger_int_envelope(&oscillators[0], vel, n);
  }

  for (int i=0; i<monoNoteEnd; i+=2){
    if ((monoNoteStack[i]&0x7F) == n && monoNoteStack[i+1]==chan) {
      monoNoteStack[i] = n;
      monoNoteNow=i;
      oscillators[0].notenumber=n;
      oscillators[0].velocity=vel * outputGain;
      oscillators[0].channel=chan;
      return;
    }
  }
  if (monoNoteEnd==ARPEG_SIZE) return;

  monoNoteNow = monoNoteEnd;
  monoNoteStack[monoNoteEnd] = n;
  monoNoteStack[monoNoteEnd+1] = chan;
  monoNoteEnd+=2;
  monoNoteStack[monoNoteEnd]=0;
  monoNoteTimer=0;

  oscillators[0].notenumber=n;
  oscillators[0].velocity=vel * outputGain;
  oscillators[0].channel=chan;
  oscillators[0].released=0;

  memcpy(monoNoteReleaseStack, monoNoteStack, monoNoteEnd+1);
  monoNoteReleaseEnd=monoNoteEnd;
  monoNoteReleaseTimer=0;
}
void noteOffMonophonic(uint8_t n, uint8_t chan) {

  if (channels[chan].sustain) {
    for (int i=0; i<monoNoteEnd; i+=2){
      if (monoNoteStack[i] == n) monoNoteStack[i]|=0x80;
    }
    return;
  }

  monoNoteReleaseTimer=ARPEG_RELEASE_CATCH;

  for (int i=0; i<monoNoteEnd; i+=2){
    if (monoNoteStack[i] == n && monoNoteStack[i+1]==chan) {
      while (i<monoNoteEnd+1) {
        monoNoteStack[i]=monoNoteStack[i+2];
        i++;
      }
      monoNoteEnd-=2;
    }
  }
  if (monoNoteEnd>0) {
    if (monoNoteNow>=monoNoteEnd) monoNoteNow=monoNoteEnd-2;
    oscillators[0].notenumber=monoNoteStack[monoNoteNow]&0x7f;
    oscillators[0].channel=monoNoteStack[monoNoteNow+1];
  } else {
    oscillators[0].released=1;
    memcpy(monoNoteStack, monoNoteReleaseStack, monoNoteReleaseEnd+1);
    monoNoteEnd=monoNoteReleaseEnd;
  }
}

void noteOnPoly4(uint8_t n, uint8_t vel, uint8_t chan) {
// Identical to dual osc except for loop increment
  uint8_t i, oldest, similar=255;
  uint32_t mintime=0xffffffff;

  for (i=0; i<POLYPHONY; i+=4) {
    if (0==oscillators[i].alive) break;
    if (oscillators[i].notenumber == n) {
      similar = i;
    }
    if (oscillators[i].starttime < mintime) {
      oldest = i;
      mintime = oscillators[i].starttime;
    }
  }

  if (i==POLYPHONY) {
    i = (similar==255)?oldest:similar;
    oscillators[i].stolen=n;
    oscillators[i].stolenChannel=chan;
  } else {
    oscillators[i].notenumber=n;
    oscillators[i].channel=chan;
    oscillators[i].stolen=0;
    trigger_int_envelope(&oscillators[i], vel, n);
  }

  oscillators[i].alive = 1;
  oscillators[i].starttime = timestamp++;
  oscillators[i].released = 0;
  oscillators[i].sustained = 0;
  oscillators[i].velocity=vel * outputGain;
}

void noteOffPoly4(uint8_t n, uint8_t chan) {
// Identical to dual osc except for loop increment
  for (uint8_t i=0; i<POLYPHONY; i+=4) {
    if ( oscillators[i].alive 
     && !oscillators[i].released 
     && oscillators[i].notenumber==n 
     && oscillators[i].channel==chan 
     && !oscillators[i].sustained
     ){
      if (channels[chan].sustain) {
        oscillators[i].sustained=1;
      } else {
        oscillators[i].released=1;
      }
      break;
    }
  }

}

int32_t random(void) {
  static uint32_t seed = 123456;
  return seed = seed * 16807 % 0x7FFFFFFF;
}


void USART1_IRQHandler(void) {
  static uint8_t status=0;
  static uint8_t bytenumber =0;
  static uint8_t bytetwo = 0;

  uint8_t i = LL_USART_ReceiveData8(USART1);

  if (i==0xFF) NVIC_SystemReset();
  if (i>=0xF8) return; //system real-time

  if (i & 0x80) {
    status = i;
    bytenumber = 1;
  } else {
    uint8_t chan = status&0x0F;
    if (synthConfig.channel!=255 && synthConfig.channel != chan) return;

    if (bytenumber == 1) { // Check two-byte messages
      switch (status&0xF0) {

        case 0xD0: //After-touch
          if (i>=channels[chan].mod)
            channels[chan].lfo_depth = (float)(i*8);
          break;

        case 0xC0: //Program Change
          loadPatch(i);
          status = 0;
          break;

        default:
          bytetwo = i;
          bytenumber = 2;
      }
    } else if (bytenumber == 2){

      switch (status&0xF0) {

        case 0x90: //Note on
          if (i == 0) noteOff(bytetwo, chan); //running status uses velocity=0 for noteoff
          else {
            if (bytetwo >= channels[chan].pbSensitivity && bytetwo <= 127-channels[chan].pbSensitivity)
              noteOn(bytetwo, i, chan);
          }
          break;

        case 0x80: //Note off
          noteOff(bytetwo, chan);
          break;

        case 0xE0: //Pitch bend
          channels[chan].bend = channels[chan].pbSensitivity * (((i<<7) + bytetwo) - 0x2000);
          break;

        case 0xB0: // Continuous controller
          parameterChange(chan, bytetwo, i);
          break;
      }

      bytenumber =1; //running status
    }
  }


}

inline float calculateFrequency(struct oscillator* osc){

  int lfo;
  if (lfo_freq == 0.0) {
    //max wobble 0.5 semitones:
    // 0x1000/(((0x7FFFFFFF>>2)-0x0FFFFFFF)*1024) = 1.4901161193847656e-8
    lfo = ((float)((random()>>2)-0x0FFFFFFF) * channels[osc->channel].lfo_depth * 1.4901161193847656e-8);
  } else {
    lfo = sinLut[(int)(osc->lfo_phase)] * channels[osc->channel].lfo_depth;
  }

  float f;

  if (channels[osc->channel].pbSensitivity == 1) {
    // We should probably enforce that LFO depth is never more than a semitone
    f = channels[osc->channel].tuning[ osc->notenumber]
      * bLookup14bit1semitone[ channels[osc->channel].bend +0x2000 ]
      * bLookup14bit1semitone[ lfo  +0x2000 ];
  } else {
    int32_t bend = channels[osc->channel].bend + lfo ;
    f = channels[osc->channel].tuning[ osc->notenumber + (bend>>13) ]
      * bLookup14bit1semitone[ (bend&0x1FFF) +0x2000 ];
  }
  return f;
}

static inline float calculateFrequencyMonophonic(struct oscillator* osc){
  // Lots of repetition here - but it's the only way to ensure that portamento happens before LFO.
  static float f=0.0;

  phase_incr(osc->lfo_phase, lfo_freq)
  int lfo;
  if (lfo_freq == 0.0) {
    //max wobble 0.5 semitones:
    // 0x1000/(((0x7FFFFFFF>>2)-0x0FFFFFFF)*1024) = 1.4901161193847656e-8
    lfo = ((float)((random()>>2)-0x0FFFFFFF) * channels[osc->channel].lfo_depth * 1.4901161193847656e-8);
  } else {
    lfo = sinLut[(int)(osc->lfo_phase)] * channels[osc->channel].lfo_depth;
  }

  float ft;

  if (channels[osc->channel].pbSensitivity == 1) {
    ft = channels[osc->channel].tuning[ osc->notenumber]
      * bLookup14bit1semitone[ channels[osc->channel].bend +0x2000 ];
  } else {
    ft = channels[osc->channel].tuning[ osc->notenumber + (channels[osc->channel].bend>>13) ]
      * bLookup14bit1semitone[ (channels[osc->channel].bend&0x1FFF) +0x2000 ];
  }

  f += (ft-f)*portamento;

  return f * bLookup14bit1semitone[ lfo  +0x2000 ];
}


// Generate a cachable envelope delta. Warp the edges so that state transitions always happen at the buffer boundaries
inline float envelope(struct oscillator* osc){
  float d = 0.0;

  if (osc->stolen) {
    return -osc->amplitude /BUFFERSIZE;
  }

  if (osc->released) {
    d = releaseRate;
    if (osc->amplitude < -releaseRate*BUFFERSIZE) {
      d = - osc->amplitude / BUFFERSIZE;
      osc->alive =0;
    }
  } else if (osc->amplitude < osc->velocity){
    d = attackRate;
    if (osc->amplitude > osc->velocity - attackRate*BUFFERSIZE) {
      d = (osc->velocity - osc->amplitude)/BUFFERSIZE;
    }
  }

  return d;
}

// Alternate envelope that allows zero-length slopes
#define envelopeZero_setup() if (osc->released && releaserate_cc==0) {osc->alive=0;osc->amplitude=0;osc->phase=8192.0; return;}

inline float envelopeZero(struct oscillator* osc){
  float d = 0.0;

  if (osc->stolen) {
    return -osc->amplitude /BUFFERSIZE;
  }

  if (osc->released) {
    d = releaseRate;
    if (osc->amplitude < -releaseRate*BUFFERSIZE) {
      d = - osc->amplitude / BUFFERSIZE;
      osc->alive =0;
    }
  } else {
    if (osc->amplitude < osc->velocity){
      if (attackrate_cc==0) {osc->amplitude = osc->velocity; return 0.0;}
      d = attackRate;
      if (osc->amplitude > osc->velocity - attackRate*BUFFERSIZE) {
        d = (osc->velocity - osc->amplitude)/BUFFERSIZE;
      }
    }
  }

  return d;
}

inline float intEnvelope(struct oscillator* osc){
  float d;
  if (osc->intAttack) {
    d = fm_attack;
    if (osc->fm_amplitude +fm_attack*BUFFERSIZE>=osc->fm_depth_cache) {
      d = (osc->fm_depth_cache - osc->fm_amplitude) / BUFFERSIZE;
      osc->intAttack=0;
    }
  } else {
    d = - osc->fm_amplitude*(1-fm_decay);
  }

  return d;
}

inline void graceful_theft(struct oscillator* osc){
  if (osc->stolen) {
    osc->amplitude=0.0;

    osc->channel = osc->stolenChannel;
    osc->notenumber = osc->stolen;
    osc->stolen = 0;

    trigger_int_envelope(osc, osc->velocity, osc->notenumber);
  }
}


void oscAlgo1(struct oscillator* osc, uint16_t* buf){

  phase_incr(osc->lfo_phase, lfo_freq)

  float f = calculateFrequency(osc);
  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr_safe(osc->fm_phase, fm_freq*f)

    osc->fm_amplitude += preAmpDiff;

    osc->phase += f  + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude *f;
    phase_wrap(osc->phase)

    buf[i] += mainLut[(int)(osc->phase)] * osc->amplitude;

  }

  graceful_theft(osc);
}

void oscAlgo2(struct oscillator* osc, uint16_t* buf){

  phase_incr(osc->lfo_phase, lfo_freq)

  float f = calculateFrequency(osc);
  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr(osc->phase, f)

    osc->fm_amplitude += preAmpDiff;

    osc->fm_phase = mainLut[(int)(osc->phase)] * osc->fm_amplitude *4096.0;
    phase_wrap(osc->fm_phase)

    buf[i] += sinLut[(int)(osc->fm_phase)] * osc->amplitude;

  }

  graceful_theft(osc);
}

void oscAlgo1Stereo(struct oscillator* osc, struct oscillator* osc2, uint16_t* buf, uint16_t* buf2) {

  phase_incr(osc->lfo_phase, lfo_freq)

  float fr = calculateFrequency(osc)*detuneUp;
  float fl = calculateFrequency(osc)*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr_safe(osc->fm_phase, fm_freq*fl)
    phase_incr_safe(osc2->fm_phase,fm_freq*fr)

    osc->fm_amplitude += preAmpDiff;

    osc->phase  += fl + sinLut[(int)( osc->fm_phase)]*osc->fm_amplitude *fl;
    osc2->phase += fr + sinLut[(int)(osc2->fm_phase)]*osc->fm_amplitude *fr;
    phase_wrap(osc->phase)
    phase_wrap(osc2->phase)

    buf[i] += mainLut[(int)(osc->phase)] * osc->amplitude;
    buf2[i]+= mainLut[(int)(osc2->phase)]* osc->amplitude;

  }

  graceful_theft(osc);
}


void oscAlgo2Stereo(struct oscillator* osc, struct oscillator* osc2, uint16_t* buf, uint16_t* buf2){

  phase_incr(osc->lfo_phase, lfo_freq)

  float fr = calculateFrequency(osc)*detuneUp;
  float fl = calculateFrequency(osc)*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr(osc->phase, fl)
    phase_incr(osc2->phase, fr)

    osc->fm_amplitude += preAmpDiff;

    osc->fm_phase  = mainLut[(int)( osc->phase)] * osc->fm_amplitude *4096.0;
    osc2->fm_phase = mainLut[(int)(osc2->phase)] * osc->fm_amplitude *4096.0;

    phase_wrap(osc->fm_phase)
    phase_wrap(osc2->fm_phase)

    buf[i] += sinLut[(int)( osc->fm_phase)] * osc->amplitude;
    buf2[i]+= sinLut[(int)(osc2->fm_phase)] * osc->amplitude;

  }

  graceful_theft(osc);
}

void oscAlgo1Quad(struct oscillator* osc, struct oscillator* osc2, uint16_t* buf, uint16_t* buf2) {

  // reuse "unused" floats in second oscillator
  // lfo_phase, fm_phase

  phase_incr(osc->lfo_phase, lfo_freq)

  float fr = calculateFrequency(osc)*detuneUp;
  float fl = calculateFrequency(osc)*detuneDown;
  float f3 = calculateFrequency(osc)*detuneUp*detuneUp;
  float f4 = calculateFrequency(osc)*detuneDown*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr_safe(osc->fm_phase, fm_freq*fr)

    osc->fm_amplitude += preAmpDiff;

    osc->phase      += fl + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude *fl;
    osc2->lfo_phase += f3 + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude *f3;
    osc2->phase     += fr + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude *fr;
    osc2->fm_phase  += f4 + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude *f4;
    phase_wrap(osc->phase)
    phase_wrap(osc2->phase)
    phase_wrap(osc2->lfo_phase)
    phase_wrap(osc2->fm_phase)

    buf[i] += (mainLut[(int)(osc->phase)] + mainLut[(int)(osc2->lfo_phase)])* osc->amplitude;
    buf2[i]+= (mainLut[(int)(osc2->phase)]+ mainLut[(int)(osc2->fm_phase)]) * osc->amplitude;

  }

  graceful_theft(osc);
}

void oscAlgo2Quad(struct oscillator* osc, struct oscillator* osc2, uint16_t* buf, uint16_t* buf2){

  phase_incr(osc->lfo_phase, lfo_freq)

  float fr = calculateFrequency(osc)*detuneUp;
  float fl = calculateFrequency(osc)*detuneDown;
  float f3 = calculateFrequency(osc)*detuneUp*detuneUp;
  float f4 = calculateFrequency(osc)*detuneDown*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr(osc->phase, fl)
    phase_incr(osc2->phase, fr)
    phase_incr(osc2->lfo_phase, f3)
    phase_incr(osc2->fm_phase, f4)

    osc->fm_amplitude += preAmpDiff;

    osc->fm_phase  = (mainLut[(int)(osc->phase)] + mainLut[(int)(osc2->lfo_phase)])* osc->fm_amplitude *4096.0;
    phase_wrap(osc->fm_phase)
    buf[i] += sinLut[(int)(osc->fm_phase)] * osc->amplitude;

    osc->fm_phase = (mainLut[(int)(osc2->phase)]+ mainLut[(int)(osc2->fm_phase)]) * osc->fm_amplitude *4096.0;
    phase_wrap(osc->fm_phase)
    buf2[i]+= sinLut[(int)(osc->fm_phase)] * osc->amplitude;

  }

  graceful_theft(osc);
}

void oscAlgo1Poly4(struct oscillator* osc, struct oscillator* osc2, struct oscillator* osc3, struct oscillator* osc4, uint16_t* buf, uint16_t* buf2) {

  phase_incr(osc->lfo_phase, lfo_freq)

  float f1 = calculateFrequency(osc)*detuneUp;
  float f2 = calculateFrequency(osc)*detuneDown;
  float f3 = calculateFrequency(osc)*detuneUp*detuneUp;
  float f4 = calculateFrequency(osc)*detuneDown*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    osc->amplitude += ampDiff;

    phase_incr(osc->fm_phase, fm_freq*f1)
    phase_incr(osc2->fm_phase,fm_freq*f2)
    phase_incr(osc3->fm_phase,fm_freq*f3)
    phase_incr(osc4->fm_phase,fm_freq*f4)

    osc->fm_amplitude += preAmpDiff;

    osc->phase  += f1 + sinLut[(int)( osc->fm_phase)]*osc->fm_amplitude *f1;
    osc2->phase += f2 + sinLut[(int)(osc2->fm_phase)]*osc->fm_amplitude *f2;
    osc3->phase += f3 + sinLut[(int)(osc3->fm_phase)]*osc->fm_amplitude *f3;
    osc4->phase += f4 + sinLut[(int)(osc4->fm_phase)]*osc->fm_amplitude *f4;
    phase_wrap(osc->phase)
    phase_wrap(osc2->phase)
    phase_wrap(osc3->phase)
    phase_wrap(osc4->phase)

    buf[i] += (mainLut[(int)(osc->phase)] + mainLut[(int)(osc3->phase)])* osc->amplitude;
    buf2[i]+= (mainLut[(int)(osc2->phase)]+ mainLut[(int)(osc4->phase)])* osc->amplitude;

  }

  graceful_theft(osc);
}


void algoMonophonic1(float f, uint16_t* buf, uint16_t* buf2) {

  struct oscillator* osc= &oscillators[0];
  struct oscillator* osc2= &oscillators[1];

  float fr = f*detuneUp;
  float fl = f*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {
    osc->amplitude += ampDiff;

    phase_incr_safe(osc->fm_phase, fm_freq*fl)
    phase_incr_safe(osc2->fm_phase,fm_freq*fr)

    osc->fm_amplitude += preAmpDiff;

    osc->phase  += fl + sinLut[(int)( osc->fm_phase)]*osc->fm_amplitude *fl;
    osc2->phase += fr + sinLut[(int)(osc2->fm_phase)]*osc->fm_amplitude *fr;
    phase_wrap(osc->phase)
    phase_wrap(osc2->phase)

    buf[i] = 2048+mainLut[(int)(osc->phase)] * osc->amplitude;
    buf2[i]= 2048+mainLut[(int)(osc2->phase)]* osc->amplitude;
  }

}
void algoMonophonic2(float f, uint16_t* buf, uint16_t* buf2) {

  struct oscillator* osc= &oscillators[0];
  struct oscillator* osc2= &oscillators[1];

  float fr = f*detuneUp;
  float fl = f*detuneDown;

  float preAmpDiff = intEnvelope(osc);
  float ampDiff = envelope(osc);

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {
    osc->amplitude += ampDiff;

    phase_incr(osc->phase, fl)
    phase_incr(osc2->phase, fr)

    osc->fm_amplitude += preAmpDiff;

    osc->fm_phase  = mainLut[(int)( osc->phase)] * osc->fm_amplitude *4096.0;
    osc2->fm_phase = mainLut[(int)(osc2->phase)] * osc->fm_amplitude *4096.0;

    phase_wrap(osc->fm_phase)
    phase_wrap(osc2->fm_phase)

    buf[i]  = 2048+sinLut[(int)( osc->fm_phase)] * osc->amplitude;
    buf2[i] = 2048+sinLut[(int)(osc2->fm_phase)] * osc->amplitude;
  }

}



const float bleptable[]={0,0.0077972412109375,0.01556396484375,0.0233001708984375,0.031005859375,0.0386810302734375,0.04632568359375,0.0539398193359375,0.0615234375,0.0690765380859375,0.07659912109375,0.0840911865234375,0.091552734375,0.0989837646484375,0.10638427734375,0.1137542724609375,0.12109375,0.1284027099609375,0.13568115234375,0.1429290771484375,0.150146484375,0.1573333740234375,0.16448974609375,0.1716156005859375,0.1787109375,0.1857757568359375,0.19281005859375,0.1998138427734375,0.206787109375,0.2137298583984375,0.22064208984375,0.2275238037109375,0.234375,0.2411956787109375,0.24798583984375,0.2547454833984375,0.261474609375,0.2681732177734375,0.27484130859375,0.2814788818359375,0.2880859375,0.2946624755859375,0.30120849609375,0.3077239990234375,0.314208984375,0.3206634521484375,0.32708740234375,0.3334808349609375,0.33984375,0.3461761474609375,0.35247802734375,0.3587493896484375,0.364990234375,0.3712005615234375,0.37738037109375,0.3835296630859375,0.3896484375,0.3957366943359375,0.40179443359375,0.4078216552734375,0.413818359375,0.4197845458984375,0.42572021484375,0.4316253662109375,0.4375,0.4433441162109375,0.44915771484375,0.4549407958984375,0.460693359375,0.4664154052734375,0.47210693359375,0.4777679443359375,0.4833984375,0.4889984130859375,0.49456787109375,0.5001068115234375,0.505615234375,0.5110931396484375,0.51654052734375,0.5219573974609375,0.52734375,0.5326995849609375,0.53802490234375,0.5433197021484375,0.548583984375,0.5538177490234375,0.55902099609375,0.5641937255859375,0.5693359375,0.5744476318359375,0.57952880859375,0.5845794677734375,0.589599609375,0.5945892333984375,0.59954833984375,0.6044769287109375,0.609375,0.6142425537109375,0.61907958984375,0.6238861083984375,0.628662109375,0.6334075927734375,0.63812255859375,0.6428070068359375,0.6474609375,0.6520843505859375,0.65667724609375,0.6612396240234375,0.665771484375,0.6702728271484375,0.67474365234375,0.6791839599609375,0.68359375,0.6879730224609375,0.69232177734375,0.6966400146484375,0.700927734375,0.7051849365234375,0.70941162109375,0.7136077880859375,0.7177734375,0.7219085693359375,0.72601318359375,0.7300872802734375,0.734130859375,0.7381439208984375,0.74212646484375,0.7460784912109375,0.75,0.7538909912109375,0.75775146484375,0.7615814208984375,0.765380859375,0.7691497802734375,0.77288818359375,0.7765960693359375,0.7802734375,0.7839202880859375,0.78753662109375,0.7911224365234375,0.794677734375,0.7982025146484375,0.80169677734375,0.8051605224609375,0.80859375,0.8119964599609375,0.81536865234375,0.8187103271484375,0.822021484375,0.8253021240234375,0.82855224609375,0.8317718505859375,0.8349609375,0.8381195068359375,0.84124755859375,0.8443450927734375,0.847412109375,0.8504486083984375,0.85345458984375,0.8564300537109375,0.859375,0.8622894287109375,0.86517333984375,0.8680267333984375,0.870849609375,0.8736419677734375,0.87640380859375,0.8791351318359375,0.8818359375,0.8845062255859375,0.88714599609375,0.8897552490234375,0.892333984375,0.8948822021484375,0.89739990234375,0.8998870849609375,0.90234375,0.9047698974609375,0.90716552734375,0.9095306396484375,0.911865234375,0.9141693115234375,0.91644287109375,0.9186859130859375,0.9208984375,0.9230804443359375,0.92523193359375,0.9273529052734375,0.929443359375,0.9315032958984375,0.93353271484375,0.9355316162109375,0.9375,0.9394378662109375,0.94134521484375,0.9432220458984375,0.945068359375,0.9468841552734375,0.94866943359375,0.9504241943359375,0.9521484375,0.9538421630859375,0.95550537109375,0.9571380615234375,0.958740234375,0.9603118896484375,0.96185302734375,0.9633636474609375,0.96484375,0.9662933349609375,0.96771240234375,0.9691009521484375,0.970458984375,0.9717864990234375,0.97308349609375,0.9743499755859375,0.9755859375,0.9767913818359375,0.97796630859375,0.9791107177734375,0.980224609375,0.9813079833984375,0.98236083984375,0.9833831787109375,0.984375,0.9853363037109375,0.98626708984375,0.9871673583984375,0.988037109375,0.9888763427734375,0.98968505859375,0.9904632568359375,0.9912109375,0.9919281005859375,0.99261474609375,0.9932708740234375,0.993896484375,0.9944915771484375,0.99505615234375,0.9955902099609375,0.99609375,0.9965667724609375,0.99700927734375,0.9974212646484375,0.997802734375,0.9981536865234375,0.99847412109375,0.9987640380859375,0.9990234375,0.9992523193359375,0.99945068359375,0.9996185302734375,0.999755859375,0.9998626708984375,0.99993896484375,0.9999847412109375};



#define threshold osc->fm_phase
#define output osc->fm_depth_cache

inline float blepSquare(struct oscillator* osc, uint8_t* state, float f, float idt, float duty, float pulseNorm){

  osc->phase +=f;

  if (osc->phase >= threshold) {

    switch (*state) {

      case 0: // duty-f;
        threshold=0;
        *state=1;
        return pulseNorm+bleptable[ (int)((duty-osc->phase)*idt) ];

      case 1: //duty
        threshold=8192.0-f;
        *state=2;
        output=pulseNorm-1;
        return pulseNorm-bleptable[ (int)((osc->phase-duty)*idt) ];

      case 2: //8192-f
        threshold=0;
        *state=3;
        return pulseNorm-bleptable[ (int)((8192-osc->phase)*idt) ];

      case 3: // 8192
        osc->phase-=8192.0f;
        threshold=duty-f;
        *state=0;
        output=pulseNorm+1.0;
        return pulseNorm+bleptable[ (int)(osc->phase*idt) ];

    }

  }
  return output;

}

inline void blepSquareRecalc(struct oscillator* osc, uint8_t* state, float f, float idt, float duty, float pulseNorm) {

  if (osc->phase<duty-f) {
    *state=0;
    output=pulseNorm+1.0;
    threshold=duty-f;
  } else if (osc->phase<duty) {
    output=pulseNorm+1.0;
    *state=1;
    threshold=duty;
  } else if (osc->phase<8192-f) {
    output=pulseNorm-1.0;
    *state=2;
    threshold=8192.0-f;
  } else {
    output=pulseNorm-1.0;
    *state=3;
    threshold=8192.0;
  }
}

inline float blepSaw(struct oscillator* osc, uint8_t* state, float f, float idt, float incr){

  output +=incr;
  osc->phase +=f;

  if (osc->phase >= threshold) {
    if (*state==0) {
      threshold=8192.0-f;
      *state=1;
      osc->phase-=8192.0;
      output-=2.0;
      return output+1 - bleptable[ (int)((osc->phase)*idt) ];
    } else {
      threshold=8192.0;
      *state=0;
      return output-1 + bleptable[ (int)((8192.0-osc->phase)*idt) ];
    }
  }

  return output;
}

inline void blepSawRecalc(struct oscillator* osc, uint8_t* state, float f, float idt, float incr) {

  output=osc->phase/4096.0 -1.0;

  if (osc->phase<8192.0-f) {
    *state=1;
    threshold=8192.0-f;
  } else {
    *state=0;
    threshold=8192.0;
  }

}


#undef threshold
#undef output


#define SQUARE
  #include "algo3_mono.h"
  #include "algo3_poly16.h"
#undef SQUARE

#define SAW
  #include "algo3_mono.h"
  #include "algo3_poly16.h"
#undef SAW


void generateIntoBufferFullPoly(uint16_t* buf, uint16_t* buf2){

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {buf[i]=2048;}

  for (uint8_t i=POLYPHONY; i--;) {
    if (oscillators[i].alive)
      doOscillator(&oscillators[i], buf);
  }
}

void generateIntoBufferDualOsc(uint16_t* buf, uint16_t* buf2){

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {buf[i]=2048; buf2[i]=2048;}

  for (uint8_t i=0; i<POLYPHONY; i+=2) {
    if (oscillators[i].alive)
      doOscillatorStereo(&oscillators[i], &oscillators[i+1], buf, buf2);
  }
}

void generateIntoBufferMonophonic(uint16_t* buf, uint16_t* buf2){

  struct oscillator* osc= &oscillators[0];
  float f = calculateFrequencyMonophonic(osc);

  if (arpegSpeed!=31 && ++monoNoteTimer>arpegSpeed) {
    monoNoteNow+=2;
    if (monoNoteNow>=monoNoteEnd) monoNoteNow=0;
    osc->notenumber = monoNoteStack[monoNoteNow]&0x7f;
    osc->channel = monoNoteStack[monoNoteNow+1];
    monoNoteTimer=0;
  }
  if (monoNoteReleaseTimer && osc->released==0 && --monoNoteReleaseTimer==0){
    memcpy(monoNoteReleaseStack, monoNoteStack, monoNoteEnd+1);
    monoNoteReleaseEnd=monoNoteEnd;
  }

  monophonicAlgo(f, buf, buf2);

}

void generateIntoBufferPoly4(uint16_t* buf, uint16_t* buf2){

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {buf[i]=2048; buf2[i]=2048;}

  for (uint8_t i=0; i<POLYPHONY; i+=4) {
    if (oscillators[i].alive)
      doOscillatorPoly4(&oscillators[i], &oscillators[i+1], &oscillators[i+2], &oscillators[i+3], buf, buf2);
  }
}

void DMA1_Channel3_IRQHandler(void)
{
  DMA_HandleTypeDef *hdma = DacHandle.DMA_Handle1;
  uint32_t flag_it = hdma->DmaBaseAddress->ISR;
  uint32_t source_it = hdma->Instance->CCR;

  // Half Transfer Complete Interrupt
  if ((RESET != (flag_it & (DMA_FLAG_HT1 << hdma->ChannelIndex))) && (RESET != (source_it & DMA_IT_HT))) {
    hdma->DmaBaseAddress->IFCR = (DMA_ISR_HTIF1 << hdma->ChannelIndex);  //Clear Flag
    generateIntoBuffer(&buffer[0], &buffer2[0]);
  }

  // Transfer Complete Interrupt
  else if ((RESET != (flag_it & (DMA_FLAG_TC1 << hdma->ChannelIndex))) && (RESET != (source_it & DMA_IT_TC))) {
    hdma->DmaBaseAddress->IFCR = (DMA_ISR_TCIF1 << hdma->ChannelIndex);  //Clear Flag
    generateIntoBuffer(&buffer[BUFFERSIZE], &buffer2[BUFFERSIZE]);
  }

  return;
}





int main(void) {

  HAL_Init();
  SystemClock_Config();

   __HAL_RCC_GPIOA_CLK_ENABLE();

  USART1_Init();

  DacHandle.Instance = DAC1;
  TIM6_Config();




  if (HAL_DAC_Init(&DacHandle) != HAL_OK)
    Error_Handler();
  
  sConfig.DAC_Trigger = DAC_TRIGGER_T6_TRGO;
  sConfig.DAC_OutputBuffer = DAC_OUTPUTBUFFER_ENABLE;

  if (HAL_DAC_ConfigChannel(&DacHandle, &sConfig, DAC_CHANNEL_1) != HAL_OK)
    Error_Handler();

  if (HAL_DAC_Start_DMA(&DacHandle, DAC_CHANNEL_1, (uint32_t *)buffer, BUFFERSIZE*2, DAC_ALIGN_12B_R) != HAL_OK)
    Error_Handler();
  
  if (HAL_DAC_ConfigChannel(&DacHandle, &sConfig, DAC_CHANNEL_2) != HAL_OK)
    Error_Handler();

  if (HAL_DAC_Start_DMA(&DacHandle, DAC_CHANNEL_2, (uint32_t *)buffer, BUFFERSIZE*2, DAC_ALIGN_12B_R) != HAL_OK)
    Error_Handler();
  

  for (uint8_t i=16;i--;) {
    channels[i].pbSensitivity = DEFAULT_PB_RANGE;
    parameterChange(i, cc_per_channel_tuning, synthConfig.startupTuning[i]);

  }
  
  loadPatch(0);

  while (1) {
    setWaveform(targetWave, waveParam);
  }
}

void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  RCC_PeriphCLKInitTypeDef PeriphClkInit;

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = 16;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;

  RCC_OscInitStruct.PLL.PLLM = 1;
#if CPU_FREQ == 32
  RCC_OscInitStruct.PLL.PLLN = 12;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV6;
#elif CPU_FREQ == 48
  RCC_OscInitStruct.PLL.PLLN = 12;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV4;
#elif CPU_FREQ == 64
  RCC_OscInitStruct.PLL.PLLN = 8;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
#else
  RCC_OscInitStruct.PLL.PLLN = 10;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
#endif
  //not used
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV7;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;

  if(HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    Error_Handler();
  
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;  
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;  
  if(HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
    Error_Handler();

  PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1;
  PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK2;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
    Error_Handler();

}


void USART1_Init(void) {

  huart1.Instance = USART1;
  huart1.Init.BaudRate = 31250;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;

  if (HAL_UART_Init(&huart1) != HAL_OK)
    Error_Handler();

  //NVIC_SetPriority(USART1_IRQn, 0);
  //NVIC_EnableIRQ(USART1_IRQn);
  LL_USART_Enable(USART1);
  LL_USART_EnableIT_RXNE(USART1);

}


void TIM6_Config(void)
{
  static TIM_HandleTypeDef  htim;
  TIM_MasterConfigTypeDef sMasterConfig;

  /*##-1- Configure the TIM peripheral #######################################*/
  /* Time base configuration */
  htim.Instance = TIM6;

  htim.Init.Period            = DAC_TIMER_PERIOD;
  htim.Init.Prescaler         = 0;
  htim.Init.ClockDivision     = 0;
  htim.Init.CounterMode       = TIM_COUNTERMODE_UP;
  htim.Init.RepetitionCounter = 0;
  HAL_TIM_Base_Init(&htim);

  /* TIM6 TRGO selection */
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_UPDATE;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;

  HAL_TIMEx_MasterConfigSynchronization(&htim, &sMasterConfig);

  /*##-2- Enable TIM peripheral counter ######################################*/
  HAL_TIM_Base_Start(&htim);
}



static void Error_Handler(void)
{
  #ifdef RESET_ON_FAULT
    NVIC_SystemReset();
  #else
    while(1){}
  #endif
}

