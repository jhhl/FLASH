

#include "stm32l4xx_hal.h"
#include "stm32l4xx_ll_usart.h"
#include "math.h"

#define PI 3.14159265358979323846


// one of 32, 48, 64, 80
#define CPU_FREQ 64

#define DAC_TIMER_PERIOD ((CPU_FREQ*1000000)/(44100))


#include "lookupTables.h"

DAC_HandleTypeDef    DacHandle;
UART_HandleTypeDef   huart1;
static DAC_ChannelConfTypeDef sConfig;

void SystemClock_Config(void);
static void TIM6_Config(void);
static void USART1_Init(void);
static void Error_Handler(void);


#define BUFFERSIZE 256
#define POLYPHONY 16
// To be absolutely sure it isn't going to clip, wave amplitude should be less than 2048/polyphony = 128...
#define WAVE_AMPLITUDE 128

#define DEFAULT_PB_RANGE 2

uint16_t buffer[BUFFERSIZE*2] = {0};

  float fm_freq = 0.1;
  float fm_depth = 0.5;
  float fm_decay = 0.9999;

struct channel {
  uint8_t volume;
  int32_t bend;
  uint8_t RPNstack[4];
  uint8_t pbSensitivity;
  uint8_t mod;
  float lfo_depth;
  float lfo_freq;
  const float* tuning;
  unsigned sustain:1;
} channels[16];

struct oscillator {
  uint8_t channel;
  uint8_t notenumber;
  uint8_t velocity;
  float phase;
  float amplitude;
  float fm_phase;
  float fm_amplitude;
  float lfo_phase;
  uint32_t starttime;
  unsigned alive:1;
  unsigned released:1;
  unsigned sustained:1;
} oscillators[POLYPHONY];

uint32_t timestamp = 0;

float mainLut[8192]={0};

void oscAlgo1(struct oscillator* osc, uint16_t* buf);
void oscAlgo2(struct oscillator* osc, uint16_t* buf);
void (*doOscillator)(struct oscillator* osc, uint16_t* buf) = &oscAlgo1;

void antialias(){
// Must be symmetric

#define AVGP 128

  float b[AVGP]={};
  float sum = 0;
  uint8_t idx = 0;
  
  for (uint8_t i=0; i<AVGP; i++) {
    b[i] = mainLut[8192 - AVGP + i];
  }

  for (uint16_t i=0;i<8192;i++) {
    sum=0;
    for (uint8_t j=0; j<AVGP; j++) {
      sum+=b[j];
    }
    b[idx++] = mainLut[i];
    mainLut[i] = sum*0.0078125;//*(1/AVGP);
    
    if (idx==AVGP) idx=0;
  }

}

void setWaveform(uint8_t id) {

// TODO: normalize waveforms

  // %8192 == &8191

  switch (id) {

  case 1: // Hammondish
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[(i)&8191]*0.25 + sinLut[(i*2)&8191]*0.25 + sinLut[(i*3) &8191]*0.25 + sinLut[(i*4) &8191]*0.25;
    }
    break;

  case 2: // sine cubed
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i]*sinLut[i]*sinLut[i];
    }
    break;

  case 3: // half sine
    for (uint16_t i=0;i<4096;i++) {
      mainLut[i]=sinLut[i];
    }
    for (uint16_t i=4096;i<8192;i++) {
      mainLut[i]=0;
    }
    break;
  case 4: // abs sine
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]= sinLut[i] > 0 ? sinLut[i] : -sinLut[i];
    }
//antialias();
    break;
  case 5: // 
    for (uint16_t i=0;i<4096;i++) {
      mainLut[i]=0.5;
    }
    for (uint16_t i=4096;i<8192;i++) {
      mainLut[i]=-0.5;
    }
//antialias();
    break;
  case 6: // 
    for (uint16_t i=0;i<4096;i++) {
      mainLut[i]=0.5;
    }
    for (uint16_t i=4096;i<8192;i++) {
      mainLut[i]=-0.5;
    }
antialias();
antialias();
    break;

  default: //sine
    for (uint16_t i=0;i<8192;i++) {
      mainLut[i]=sinLut[i];
    }
  }
}


void noteOn(uint8_t n, uint8_t vel, uint8_t chan) {

// find a free oscillator
// set it up
  uint8_t i, oldest;
  uint32_t mintime=0xffffffff;

  for (i=POLYPHONY; i--;) {
    if (0==oscillators[i].alive) break;
    if (oscillators[i].starttime < mintime) {
      oldest = i;
      mintime = oscillators[i].starttime;
    }
  }

  if (oscillators[i].alive!=0) {
    i = oldest;
  }

  oscillators[i].alive = 1;
  oscillators[i].starttime = timestamp++;
  oscillators[i].released = 0;
  oscillators[i].sustained = 0;
  oscillators[i].notenumber=n;
  oscillators[i].channel=chan;
  oscillators[i].velocity=vel;

  oscillators[i].fm_amplitude = (vel/127.0)*fm_depth * fEqualLookup[ n ];
  //oscillators[i].phase = 1.0f;


}

void noteOff(uint8_t n, uint8_t chan) {
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


uint32_t random(void) {
  static uint32_t seed = 123456;
  return seed = seed * 16807 % 0x7FFFFFFF;
}


void USART1_IRQHandler(void) {
  static uint8_t status=0;
  static uint8_t bytenumber =0;
  static uint8_t bytetwo = 0;

  static uint8_t fm_freq_cc[] = {0,0};

  uint8_t i = LL_USART_ReceiveData8(USART1);

  if (i & 0x80) {
    status = i;
    bytenumber = 1;

  } else {
    uint8_t chan = status&0x0F;
    
    if (bytenumber == 1) {
      if ((status & 0xF0) == 0xD0){

        if (i>channels[chan].mod)
          channels[chan].lfo_depth = (float)(i*8);

      } else {
        bytetwo = i;
        bytenumber = 2;
      }
    } else if (bytenumber == 2){

      switch (status & 0xF0) {

        case 0x90: //Note on
          if (i == 0) noteOff(bytetwo, chan); //running status uses velocity=0 for noteoff
          else noteOn(bytetwo, i, chan);
        break;

        case 0x80: //Note off
          noteOff(bytetwo, chan);
        break;

        case 0xE0: //Pitch bend
          channels[chan].bend = channels[chan].pbSensitivity * (((i<<7) + bytetwo) - 0x2000);
        break;


        case 0xB0: // Continuous controller

          switch (bytetwo) {

            case 1: //modulation
              channels[chan].mod = i;
              channels[chan].lfo_depth = (float)(i*8);
            break;
            case 76:
              channels[chan].lfo_freq = 204.8 + (float)(i*4);
            break;

            case 20:
              fm_freq_cc[0] = i;
              fm_freq=(float)((fm_freq_cc[0]<<7) + fm_freq_cc[1])/1024;
            break;
            case 21:
              fm_freq_cc[1] = i;
              fm_freq=(float)((fm_freq_cc[0]<<7) + fm_freq_cc[1])/1024;
            break;
            case 22:
              fm_depth=(float)(i*25)/127;
            break;
            case 23:
              fm_decay=0.9995 + ((float)(i)/254000);
            break;
            case 24:
              doOscillator = i>64? &oscAlgo2 : &oscAlgo1;
            break;

            case 25:
              setWaveform(i);
            break;

            case 64: //sustain pedal
              channels[chan].sustain = (i>63);
              if (channels[chan].sustain == 0) {//pedal released
                //loop through oscillators and release any with sustained=true
                for (uint8_t i=POLYPHONY; i--;) {
                  if (oscillators[i].sustained && oscillators[i].alive && !oscillators[i].released && oscillators[i].channel==chan) {
                    oscillators[i].released=1;
                    oscillators[i].sustained=0;
                  }
                }
              }
            break;

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

            case 3: // Per-channel tuning
              if (i == 0) {
                  channels[chan].pbSensitivity=DEFAULT_PB_RANGE;
                  channels[chan].tuning = &fEqualLookup[0];
              } else if (i<=16) {
                  channels[chan].pbSensitivity=1;
                  channels[chan].tuning = &fTuningTables[i-1][0];
              }
            break;

            case 9: // All channels tuning
              if (i == 0) {
                for (int j=0;j<16;j++) {
                  channels[j].pbSensitivity=DEFAULT_PB_RANGE;
                  channels[j].tuning = &fEqualLookup[0];
                }
              } else {
                for (int j=0;j<16;j++) {
                  channels[j].pbSensitivity=1;
                  channels[j].tuning = &fTuningTables[j][0];
                }
              }
            break;

          }
        break;

      }


      bytenumber =1; //running status
    }
  }


}



void oscAlgo1(struct oscillator* osc, uint16_t* buf){

  osc->lfo_phase += channels[osc->channel].lfo_freq;
  if (osc->lfo_phase>8192.0f) osc->lfo_phase-=8192.0f;

  float f;

  if (channels[osc->channel].pbSensitivity == 1) {

    // We should probably enforce that LFO depth is never more than a semitone
    f = channels[osc->channel].tuning[ osc->notenumber]
      * bLookup14bit1semitone[ channels[osc->channel].bend +0x2000 ]
      * bLookup14bit1semitone[ (int)(sinLut[(int)(osc->lfo_phase)] * channels[osc->channel].lfo_depth) +0x2000 ];

  } else {
    int32_t bend = channels[osc->channel].bend + (int)(sinLut[(int)(osc->lfo_phase)] * channels[osc->channel].lfo_depth);

    f = channels[osc->channel].tuning[ osc->notenumber + (bend>>13) ]
      * bLookup14bit1semitone[ (bend&0x1FFF) +0x2000 ];
  }

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    //Simple envelope
    if (osc->released) {
      osc->amplitude-=0.25;
      if (osc->amplitude <= 0.0) {osc->alive =0;osc->amplitude=0;}
    } else if (osc->amplitude < osc->velocity) osc->amplitude+=0.25;


    osc->fm_phase += fm_freq*f;
    if (osc->fm_phase>8192.0f) osc->fm_phase-=8192.0f;


    osc->fm_amplitude *= fm_decay;

    osc->phase += f  + sinLut[(int)(osc->fm_phase)]*osc->fm_amplitude;
    while (osc->phase>8192.0f) osc->phase-=8192.0f;
    while (osc->phase<0.0f) osc->phase+=8192.0f;

    buf[i] += mainLut[(int)(osc->phase)] * osc->amplitude;

  }


}

void oscAlgo2(struct oscillator* osc, uint16_t* buf){

  osc->lfo_phase += channels[osc->channel].lfo_freq;
  if (osc->lfo_phase>4.0f) osc->lfo_phase-=4.0f;


  int32_t bend = channels[osc->channel].bend + (int)(sinLut[(int)(osc->lfo_phase *2048)] * channels[osc->channel].lfo_depth);

  bend += (random()>>19)-2048;

  float f = fEqualLookup[ osc->notenumber + (bend/0x2000) ] 
          * bLookup14bit1semitone[ (bend%0x2000) +0x2000 ];
          

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {

    //Simple envelope
    if (osc->released) {
      osc->amplitude-=0.25;
      if (osc->amplitude <= 0.0) {osc->alive =0;osc->amplitude=0;}
    } else if (osc->amplitude < osc->velocity) osc->amplitude+=0.25;


    osc->fm_phase += fm_freq*f;
    if (osc->fm_phase>4.0f) osc->fm_phase-=4.0f;


    osc->fm_amplitude *= fm_decay;

    osc->phase += f  + sinLut[(int)(osc->fm_phase *2048)]*osc->fm_amplitude;
    while (osc->phase>4.0f) osc->phase-=4.0f;
    while (osc->phase<0.0f) osc->phase+=4.0f;

    buf[i] += mainLut[(int)(osc->phase *2048)] * osc->amplitude;

  }


}


void generateIntoBuffer(uint16_t* buf){

  for (uint16_t i = 0; i<BUFFERSIZE; i++) {buf[i]=2048;}

  for (uint8_t i=POLYPHONY; i--;) {
    if (oscillators[i].alive)
      doOscillator(&oscillators[i], buf);

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

    generateIntoBuffer(&buffer[0]);

  }

  // Transfer Complete Interrupt
  else if ((RESET != (flag_it & (DMA_FLAG_TC1 << hdma->ChannelIndex))) && (RESET != (source_it & DMA_IT_TC))) {

    hdma->DmaBaseAddress->IFCR = (DMA_ISR_TCIF1 << hdma->ChannelIndex);  //Clear Flag

    generateIntoBuffer(&buffer[BUFFERSIZE]);


  }


  return;

}





int main(void) {

  HAL_Init();
  SystemClock_Config();

   __HAL_RCC_GPIOA_CLK_ENABLE();


  // __HAL_RCC_GPIOC_CLK_ENABLE();
  // GPIO_InitTypeDef GPIO_InitStruct;
  // GPIO_InitStruct.Pin = GPIO_PIN_0;
  // GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  // GPIO_InitStruct.Pull = GPIO_NOPULL;
  // GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  // HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  // HAL_GPIO_TogglePin(GPIOC, GPIO_PIN_0);

  
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
  
fm_freq=1.0;
fm_depth=(float)(64*25)/127;
fm_decay = 0.9995 + ((float)(121)/254000);


  for (uint8_t i=16;i--;) {
    channels[i].pbSensitivity = DEFAULT_PB_RANGE;
    channels[i].tuning = &fEqualLookup[0];
    channels[i].lfo_freq = (0.1+(float)(48 )/512)* 2048;
  };
  
  setWaveform(0);

  while (1) {};
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

  NVIC_SetPriority(USART1_IRQn, 0);
  NVIC_EnableIRQ(USART1_IRQn);
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
  while(1){} 
}

