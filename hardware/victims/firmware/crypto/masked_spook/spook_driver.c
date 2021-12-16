/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 * From https://git-crypto.elen.ucl.ac.be/spook/masked_spook_sw/-/blob/master/board_m0/Src/main.c
 *
 ******************************************************************************
 */

#include "main.h"
#include <string.h>
#include "crypto_aead.h"
#include "api.h"
#include "prng.h"
#include "s1p.h"
#include "utils_masking.h"
#include "primitives.h"
#ifndef D
    #define D=1
#endif
#define MAX_LEN 256

// Implements the CAL
#include "aead_independent.h"

// UART_HandleTypeDef huart1;
// static void MX_GPIO_Init(void);
// static void MX_USART1_UART_Init(void);

/// UART interface
uint8_t header[4];
uint8_t waiting_for; // 0 -> HEADER , 1-> DATA
uint8_t *dest;

// PRNG handling
shadow_state prng_state;
uint32_t seed[4];
uint32_t N;
uint32_t fixed_key;

// DEST | ENC | LEN | UNUSED
// AEAD inputs outputs
uint8_t c[MAX_LEN+CRYPTO_ABYTES];
uint8_t ad[MAX_LEN];
uint8_t m[MAX_LEN],m_len;
uint8_t npub[CRYPTO_NPUBBYTES];
uint32_t k[(CRYPTO_KEYBYTES/4)*D];
uint32_t initial_key[4*D];
uint32_t clen,adlen,mlen;

// void SystemClock_Config(void);

static void simple_refresh(uint32_t *out,uint32_t *in){
    uint32_t r,s;
    for(int i=0;i<4;i++){
        r=0;
        for(int d =0; d<(D-1);d++){
            s = get_random();
            out[(i*D)+d] = in[(i*D)+d] ^s;
            r ^=s;
        }
        out[(i*D) + D - 1] = in[(i*D)+D-1] ^ r;
    }
}
// /////////////////////////////////
// /////////////// IRQ UART Handling
// ///////////////////////////////
// void USART1_IRQHandler(void){
//     HAL_UART_IRQHandler(&huart1);
// }



// void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart){
    // if(header[0]==5 && waiting_for==1){ // We just received
    //
static void subcmd_05(){
        for(int i=0;i<4;i++)
            memset(prng_state[i],0,16);
        memcpy(prng_state[0],seed,16);
}
static void subcmd_04(){
    // }else if(header[0]==4 && waiting_for==1){ //received a key
        memcpy(initial_key,k,16*D);
    // }
}


    if(waiting_for == 0){ // received an header
        unsigned long long len = header[2] + header[3]*256;
        switch(header[0]){
            case 0:
                dest = c;
                clen = len;
                break;
            case 1:
                dest = ad;
                adlen = len;
                break;
            case 2:
                dest = m;
                mlen = len;
                break;
            case 3:
                dest = npub;
                break;
            case 4:
                dest = (uint8_t*) k;
                break;
            case 5:
                dest = (uint8_t *) seed;
                break;
            case 6:
                dest = (uint8_t *) &N;
                break;
            case 7:
                dest = (uint8_t *) &fixed_key;
                break;
            default:
                break;
        }
        HAL_GPIO_WritePin(GPIOC, LD3_Pin, GPIO_PIN_RESET); // LED ON
        waiting_for = 1; // waiting for data now
        if(len>0)
            HAL_UART_Receive_IT(&huart1,dest,len);
        else
            HAL_UART_Receive_IT(&huart1,header,4);

    }else if(header[1]==1 && waiting_for==1){ // received data and want to encrypt
        /// ENCRYPT
        HAL_GPIO_WritePin(GPIOC, LD3_Pin, GPIO_PIN_RESET);  // LED OF
        for(int n =0; n<N;n++){
            init_rng(prng_state[0]);
            fill_table();

            HAL_GPIO_WritePin(GPIOC, LD4_Pin, GPIO_PIN_RESET); // trig on
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_SET); // trig on
            crypto_aead_encrypt(
                    c,&clen,
                    m,mlen,
                    ad,adlen,
                    NULL,npub,k);
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET); // trig of
            HAL_GPIO_WritePin(GPIOC, LD4_Pin, GPIO_PIN_RESET); // trig on
            /// END ENCRYPT

            shadow(prng_state);             // exectute one shadow
            memcpy(npub,&prng_state[1][0],16); // change the nonce
            init_rng(prng_state[2]);       // reset prng
            fill_table();

            if(fixed_key==0){
                for(int i=0;i<(4*D);i++){
                    k[i] = get_random();
                }
            }else{
                simple_refresh(k,initial_key);
            }
        }
        memcpy(initial_key,k,D*16);
        waiting_for = 0;
        HAL_UART_Transmit(&huart1,c,clen,100);
        HAL_UART_Receive_IT(&huart1,header,4);
    }else if(header[1]==2 && waiting_for==1){ // received data and want to decrypt
        /// ENCRYPT
        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_SET); // trig on
        HAL_GPIO_WritePin(GPIOC, LD3_Pin, GPIO_PIN_RESET);  // LED OF

        crypto_aead_decrypt(
                m,&mlen,NULL,
                c,clen,
                ad,adlen,
                npub,k);

        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET); // trig of
        /// END ENCRYPT

        waiting_for = 0;
        HAL_UART_Transmit(&huart1,m,mlen,100);
        HAL_UART_Receive_IT(&huart1,header,4);
    }else{
        waiting_for = 0;
        HAL_UART_Receive_IT(&huart1,header,4);
    }
}
//
// int main(void)
// {
//     N = 1;
//     fixed_key = 1;
//     adlen = 0;
//     mlen = 0;
//     waiting_for = 0; // waiting for header first
//     HAL_Init();
//     SystemClock_Config();
//     MX_GPIO_Init();
//     MX_USART1_UART_Init();
//     HAL_NVIC_SetPriority(USART1_IRQn,0,0);
//     HAL_NVIC_EnableIRQ(USART1_IRQn);
//
//     HAL_GPIO_WritePin(GPIOC, LD3_Pin, GPIO_PIN_RESET);
//     HAL_GPIO_WritePin(GPIOC, LD3_Pin, GPIO_PIN_SET);
//     HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);
//
//     HAL_UART_Receive_IT(&huart1,header,4);
//     while (1){
//     }
// }

////////////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
////////////// !!!!!!!!!!!!!! SYSTEM CONFIGURATION (auto generated) !!!!!!!!!!!!!!!!!!!!!!
////////////// !!!!!!!!!!!!!!           DO NOT MODIFY               !!!!!!!!!!!!!!!!!!!!!!
////////////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// void SystemClock_Config(void)
// {
//   RCC_OscInitTypeDef RCC_OscInitStruct = {0};
//   RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
//   RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};
//
//   /** Initializes the CPU, AHB and APB busses clocks
//   */
//   RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
//   RCC_OscInitStruct.HSEState = RCC_HSE_ON;
//   RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
//   RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
//   RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL6;
//   RCC_OscInitStruct.PLL.PREDIV = RCC_PREDIV_DIV1;
//   if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
//   {
//     Error_Handler();
//   }
//   /** Initializes the CPU, AHB and APB busses clocks
//   */
//   RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
//                               |RCC_CLOCKTYPE_PCLK1;
//   RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
//   RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
//   RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
//
//   if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
//   {
//     Error_Handler();
//   }
//   PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1;
//   PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_SYSCLK;
//   if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
//   {
//     Error_Handler();
//   }
// }
//
// /**
//   * @brief USART1 Initialization Function
//   * @param None
//   * @retval None
//   */
// static void MX_USART1_UART_Init(void)
// {
//
//   /* USER CODE BEGIN USART1_Init 0 */
//
//   /* USER CODE END USART1_Init 0 */
//
//   /* USER CODE BEGIN USART1_Init 1 */
//
//   /* USER CODE END USART1_Init 1 */
//   huart1.Instance = USART1;
//   huart1.Init.BaudRate = 115200;
//   huart1.Init.WordLength = UART_WORDLENGTH_8B;
//   huart1.Init.StopBits = UART_STOPBITS_1;
//   huart1.Init.Parity = UART_PARITY_NONE;
//   huart1.Init.Mode = UART_MODE_TX_RX;
//   huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
//   huart1.Init.OverSampling = UART_OVERSAMPLING_16;
//   huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
//   huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
//   if (HAL_UART_Init(&huart1) != HAL_OK)
//   {
//     Error_Handler();
//   }
//   /* USER CODE BEGIN USART1_Init 2 */
//
//   /* USER CODE END USART1_Init 2 */
//
// }

// /**
//   * @brief GPIO Initialization Function
//   * @param None
//   * @retval None
//   */
// static void MX_GPIO_Init(void)
// {
//   GPIO_InitTypeDef GPIO_InitStruct = {0};
//
//   /* GPIO Ports Clock Enable */
//   __HAL_RCC_GPIOF_CLK_ENABLE();
//   __HAL_RCC_GPIOA_CLK_ENABLE();
//   __HAL_RCC_GPIOB_CLK_ENABLE();
//   __HAL_RCC_GPIOC_CLK_ENABLE();
//
//   /*Configure GPIO pin Output Level */
//   HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET);
//
//   /*Configure GPIO pin Output Level */
//   HAL_GPIO_WritePin(GPIOC, LD4_Pin|LD3_Pin, GPIO_PIN_RESET);
//
//   /*Configure GPIO pin : B1_Pin */
//   GPIO_InitStruct.Pin = B1_Pin;
//   GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
//   GPIO_InitStruct.Pull = GPIO_NOPULL;
//   HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);
//
//   /*Configure GPIO pin : PB13 */
//   GPIO_InitStruct.Pin = GPIO_PIN_13;
//   GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
//   GPIO_InitStruct.Pull = GPIO_NOPULL;
//   GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
//   HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);
//
//   /*Configure GPIO pins : LD4_Pin LD3_Pin */
//   GPIO_InitStruct.Pin = LD4_Pin|LD3_Pin;
//   GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
//   GPIO_InitStruct.Pull = GPIO_NOPULL;
//   GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
//   HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);
//
// }
//
// /* USER CODE BEGIN 4 */
//
// /* USER CODE END 4 */
//
// /**
//   * @brief  This function is executed in case of error occurrence.
//   * @retval None
//   */
// void Error_Handler(void)
// {
//   /* USER CODE BEGIN Error_Handler_Debug */
//     /* User can add his own implementation to report the HAL error return state */
//
//   /* USER CODE END Error_Handler_Debug */
// }
//
// #ifdef  USE_FULL_ASSERT
// /**
//   * @brief  Reports the name of the source file and the source line number
//   *         where the assert_param error has occurred.
//   * @param  file: pointer to the source file name
//   * @param  line: assert_param error line source number
//   * @retval None
//   */
// void assert_failed(char *file, uint32_t line)
// {
//   /* USER CODE BEGIN 6 */
//     /* User can add his own implementation to report the file name and line number,
// tex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
//   /* USER CODE END 6 */
// }
// #endif /* USE_FULL_ASSERT */
//
// /************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
