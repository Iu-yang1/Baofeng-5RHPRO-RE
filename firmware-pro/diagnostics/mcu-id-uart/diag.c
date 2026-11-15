/* UV-5RH Pro MCU-ID UART diagnostic: EXPERIMENTAL, NO HARDWARE VALIDATION.
 * Standalone Cortex-M3/M4 Thumb firmware, linked as a candidate APP at 0x08001000.
 * Reads core identification and optional vendor ID fields; no RF or Flash writes.
 * WARNING: vendor-specific address reads may BusFault on other silicon.
 * The linker/serial pin assumptions and recovery path are NOT verified.
 */
#include <stdint.h>

#ifndef DIAG_PCLK2_HZ
#define DIAG_PCLK2_HZ 8000000u
#endif
#ifndef DIAG_BAUD
#define DIAG_BAUD 9600u
#endif
#ifndef DIAG_READ_VENDOR_IDS
#define DIAG_READ_VENDOR_IDS 1
#endif

#define MMIO32(addr) (*(volatile uint32_t *)(uintptr_t)(addr))
#define MMIO16(addr) (*(volatile uint16_t *)(uintptr_t)(addr))
#define MMIO8(addr)  (*(volatile uint8_t *)(uintptr_t)(addr))
#define RCC_APB2ENR 0x40021018u
#define GPIOA_CRH   0x40010804u
#define USART1_SR   0x40013800u
#define USART1_DR   0x40013804u
#define USART1_BRR  0x40013808u
#define USART1_CR1  0x4001380Cu

extern uint32_t _stack_top;
void Reset_Handler(void);
void Default_Handler(void);
__attribute__((used, section(".isr_vector")))
const uintptr_t vectors[16] = {
    (uintptr_t)&_stack_top, (uintptr_t)&Reset_Handler,
    (uintptr_t)&Default_Handler, (uintptr_t)&Default_Handler,
    (uintptr_t)&Default_Handler, (uintptr_t)&Default_Handler,
    (uintptr_t)&Default_Handler, 0, 0, 0, 0,
    (uintptr_t)&Default_Handler, (uintptr_t)&Default_Handler,
    0, (uintptr_t)&Default_Handler, (uintptr_t)&Default_Handler,
};

void Default_Handler(void) { for (;;) { __asm__ volatile("nop"); } }

static void uart1_init(void) {
    /* Candidate standard STM32F1 GPIOA PA9(TX), PA10(RX) layout. */
    MMIO32(RCC_APB2ENR) |= (1u << 0) | (1u << 2) | (1u << 14);
    uint32_t crh = MMIO32(GPIOA_CRH);
    MMIO32(GPIOA_CRH) = (crh & ~(0xFFu << 4)) | (0x4Bu << 4);
    MMIO32(USART1_CR1) = 0u;
    MMIO32(USART1_BRR) = (DIAG_PCLK2_HZ + DIAG_BAUD / 2u) / DIAG_BAUD;
    MMIO32(USART1_CR1) = (1u << 13) | (1u << 3) | (1u << 2);
}

static void tx_char(char ch) {
    while ((MMIO32(USART1_SR) & (1u << 7)) == 0) {}
    MMIO32(USART1_DR) = (uint32_t)(unsigned char)ch;
}

static void tx_str(const char *s) {
    while (*s) tx_char(*s++);
}

static void tx_hex(uint32_t value, unsigned digits) {
    static const char symbols[] = "0123456789ABCDEF";
    while (digits) {
        --digits;
        tx_char(symbols[(value >> (digits * 4u)) & 15u]);
    }
}

static void transmit_identification(void) {
    tx_str("UV5RHPRO-ID/1,CPUID=0x");
    tx_hex(MMIO32(0xE000ED00u), 8);
#if DIAG_READ_VENDOR_IDS
    /* An absent/undefined MMIO address can cause a BusFault/HardFault.
       All device-specific reads are optional at build time. */
    tx_str(",FSIZE_RAW=0x");
    tx_hex(MMIO16(0x1FFFF7E0u), 4);
    tx_str(",DBG_ID=0x");
    tx_hex(MMIO32(0xE0042000u), 8);
    tx_str(",AT_PROJECT=0x");
    tx_hex(MMIO8(0x1FFFF7F3u), 2);
    tx_str(",AIR_UID0_MASK=0x");
    tx_hex(MMIO32(0x1FFFF7E8u) >> 4, 7);
    tx_char('X');
#endif
    tx_str("\r\n");
}

void Reset_Handler(void) {
    uart1_init();
    for (;;) {
        transmit_identification();
        /* Approximate retry interval. Not used for baud calculation. */
        for (volatile uint32_t i = 0; i < 3000000u; ++i)
            __asm__ volatile("nop");
    }
}
