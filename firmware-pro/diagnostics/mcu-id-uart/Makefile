# Experimental ELF only. Do not generate or install Baofeng .dat packages.
CLANG ?= clang
BAUD ?= 9600
PCLK2_HZ ?= 8000000
VENDOR_READS ?= 1
CFLAGS = -target armv7m-none-eabi -mcpu=cortex-m3 -mthumb -Os -std=c11 -ffreestanding -fno-builtin -fdata-sections -ffunction-sections -Wall -Wextra -Werror -DDIAG_BAUD=$(BAUD) -DDIAG_PCLK2_HZ=$(PCLK2_HZ) -DDIAG_READ_VENDOR_IDS=$(VENDOR_READS)
LDFLAGS = -nostdlib -fuse-ld=lld -Wl,-T,linker.ld -Wl,--gc-sections -Wl,--no-undefined

.PHONY: all clean
all: build/id_probe.elf
build/id_probe.elf: diag.c linker.ld
	mkdir -p build
	$(CLANG) $(CFLAGS) $(LDFLAGS) diag.c -o $@
clean:
	rm -rf build
