# Generates a fully position independent .bin

#---------- Performance  ----------#

# MAKEFLAGS += -s -j1
MAKEFLAGS += -s -j$(NUMBER_OF_PROCESSORS)

#---------- Project Settings  ----------#

PROJECT := hannibal
CC_X64	:= x86_64-w64-mingw32-g++

#---------- Compiler Flags  ----------#

# https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html
# https://gcc.gnu.org/onlinedocs/gcc/Cygwin-and-MinGW-Options.html
# https://forum.tinycorelinux.net/index.php/topic,26375.0.html

CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS += -nolibc -nostdlib++ 
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS += -falign-labels=1 -fPIC
CFLAGS += -Iinclude -masm=intel -fpermissive -mrdrnd
CFLAGS += -D PIC_BUILD -D PROFILE_MYTHIC_HTTP

DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$(*F).d

#---------- Linker Flags  ----------#

LDFLAGS := -Wl,-Tscripts/Linker.ld
LDFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup

#---------- Paths ----------#

ASM_DIR := asm/x64
SRC_DIR := src
OBJ_DIR := bin/obj
BIN_DIR := bin
DEP_DIR := $(BIN_DIR)/deps
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES := $(SRC_FILES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEP_FILES := $(SRC_FILES:$(SRC_DIR)/%.c=$(DEP_DIR)/%.d)
ASM_FILES := $(wildcard $(ASM_DIR)/*.asm)
ASM_OBJ_FILES := $(ASM_FILES:asm/x64/%.asm=bin/obj/%.o)

#---------- Targets ----------#

all: $(BIN_DIR)/$(PROJECT).exe

$(BIN_DIR)/$(PROJECT).exe: $(ASM_OBJ_FILES) $(OBJ_FILES)
	@ echo "[+] Linking x64 Executable"
	@ $(CC_X64) bin/obj/*.o -o $(BIN_DIR)/$(PROJECT).exe $(CFLAGS) $(LDFLAGS)
	@python scripts/build.py -f $(BIN_DIR)/$(PROJECT).exe -o $(BIN_DIR)/$(PROJECT).bin
	
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEP_DIR)/%.d | $(DEP_DIR)
	@echo "[+] Compiling $< -> $@"
	@ $(CC_X64) -o $@ -c  $< $(DEPFLAGS) $(CFLAGS) $(LDFLAGS)

$(ASM_OBJ_FILES): $(OBJ_DIR)/%.o: asm/x64/%.asm
	@echo "[+] Assembling $? -> $@"
	@ nasm -f win64 $? -o $@

$(DEP_DIR):
	@if not exist $(DEP_DIR) mkdir "$(DEP_DIR)"

$(DEP_FILES):

-include $(DEP_FILES)

#---------- Utility ----------#

clean:
	@ del /q bin\obj\*.o 2>nul
	@ del /q bin\obj\*.s 2>nul
	@ del /q bin\obj\*.ii 2>nul
	@ del /q "$(DEP_DIR)"
	@ del /q bin\*.bin 2>nul
	@ del /q bin\*.exe 2>nul

print:
	@echo "SRC_FILES: $(SRC_FILES)"
	@echo "OBJ_FILES: $(OBJ_FILES)"
	@echo "ASM_FILES: $(ASM_FILES)"
	@echo "DEP_FILES: $(DEP_FILES)"
	@echo "ASM_OBJ_FILES": $(ASM_OBJ_FILES)"