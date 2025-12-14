SOURCE:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD?=$(CURDIR)
export RUST_TARGET_PATH=$(SOURCE)/targets

ifeq ($(TARGET),)
	ARCH?=$(shell uname -m)
else
	ARCH?=$(shell echo "$(TARGET)" | cut -d - -f1)
endif

ifeq ($(ARCH),riscv64gc)
	override ARCH:=riscv64
	GNU_TARGET=riscv64-unknown-redox
else ifeq ($(ARCH),i686)
	override ARCH:=i586
	GNU_TARGET=i686-unknown-redox
else
	GNU_TARGET=$(ARCH)-unknown-redox
endif


all: $(BUILD)/kernel $(BUILD)/kernel.sym

LD_SCRIPT=$(SOURCE)/linkers/$(ARCH).ld
LOCKFILE=$(SOURCE)/Cargo.lock
MANIFEST=$(SOURCE)/Cargo.toml
TARGET_SPEC=$(RUST_TARGET_PATH)/$(ARCH)-unknown-kernel.json

$(BUILD)/kernel.all: $(LD_SCRIPT) $(LOCKFILE) $(MANIFEST) $(TARGET_SPEC) $(shell find $(SOURCE) -name "*.rs" -type f)
	cargo rustc \
		--bin kernel \
		--manifest-path "$(MANIFEST)" \
		--target "$(TARGET_SPEC)" \
		--release \
		-Z build-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
		-- \
		-C link-arg=-T -Clink-arg="$(LD_SCRIPT)" \
		-C link-arg=-z -Clink-arg=max-page-size=0x1000 \
		--emit link="$(BUILD)/kernel.all"

$(BUILD)/kernel.sym: $(BUILD)/kernel.all
	$(GNU_TARGET)-objcopy \
		--only-keep-debug \
		"$(BUILD)/kernel.all" \
		"$(BUILD)/kernel.sym"

$(BUILD)/kernel: $(BUILD)/kernel.all
	$(GNU_TARGET)-objcopy \
		--strip-debug \
		"$(BUILD)/kernel.all" \
		"$(BUILD)/kernel"
