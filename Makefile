export RUST_TARGET_PATH=targets

ifeq ($(TARGET),)
	ARCH?=$(shell uname -a)
else
	ARCH?=$(shell echo "$(TARGET)" | cut -d - -f1)
endif

BUILD?=target/$(ARCH)-unknown-kernel

all: $(BUILD)/kernel $(BUILD)/kernel.sym

LD_SCRIPT=linkers/$(ARCH).ld
TARGET_SPEC=targets/$(ARCH)-unknown-kernel.json

$(BUILD)/kernel.all: $(LD_SCRIPT) $(TARGET_SPEC) $(shell find . -name "*.rs" -type f)
	cargo rustc \
		--bin kernel \
		--target "$(TARGET_SPEC)" \
		--release \
		-Z build-std=core,alloc \
		-- \
		-C link-arg=-T -Clink-arg="$(LD_SCRIPT)" \
		-C link-arg=-z -Clink-arg=max-page-size=0x1000 \
		--emit link="$(BUILD)/kernel.all"

$(BUILD)/kernel.sym: $(BUILD)/kernel.all
	$(TARGET)-objcopy \
		--only-keep-debug \
		"$(BUILD)/kernel.all" \
		"$(BUILD)/kernel.sym"

$(BUILD)/kernel: $(BUILD)/kernel.all
	$(TARGET)-objcopy \
		--strip-debug \
		"$(BUILD)/kernel.all" \
		"$(BUILD)/kernel"
