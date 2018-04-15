# Porting the core Redox kernel to arm AArch64: An outline

## Intro

This document is [my](https://github.com/raw-bin) attempt at:

* Capturing thinking on the work needed for a core Redox kernel port
* Sharing progress with the community as things evolve
* Creating a template that can be used for ports to other architectures

Core Redox kernel means everything needed to get to a non-graphical console-only multi-user shell.

Only the 64-bit execution state (AArch64) with the 64-bit instruction set architecture (A64)  shall be supported for the moment. For more background/context read [this](https://developer.arm.com/products/architecture/a-profile/docs/den0024/latest/introduction).

This document is intended to be kept *live*. It will be updated to reflect the current state of work and any feedback received.

It is hard~futile to come up with a strict sequence of work for such ports but this document is a reasonable template to follow.

## Intended target platform

The primary focus is on [qemu's virt machine platform emulation for the AArch64 architecture](https://github.com/qemu/qemu/blob/master/hw/arm/virt.c#L127).

Targeting a virtual platform is a convenient way to bring up the mechanics of architectural support and makes the jump to silicon easier. The preferred boot chain for AArch64 (explained later) is well supported on this platform and boot-over-tftp from localhost makes the debug cycle very efficient.

Once the core kernel port is complete a similar follow on document will be created that is dedicated to silicon bring-up.

## Boot protocol elements

Item | Notes
-----|-------
[Linux kernel boot protocol for AArch64](https://www.kernel.org/doc/Documentation/arm64/booting.txt) | The linked document describes assumptions made from the bootloader which are field tested and worthwhile to have for Redox an AArch64. <br/> The intent is to consider most of the document except anything tied to the Linux kernel itself.
[Flattened Device Tree](https://elinux.org/Device_Tree_Reference) | FDT binary blobs supplied by the bootloader shall provide the Redox kernel with misc platform \{memory, interrupt, devicemem} maps. Qemu's virt machine platform synthetically creates an FDT blob at a specific address which is very handy.

## Boot flow elements

The following table lists the boot flow in order.

Item | Notes
-----|-------
[ARM Trusted Firmware (TF-A)](https://github.com/ARM-software/arm-trusted-firmware) | TF-A is a de-facto standard reference firmware implementation and proven in the field. <br/> TF-A runs post power-on on Armv8-A implementations and eventually hands off to further stages of the boot flow.<br />For qemu's virt machine platform, it is essentially absent but I mean to rely on it heavily for silicon bring up hence mentioning it here. 
[u-boot](https://www.denx.de/wiki/U-Boot) | u-boot will handle early console access, media access for fetching redox kernel images from non-volatile storage/misc disk subsystems/off the network. <br /> u-boot supports loading EFI applications. If EFI support to AArch64 Redox is added in the future that should essentially work out of the box. <br /> u-boot will load redox and FDT binary blobs into RAM and jump to the redox kernel.
Redox early-init stub | For AArch64, the redox kernel will contain an A64 assembly stub that will setup the MMU from scratch. This is akin to the [x86_64 redox bootloader](https://github.com/redox-os/bootloader/blob/master/x86_64/startup-x86_64.asm). <br /> This stub sets up identity maps for MMU initialization, maps the kernel image itself as well as the device memory for the UART console. At present this stub shall be a part of the kernel itself for simplicity.
Redox kstart entry | The early init stub hands off here. kstart will then re-init the MMU more comprehensively.

## Supported devices

The following devices shall be supported. All necessary information specific to these devices will be provided to the redox kernel by the platform specific FDT binary blob.

Device | Notes
-------|-------
[Generic Interrupt Controller v2](https://developer.arm.com/products/architecture/a-profile/docs/ihi0048/b/arm-generic-interrupt-controller-architecture-version-20-architecture-specification) | The GIC is an Arm-v8A architectural element and is supported by all architecturally compliant processor implementations. GICv2 is supported by qemu's virt machine emulation and most subsequent GIC implementations are backward compatible to GICv2.
[Generic Timer](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0500d/BGBBIJCB.html) | The Generic Timer Architecture is an Arm-v8A architectural element and is implemented by all compliant processor implementations. It is supported by qemu.
[PrimeCell UART PL011](http://infocenter.arm.com/help/topic/com.arm.doc.ddi0183f/DDI0183.pdf) | The PL011 UART is supported by qemu and most ARM systems.

## Intended development sequence and status

Item | Description | Status | Notes
-----|-------|-----|-----
Redox AArch64 toolchain | Create an usable redox AArch64 toolchain specification | Done | Using this JSON spec in isolated tests produces valid AArch64 soft float code
Stubbed kernel image | Stub out AArch64 kernel support using the existing x86_64 arch code as a template <br /> Modify redox kernel build glue and work iteratively to get a linkable (non-functional) image |  Not done yet |
Boot flow | Create a self hosted u-boot -> redox kernel workflow <br /> Should obtain the stubbed image from a local TFTP server, load it into RAM and jump to it  | Not done yet |
GDB Debug flow | Create a debug workflow centered around qemu's GDB stub <br /> This should allow connecting to qemu's GDB stub and debug u-boot/redox stub via a GDB client and single stepping through code | Not done yet |
Verify Redox entry | Verify that control reaches the redox kernel from u-boot | Not done yet |
AArch64 early init stub | Add support for raw asm code for early AArch64 init in the redox kernel <br /> Verify that this code is located appropriately in the link map and that control reaches this code from u-boot | Not done yet |
Basic DTB support | Integrate the [device_tree crate](https://mbr.github.io/device_tree-rs/device_tree/) <br /> Use the crate to access the qemu supplied DTB image and extract the memory map | Not done yet |
Basic UART support | Use the device_tree crate to get the UART address from the DTB image and set up the initial console <br /> This is a polling mode only setup | Not done yet |
Initial MMU support | Implement initial MMU support in the early init stub <br /> This forces the MMU into a clean state overriding any bootloader specific setup <br /> Create an identity map for MMU init <br /> Create a mapping for the kernel image <br /> Create a mapping for any devices needed at this stage (UART)| Not done yet |
kmain entry | Verify that kmain entry works post early MMU init | Not done yet |
Basic Redox MMU support | Get Redox to create a final set of mappings for everything <br /> Verify that this works as expected| Not done yet |
Basic libc support | Flesh out a basic set of libc calls as required for simple user-land apps | Not done yet |
userspace_init entry | Verify user-space entry and /sbin/init invocation | Not done yet |
Basic Interrupt controller support | Add a GIC driver <br /> Verify functionality | Not done yet |
Basic Timer support | Add a Generic Timer driver <br /> Verify functionality | Not done yet |
UART interrupt support | Add support for UART interrupts | Not done yet |
Task context switch support | Add context switching support <br /> Verify functionality | Not done yet |
Login shell | Iteratively add and verify multi-user login shell support | Not done yet |
Publish development branch on github | Work with the community to post work done after employer approval | Not done yet |
Break out the Bubbly | Drink copious quantities of alcohol to celebrate | Not done yet |
Silicon bring-up | Plan silicon bring-up | Not done yet |
