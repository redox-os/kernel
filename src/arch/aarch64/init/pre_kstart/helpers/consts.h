#define PAGE_SIZE               4096
#define GIGABYTE                0x40000000
#define VIRT_BITS               48
#define NUM_TABLES              14

#define EARLY_KSTACK_SIZE       (PAGE_SIZE)                         // Initial stack

#define DEVMAP_VBASE            0xfffffe0000000000

#define SCTLR_M                 0x00000001                          // SCTLR_M bit used to control MMU on/off

#define DEVICE_MEM              0                                   // Memory type specifiers
#define NORMAL_UNCACHED_MEM     1
#define NORMAL_CACHED_MEM       2

#define DESC_VALID_BIT          0                                   // Descriptor validity setting
#define DESC_VALID              1
#define DESC_INVALID            0

#define DESC_TYPE_BIT           1                                   // Descriptor type
#define DESC_TYPE_TABLE         1
#define DESC_TYPE_PAGE          1
#define DESC_TYPE_BLOCK         0

#define BLOCK_DESC_MASK         (~((0xffff << 48) | (0xffff)))      // Convenience mask for block desciptors
#define ACCESS_FLAG_BIT         (1 << 10)
