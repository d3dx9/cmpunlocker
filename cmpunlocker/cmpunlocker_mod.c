/* cmpunlocker_mod.c — One-shot kernel module for CMP 170HX 80GB unlock.
 *
 * This module does the post-exploit writes (PLM stays open from the
 * ROP chain in the patched firmware, then this module writes the rest
 * once at module load time).
 *
 * Build:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *   # or
 *   gcc -I/lib/modules/$(uname -r)/build/include \
 *       -include linux/module.h -fPIC -shared -o cmpunlocker.ko cmpunlocker_mod.c
 *
 * Install:
 *   sudo cp cmpunlocker.ko /lib/modules/$(uname -r)/extra/
 *   sudo depmod -a
 *   echo cmpunlocker | sudo tee /etc/modules-load.d/cmpunlocker.conf
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cmpunlocker");
MODULE_DESCRIPTION("One-shot unlock writes for CMP 170HX");
MODULE_VERSION("1.0");

/* Community-verified unlock values */
static const struct {
    u32 addr;
    u32 value;
    const char *label;
} UNLOCK_WRITES[] = {
    /* These were already done by the ROP chain in the firmware, but
     * re-writing them on module load ensures they survive FLR/module
     * reload events. */
    { 0x9A0204, 0x02669000, "CFG1 (40GB geometry)" },
    { 0x100CE0, 0x0000028a, "LMR (memory rank)" },
    { 0x1FA824, 0x1FFFFE00, "WPR2 lo (teardown)" },
    { 0x1FA828, 0x00000000, "WPR2 hi (teardown)" },
    { 0x8403C4, 0x000000FF, "resetPLM (open)" },

    /* Post-exploit writes that need PLM access */
    { 0x100114, 0x00000010, "ECC scrub interval" },
    { 0x88000C, 0x00000001, "NVLink link enable" },
    { 0x000118, 0x00000004, "PCIe Link Control 2 → Gen 4" },

    /* Compute unlock (SS0/SS1 for SM clock) */
    { 0x82381C, 0x88888888, "SS0 (FEAT_OVR_SM_SPD)" },
    { 0x823820, 0x00000008, "SS1 (FEAT_OVR_SM_SPD_1)" },
};

static int cmpunlocker_write_bar0(struct pci_dev *pdev, u32 offset, u32 value)
{
    void __iomem *bar;

    /* BAR0 size must be at least 0x200000 (PCI MMIO for the GPU registers). */
    if (pci_resource_len(pdev, 0) < 0x200000) {
        pr_err("cmpunlocker: BAR0 too small (%llu bytes)\n",
               (unsigned long long)pci_resource_len(pdev, 0));
        return -ENODEV;
    }

    bar = pci_iomap(pdev, 0, pci_resource_len(pdev, 0));
    if (!bar) {
        pr_err("cmpunlocker: failed to iomap BAR0\n");
        return -ENOMEM;
    }

    pr_info("cmpunlocker: write 0x%06x = 0x%08x\n", offset, value);
    iowrite32(value, bar + offset);

    pci_iounmap(pdev, bar);
    return 0;
}

static int cmpunlocker_probe(struct pci_dev *pdev,
                              const struct pci_device_id *id)
{
    int i, ret;
    int wrote = 0;

    pr_info("cmpunlocker: probing %04x:%04x\n", pdev->vendor, pdev->device);

    for (i = 0; i < ARRAY_SIZE(UNLOCK_WRITES); i++) {
        ret = cmpunlocker_write_bar0(pdev,
                                     UNLOCK_WRITES[i].addr,
                                     UNLOCK_WRITES[i].value);
        if (ret == 0)
            wrote++;
    }

    pr_info("cmpunlocker: wrote %d/%d unlock values\n",
            wrote, (int)ARRAY_SIZE(UNLOCK_WRITES));
    return 0;
}

static void cmpunlocker_remove(struct pci_dev *pdev)
{
    pr_info("cmpunlocker: remove\n");
}

/* Match CMP 170HX and A100 device IDs */
static const struct pci_device_id cmpunlocker_ids[] = {
    { PCI_DEVICE(0x10de, 0x20b0) },  /* CMP 170HX 40GB */
    { PCI_DEVICE(0x10de, 0x20c2) },  /* CMP 170HX 40GB */
    { PCI_DEVICE(0x10de, 0x2082) },  /* CMP 170HX 10GB */
    { PCI_DEVICE(0x10de, 0x20b2) },  /* A100 40GB */
    { PCI_DEVICE(0x10de, 0x20b4) },  /* A100 80GB */
    { }
};
MODULE_DEVICE_TABLE(pci, cmpunlocker_ids);

static struct pci_driver cmpunlocker_driver = {
    .name       = "cmpunlocker",
    .id_table   = cmpunlocker_ids,
    .probe      = cmpunlocker_probe,
    .remove     = cmpunlocker_remove,
};

module_pci_driver(cmpunlocker_driver);