# Secure_Arch_AMD_Install_Oculink_eGPU
Installation Steps for a new Lenovo Thinkbook TGX (Oculink) Security Enhanhed Arch Gnome Wayland AMD only

# Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)
This action plan outlines the steps to install and configure Arch Linux on a Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H without dGPU, **using GNOME Wayland, BTRFS, LUKS2, TPM2, AppArmor, systemd-boot with UKI, Secure Boot, and an OCuP4V2 OCuLink GPU Dock ReDriver with an AMD GPU**. This laptop has two M.2, we will have Windows in a slot to help updating BIOS and Firmware at least in the beginning.

Observation: Not adopting linux-hardened kernel because of complexity in the setup.

**Attention:** Before executing commands, especially those involving **dd, mkfs, cryptsetup, parted, and efibootmgr, re-read them multiple times to ensure you understand their effect** and that the target device/partition is correct. Ensure LUKS and TPM unlocking work perfectly before touching Secure Boot, and ensure Secure Boot works before diving into the eGPU.

# Step 1: Verify Hardware

    Access UEFI BIOS (F2 at boot):

        Enable TPM 2.0, Secure Boot, Resizable BAR, SVM/VT-x, and Intel VT-d (IOMMU).

        Check for “Hybrid Graphics” or “PCIe Hotplug” options.

        Set a strong UEFI BIOS password, store it in Bitwarden, and disable legacy boot.

# Step 2: Install Windows on Primary NVMe M.2 (/dev/nvme0n1)

Follow some of the installations Privacy advises from the Privacy Guides Wiki Minimizing [Windows 11 Data Collection](https://discuss.privacyguides.net/t/minimizing-windows-11-data-collection/28193)

    Install Windows 11 Pro for BIOS/firmware updates via Lenovo Vantage. Allow Windows to create its default partitions, including a ~100-300 MB EFI System Partition (ESP) at /dev/nvme0n1p1. 

    Disable Windows Fast Startup to prevent ESP lockout (powercfg /h off).

    Disable BitLocker if not needed (Powershell): a) manage-bde -status b) Disable-BitLocker -MountPoint "C:" c) powercfg /a

    Verify TPM 2.0 is active using tpm.msc. Clear TPM if previously provisioned.

    Verify Windows boots correctly and **check Resizable BAR sizes in Device Manager** or wmic path Win32_VideoController get CurrentBitsPerPixel,VideoMemoryType or `dmesg | grep -i "BAR.*size"` (in Linux later).

    Check Oculink support 'dmidecode -s bios-version'

    Verify NVMe drives **Windows Disk Management**.

Review the guides for additional Privacy on the post installation [Group Police](https://www.privacyguides.org/en/os/windows/group-policies/), [Windows Privacy Settings](https://discuss.privacyguides.net/t/windows-privacy-settings/27333) and [Windows Post-Install Hardening Guide](https://discuss.privacyguides.net/t/windows-post-install-hardening-guide/27335)

# Step 3: Prepare Installation Media

    Download the latest Arch Linux ISO from archlinux.org.

    Verify the ISO signature and create a bootable USB drive.

# Step 4: Pre-Arch Installation Steps

Boot Arch Live USB (disable Secure Boot temporarily in UEFI).

## Step 4: **Pre-Arch Installation Steps**
**Boot Arch Live USB (disable Secure Boot temporarily in UEFI)**
  - Pre-computation and Pre-determination of System Identifiers
    - **LUKS Partition UUID:**
    - After encrypting your chosen partition (e.g. /dev/nvme1n1p2) with LUKS, retrieve its UUID. This UUID is distinct from the UUID of the logical volume within the LUKS container.
      - cryptsetup luksUUID /dev/nvme1n1p2
    - Record this UUID. It will be essential for the crypttab entry and potentially for rd.luks.uuid in your kernel parameters if not using the /dev/mapper name directly in the bootloader.
    - **Root Filesystem UUID:**
    - Once your root filesystem (e.g., BTRFS on /dev/mapper/cryptroot) is created, obtain its UUID.
      - blkid -s UUID -o value /dev/mapper/cryptroot
    - Record this UUID. This will be used in your /etc/fstab entry for the root filesystem.
    - **Swap File/Partition Offset (for Hibernation):**
    - If you are using a swap file on a BTRFS subvolume and plan to use hibernation, you'll need to determine the physical offset of the swap file within the filesystem. This offset is crucial for the resume_offset kernel parameter. First, ensure your swap file is created and chattr +C is applied to prevent Copy-On-Write for the swap file. Then, get the offset:
      - SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
      - echo "resume_offset=${SWAP_OFFSET}" >> /mnt/etc/default/grub # Example for grub, you correctly put it in the UKI options.
    - Record this SWAP_OFFSET value. This numerical value will be directly inserted into your systemd-boot kernel parameters and potentially your fstab if you're using resume= with a swap file.

a) Partition the Second NVMe M.2 (/dev/nvme1n1):

    parted /dev/nvme1n1 --script mklabel gpt mkpart ESP fat32 1MiB 1GiB set 1 esp on mkpart crypt btrfs 1GiB 100% align-check optimal 1 quit

    lsblk -f /dev/nvme0n1 /dev/nvme1n1  # Confirm /dev/nvme0n1p1 (Windows ESP) and /dev/nvme1n1p1 (Arch ESP)

    efibootmgr  # Check if UEFI recognizes both ESPs

b) Format ESP:

    mkfs.fat -F32 -n ARCH_ESP /dev/nvme1n1p1

c) Set Up LUKS2 Encryption for the BTRFS file system:

    cryptsetup luksFormat --type luks2 /dev/nvme1n1p2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000000

    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot

    mkdir -p /mnt/usb

    lsblk

    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**

    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile

    Create a keyfile for automatic unlocking (recommended for TPM):

        dd if=/dev/random of=/mnt/crypto_keyfile bs=512 count=4 iflag=fullblock

        chmod 600 /mnt/crypto_keyfile

        cryptsetup luksAddKey /dev/nvme1n1p2 /mnt/crypto_keyfile

d) Create BTRFS Filesystem and Subvolumes:

    mkfs.btrfs /dev/mapper/cryptroot

    mount /dev/mapper/cryptroot /mnt

    Create subvolumes for `@`, `@snapshots`, `@home`, `@data`, `@var`, `@var_lib`, `@log`, `@swap`, `@srv`:

        btrfs subvolume create /mnt/@

        btrfs subvolume create /mnt/@snapshots

        btrfs subvolume create /mnt/@home

        btrfs subvolume create /mnt/@data

        btrfs subvolume create /mnt/@var

        btrfs subvolume create /mnt/@var_lib

        btrfs subvolume create /mnt/@log

        btrfs subvolume create /mnt/@swap

        btrfs subvolume create /mnt/@srv

    umount /mnt

    Mount subvolumes with appropriate options (e.g., compress=zstd:3, ssd, nodatacow for specific subvolumes like @var).

        mount -o subvol=@,compress=zstd:3,ssd /dev/mapper/cryptroot /mnt

        mkdir -p /mnt/{boot,windows-efi,.snapshots,home,data,var,var/lib,var/log,swap,srv}

        mount /dev/nvme1n1p1 /mnt/boot

        mount /dev/nvme0n1p1 /mnt/windows-efi

        mount -o subvol=@home,compress=zstd:3,ssd /dev/mapper/cryptroot /mnt/home

        mount -o subvol=@data,compress=zstd:3,ssd /dev/mapper/cryptroot /mnt/data

        mount -o subvol=@var,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var

        mount -o subvol=@var_lib,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var/lib

        mount -o subvol=@log,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var/log

        mount -o subvol=@srv,compress=zstd:3,ssd /dev/mapper/cryptroot /mnt/srv

        mount -o subvol=@swap,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/swap

        mount -o subvol=@snapshots,ssd,noatime /dev/mapper/cryptroot /mnt/.snapshots

e) Configure Swap File:

    Create a swap file on the @swap subvolume, ensuring chattr +C is set to disable Copy-on-Write.

        truncate -s 0 /mnt/swap/swapfile

        chattr +C /mnt/swap/swapfile

        fallocate -l 24G /mnt/swap/swapfile

        chmod 600 /mnt/swap/swapfile

        mkswap /mnt/swap/swapfile

        Obtain the swapfile's physical offset for hibernation:

            SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')

            echo "resume_offset=${SWAP_OFFSET}" > /mnt/etc/swap_offset

f) Generate fstab:

    genfstab -U /mnt | tee /mnt/etc/fstab

    Manually edit /mnt/etc/fstab to verify subvolume options, add umask=0077 to /boot, and add entries for tmpfs and the swapfile, ensuring you use the numerical resume_offset value.
