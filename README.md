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
  - Pre-computation and Pre-determination of System Identifiers
    - **LUKS for rd.luks.uuid and Partition UUID:**
    - After encrypting your chosen partition (e.g. /dev/nvme1n1p2) with LUKS, retrieve its UUID. This UUID is distinct from the UUID of the logical volume within the LUKS container:
      - LUKS_HEADER_UUID=$(cryptsetup luksUUID /dev/nvme1n1p2)
    - Record this UUID. It will be essential for the crypttab entry and for (rd.luks.uuid=...) in the kernel parameters, since we are not using the /dev/mapper name directly in the bootloader.
      - LUKS_UUID=$(blkid -s UUID -o value /dev/nvme1n1p2)
    - Record this UUID. It will be essential for kernel and crypttab, always good for mapping partition UUID.
    - **Root Filesystem UUID:**
    - Once your root filesystem (e.g., BTRFS on /dev/mapper/cryptroot) is created, obtain its UUID.
      - ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
      - echo $ROOT_UUID   # Should output a UUID like 48d0e960-1b5e-4f2c-8caa-... 
    - Record this UUID. Both bootloader (root=UUID=...) and /etc/fstab file need this to identify and mount the correct root filesystem after the LUKS container is opened.
    - **Swap File/Partition Offset (for Hibernation):**
    - If you are using a swap file on a BTRFS subvolume and plan to use hibernation, you'll need to determine the physical offset of the swap file within the filesystem. This offset is crucial for the resume_offset kernel parameter. Ensure your swap file is created and chattr +C is applied to prevent Copy-On-Write for the swap file (this is achieved in the step 4e). Get the resume_offset:
      - SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
      - SWAP_OFFSET=$(cat /etc/swap_offset)
      - echo "resume_offset=${SWAP_OFFSET}" >> /mnt/etc/default/grub # Example for grub, correctly added it in the UKI options.
    - Record this SWAP_OFFSET value. This numerical value will be directly inserted into your systemd-boot kernel parameters and potentially your fstab if you're using resume_offset= with a swap file.

a) Partition the Second NVMe M.2 (/dev/nvme1n1):

    parted /dev/nvme1n1 --script mklabel gpt mkpart ESP fat32 1MiB 1GiB set 1 esp on mkpart crypt btrfs 1GiB 100% align-check optimal 1 quit
    lsblk -f /dev/nvme0n1 /dev/nvme1n1  # Confirm /dev/nvme0n1p1 (Windows ESP) and /dev/nvme1n1p1 (Arch ESP)
    efibootmgr  # Check if UEFI recognizes both ESPs

b) Format ESP:

    mkfs.fat -F32 -n ARCH_ESP /dev/nvme1n1p1

c) Set Up LUKS2 Encryption for the BTRFS file system:

    Format the partition:
    cryptsetup luksFormat --type luks2 /dev/nvme1n1p2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000000

    Open it:
    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot

    Create the keyfile for automatic unlocking (recommended for TPM):
    dd if=/dev/urandom of=/mnt/crypto_keyfile bs=512 count=4 iflag=fullblock
    chmod 600 /mnt/crypto_keyfile

    Add the keyfile to LUKS:
    cryptsetup luksAddKey /dev/nvme1n1p2 /mnt/crypto_keyfile

    Back it up to USB:
    mkdir -p /mnt/usb
    lsblk
    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**
    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile

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
        mount -o subvol=@swap,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/swap # Ensure NoCoW is set!
        mount -o subvol=@snapshots,ssd,noatime /dev/mapper/cryptroot /mnt/.snapshots

e) Configure Swap File:

    Create a swap file on the @swap subvolume, ensuring chattr +C is set to disable Copy-on-Write.
        touch /mnt/swap/swapfile 
        chattr +C /mnt/swap/swapfile
        fallocate -l 24G /mnt/swap/swapfile || { echo "fallocate failed"; exit 1; }
        chmod 600 /mnt/swap/swapfile
        mkswap /mnt/swap/swapfile || { echo "mkswap failed"; exit 1; }

        Obtain the swapfile's physical offset for hibernation:
        SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
        #Replace $SWAP_OFFSET with actual precomputed values:
        
        echo $SWAP_OFFSET > /mnt/etc/swap_offset
        umount /mnt/swap
        #Replace $SWAP_OFFSET with actual precomputed values:
        echo "/swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0" >> /mnt/etc/fstab

f) Generate fstab:

    genfstab -U /mnt | tee /mnt/etc/fstab
    Manually edit /mnt/etc/fstab to verify subvolume options, add umask=0077 to /boot, and add entries for tmpfs and the swapfile, ensuring you use the numerical resume_offset value.

    **Adjust Btrfs subvolume and mount options (use $ROOT_UUID number from the pre-computation):
      - UUID=$ROOT_UUID / btrfs subvol=@,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      - UUID=$ROOT_UUID /home btrfs subvol=@home,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      - UUID=$ROOT_UUID /data btrfs subvol=@data,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      - UUID=$ROOT_UUID /var btrfs subvol=@var,nodatacow,noatime 0 0
      - UUID=$ROOT_UUID /var/lib btrfs subvol=@var_lib,nodatacow,noatime 0 0
      - UUID=$ROOT_UUID /var/log btrfs subvol=@log,nodatacow,noatime 0 0
      - UUID=$ROOT_UUID /srv btrfs subvol=@srv,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      - UUID=$ROOT_UUID /swap btrfs subvol=@swap,nodatacow,noatime 0 0
      - UUID=$ROOT_UUID /.snapshots btrfs subvol=@snapshots,ssd,noatime 0 0

    **Edit ESP (/boot) entry. Change defaults to umask=0077 for improved security. It will look something like: `UUID=<ARCH_ESP_UUID_VALUE> /boot vfat defaults 0 2`. Change `defaults` to `umask=0077`:
      - UUID=$ARCH_ESP_UUID /boot vfat umask=0077 0 2

    **Edit Windows ESP entry
      - UUID=$WINDOWS_ESP_UUID /windows-efi vfat noauto,x-systemd.automount,umask=0077 0 2 

    **Add tmpfs entries:
      - tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0
      - tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0

    **Add swapfile entry (with numerical resume offset):
    #Replace $SWAP_OFFSET with actual precomputed values:
      - /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0

    **Validation Steps (List ESP UUIDs and check mapping):
      - blkid | grep -E 'nvme0n1p1|nvme1n1p1' #(Ensure each UUID matches the correct fstab line for /boot and /windows-efi)

    **Verify your final fstab:
      - cat /mnt/etc/fstab

g) Check network:

      - ping -c 3 archlinux.org
      - nmcli device wifi connect <SSID> password <password>  # If using Wi-Fi
      - Copy DNS into the new system so it can resolve mirrors
      - cp /etc/resolv.conf /mnt/etc/resolv.conf #Copying /etc/resolv.conf from the live environment can be problematic if the network configuration changes or if the live environment's DNS servers aren't reliable/private for your permanent installation. NetworkManager will typically manage resolv.conf once installed and enabled.

# Step 5: Install Arch Linux

    Configure the mirrorlist with reflector.
    -  pacman -Sy reflector
    -  reflector --latest 10 --sort rate --save /etc/pacman.d/mirrorlist 

    Install base system and necessary packages:
    -  pacstrap /mnt base base-devel linux linux-firmware mkinitcpio intel-ucode zsh btrfs-progs sudo cryptsetup dosfstools efibootmgr networkmanager mesa libva-mesa-driver pipewire wireplumber sof-firmware vulkan-intel lib32-vulkan-intel pipewire-pulse pipewire-alsa pipewire-jack archlinux-keyring arch-install-scripts intel-media-driver sbctl git vulkan-radeon lib32-vulkan-radeon

    Chroot into the system:
    -  arch-chroot /mnt

    Move the crypto keyfile: 
    -  mv /crypto_keyfile /root/luks-keyfile && chmod 600 /root/luks-keyfile

    Keyring initialization:
    - nano /etc/pacman.conf uncomment [multilib]
    - add **Include = /etc/pacman.d/mirrorlist** below the [core], [extra], [community], and [multilib] sections in /etc/pacman.conf
    - pacman-key --init
    - pacman-key --populate archlinux
    - pacman -Sy
    - pacman -Syy

# Step 6: System Configuration

    Set timezone, locale, and hostname.
    - ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime
    - hwclock --systohc
    - echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen
    - locale-gen
    - echo 'LANG=en_US.UTF-8' > /etc/locale.conf
    - echo 'thinkbook' > /etc/hostname
    - cat <<'EOF' > /etc/hosts
      - 127.0.0.1 localhost
      - ::1 localhost
      - 127.0.1.1 thinkbook.localdomain thinkbook
    - EOF

    Create User Account
    - Set root password:
      - passwd
    - Create a user with Zsh as the default shell:
      - useradd -m -G wheel,video,input,storage,audio,power,lp -s /usr/bin/zsh <username>
      - passwd <username>
    - Configure `sudo`:
      - sed -i '/^# %wheel ALL=(ALL:ALL) ALL/s/^# //' /etc/sudoers
      - 127.0.0.1 l

# Step 7: Set Up TPM and LUKS2

    Install tpm2-tools and dependencies: 
      - pacman -S --noconfirm tpm2-tools tpm2-tss systemd-ukify

    Verify TPM device is detected
      - tpm2_getcap properties-fixed 

    Enroll the LUKS key to the TPM, binding to PCRs 0, 4, and 7 (firmware, bootloader, Secure Boot state):
      - systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2

    Testing the TPM unlocking works with the current PCR value:
      - systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2
      - systemd-cryptenroll --dump-pcrs /dev/nvme1n1p2 > /mnt/usb/tpm-pcr-initial.txt #This helps catch firmware changes in the future.

    Add the keyfile and sd-encrypt hook to /etc/mkinitcpio.conf:
      - cryptsetup luksDump /dev/nvme1n1p2 | grep -i tpm #This command is for informational purposes, to see if the TPM slot is registered. It doesn't directly modify mkinitcpio.conf
      - sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf #Ensure the order is: base systemd autodetect modconf block plymouth sd-encrypt resume filesystems. Incorrect order can cause Plymouth to fail or LUKS to prompt incorrectly. Ensure `plymouth` is before `sd-encrypt` in `/etc/mkinitcpio.conf` HOOKS and regenerate.
      - sed -i 's/^BINARIES=(.*)/BINARIES=(\/usr\/lib\/systemd\/systemd-cryptsetup \/usr\/bin\/btrfs)/' /etc/mkinitcpio.conf
      - echo 'FILES=(/root/luks-keyfile)' >> /etc/mkinitcpio.conf
    
    The Arch Wiki on Intel graphics recommends adding the i915 module to /etc/mkinitcpio.conf for early KMS (Kernel Mode Setting) to prevent flickering or display issues during boot:
      - echo 'MODULES=(i915)' >> /etc/mkinitcpio.conf
      - mkinitcpio -P

    Update /etc/crypttab to use the TPM for unlocking:
      - echo "cryptroot /dev/nvme1n1p2 /root/luks-keyfile luks,tpm2-device=auto,tpm2-pcrs=0+4+7" >> /etc/crypttab
      - tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-initial.txt #Ensure PCRs 0, 4 and 7 (firmware, boot loader and Secure Boot state) are stable across reboots. If PCR values change unexpectedly, TPM unlocking may fail, requiring the LUKS passphrase. Also, very important to document PCR values.

    Enable Plymouth for a graphical boot splash. Add the plymouth hook to mkinitcpio.conf before sd-encrypt:
      - pacman -S --noconfirm plymouth
      - plymouth-set-default-theme -R bgrt

    Back up keyfile to a secure USB:
      - lsblk
      - mkfs.fat -F32 /dev/sdX1 **Replace sdX1 with USB partition confirmed via lsblk previously executed**
      - mkdir -p /mnt/usb
      - mount /dev/sdX1 /mnt/usb **Replace sdX1 with USB partition confirmed via lsblk previously executed**
      - cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
      - umount /mnt/usb
      - echo "WARNING: Store the LUKS recovery passphrase securely in Bitwarden. TPM unlocking may fail after firmware updates or Secure Boot changes."

# Step 8: Configure systemd-boot with UKI

    Install systemd-boot: 
    -  mount /dev/nvme1n1p1 /boot
    -  bootctl --esp-path=/boot/EFI install

    Configure /etc/mkinitcpio.d/linux.preset with kernel parameters: 
    cat <<'EOF' > /etc/mkinitcpio.d/linux.preset # Do not append UKI_OUTPUT_PATH directly to /etc/mkinitcpio.conf. 
     - default_options="rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID resume=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw quiet splash intel_iommu=on iommu=pt pci=pcie_bus_perf,realloc mitigations=auto,nosmt slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1"
     - default_uki="/boot/EFI/Linux/arch.efi"
     - all_config="/etc/mkinitcpio.conf"
    EOF

    Edit /etc/mkinitcpio.conf:
    -  sed -i 's/^HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf
    
    Regenerate the initramfs to create the UKI:  
    -  mkinitcpio -P

    Verify HOOKS order:
    -  grep HOOKS /etc/mkinitcpio.conf # Should show block plymouth sd-encrypt resume filesystems

    Create boot entries in /boot/loader/entries/ for Arch and Windows.
    Copy Windows EFI files to Arch ESP:
    -  cp -r /mnt/windows-efi/EFI/Microsoft /boot/EFI/
    -  umount /mnt/windows-efi

    Create /boot/loader/entries/windows.conf with:
    cat <<EOF > /boot/loader/entries/windows.conf
    -  title Windows 11
    -  efi /EFI/Microsoft/Boot/bootmgfw.efi
    EOF

    Create Arch bootloader entry (/boot/loader/entries/arch.conf):
    cat <<EOF > /boot/loader/entries/arch.conf
    -  title Arch Linux
    -  efi /EFI/Linux/arch.efi
    #Replace <LUKS_UUID>, <ROOT_UUID>, <SWAP_OFFSET> with actual precomputed values:
    -  options rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID resume=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw quiet splash intel_iommu=on iommu=pt pci=pcie_bus_perf,realloc mitigations=auto,nosmt slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1
    EOF
    -  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch.conf

    Check with bootctl list (confirm both entries appear):
    -  bootctl list

    Perform a sanity check on the value in the resume_offset:
    -  grep resume_offset /mnt/etc/fstab /boot/loader/entries/arch.conf # ensure the numerical value (e.g., resume_offset=12345678) is present and not a variable.

    Set Boot Order:
    -  BOOT_ARCH=$(efibootmgr | grep 'Arch Linux' | awk '{print $1}' | sed 's/Boot//;s/*//')
    -  BOOT_WIN=$(efibootmgr | grep 'Windows' | awk '{print $1}' | sed 's/Boot//;s/*//')
    -  efibootmgr --bootorder ${BOOT_ARCH},${BOOT_WIN} # Ensure both Arch and Windows entries are listed

    Create Fallback Bootload:
    Create minimal UKI config /etc/mkinitcpio-minimal.conf (copy /etc/mkinitcpio.conf, remove non-essential hooks):
    -  cp /etc/mkinitcpio.conf /etc/mkinitcpio-minimal.conf
    -  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block sd-encrypt filesystems)/' /etc/mkinitcpio-minimal.conf
    -  echo 'UKI_OUTPUT_PATH="/boot/EFI/Linux/arch-fallback.efi"' >> /etc/mkinitcpio-minimal.conf
    -  mkinitcpio -P -c /etc/mkinitcpio-minimal.conf
    -  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
    Create fallback boot entry (/boot/loader/entries/arch-fallback.conf):
    cat <<EOF > /boot/loader/entries/arch-fallback.conf
    -  title Arch Linux (Fallback)
    -  efi /EFI/Linux/arch-fallback.efi
    #Replace <LUKS_UUID> and <ROOT_UUID> with actual precomputed values:
    -  options rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID rw pci=pcie_bus_perf,realloc mitigations=auto,nosmt slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1
    -  EOF
    -  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch-fallback.conf

    Create GRUB USB for recovery:
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk
    -  lsblk
    -  mkfs.fat -F32 -n RESCUE_USB /dev/sdX1
    -  mkdir -p /mnt/usb
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk
    -  mount /dev/sdX1 /mnt/usb
    -  pacman -Sy grub
    -  grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB
    -  cp /root/luks-keyfile /mnt/usb/luks-keyfile
    -  chmod 600 /mnt/usb/luks-keyfile
    -  cp /boot/vmlinuz-linux /mnt/usb/
    -  cp /boot/initramfs-linux.img /mnt/usb/
    cat <<'EOF' > /mnt/usb/boot/grub/grub.cfg
    -  set timeout=5
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk, $LUKS_UUID and $ROOT_UUID
    -  menuentry "Arch Linux Rescue" {linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot cryptkey=UUID=$(blkid -s UUID -o value /dev/sdX1):fat32:/luks-keyfile root=UUID=$ROOT_UUID rw initrd /initramfs-linux.img}
    EOF
    -  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
    -  umount /mnt/usb

    Ensure the initramfs includes necessary hooks:
    -  cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
    -  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block sd-encrypt filesystems)/' /mnt/usb/mkinitcpio-rescue.conf
    -  mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
    -  cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

    Add Pacman Hook for UKI Regeneration:
    -  mkdir -p /etc/pacman.d/hooks
    cat << 'EOF' > /etc/pacman.d/hooks/90-mkinitcpio.hook 
    -  [Trigger]
    -  Operation = Install
    -  Operation = Upgrade
    -  Type = Package
    -  Target = linux
    -  Target = linux-firmware
    -  [Action]
    -  Description = Regenerating UKI
    -  When = PostTransaction
    -  Exec = /usr/bin/mkinitcpio -P
    EOF

# Step 9: Configure Secure Boot

    Create and enroll your keys into the firmware:
     -  sbctl create-keys
     -  sbctl enroll-keys --tpm-eventlog

    Reboot and enroll the keys when prompted by your UEFI BIOS.

    After rebooting back into the chroot, sign your bootloader and UKI.
     -  sbctl sign -s /usr/lib/systemd/boot/efi/systemd-bootx64.efi
     -  sbctl sign -s /boot/EFI/Linux/arch.efi
     -  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
     -  sbctl sign --all

     Confirm “Secure Boot enabled; all OK”
     -  sbctl status
     #Replace secure_boot_number with secure boot number, the command bellow should return 0
     -  efivar -p -n secure_boot_number-SetupMode
     If enrollment fails, re-run sbctl enroll-keys --tpm-eventlog and reboot again, ensuring the MOK enrollment prompt is completed correctly.

    Reboot and Enable Secure Boot in the UEFI BIOS.

    Verify Secure Boot is active:
    -  bootctl status | grep -i secure - sbctl status - sbctl verify /boot/EFI/Linux/arch.efi
    #Should return "signed"

# Step 10: Install and Configure DE and Applications

    Update the system: pacman -Syu
    Install GNOME: pacman -S --needed gnome
    Install Yay: git clone https://aur.archlinux.org/yay.git && cd yay && makepkg -si
    -  Configure to show PKGBUILD diffs (edit the Yay config file):
    -  yay -Y --editmenu
    -  diffmenu = true
    -  useask = true
    -  Verify if Yay shows the PKGBUILD diffs
    -  yay -Pg | grep -E 'diffmenu|answerdiff'
    Install Bubblejail: yay -S --needed bubblejail
    Install Alacritty: pacman -S --needed alacritty #https://www.youtube.com/watch?v=76GbxnD8wnM
    -  Configure Bubblejail for Alacritty: bubblejail create --profile generic-gui-app alacritty
    -  Allow eGPU access: bubblejail config alacritty --add-service wayland --add-service dri
    -  Test if is correct: bubblejail run Alacritty -- env | grep -E 'WAYLAND|XDG_SESSION_TYPE'
    Install Flatpak: pacman -S --needed flatpak
    Install Thinklmi to verify BIOS settings: pacman -S --needed thinklmi #Check BIOS settings: sudo thinklmi

    Install applications via pacman,yay or flatpak: gnome-tweaks gnome-software-plugin-flatpak networkmanager bluez bluez-utils ufw apparmor tlp cpupower upower systemd-timesyncd zsh snapper fapolicyd sshguard rkhunter lynis usbguard aide pacman-notifier mullvad-browser brave-browser tor-browser bitwarden helix zellij yazi blender krita gimp gcc gdb rustup python-pygobject git fwupd xdg-ninja libva-vdpau-driver zram-generator ripgrep fd eza gstreamer gst-plugins-good gst-plugins-bad gst-plugins-ugly ffmpeg gst-libav fprintd dnscrypt-proxy systeroid rage zoxide jaq atuin gitui glow delta tokei dua tealdeer fzf procs gping dog httpie bottom bandwhich gnome-bluetooth opensnitch

    Enable systemd services: systemctl enable gdm bluetooth ufw auditd apparmor systemd-timesyncd tlp NetworkManager fstrim.timer dnscrypt-proxy fapolicyd sshguard rkhunter
    After enabling all systemd services, run systemctl --failed. It should show 0 loaded units listed.

    Configure Flatseal for Flatpak apps:
    -  flatpak override --user --filesystem=home
    Allow GPU access for Steam:
    -  flatpak override --user com.valvesoftware.Steam --device=dri

# Step 11: Configure Power Management, Security and Privacy

    Configure Power Management:
    -  systemctl mask power-profiles-daemon
    -  systemctl disable power-profiles-daemon

    The Arch Wiki on Intel graphics suggests enabling power-saving features for Intel iGPUs to reduce battery consumption:
    -  echo 'options i915 enable_fbc=1 enable_psr=1' >> /etc/modprobe.d/i915.conf

    Configure Wayland envars:
    cat << 'EOF' > /etc/environment 
    -  MOZ_ENABLE_WAYLAND=1
    -  GDK_BACKEND=wayland
    -  CLUTTER_BACKEND=wayland
    -  QT_QPA_PLATFORM=wayland
    -  SDL_VIDEODRIVER=wayland
    -  GBM_BACKEND=amdgpu
    - #The envars below may be removed and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU
    -  LIBVA_DRIVER_NAME=radeonsi
    -  LIBVA_DRIVER_NAME=iHD
    EOF

    Configure MAC randomization:
    -  mkdir -p /etc/NetworkManager/conf.d
    cat << 'EOF' > /etc/NetworkManager/conf.d/00-macrandomize.conf 
    -  [device]
    -  wifi.scan-rand-mac-address=yes
    -  [connection]
    -  wifi.cloned-mac-address=random
    EOF
    -  systemctl restart NetworkManager
    -  nmcli connection down <connection_name> && nmcli connection up <connection_name>

    Configure firewall:
    -  ufw allow ssh
    -  ufw default deny incoming
    -  ufw default allow outgoing
    -  ufw enable

    Configure GNOME privacy:
    -  gsettings set org.gnome.desktop.privacy send-software-usage-info false
    -  gsettings set org.gnome.desktop.privacy report-technical-problems false

    Configure IP spoofing protection:
    cat << 'EOF' > /etc/host.conf
    -  order bind,hosts
    -  nospoof on
    EOF

    Configure security limits:
    cat << 'EOF' >> /etc/security/limits.conf 
    -  hard nproc 8192
    EOF

    Configure auditd:
    cat << 'EOF' > /etc/audit/rules.d/audit.rules
    -  -w /etc/passwd -p wa -k passwd_changes
    -  -w /etc/shadow -p wa -k shadow_changes
    -  -a always,exit -F arch=b64 -S execve -k exec
    EOF
    -  systemctl restart auditd

    Configure dnscrypt-proxy:
    -  nmcli connection modify <connection_name> ipv4.dns "127.0.0.1" ipv4.ignore-auto-dns yes #replace <connection_name> with actual network connection (e.g., nmcli connection show to find it)
    -  nmcli connection modify <connection_name> ipv6.dns "::1" ipv6.ignore-auto-dns yes
    cat << 'EOF' > /etc/dnscrypt-proxy/dnscrypt-proxy.toml 
    -  server_names = ["quad9-dnscrypt-ip4-filter-pri", "adguard-dns", "mullvad-adblock"]
    -  listen_addresses = ["127.0.0.1:53", "[::1]:53"]
    -  require_dnssec = true
    -  require_nolog = true
    -  require_nofilter = false
    EOF
    -  systemctl restart dnscrypt-proxy
    Test DNS resolution:
    -  drill -D archlinux.org

    Configure usbguard with GSConnect exception:
    -  usbguard generate-policy > /etc/usbguard/rules.conf
    Test usbguard rules before enabling:
    -  usbguard list-devices # Identify GSConnect device ID
    -  usbguard allow-device <device-id> # For GSConnect and other known devices
    If passed the USB test enable it:
    -  systemctl enable --now usbguard

    Run Lynis audit and create timer:
    cat << 'EOF' > /etc/systemd/system/lynis-audit.timer
    -  [Unit]
    -  Description=Run Lynis audit weekly
    -  [Timer]
    -  OnCalendar=weekly
    -  Persistent=true
    -  [Install]
    -  WantedBy=timers.target
    EOF
    cat << 'EOF' > /etc/systemd/system/lynis-audit.service
    -  [Unit]
    -  Description=Run Lynis audit
    -  [Service]
    -  Type=oneshot
    -  ExecStart=/usr/bin/lynis audit system
    EOF
    -  systemctl enable --now lynis-audit.timer
    -  systemctl enable lynis-audit.service

    Configure AIDE:
    -  aide --init
    -  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    -  systemctl enable --now aide-check.timer

    Configure sysctl hardening:
    cat << 'EOF' > /etc/sysctl.d/99-hardening.conf
    -  net.ipv4.conf.default.rp_filter=1
    -  net.ipv4.conf.all.rp_filter=1
    -  net.ipv4.tcp_syncookies=1
    -  net.ipv4.ip_forward=0
    -  net.ipv4.conf.all.accept_redirects=0
    -  net.ipv6.conf.all.accept_redirects=0
    -  net.ipv4.conf.default.accept_redirects=0
    -  net.ipv6.conf.default.accept_redirects=0
    -  net.ipv4.conf.all.send_redirects=0
    -  net.ipv4.conf.default.send_redirects=0
    -  net.ipv4.conf.all.accept_source_route=0
    -  net.ipv6.conf.all.accept_source_route=0
    -  net.ipv4.conf.default.accept_source_route=0
    -  net.ipv6.conf.default.accept_source_route=0
    -  net.ipv4.conf.all.log_martians=1
    -  net.ipv4.icmp_ignore_bogus_error_responses=1
    -  net.ipv4.icmp_echo_ignore_broadcasts=1
    -  kernel.randomize_va_space=2
    -  kernel.dmesg_restrict=1
    -  kernel.kptr_restrict=2
    -  net.core.bpf_jit_harden=2
    EOF
    -  sysctl -p /etc/sysctl.d/99-hardening.conf

    Audit SUID binaries:
    -  find / -perm -4000 -type f -exec ls -l {} ; > /data/suid_audit.txt
    -  cat /data/suid_audit.txt # Remove SUID from non-essential binaries
    -  chmod u-s /usr/bin/ping
    -  setcap cap_net_raw+ep /usr/bin/ping

    Configure zram:
    cat << 'EOF' > /etc/systemd/zram-generator.conf 
    -  [zram0]
    -  zram-size = 50%
    -  compression-algorithm = zstd
    EOF
    -  systemctl enable --now systemd-zram-setup@zram0.service

# Step 12: Configure eGPU (AMD)

    Modern GNOME and Mesa have excellent hot-plugging support. Start without any custom udev rules.

    Enable switcheroo-control for better integration:
    -  pacman -S switcheroo-control
    -  systemctl enable --now switcheroo-control

    Install bolt for managing Thunderbolt/USB4 devices, which may also handle the OCuLink connection:
    -  pacman -S bolt
    -  systemctl enable --now bolt
    #Authorize the OCuLink dock if listed
    -  boltctl list
    -  echo "always-auto-connect = true" | sudo tee -a /etc/boltd/boltd.conf

    Enable PCIe hotplug:
    -  echo "pciehp" | sudo tee /etc/modules-load.d/pciehp.conf

    Verify GPU switching:
    -  DRI_PRIME=1 glxinfo | grep "OpenGL renderer" # Should show AMD

# Step 13: Configure Snapper and Backups

    Create global filter:
    -  mkdir -p /etc/snapper/filters
    -  echo -e "/home/.cache\n/tmp\n/run\n/.snapshots" | sudo tee /etc/snapper/filters/global-filter.txt

    Create configurations: 
    -  snapper --config root create-config /
    -  snapper --config home create-config /home
    -  snapper --config data create-config /data

    Edit /etc/snapper/configs/root: 
    cat << 'EOF' | sudo tee /etc/snapper/configs/root 
    -  TIMELINE_CREATE="yes"
    -  TIMELINE_CLEANUP="yes"
    -  TIMELINE_MIN_AGE="1800"
    -  TIMELINE_LIMIT_HOURLY="0"
    -  TIMELINE_LIMIT_DAILY="7"
    -  TIMELINE_LIMIT_WEEKLY="4"
    -  TIMELINE_LIMIT_MONTHLY="6"
    -  TIMELINE_LIMIT_YEARLY="0"
    -  SUBVOLUME="/"
    -  ALLOW_GROUPS=""
    -  SYNC_ACL="no"
    -  FILTER="/etc/snapper/filters/global-filter.txt"
    EOF

    Edit /etc/snapper/configs/home and /etc/snapper/configs/data similarly, updating SUBVOLUME to /home and /data:
    cat << 'EOF' | sudo tee /etc/snapper/configs/home
    -  TIMELINE_CREATE="yes"
    -  TIMELINE_CLEANUP="yes"
    -  TIMELINE_MIN_AGE="1800"
    -  TIMELINE_LIMIT_HOURLY="0"
    -  TIMELINE_LIMIT_DAILY="7"
    -  TIMELINE_LIMIT_WEEKLY="4"
    -  TIMELINE_LIMIT_MONTHLY="6"
    -  TIMELINE_LIMIT_YEARLY="0"
    -  SUBVOLUME="/home"
    -  ALLOW_GROUPS=""
    -  SYNC_ACL="no"
    -  FILTER="/etc/snapper/filters/global-filter.txt"
    EOF

    cat << 'EOF' | sudo tee /etc/snapper/configs/data
    -  TIMELINE_CREATE="yes"
    -  TIMELINE_CLEANUP="yes"
    -  TIMELINE_MIN_AGE="1800"
    -  TIMELINE_LIMIT_HOURLY="0"
    -  TIMELINE_LIMIT_DAILY="7"
    -  TIMELINE_LIMIT_WEEKLY="4"
    -  TIMELINE_LIMIT_MONTHLY="6"
    -  TIMELINE_LIMIT_YEARLY="0"
    -  SUBVOLUME="/data"
    -  ALLOW_GROUPS=""
    -  SYNC_ACL="no"
    -  FILTER="/etc/snapper/filters/global-filter.txt"
    EOF

    Enable Snapper: 
    -  systemctl enable --now snapper-timeline.timer snapper-cleanup.timer

    Config permissions:
    -  chmod 640 /etc/snapper/configs/*

    Add a disk space limit to Snapper configs:
    -  echo "NUMBER_LIMIT=50" >> /etc/snapper/configs/root
    -  echo "NUMBER_LIMIT=50" >> /etc/snapper/configs/home
    -  echo "NUMBER_LIMIT=50" >> /etc/snapper/configs/data

    Enable NUMBER_CLEANUP to Snapper configs:
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/root
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/home
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/data

    Verify configuration: 
    -  snapper --config root get-config
    -  snapper --config home get-config
    -  snapper --config data get-config

    Test snapshot creation: 
    -  snapper --config root create --description "Initial test snapshot"
    -  snapper --config home create --description "Initial test snapshot"
    -  snapper --config data create --description "Initial test snapshot"
    -  snapper list

# Step 14: Configure Dotfiles
  - Install chezmoi:
    - yay -S chezmoi
    - chezmoi init --apply
    - chezmoi add ~/.zshrc
    - chezmoi add -r ~/.config/gnome
    - dconf dump /org/gnome/ > ~/.config/gnome-settings.dconf
    - chezmoi add ~/.config/gnome-settings.dconf
    - chezmoi cd
    - git add . && git commit -m "Initial dotfiles"
  Backup existing configs before applying:
    - cp -r ~/.zshrc ~/.config/gnome ~/.config/gnome-backup
   
 # Step 15: Test the Setup
  - Reboot and confirm `systemd-boot` shows Arch and Windows entries.
  - Test Arch boot with TPM-based LUKS unlocking and passphrase fallback.
  - Test Windows boot.
  - Test eGPU:
   - **AMD GPU**:
     - lspci | grep -i amd
     - dmesg | grep -i amdgpu
     - ls /sys/class/drm/card*
     - DRI_PRIME=1 glxinfo | grep "OpenGL renderer"   
 - Test hotplugging:
   -  udevadm monitor
   -  echo "0000:xx:00.0" | sudo tee /sys/bus/pci/devices/0000:xx:00.0/remove
   -  echo 1 | sudo tee /sys/bus/pci/rescan
   -  pkill -HUP gnome-shell
 - Test hibernation:
   - systemctl hibernate
   - dmesg | grep -i "hibernate\|swap" # After resuming, check dmesg for errors
   - filefrag -v /mnt/swap/swapfile  # Ensure no fragmentation
   - systemctl enable systemd-hibernate-resume.service
 - Test fwupd
   - fwupdmgr refresh
   - fwupdmgr update
 - Check for ThinkBook-specific quirks:
   - dmesg | grep -i "firmware\|wifi\|suspend\|battery" # Look for unusual warnings or errors related to hardware 
 - Test Snapshots
   - snapper --config root create --description "Test snapshot"
   - snapper list
 - Test Timers
   - journalctl -u yay-update.timer
   - journalctl -u snapper-timeline.timer
   - journalctl -u fstrim.timer
   - journalctl -u lynis-audit.timer
 - Stress Test
   Run stress tests incrementally:
   - stress-ng --cpu 2 --io 1 --vm 1 --vm-bytes 512M --timeout 24h
   - yay -S stress-ng memtester fio
   - stress-ng --cpu 4 --io 2 --vm 2 --vm-bytes 1G --timeout 72h
   - memtester 1024 5
   - fio --name=write_test --filename=/data/fio_test --size=1G --rw=write
 - Verify Wayland
   - echo $XDG_SESSION_TYPE
 - Verify Security
   - auditctl -l
   - apparmor_status 
 - Test AUR builds with /tmp (no noexec)
   - yay --builddir ~/.cache/yay_build
 - Verify Security Boot
   - mokutil --sb-state 

# Step 16: Create Recovery Documentation
  - Document UEFI password, LUKS passphrase, keyfile location, MOK password, and recovery steps in Bitwarden.
  - Create a recovery USB with Arch ISO, minimal UKI, and `systemd-cryptsetup`.
    - dd if=archlinux-<version>-x86_64.iso of=/dev/sdb bs=4M status=progress oflag=sync 
  - Back up LUKS header and SBCTL keys:
    - cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /path/to/luks-header-backup
    - cp -r /etc/sbctl /path/to/backup/sbctl-keys
  - Store LUKS header on USB (Missing LUKS header backup could prevent recovery from disk failure):
    - cp /mnt/usb/luks-header-backup /mnt/usb2/luks-header-backup

# Step 17: Backup Strategy
  - Local Snapshots:
    - Managed by Snapper for `@`, `@home`, `@data`, excluding `/var`, `/var/lib`, `/log`, `/tmp`, `/run`.
  - Offsite Snapshots:
    - To be refined savig the data in local server - check btrbk and restic
   
# Step 18: Post-Installation Maintenance and Verification
   a) Regular System Updates:
     - Always update your system regularly: `sudo pacman -Syu`
     - Check for AUR updates: `yay -Syu`

  b) BTRFS Scrub:
    - Schedule weekly or monthly BTRFS scrubs to check for data integrity issues:
      - `sudo btrfs scrub start /`
      - `sudo btrfs scrub status /`
      - Consider setting up a systemd timer for this (e.g., `btrfs-scrub@.timer` and `btrfs-scrub@.service` if provided by `btrfs-progs` or a custom one).

  c) Remove Orphaned Packages:
    - Periodically remove packages that are no longer required: `sudo pacman -Rns $(pacman -Qdtq)`

  d) Review Snapper Snapshots:
    - Regularly review your snapshots: `snapper list`
    - Manually delete old snapshots if needed (though `snapper-cleanup.timer` handles this): `snapper delete <snapshot_number>`

  e) Check for SUID/SGID Changes (AIDE):
    - `sudo aide --check` (After running `aide --init` and `mv` in initial setup)

  f) Perform Security Audits:
    - Run `lynis audit system` weekly/monthly (already scheduled by your timer).
    - Run `rkhunter --check` periodically.
    - Run `sudo usbguard generate-policy` if you add new USB devices and need to update rules.

  g) Verify Firmware Updates:
    - `fwupdmgr refresh` and `fwupdmgr update` periodically.

  h) Check Systemd Journal for Errors:
    - `journalctl -p 3 -xb` (errors from current boot)
    - `journalctl -p 3` (all errors)

  i) Test AUR builds with /tmp (if noexec applied):**
    - If you encounter issues, consider configuring `yay` to use a different build directory (e.g., `yay --builddir ~/.cache/yay_build`) or temporarily removing `noexec` from `/tmp` for builds, then re-adding it. (This point is already in your Step 15, but it's good to reiterate it in maintenance as it's an ongoing consideration).

  j) Schedule periodic BTRFS balance:
    cat <<'EOF' > /etc/systemd/system/btrfs-balance.timer
    -  [Unit]
    -  Description=Run BTRFS balance monthly
    -  [Timer]
    -  OnCalendar=monthly
    -  Persistent=true
    -  [Install]
    -  WantedBy=timers.target
    EOF
    cat <<'EOF' > /etc/systemd/system/btrfs-balance.service
    -  [Unit]
    -  Description=Run BTRFS balance
    -  [Service]
    -  Type=oneshot
    -  ExecStart=/usr/bin/btrfs balance start -dusage=50 /
    EOF
    -  systemctl enable --now btrfs-balance.timer
    

    

    

    

