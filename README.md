# Secure Arch Install for a Intel Lenovo Thinkbook using an AMD eGPU via Oculink
Installation Steps for a new Lenovo Thinkbook TGX (Oculink) Security Enhanced Arch Gnome Wayland AMD eGPU

# Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)
This action plan outlines the steps to install and configure Arch Linux on a Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H without dGPU but with Intel iGPU (Intel Arc 140T), **using GNOME Wayland, BTRFS, LUKS2, TPM2, AppArmor, systemd-boot with UKI, Secure Boot, and an OCuP4V2 OCuLink GPU Dock ReDriver with an AMD eGPU**. This laptop has two M.2, we will have Windows in a slot to help updating BIOS and Firmware at least in the beginning.

Observation: Not adopting linux-hardened kernel because of complexity in the setup using eGPU and performance penalty. Nevertheless, a lot of the security changes from the linux-hardened kernel are manually introduced. 

**Attention:** Before executing commands, especially those involving **dd, mkfs, cryptsetup, parted, and efibootmgr, re-read them multiple times to ensure you understand their effect** and that the target device/partition is correct. Ensure LUKS and TPM unlocking work perfectly before touching Secure Boot, and ensure Secure Boot works before diving into the eGPU.

# Step 1: Verify Hardware
    Access UEFI BIOS (F1 at boot):
        Enable TPM 2.0 (Security Chip) and Intel VT-d (IOMMU).
        Set a strong UEFI BIOS password and store it in Bitwarden.
        Disable Secure Boot temporarily in UEFI.
        Visit the builds that are working: Filter by "Thinkbook" - https://egpu.io/best-external-graphics-card-builds/

# Step 2: Install Windows on Primary NVMe M.2 (/dev/nvme0n1)

Follow some of the installations Privacy advises from the Privacy Guides Wiki Minimizing [Windows 11 Data Collection](https://discuss.privacyguides.net/t/minimizing-windows-11-data-collection/28193)

    Install Windows 11 Pro for BIOS/firmware updates via Lenovo Vantage. Allow Windows to create its default partitions, including a ~100-300 MB EFI System Partition (ESP) at /dev/nvme0n1p1. 
    Disable Windows Fast Startup to prevent ESP lockout: powercfg /h off
    Disable BitLocker (Powershell): a) manage-bde -status b) Disable-BitLocker -MountPoint "C:"
    Verify TPM 2.0 is active using tpm.msc. Clear TPM if previously provisioned.
    Verify Windows boots correctly and **check Resizable BAR sizes in Device Manager** or wmic path Win32_VideoController get CurrentBitsPerPixel,VideoMemoryType or `dmesg | grep -i "BAR.*size"` (in Linux later).
    Verify NVMe drives **Windows Disk Management**.
    
Review the guides for additional Privacy on the post installation [Group Police](https://www.privacyguides.org/en/os/windows/group-policies/) and [Windows Privacy Settings](https://discuss.privacyguides.net/t/windows-privacy-settings/27333) 

    Before start the next steps backup registry settings (powershell):
    -  reg export "HKLM\SOFTWARE" C:\backup_registry.reg

    Disables diagnostic data, feedback, and telemetry services (powershell):
    -  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    -  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1
    -  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0
    -  Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n0.0.0.0 vortex.data.microsoft.com`n0.0.0.0 settings-win.data.microsoft.com`n0.0.0.0 watson.telemetry.microsoft.com"
    -  Stop-Service -Name "DiagTrack" -Force
    -  Set-Service -Name "DiagTrack" -StartupType Disabled
    -  Stop-Service -Name "dmwappushservice" -Force
    -  Set-Service -Name "dmwappushservice" -StartupType Disabled
    -  Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("9.9.9.9","149.112.112.112")

    Restrict App Permissions:
    -  Open Settings > Privacy & Security > General:
      - Turn off “Let apps show me personalized ads”.
      - Turn off “Let Windows improve Start and search”.

    Disables Cortana and web search in Start menu (powershell):
    -  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortana" -Value 0
    -  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0

    Uninstalls preinstalled apps (e.g., Xbox, Candy Crush) (powershell):
    -  Get-AppxPackage -AllUsers *XboxApp* | Remove-AppxPackage
    -  Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage
    -  Get-AppxPackage -AllUsers *MicrosoftNews* | Remove-AppxPackage
    -  Get-AppxPackage -AllUsers *Weather* | Remove-AppxPackage
    -  Get-AppxPackage -AllUsers *Teams* | Remove-AppxPackage

    Disable unnecessary services (e.g., Xbox Live, Game Bar) that might run in the background (powershell):
    -  Stop-Service -Name "XboxGipSvc" -Force
    -  Set-Service -Name "XboxGipSvc" -StartupType Disabled

    Group Policy Settings (powershell):
    -  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
    -  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
    -  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
    
    Enable tamper protection and real-time protection via Settings > Windows Security > Virus & Threat Protection.

    Back up the Windows EFI partition UUID - (powershell, store this on a USB or in Bitwarden):
    -  Insert a USB drive (e.g., F:)
    -  Mount the ESP: mountvol Z: /S
    -  Back up the ESP contents: robocopy Z:\ F:\EFI-Backup /MIR /XJ #Replace F: with the USB drive letter
    -  Record the ESP UUID: Get-Partition -DiskNumber 0 -PartitionNumber 1 | Select-Object -ExpandProperty Guid | Out-File F:\windows-esp-uuid.txt
    -  Unmount the ESP: mountvol Z: /D
    -  Store F:\EFI-Backup and F:\windows-esp-uuid.txt securely (e.g., Bitwarden or encrypted cloud).    
    
#Milestone 1: After Step 2 (Windows Installation) - Can pause at this point

# Step 3: Prepare Installation Media
    Download the latest Arch Linux ISO from archlinux.org.
    Verify the ISO signature using gpg (see Arch Linux website for instructions) and create a bootable USB drive (Use Rufus in Windows to create a bootable USB -- DD mode in Rufus). Do not use Ventoy. Just use dd or gnome-disks or more trusted programs like Rufus.
Also don’t use Balena Etcher either, that thing has trackers.
    Test the USB by rebooting and selecting it in the BIOS boot menu.
    Verify network connectivity
    -  ping -c 3 archlinux.org

# Step 4: Pre-Arch Installation Steps

Boot Arch Live USB
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

    Format the partition with LUKS2, using pbkdf2 for compatibility with systemd-cryptenroll:
    cryptsetup luksFormat --type luks2 /dev/nvme1n1p2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000000

    Open the LUKS partition:
    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot

    Create a keyfile for recovery purposes (e.g., GRUB rescue USB), not for initramfs. WHY: The modern systemd approach uses sd-encrypt and systemd-cryptenroll for TPM-based unlocking, eliminating the need for a keyfile in the initramfs. The keyfile is retained for recovery scenarios:
    dd if=/dev/urandom of=/mnt/crypto_keyfile bs=512 count=4 iflag=fullblock
    chmod 600 /mnt/crypto_keyfile

    Add the keyfile to LUKS in keyslot 1 for clarity. # WHY: Explicitly specifying keyslot 1 avoids ambiguity and ensures the passphrase (in keyslot 0) and keyfile are distinct, improving key management for recovery purposes:
    cryptsetup luksAddKey /dev/nvme1n1p2 /mnt/crypto_keyfile --key-slot 1

    Back it up to USB:
    mkdir -p /mnt/usb
    lsblk
    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**
    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile
    shred -u /mnt/crypto_keyfile
    echo "WARNING: Store the LUKS keyfile securely in Bitwarden for recovery purposes."

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

   #Why These Subvolumes?
   
       `@`: Isolates the root filesystem for easy snapshotting and rollback.
       `@home`: Separates user data, allowing independent snapshots and backups.
       `@snapshots`: Stores Snapper snapshots for system recovery.
       `@var`, `@var_lib`, `@log`: Disables Copy-on-Write (noatime, nodatacow) to improve performance for frequently written data.
       `@swap`: Ensures swapfile compatibility with hibernation (noatime, nodatacow).
       `@srv`, `@data`: Provides flexible storage for server data or user files with compression (zstd:3).

e) Configure Swap File:

    Create a swap file on the @swap subvolume, ensuring chattr +C is set to disable Copy-on-Write.
        touch /mnt/swap/swapfile 
        chattr +C /mnt/swap/swapfile
        fallocate -l 32G /mnt/swap/swapfile || { echo "fallocate failed"; exit 1; }
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

    **Verify your final fstab and UUIDs:
      - cat /mnt/etc/fstab
      - blkid | grep -E "$ROOT_UUID|$LUKS_UUID|$ARCH_ESP_UUID|$WINDOWS_ESP_UUID"

#Milestone 2: After Step 4f (fstab Generation) - Can pause at this point

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
    -  pacstrap /mnt base base-devel linux linux-firmware mkinitcpio intel-ucode zsh btrfs-progs sudo cryptsetup dosfstools efibootmgr networkmanager mesa libva-mesa-driver pipewire wireplumber sof-firmware vulkan-intel lib32-vulkan-intel pipewire-pulse pipewire-alsa pipewire-jack archlinux-keyring arch-install-scripts intel-media-driver sbctl git vulkan-radeon lib32-vulkan-radeon reflector udisks2 fwupd openssh rsync pacman-contrib polkit flatpak gdm acpi acpid thermald intel-gpu-tools nvme-cli wireless-regdb ethtool

    Chroot into the system:
    -  arch-chroot /mnt

    #DEPRECATED - DO NOT EXECUTE. Move the crypto keyfile: 
    -  mv /crypto_keyfile /root/luks-keyfile && chmod 600 /root/luks-keyfile
    #Do not move the crypto keyfile to /root/luks-keyfile. WHY: The keyfile is no longer needed in the initramfs for TPM-based unlocking with sd-encrypt. It is retained on the USBs for recovery purposes (e.g., GRUB rescue USB).

    Keyring initialization:
    - nano /etc/pacman.conf uncomment [multilib]
    - add **Include = /etc/pacman.d/mirrorlist** below the [core], [extra], [community], and [multilib] sections in /etc/pacman.conf
    - pacman -Sy
    - pacman -Syy

    The Arch Wiki on Intel graphics recommends adding the i915 module to /etc/mkinitcpio.conf for early KMS (Kernel Mode Setting) to prevent flickering or display issues during boot:
    - echo 'MODULES=(i915)' >> /etc/mkinitcpio.conf
    - mkinitcpio -P

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

#Milestone 3: After Step 6 (System Configuration) - Can pause at this point

# Step 7: Set Up TPM and LUKS2

    Install tpm2-tools and dependencies: 
      - pacman -S --noconfirm tpm2-tools tpm2-tss systemd-ukify tpm2-tss-engine

    Verify TPM device is detected
      - tpm2_getcap properties-fixed 

    Enroll the LUKS key to the TPM, binding to PCRs 0, 4, and 7 (firmware, bootloader, Secure Boot state):
      - systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2

    Testing the TPM unlocking works with the current PCR value and Back up PCR values for stability checking:
      - systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 #If the test fails, check PCR values (tpm2_pcrread sha256:0,4,7) and ensure the TPM2 module is correctly initialized.
      - systemd-cryptenroll --dump-pcrs /dev/nvme1n1p2 > /mnt/usb/tpm-pcr-initial.txt #This helps catch firmware changes in the future.
      - tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-backup.txt #Ensure PCRs 0, 4 and 7 (firmware, boot loader and Secure Boot state) are stable across reboots. If PCR values change unexpectedly, TPM unlocking may fail, requiring the LUKS passphrase. Also, very important to document PCR values.

    Verification for TPM PCR 4 Measurement:
      - tpm2_pcrread sha256:4 | grep -v "0x0000000000000000000000000000000000000000000000000000000000000000" #Verify PCR 4 is non-zero (indicating measurement by systemd-boot)

    Add the keyfile and sd-encrypt hook to /etc/mkinitcpio.conf:
      - cryptsetup luksDump /dev/nvme1n1p2 | grep -i tpm #This command is for informational purposes, to see if the TPM slot is registered. It doesn't directly modify mkinitcpio.conf
      - sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf #Ensure the order is: base systemd autodetect modconf block plymouth sd-encrypt resume filesystems. Incorrect order can cause Plymouth to fail or LUKS to prompt incorrectly. Ensure `plymouth` is before `sd-encrypt` in `/etc/mkinitcpio.conf` HOOKS and regenerate.
      Include btrfs binary for BTRFS filesystem support
      - sed -i 's/^BINARIES=(.*)/BINARIES=(\/usr\/bin\/btrfs)/' /etc/mkinitcpio.conf
      - mkinitcpio -P

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

    Store a copy in an encrypted, offsite location (e.g., Bitwarden or encrypted cloud):
      - sha256sum /mnt/usb/luks-header-backup > /mnt/usb/luks-header-backup.sha256
      - echo "WARNING: Ensure /mnt/usb/luks-header-backup is stored securely. Consider an additional encrypted backup (e.g., Bitwarden attachment or cloud)." 

    Test Boot with TPM2/LUKS2. Exit chroot, unmount filesystems, and reboot (with Secure Boot disabled):
      - exit
      - umount -R /mnt
      - reboot
      #Verify that TPM2 automatically unlocks the LUKS2 partition without requiring a passphrase. Repeat 3–5 times to ensure reliability. If unlocking fails, boot with the recovery passphrase, recheck TPM2 configuration, and verify PCR values.

#Milestone 4: After Step 7 (TPM and LUKS2 Setup, Before Secure Boot) - Can stop at this point

# Step 8: Configure Secure Boot

    Create and enroll your keys into the firmware:
     -  arch-chroot /mnt
     -  sbctl create-keys
     -  sbctl enroll-keys --tpm-eventlog
     -  mkinitcpio -P  #Regenerate UKI first
     -  sbctl sign -s /usr/lib/systemd/boot/efi/systemd-bootx64.efi
     -  sbctl sign -s /boot/EFI/Linux/arch.efi
     -  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
     -  sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI

    Check Plymouth compatibility with Secure Boot:
     -  sbctl verify /usr/lib/plymouth/plymouthd
     #If Plymouth binaries are unsigned, sign them:
     -  sbctl sign -s /usr/lib/plymouth/plymouthd

    Check GDM compatibility with Secure Boot:
     -  sbctl verify /usr/lib/gdm/gdm
     #If GDM binaries are unsigned, sign them:
     -  sbctl sign -s /usr/lib/gdm/gdm

    Verification step for MOK enrollment:
     -  mokutil --list-enrolled

    Automatically sign updated EFI binaries:
     cat << 'EOF' > /etc/pacman.d/hooks/91-sbctl-sign.hook
     -  [Trigger]
     -  Operation = Install
     -  Operation = Upgrade
     -  Type = Package
     -  Target = systemd
     -  Target = linux
     -  Target = fwupd
     -  Target = plymouth
     -  [Action]
     -  Description = Signing EFI binaries with sbctl
     -  When = PostTransaction
     -  Exec = /usr/bin/sbctl sign -s /usr/lib/systemd/boot/efi/systemd-bootx64.efi /boot/EFI/Linux/arch.efi /boot/EFI/Linux/arch-fallback.efi /boot/EFI/BOOT/BOOTX64.EFI /efi/EFI/arch/fwupdx64.efi /usr/lib/plymouth/plymouthd /usr/lib/plymouth/plymouthd /usr/bin/astal /usr/bin/ags
     EOF

    Reboot and enroll the keys when prompted by your UEFI BIOS:
     -  exit
     -  umount -R /mnt
     -  reboot
     #Follow the UEFI prompt to enroll the keys. If enrollment fails, rerun sbctl enroll-keys --tpm-eventlog and reboot.

    Enable Secure Boot in UEFI:
     -  Enter the UEFI BIOS and enable Secure Boot.

    Update TPM2 PCR Policy for Secure Boot:
     -  arch-chroot /mnt
     -  systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2
     -  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2
     
    After rebooting back into the chroot, confirm “Secure Boot enabled; all OK”
     -  sbctl status

    Verify Secure Boot is active:
     -  bootctl status | grep -i secure 
     -  sbctl status 
     -  sbctl verify /boot/EFI/Linux/arch.efi #Should return "signed"
    
    Replace secure_boot_number with secure boot number, the command bellow should return 0
     -  efivar -p -n secure_boot_number-SetupMode #If enrollment fails, re-run sbctl enroll-keys --tpm-eventlog and reboot again, ensuring the MOK enrollment prompt is completed correctly.
     -  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2

    Back up new PCR values post-Secure Boot:
     -  tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-post-secureboot.txt
     -  diff /mnt/usb/tpm-pcr-backup.txt /mnt/usb/tpm-pcr-post-secureboot.txt
     #If TPM2 unlocking fails, use the LUKS recovery passphrase and recheck PCR 7 values.

# Step 9: Configure systemd-boot with UKI

    Install systemd-boot: 
    -  mount /dev/nvme1n1p1 /boot
    -  bootctl --esp-path=/boot install

    Configure /etc/mkinitcpio.d/linux.preset with kernel parameters: 
    cat <<'EOF' > /etc/mkinitcpio.d/linux.preset # Do not append UKI_OUTPUT_PATH directly to /etc/mkinitcpio.conf. 
     - default_options="rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw quiet splash intel_iommu=on amd_iommu=on iommu=pt pci=pcie_bus_perf,realloc mitigations=auto,nosmt slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 rd.emergency=poweroff tpm2-measure=yes amdgpu.dc=1 amdgpu.dpm=1"
     #amdgpu.dcdebugmask=0x10 is a debugging parameter for the AMDGPU driver’s display core (DC). It enables specific debug output, which is useful for troubleshooting display-related issues (e.g., flickering, black screens, or eGPU initialization problems). However, it’s not intended for permanent use in a production environment, as it may introduce unnecessary overhead or verbosity in logs, potentially impacting performance or stability. Therefore it is not added but if needed can be added to help troublesoot.
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
    -  rsync -aHAX /mnt/windows-efi/EFI/Microsoft /boot/EFI/
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
    EOF
    -  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch.conf

    Check with bootctl list (confirm both entries appear):
    -  bootctl list

    Perform a sanity check on the value in the resume_offset:
    -  grep resume_offset /mnt/etc/fstab /boot/loader/entries/arch.conf # ensure the numerical value (e.g., resume_offset=12345678) is present and not a variable.
    #if above doesn't work uses the following:
    -  grep resume_offset /etc/fstab /boot/loader/entries/arch.conf

    Step to verify UKI integrity:
    -  sbctl verify /boot/EFI/Linux/arch.efi

    Set Boot Order:
    -  BOOT_ARCH=$(efibootmgr | grep 'Arch Linux' | awk '{print $1}' | sed 's/Boot//;s/*//')
    -  BOOT_WIN=$(efibootmgr | grep 'Windows' | awk '{print $1}' | sed 's/Boot//;s/*//')
    -  efibootmgr --bootorder ${BOOT_ARCH},${BOOT_WIN} # Ensure both Arch and Windows entries are listed

    Create Fallback Bootload:
    Create minimal UKI config /etc/mkinitcpio-minimal.conf (copy /etc/mkinitcpio.conf, remove non-essential hooks):
    -  cp /etc/mkinitcpio.conf /etc/mkinitcpio-minimal.conf
    -  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems)/' /etc/mkinitcpio-minimal.conf
    -  echo 'UKI_OUTPUT_PATH="/boot/EFI/Linux/arch-fallback.efi"' >> /etc/mkinitcpio-minimal.conf
    -  mkinitcpio -P -c /etc/mkinitcpio-minimal.conf
    -  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
    Create fallback boot entry (/boot/loader/entries/arch-fallback.conf):
    cat <<EOF > /boot/loader/entries/arch-fallback.conf
    -  title Arch Linux (Fallback)
    -  efi /EFI/Linux/arch-fallback.efi
    -  EOF
    -  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch-fallback.conf

    Create GRUB USB for recovery (it’s for recovery only, not a primary bootloader option, systemd-boot is the primary option):
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk
    -  lsblk
    -  mkfs.fat -F32 -n RESCUE_USB /dev/sdX1
    -  mkdir -p /mnt/usb
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk
    -  mount /dev/sdX1 /mnt/usb
    -  pacman -Sy grub
    -  grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB
    -  cp /mnt/usb/crypto_keyfile /mnt/usb/luks-keyfile
    -  chmod 600 /mnt/usb/luks-keyfile
    -  cp /boot/vmlinuz-linux /mnt/usb/
    -  cp /boot/initramfs-linux.img /mnt/usb/
    cat <<'EOF' > /mnt/usb/boot/grub/grub.cfg
    -  set timeout=5
    #Replace /dev/sdX1 with your USB partition confirmed via lsblk, $LUKS_UUID and $ROOT_UUID
    -  menuentry "Arch Linux Rescue" {linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot root=UUID=$ROOT_UUID rw initrd /initramfs-linux.img}
    EOF
    -  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
    -  umount /mnt/usb

    Ensure the initramfs includes necessary hooks:
    -  cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
    -  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block sd-encrypt filesystems)/' /mnt/usb/mkinitcpio-rescue.conf
    -  mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
    -  cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

    Ensure hibernation service is disabled:
    -  systemctl disable systemd-hibernate-resume.service #Disable systemd-hibernate-resume.service, as hibernation is handled by the resume hook and resume_offset.

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

    Enable systemd-homed and create user accounts with LUKS2-encrypted home directories:
    -  systemctl enable --now systemd-homed.service
    -  chattr +C /home
    -  homectl create username --storage=luks --fs-type=btrfs --shell=/bin/zsh --member-of=wheel --disk-size=500G

#Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can stop at this point

# Step 10: Install and Configure DE and Applications

    Update the system: pacman -Syu
    Install GNOME: pacman -S --needed gnome
    Install Paru: git clone https://aur.archlinux.org/paru.git && cd paru && makepkg -si && cd .. && rm -rf paru
    -  Configure to show PKGBUILD diffs (edit the Paru config file):
    -  paru -Y --editmenu
    -  diffmenu = true
    -  useask = true
    -  CombinedUpgrade = false
    -  PgpFetch = true
    -  Verify if paru shows the PKGBUILD diffs
    -  paru -Pg | grep -E 'diffmenu|answerdiff|combinedupgrade' #Should show: combinedupgrade: Off diffmenu: Edit answerdiff: Edit
    -  echo "BUILDDIR=$HOME/.cache/paru-build" >> /etc/makepkg.conf
    -  echo 'export BUILDDIR=$HOME/.cache/paru-build' >> /home/<username>/.zshrc
    -  chown <username>:<username> /home/<username>/.zshrc
    -  mkdir -p ~/.cache/paru-build
    Install Bubblejail: paru -S --needed bubblejail
    Install Alacritty with SIXEL support from ayosec/alacritty latest version, double check if this reamains the latest otherwise change v0.15.1-graphics: git clone https://aur.archlinux.org/alacritty-sixel-git.git
      -  cd alacritty-sixel-git
      -  sed -i 's/source=("git+.*"/source=("git+https:\/\/github.com\/ayosec\/alacritty.git#tag=v0.15.1-graphics"/' PKGBUILD))
      -  paru -S --needed . && cd .. && rm -rf alacritty-sixel-git
    -  Configure Bubblejail for Alacritty: bubblejail create --profile generic-gui-app alacritty
    -  Allow eGPU access: bubblejail config alacritty --add-service wayland --add-service dri
    -  Test if is correct: bubblejail run Alacritty -- env | grep -E 'WAYLAND|XDG_SESSION_TYPE'
    -  Install Astal: paru -S astal-git ags-git 
    -  Check if need to sign Astal and AGS: dmesg | grep -i "secureboot.*failed.*astal" && dmesg | grep -i "secureboot.*failed.*ags" #If no violations occur, you can skip signing and remove the sbctl sign and hook creation for Astal/AGS.
    -  Sign Astal and AGS: sbctl sign -s /usr/bin/astal /usr/bin/ags
    -  Configure Bubblejail for Astal: bubblejail create --profile generic-gui-app astal
    -  Configure Bubblejail access for Astal: bubblejail config astal --add-service wayland --add-service dri
    -  Test if is correct: bubblejail run astal -- ags -c ~/.config/astal/system-monitor.ts
    
    Install Thinklmi to verify BIOS settings: pacman -S --needed thinklmi #Check BIOS settings: sudo thinklmi
    
    Install applications via pacman, paru or flatpak: gnome-tweaks gnome-software-plugin-flatpak bluez bluez-utils ufw apparmor tlp cpupower upower systemd-timesyncd zsh fapolicyd sshguard rkhunter chkrootkit lynis usbguard aide pacman-notifier mullvad-browser brave-browser tor-browser bitwarden helix zellij yazi blender krita gimp gcc gdb rustup python-pygobject git vala gjs xdg-ninja libva-vdpau-driver zram-generator ripgrep fd eza gstreamer gst-plugins-good gst-plugins-bad gst-plugins-ugly ffmpeg gst-libav fprintd dnscrypt-proxy systeroid-git rage zoxide jaq atuin gitui glow delta tokei dua tealdeer fzf procs gping dog httpie bottom bandwhich gnome-bluetooth opensnitch baobab gnome-system-monitor hardened-malloc wireguard-tools vulkan-tools libva-utils clinfo mangohud obs-studio inkscape 

    Enable systemd services: systemctl enable gdm bluetooth ufw auditd apparmor systemd-timesyncd tlp NetworkManager fstrim.timer dnscrypt-proxy fapolicyd sshguard rkhunter chkrootkit
    After enabling all systemd services, run systemctl --failed. It should show 0 loaded units listed.

    Check if services failed to initiate:
    -  systemctl --failed
    -  journalctl -p 3 -xb

    Configure GDM:
    -  cat << 'EOF' > /etc/gdm/custom.conf
       -  [daemon]
       -  WaylandEnable=true
       -  DefaultSession=gnome-wayland.desktop
    -  EOF
    #Install GDM Settings tool for cosmetic changes
    -  paru -S gdm-settings
    
    Configure Flatseal for Flatpak apps:
    -  flatpak override --user --filesystem=home
    Allow GPU access for Steam:
    -  flatpak override --user com.valvesoftware.Steam --device=dri

    #DO NOT ADOPT THIS FOR NOW -- IT MAY INTRODUCE ADDITIONAL OVERHEAD IN USABILITY
    Enable hardened-malloc Globally:
    -  echo "LD_PRELOAD=/usr/lib/libhardened_malloc.so" >> /etc/environment
    #If specific apps (e.g., Steam, OBS) crash, apply hardened-malloc selectively via Bubblejail/Flatpak -- bubblejail config <app> --unset-env LD_PRELOAD

    Enroll Astal and AGS keys into the firmware:
    #Verify the binaries exist before signing
    -  ls /usr/bin/astal /usr/bin/ags
    -  echo "Target = astal-git" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
    -  echo "Target = ags-git" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
    -  echo "/usr/bin/astal /usr/bin/ags" | sed -i '/Exec =/ s|$| /usr/bin/astal /usr/bin/ags|' /etc/pacman.d/hooks/91-sbctl-sign.hook
    #Test the hook after installation
    -  pacman -S astal-git  #Simulate an update
    -  sbctl verify /usr/bin/astal  #Should show "signed"

    Check Secure Boot Violations:
    -  dmesg | grep -i "secureboot.*failed" #If a binary fails to execute due to Secure Boot, sbctl verify <binary> will show “unsigned.”

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
    #The envars below may be NOT INCLUDED and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU. DO NOT ADD INITIALLY:
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
    -  usbguard list-devices | grep -i "GSConnect\|KDEConnect" # Identify GSConnect device ID
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

    Configure fwupd for Firmware Updates:
    -  pacman -S fwupd udisks2
    -  systemctl enable --now udisks2.service
    -  echo '[uefi_capsule]\nDisableShimForSecureBoot=true' >> /etc/fwupd/fwupd.conf
    -  fwupdmgr refresh
    -  fwupdmgr get-updates
    -  fwupdmgr update
    -  sbctl sign -s /efi/EFI/arch/fwupdx64.efi
    -  echo "NOTE: fwupd updates may change PCR 0, requiring TPM re-enrollment. Back up the LUKS passphrase in Bitwarden and run 'systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2' if unlocking fails."
    #Note: Firmware updates may change TPM PCR values (e.g., PCR 0). Back up LUKS recovery passphrase and re-enroll TPM if unlocking fails:
    -  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2

    Configure opensnitch:
    -  systemctl enable --now opensnitch
    -  opensnitch-ui

#Milestone 6: After Step 11 - Can stop at this point

# Step 12: Configure eGPU (AMD)

    Modern GNOME and Mesa have excellent hot-plugging support. Start without any custom udev rules.

    Install AMD eGPU drivers and firmware, ensuring Secure Boot compatibility.
    -  pacman -S --noconfirm amd-ucode rocm-opencl rocm-hip libva-vdpau-driver

    Add amdgpu module for early KMS
    -  echo 'MODULES=(i915 amdgpu)' >> /etc/mkinitcpio.conf
    -  mkinitcpio -P
    - #if encounter PCIe bandwidth issues, set the correct "pcie_gen_cap" as a kernel parameter. Example: options rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID ... amdgpu.pcie_gen_cap=0x4 pcie_ports=native pciehp.pciehp_force=1. Alternatively, for module options: echo 'options amdgpu pcie_gen_cap=0x4' >> /etc/modprobe.d/amdgpu.conf

    AMD-specific power management options to complement i915 settings:
    -  echo 'options amdgpu ppfeaturemask=0xffffffff' >> /etc/modprobe.d/amdgpu.conf

    Sign Kernel Modules for Secure Boot
    -  sbctl sign --all
    -  find /lib/modules/$(uname -r)/kernel/drivers/gpu -name "*.ko" -exec sbctl verify {} \;

    Install supergfxctl from the AUR
    -  git clone https://aur.archlinux.org/supergfxctl.git
    -  cd supergfxctl
    -  makepkg -si
    -  cd .. && rm -rf supergfxctl

    Configure supergfxctl for AMD eGPU and OCuLink hotplugging
    -  cat << 'EOF' > /etc/supergfxd.conf
      -  "mode": "Hybrid",
      -  "vfio_enable": true,
      -  "vfio_save": false,
      -  "always_reboot": false,
      -  "no_logind": true,
      -  "logout_timeout_s": 180,
      -  "hotplug_type": "Asus"
    -  EOF

    Enable supergfxd service for GPU switching
    -  systemctl enable --now supergfxd

    Install supergfxctl-gex from GNOME Extensions site (do NOT run as root or sudo)
    -  pacman -S gnome-shell-extension
    -  paru -S supergfxctl-git
    -  gnome-extensions enable supergfxctl-gex@asus-linux.org
    -  echo "NOTE: supergfxctl-gex provides a GUI for GPU switching in GNOME."

    #If there are issues in power management add the following, otherwise skip (TLP configured to avoid GPU power management conflicts with supergfxctl.")
    -  cat << 'EOF' > /etc/tlp.conf
      -  #Exclude amdgpu and i915 from TLP's runtime power management to avoid conflicts with supergfxctl
      -  RUNTIME_PM_DRIVER_BLACKLIST="amdgpu i915"
    -  EOF
    -  systemctl restart tlp

    Sign supergfxctl binaries for Secure Boot
    -  sbctl sign -s /usr/bin/supergfxctl
    -  sbctl sign -s /usr/lib/supergfxctl/supergfxd

    #If supergfxctl do not handle the hotplug try to install all-ways-egpu to set AMD eGPU as primary for GNOME Wayland -- this is a plan b, should not be used at first. First test the setup without, in other words skip to the switcheroo-control setup below
    -  cd ~; curl -L https://github.com/ewagner12/all-ways-egpu/releases/latest/download/all-ways-egpu.zip -o all-ways-egpu.zip; unzip all-ways-egpu.zip; cd all-ways-egpu-main; chmod +x install.sh; sudo ./install.sh; cd ../; rm -rf all-ways-egpu.zip all-ways-egpu-main 

    Verify all-ways-egpu installation
    -  sbctl verify /usr/bin/all-ways-egpu  #Ensure binary is signed for Secure Boot

    Sign all-ways-egpu
    -  sbctl sign -s /usr/bin/all-ways-egpu
    -  echo "Target = all-ways-egpu" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
    -  echo "/usr/bin/all-ways-egpu" | sed -i '/Exec =/ s|$| /usr/bin/all-ways-egpu|' /etc/pacman.d/hooks/91-sbctl-sign.hook

    Configure all-ways-egpu
    -  all-ways-egpu setup
    #During setup, choose "n" for "Attempt to re-enable these iGPU/initially disabled devices after boot" to avoid black screen with AMD eGPU:
    -  all-ways-egpu set-boot-vga egpu
    -  all-ways-egpu set-compositor-primary egpu
    #Note: If Plymouth splash screen fails (e.g., blank screen), remove 'splash' from kernel parameters in /boot/loader/entries/arch.conf and regenerate UKI with `mkinitcpio -P` 

    Enable switcheroo-control for better integration:
    -  pacman -S switcheroo-control
    -  systemctl enable --now switcheroo-control

    Install bolt for managing Thunderbolt/USB4 devices, which may also handle the OCuLink connection:
    -  pacman -S bolt
    -  systemctl enable --now bolt
    #Authorize the OCuLink dock if listed
    -  boltctl list
    -  echo "always-auto-connect = true" | sudo tee -a /etc/boltd/boltd.conf

    Verify OCuLink dock detection for bolt
    -  boltctl list | grep -i oculink
    -  if [ $? -eq 0 ]; then
    -  boltctl authorize <uuid>  #Replace with OCuLink device UUID
    -  fi

    Enable PCIe hotplug:
    -  echo "pciehp" | sudo tee /etc/modules-load.d/pciehp.conf

    Add udev rule for OCuLink hotplugging
    #Only add this udev in case hotplug doesn't work. udev rule is a fallback if dmesg | grep -i "oculink\|pcieport" shows no detection or if lspci | grep -i amd fails after connecting the eGPU.
    -  cat << 'EOF' > /etc/udev/rules.d/99-oculink.rules
    -  SUBSYSTEM=="pci", ACTION=="add", KERNEL=="0000:*:*.0", RUN+="/bin/sh -c 'echo 1 > /sys/bus/pci/rescan'"
    -  EOF
    -  udevadm control --reload-rules
    -  udevadm trigger

    Configure systemd-logind for rebootless switching fallback
    -  sudo sed -i 's/#KillUserProcesses=no/KillUserProcesses=yes/' /etc/systemd/logind.conf
    -  systemctl restart systemd-logind

    Configure VFIO for eGPU passthrough
    -  pacman -S --needed qemu libvirt virt-manager
    -  systemctl enable --now libvirtd
    -  echo "vfio-pci vfio_iommu_type1 vfio_virqfd vfio" | sudo tee /etc/modules-load.d/vfio.conf
    -  fwupdmgr get-devices | grep -i "oculink\|redriver" | grep -i version
    -  echo "NOTE: Replace '1002:xxxx' with actual AMD eGPU PCIe IDs from 'lspci -nn | grep -i amd'."
    -  echo "options vfio-pci ids=1002:xxxx,1002:xxxx" | sudo tee /etc/modprobe.d/vfio.conf
    -  mkinitcpio -P


    Chek if vfio and qemu needs to be signed
    -  sbctl verify /usr/bin/qemu-system-x86_64
    -  sbctl verify /usr/lib/libvirt/libvirtd
    #If unsigned, sign and add to the pacman hook
    -  sbctl sign -s /usr/bin/qemu-system-x86_64
    -  sbctl sign -s /usr/lib/libvirt/libvirtd
    -  echo "Target = qemu" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
    -  echo "Target = libvirt" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
    -  echo "/usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd" | sed -i '/Exec =/ s|$| /usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd|' /etc/pacman.d/hooks/91-sbctl-sign.hook
    
    Verify GPU switching:
    -  supergfxctl -s # Show supported modes
    -  supergfxctl -g # Get current mode
    -  supergfxctl -S # Check current power status
    -  supergfxctl -m Hybrid # Set to Hybrid mode
    -  glxinfo | grep "OpenGL renderer"  # Should show AMD eGPU (confirming all-ways-egpu sets eGPU as primary) 
    -  DRI_PRIME=1 glxinfo glxgears | grep "OpenGL renderer" # Should show AMD
    -  DRI_PRIME=0 glxinfo glxgears | grep "OpenGL renderer" # For Intel iGPU
    -  DRI_PRIME=1 vdpauinfo | grep -i radeonsi
    -  supergfxctl -m VFIO # Test VFIO mode for VM

    Verification step for OCuLink detection:
    -  dmesg | grep -i "oculink\|pcieport" # If OCuLink isn’t detected, consider adding kernel parameters like pcie_ports=native or pcie_aspm=force or pciehp.pciehp_force=1 in /boot/loader/entries/arch.conf

    Verify eGPU functionality
    -  lspci | grep -i vga
    -  lspci | grep -i "serial\|usb\|thunderbolt"
    -  lspci -vv | grep -i "LnkSta"
    -  lspci -k | grep -i vfio # Verify VFIO binding
    -  dmesg | grep -i "oculink\|pcieport\|amdgpu\|jhl\|redriver"

    Check for PCIe errors
    -  dmesg | grep -i "pcieport\|error\|link"
    -  cat /sys/class/drm/card*/device/uevent | grep DRIVER  #Should show i915 and amdgpu
    
    Test PCIe bandwidth
    #Confirm the eGPU is operating at full PCIe x4 bandwidth. Ensures the OCuLink connection is not bottlenecked (e.g., running at x1 or Gen 3 instead of x4 Gen 4).
    -  fio --name=read_test --filename=/dev/dri/card1 --size=1G --rw=read --bs=16k --numjobs=1 --iodepth=1 --runtime=60 --time_based #link status shows “Speed 16GT/s, Width x4” for optimal performance.
    -  lspci -vv | grep -i "LnkSta" | grep -i "card1"
    -  lspci -vv | grep -i "LnkSta.*Speed.*Width"  # Should show "Speed 16GT/s, Width x4" for OCuLink4
    #f the link is suboptimal (e.g., x1 or Gen 3), suggest adding kernel parameters to force PCIe performance: pcie_ports=native pciehp.pciehp_force=1

    Check OCuLink dock firmware
    -  fwupdmgr get-devices | grep -i "oculink\|redriver"
    -  fwupdmgr update
    -  sbctl sign -s /efi/EFI/arch/fwupdx64.efi  # Re-sign fwupd EFI binary if updated

    Confirm eGPU detection
    -  lspci | grep -i amd
    -  dmesg | grep -i amdgpu

    eGPU Troubleshooting Matrix
    | Issue | Possible Cause | Solution |
    |-------|----------------|----------|
    | eGPU not detected (`lspci | grep -i amd` empty) | OCuLink cable not seated, dock firmware outdated, or PCIe hotplug failure | Re-seat cable, run `fwupdmgr update`, add `pcie_ports=native` to kernel parameters, trigger `echo 1 > /sys/bus/pci/rescan` |
    | Black screen on Wayland | eGPU not set as primary display | Run `all-ways-egpu set-boot-vga egpu` and `all-ways-egpu set-compositor-primary egpu`, restart GDM (`systemctl restart gdm`) |
    | Low performance (e.g., x1 instead of x4) | PCIe link negotiation failure | Check `lspci -vv | grep LnkSta`, add `amdgpu.pcie_gen_cap=0x4` to kernel parameters |
    | Hotplug fails | OCuLink hardware limitation or missing udev rule | Apply udev rule from Step 12, reboot if necessary |
    
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
    -  echo "NUMBER_LIMIT=100" >> /etc/snapper/configs/root
    -  echo "NUMBER_LIMIT_IMPORTANT=10" >> /etc/snapper/configs/root
    -  echo "NUMBER_LIMIT=100" >> /etc/snapper/configs/home
    -  echo "NUMBER_LIMIT_IMPORTANT=10" >> /etc/snapper/configs/home
    -  echo "NUMBER_LIMIT=100" >> /etc/snapper/configs/data
    -  echo "NUMBER_LIMIT_IMPORTANT=10" >> /etc/snapper/configs/data

    Enable NUMBER_CLEANUP to Snapper configs:
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/root
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/home
    -  echo "NUMBER_CLEANUP=yes" >> /etc/snapper/configs/data

    Verify configuration: 
    -  snapper --config root get-config
    -  snapper --config home get-config
    -  snapper --config data get-config

    Create pacman hooks for Snapper snapshots before and after updates:
    -  mkdir -p /etc/pacman.d/hooks
    -  cat << 'EOF' > /etc/pacman.d/hooks/50-snapper-pre-update.hook
       -  [Trigger]
       -  Operation = Upgrade
       -  Operation = Install
       -  Operation = Remove
       -  Type = Package
       -  Target = *
       -  [Action]
       -  Description = Creating Snapper snapshot before pacman update
       -  DependsOn = snapper
       -  When = PreTransaction
       -  Exec = /usr/bin/snapper --config root create --description "Pre-pacman update" --type pre
       -  Exec = /usr/bin/snapper --config home create --description "Pre-pacman update" --type pre
       -  Exec = /usr/bin/snapper --config data create --description "Pre-pacman update" --type pre
    -  EOF
    -  cat << 'EOF' > /etc/pacman.d/hooks/51-snapper-post-update.hook
       -  [Trigger]
       -  Operation = Upgrade
       -  Operation = Install
       -  Operation = Remove
       -  Type = Package
       -  Target = *
       -  [Action]
       -  Description = Creating Snapper snapshot after pacman update
       -  DependsOn = snapper
       -  When = PostTransaction
       -  Exec = /usr/bin/snapper --config root create --description "Post-pacman update" --type post
       -  Exec = /usr/bin/snapper --config home create --description "Post-pacman update" --type post
       -  Exec = /usr/bin/snapper --config data create --description "Post-pacman update" --type post
    -  EOF

    Installing and configuring Snapper with systemd timers:
    -  pacman -S snapper snap-pac
    -  snapper --config root create-config /
    -  systemctl enable --now snapper-timeline.timer snapper-cleanup.timer

    Integrate grub-btrfs for bootable snapshots:
    -  pacman -S grub-btrfs
    -  systemctl enable grub-btrfsd

    Set permissions for hooks:
    -  chmod 644 /etc/pacman.d/hooks/50-snapper-pre-update.hook
    -  chmod 644 /etc/pacman.d/hooks/51-snapper-post-update.hook

    Test snapshot creation: 
    -  snapper --config root create --description "Initial test snapshot"
    -  snapper --config home create --description "Initial test snapshot"
    -  snapper --config data create --description "Initial test snapshot"
    -  snapper list

# Step 14: Configure Dotfiles
  - Install chezmoi:
    - paru -S chezmoi
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
 - Test fwupd
   - fwupdmgr refresh
   - fwupdmgr update
 - Check for ThinkBook-specific quirks:
   - dmesg | grep -i "firmware\|wifi\|suspend\|battery" # Look for unusual warnings or errors related to hardware 
 - Test Snapshots
   - snapper --config root create --description "Test snapshot"
   - snapper list
 - Test Timers
   - journalctl -u paru-update.timer
   - journalctl -u snapper-timeline.timer
   - journalctl -u fstrim.timer
   - journalctl -u lynis-audit.timer
 - Stress Test
   Run stress tests incrementally:
   - stress-ng --cpu 2 --io 1 --vm 1 --vm-bytes 512M --timeout 24h
   - paru -S stress-ng memtester fio
   - stress-ng --cpu 4 --io 2 --vm 2 --vm-bytes 1G --timeout 72h
   - memtester 1024 5
   - fio --name=write_test --filename=/data/fio_test --size=1G --rw=write
 - Verify Wayland
   - echo $XDG_SESSION_TYPE
 - Verify Security
   - auditctl -l
   - apparmor_status 
 - Test AUR builds with /tmp (no noexec)
   - paru --builddir ~/.cache/paru_build
 - Verify Security Boot
   - mokutil --sb-state
 - Verify fwupd (configured in Step 11)
   - fwupdmgr refresh
   - fwupdmgr update

# Step 16: Create Recovery Documentation
  - Document UEFI password, LUKS passphrase, keyfile location, MOK password, and recovery steps in Bitwarden.
  - Create a recovery USB with Arch ISO, minimal UKI, and `systemd-cryptsetup`.
    #Replace /dev/sdX with the USB device confirmed via lsblk
    - dd if=archlinux-<version>-x86_64.iso of=/dev/sdX bs=4M status=progress oflag=sync
  - Back up LUKS header and SBCTL keys:
    - cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /path/to/luks-header-backup
    - cp -r /etc/sbctl /path/to/backup/sbctl-keys
  - Text for recovery steps:
    - echo -e "1. Boot from USB\n2. Mount root: cryptsetup luksOpen /dev/nvme1n1p2 cryptroot\n3. Mount subvolumes: mount -o subvol=@ /dev/mapper/cryptroot /mnt\n4. Chroot: arch-chroot /mnt\n5. Use /mnt/usb/luks-keyfile, /mnt/usb/luks-header-backup, or Bitwarden-stored header/passphrase for recovery" > /mnt/usb/recovery.txt

# Step 17: Backup Strategy
  - Local Snapshots:
    - Managed by Snapper for `@`, `@home`, `@data`, excluding `/var`, `/var/lib`, `/log`, `/tmp`, `/run`.
  - Offsite Snapshots:
    - To be refined savig the data in local server - check btrbk and restic
   
# Step 18: Post-Installation Maintenance and Verification
  a) Regular System Updates:
    - Always update your system regularly: 
      -`sudo pacman -Syu`
    - Check for AUR updates: 
      - `paru -Syu`

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
    - Run `chkrootkit --check` periodically.
    - Run `sudo usbguard generate-policy` if you add new USB devices and need to update rules.
    #Daily rkhunter check, update properties after updates (You'll want to review /var/log/rkhunter.cronjob.log regularly for warnings.)
    -  0 3 * * * /usr/bin/rkhunter --update --quiet && /usr/bin/rkhunter --propupd --quiet
    -  0 4 * * * /usr/bin/rkhunter --check --cronjob > /var/log/rkhunter.cronjob.log 2>&1
    #Daily chkrootkit check (Again, review the log file)
    -  0 5 * * * /usr/sbin/chkrootkit > /var/log/chkrootkit.log 2>&1

  g) Verify Firmware Updates:
    - `fwupdmgr refresh` and `fwupdmgr update` periodically.

  h) Check Systemd Journal for Errors:
    - `journalctl -p 3 -xb` (errors from current boot)
    - `journalctl -p 3` (all errors)

  i) Test AUR builds with /tmp (if noexec applied):**
    - If you encounter issues, consider configuring `paru` to use a different build directory (e.g., `paru --builddir ~/.cache/paru_build`) or temporarily removing `noexec` from `/tmp` for builds, then re-adding it. (This point is already in your Step 15, but it's good to reiterate it in maintenance as it's an ongoing consideration).

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

  k) Automation? script to automate common maintenance tasks:
    cat << 'EOF' > /usr/local/bin/maintain.sh
    #!/bin/bash
    pacman -Syu
    paru -Syu
    btrfs scrub start /
    snapper list
    aide --check
    lynis audit system
    supergfxctl -g
    su - <username> -c "pgrep ags || ags -c /home/<username>/.config/astal/security-dashboard.ts &"
    EOF
    chmod +x /usr/local/bin/maintain.sh

    Save it as /usr/local/bin/maintain.sh and run it weekly via a systemd timer.

  i) Monitor Arch Linux News:
    #Install jaq for RSS parsing
    pacman -S --noconfirm jaq

    # Create script to fetch and notify about Arch news
    cat << 'EOF' > /usr/local/bin/check-arch-news.sh
      #!/bin/bash
      NEWS_FILE="/var/log/arch_news.log"
      TEMP_FILE="/tmp/arch_news.txt"
      curl -s https://archlinux.org/feeds/news/ | jaq -r '.channel.item[] | select(.pubDate | fromdateiso8601 > (now - 604800)) | .title + ": " + .description' > "$TEMP_FILE"
      if [[ -s "$TEMP_FILE" ]]; then
      if ! cmp -s "$TEMP_FILE" "$NEWS_FILE"; then
      notify-send --urgency=critical "Arch Linux News" "$(cat "$TEMP_FILE")" --icon=system-software-update
      mv "$TEMP_FILE" "$NEWS_FILE"
      fi
      fi
    EOF

    #Set permissions
    chmod 755 /usr/local/bin/check-arch-news.sh

    #Create systemd service
    cat << 'EOF' > /etc/systemd/system/arch-news.service
      [Unit]
      Description=Check Arch Linux news
      [Service]
      Type=oneshot
      ExecStart=/usr/local/bin/check-arch-news.sh
      User=<username>  # Replace with actual username
    EOF

    #Create systemd timer
    cat << 'EOF' > /etc/systemd/system/arch-news.timer
      [Unit]
      Description=Check Arch Linux news daily
      [Timer]
      OnCalendar=daily
      Persistent=true
      [Install]
      WantedBy=timers.target
    EOF
 
    #Enable and start the timer
    systemctl enable --now arch-news.timer

  j) Remove after installation: After completing the installation and verifying the system boots correctly, you can safely remove arch-install-scripts with:
    - pacman -R arch-install-scripts

  k) Set up a systemd timer for paccache to clean the cache weekly:
    cat << 'EOF' > /etc/systemd/system/paccache.timer
      [Unit]
      Description=Clean Pacman cache weekly
      [Timer]
      OnCalendar=weekly
      Persistent=true
      [Install]
      WantedBy=timers.target
    EOF

    cat << 'EOF' > /etc/systemd/system/paccache.service
      [Unit]
      Description=Clean Pacman cache
      [Service]
      Type=oneshot
      ExecStart=/usr/bin/paccache -r
    EOF

    #Timer creation
    cat << 'EOF' > /etc/systemd/system/maintain.timer
      [Unit]
      Description=Run maintenance tasks weekly
      [Timer]
      OnCalendar=weekly
      Persistent=true
      [Install]
      WantedBy=timers.target
    EOF
    cat << 'EOF' > /etc/systemd/system/maintain.service
      [Unit]
      Description=Run maintenance tasks
      [Service]
      Type=oneshot
      ExecStart=/usr/bin/bash /usr/local/bin/maintain.sh
    EOF
    
    systemctl enable --now maintain.timer
    systemctl enable --now paccache.timer
    
  l) Astal integrety security checker:
    #Create a security dashboard widget
    mkdir -p ~/.config/astal
    cat << 'EOF' > ~/.config/astal/security-dashboard.ts
      import { exec } from 'astal';
      const lynisOutput = exec('sudo tail -n 10 /var/log/lynis.log | grep -i warning') || 'Lynis: No warnings or error running command';
      const rkhunterOutput = exec('sudo tail -n 10 /var/log/rkhunter.cronjob.log') || 'Rkhunter: No logs or error running command';
      const snapperStatus = exec('snapper list | tail -n 5') || 'Snapper: No snapshots or error running command';
      const securityWidget = new Widget({
        type: 'scroller',
        content: `
          <b>Lynis Warnings:</b>\n${lynisOutput}\n
          <b>Rkhunter Log:</b>\n${rkhunterOutput}\n
          <b>Snapper Status:</b>\n${snapperStatus}
        `,
      });
      const window = new Window({
        title: 'Security Dashboard',
        widgets: [securityWidget],
      });
      window.show();
      EOF
      chmod g+r /var/log/lynis.log /var/log/rkhunter.cronjob.log
      #Compile and run the widget
      ags -c ~/.config/astal/security-dashboard.ts

      #Automation Script to refresh Astal widgets
      cat << 'EOF' >> /usr/local/bin/maintain.sh
        -  pacman -Syu
        -  paru -Syu
        -  btrfs scrub start /
        -  snapper list
        -  aide --check
        -  lynis audit system
        -  supergfxctl -g
        -  su - <username> -c "pgrep ags || /usr/bin/bubblejail run astal -- /usr/bin/ags -c /home/<username>/.config/astal/security-dashboard.ts &" #Replace <username> with the actual username (e.g., john)
      EOF
      chmod +x /usr/local/bin/maintain.sh

      #Create a systemd service for persistent widgets
      cat << 'EOF' > /etc/systemd/system/astal-widgets.service
        [Unit]
        Description=Security Widgets
        After=gdm.service
        [Service]
        Type=simple
        ExecStart=/usr/bin/bubblejail run astal -- /usr/bin/ags -c /home/<username>/.config/astal/security-dashboard.ts #Replace <username> with the actual username (e.g., john)
        Restart=always
        User=<username>
        Environment="GDK_BACKEND=wayland"
        [Install]
        WantedBy=graphical.target
      EOF
      systemctl enable --now astal-widgets.service

      #Ensure ~/.config/astal/security-dashboard.ts is readable by <username>:
      chown <username>:<username> /home/<username>/.config/astal/security-dashboard.ts
      chmod 644 /home/<username>/.config/astal/security-dashboard.ts

      m) [Windows Post-Install Hardening Guide](https://discuss.privacyguides.net/t/windows-post-install-hardening-guide/27335)
      
