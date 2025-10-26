# Secure Arch Installation for an Intel Lenovo ThinkBook using an AMD eGPU via OCuLink

## Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)

- This guide provides a **comprehensive action plan** for installing and configuring **Arch Linux** on a **Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H** with **Intel iGPU (Intel Arc 140T)**, no dGPU, using **GNOME Wayland**, **BTRFS**, **LUKS2**, **TPM2**, **AppArmor**, **systemd-boot with Unified Kernel Image (UKI)**, **Secure Boot**, and an **OCuP4V2 OCuLink GPU Dock ReDriver with an AMD eGPU**.
- The laptop has **two M.2 NVMe slots**; we will install **Windows 11 Pro** on one slot (`/dev/nvme0n1`) for BIOS and firmware updates, and **Arch Linux** on the second slot (`/dev/nvme1n1`).
- **Observation**: The `linux-hardened` kernel is avoided due to complexities with eGPU setup and performance penalties. Instead, we manually incorporate security enhancements inspired by `linux-hardened`, such as kernel parameters for memory safety and mitigations.
- **Attention**: Commands involving `dd`, `mkfs`, `cryptsetup`, `parted`, and `efibootmgr` can **destroy data** if executed incorrectly. **Re-read each command multiple times** to confirm the target device/partition is correct. Test **LUKS and TPM unlocking** thoroughly before enabling **Secure Boot**, and verify **Secure Boot** functionality before configuring the **eGPU**.

## Step 1: Verify Hardware

- Access the **UEFI BIOS** by pressing `F1` at boot:
  - Enable **TPM 2.0** (Security Chip) under the Security menu.
  - Enable **Intel VT-d** (IOMMU) for improved eGPU and virtualization support.
  - Set a **strong UEFI BIOS password** (at least 12 characters, mixed case, numbers, and symbols).
  - **Store the UEFI BIOS password in Bitwarden** or another secure password manager.
  - Temporarily disable **Secure Boot** in the UEFI settings to simplify initial setup.
- Visit the eGPU community builds for reference:
  - Filter by "Thinkbook" at https://egpu.io/best-external-graphics-card-builds/.
  - Confirm compatibility of the **OCuP4V2 OCuLink GPU Dock** with your AMD eGPU model.

## Step 2: Install Windows on Primary NVMe M.2 (/dev/nvme0n1)

- Follow privacy recommendations from the **Privacy Guides Wiki** for [Minimizing Windows 11 Data Collection](https://discuss.privacyguides.net/t/minimizing-windows-11-data-collection/28193).
- Install **Windows 11 Pro** on `/dev/nvme0n1` to facilitate BIOS and firmware updates via **Lenovo Vantage**:
  - During installation, allow Windows to create its default partitions, including a ~100-300 MB **EFI System Partition (ESP)** at `/dev/nvme0n1p1`.
  - Choose a local account to minimize telemetry (avoid signing in with a Microsoft account).
- Disable **Windows Fast Startup** to prevent ESP lockout during Linux setup:
  ```powershell
  powercfg /h off
  ```
- Disable **BitLocker** encryption to avoid conflicts with Linux accessing the ESP:
  ```powershell
  manage-bde -status
  Disable-BitLocker -MountPoint "C:"
  ```
- Verify **TPM 2.0** is active:
  - Run `tpm.msc` in Windows and confirm TPM is enabled.
  - If TPM was previously provisioned, clear it via `tpm.msc` (Security > Clear TPM).
- Verify **Windows boots correctly** and check **Resizable BAR sizes**:
  - In **Device Manager**, check GPU properties for BAR settings.
  - Alternatively, run:
    ```powershell
    wmic path Win32_VideoController get CurrentBitsPerPixel,VideoMemoryType
    ```
  - In Linux later, check BAR sizes with:
    ```bash
    dmesg | grep -i "BAR.*size"
    ```
- Verify both NVMe drives (`/dev/nvme0n1` for Windows, `/dev/nvme1n1` for Arch) in **Windows Disk Management**.
- Review additional privacy guides for post-installation hardening:
  - [Group Policy Settings](https://www.privacyguides.org/en/os/windows/group-policies/)
  - [Windows Privacy Settings](https://discuss.privacyguides.net/t/windows-privacy-settings/27333)
- Back up registry settings to preserve Windows configuration:
  ```powershell
  reg export "HKLM\SOFTWARE" C:\backup_registry.reg
  ```
- Disable diagnostic data, feedback, and telemetry services:
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0
  Stop-Service -Name "DiagTrack" -Force
  Set-Service -Name "DiagTrack" -StartupType Disabled
  Stop-Service -Name "dmwappushservice" -Force
  Set-Service -Name "dmwappushservice" -StartupType Disabled
  Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("9.9.9.9","149.112.112.112")
  ```
- Restrict App Permissions:
  - Open **Settings > Privacy & Security > General**:
    - Turn off “Let apps show me personalized ads”.
    - Turn off “Let Windows improve Start and search”.
- Disable **Cortana** and web search in Start menu:
  ```powershell
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortana" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
  ```
- Uninstall preinstalled apps (e.g., Xbox, Candy Crush):
  ```powershell
  Get-AppxPackage -AllUsers *XboxApp* | Remove-AppxPackage
  Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage
  Get-AppxPackage -AllUsers *MicrosoftNews* | Remove-AppxPackage
  Get-AppxPackage -AllUsers *Weather* | Remove-AppxPackage
  Get-AppxPackage -AllUsers *Teams* | Remove-AppxPackage
  ```
- Disable unnecessary services (e.g., Xbox Live, Game Bar):
  ```powershell
  Stop-Service -Name "XboxGipSvc" -Force
  Set-Service -Name "XboxGipSvc" -StartupType Disabled
  ```
- Apply Group Policy Settings for privacy:
  ```powershell
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
  ```
- Enable **tamper protection** and **real-time protection**:
  - Navigate to **Settings > Windows Security > Virus & Threat Protection** and enable both.
- Back up the **Windows EFI partition UUID** for dual-boot compatibility:
  ```powershell
  # Insert a USB drive (e.g., F:)
  mountvol Z: /S
  robocopy Z:\ F:\EFI-Backup /MIR /XJ  # Replace F: with the USB drive letter
  Get-Partition -DiskNumber 0 -PartitionNumber 1 | Select-Object -ExpandProperty Guid | Out-File F:\windows-esp-uuid.txt
  mountvol Z: /D
  ```
- **WARNING**: Store `F:\EFI-Backup` and `F:\windows-esp-uuid.txt` securely in **Bitwarden** or an encrypted cloud service.
- **WARNING**: Ensure the USB drive is encrypted or physically secure to prevent unauthorized access to the EFI backup.

## Milestone 1: After Step 2 (Windows Installation) - Can pause at this point

## Step 3: Prepare Installation Media

- Download the latest **Arch Linux ISO** from https://archlinux.org/download/.
- Verify the ISO signature to ensure integrity:
  - Follow instructions on the Arch Linux website for `gpg` verification.
  - Example:
    ```bash
    gpg --keyserver-options auto-key-retrieve --verify archlinux-<version>-x86_64.iso.sig
    ```
- Create a bootable USB drive:
  - Use **Rufus** in Windows, selecting **DD mode** for reliable writing.
  - **Avoid Ventoy** and **Balena Etcher** due to potential trackers and reliability issues.
- Test the USB by rebooting and selecting it in the **BIOS boot menu** (press `F12` or similar).
- Verify network connectivity in the live environment:
  ```bash
  ping -c 3 archlinux.org
  ```
- If Wi-Fi is needed, configure it:
  ```bash
  nmcli device wifi list
  nmcli device wifi connect <SSID> password <password>
  ```

## Step 4: Pre-Arch Installation Steps

- Boot from the **Arch Live USB**.
- **Pre-computation and Pre-determination of System Identifiers**:
  - **LUKS for rd.luks.uuid and Partition UUID**:
    - After encrypting `/dev/nvme1n1p2` with LUKS, retrieve its UUID:
      ```bash
      LUKS_HEADER_UUID=$(cryptsetup luksUUID /dev/nvme1n1p2)
      echo $LUKS_HEADER_UUID  # Should output a UUID like 123e4567-e89b-12d3-a456-426614174000
      ```
      - **Record this UUID** for use in `/etc/crypttab` and kernel parameters (`rd.luks.uuid=...`).
    - Get the partition UUID:
      ```bash
      LUKS_UUID=$(blkid -s UUID -o value /dev/nvme1n1p2)
      echo $LUKS_UUID  # Should output a UUID like 123e4567-e89b-12d3-a456-426614174000
      ```
      - **Record this UUID** for kernel parameters and `/etc/crypttab` mappings.
      - **Why two UUIDs?** The `LUKS_HEADER_UUID` is specific to the LUKS container, while `LUKS_UUID` is the partition’s UUID used by the bootloader.
  - **Root Filesystem UUID**:
    - After creating the BTRFS filesystem on `/dev/mapper/cryptroot`, obtain its UUID:
      ```bash
      ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
      echo $ROOT_UUID  # Should output a UUID like 48d0e960-1b5e-4f2c-8caa-...
      ```
      - **Record this UUID** for the bootloader (`root=UUID=...`) and `/etc/fstab`.
  - **Swap File/Partition Offset (for Hibernation)**:
    - If using a swap file on a BTRFS subvolume for hibernation, compute the physical offset for the resume_offset kernel parameter. Ensure the swap file is created with chattr +C to disable Copy-on-Write (done in Step 4e). Get the resume_offset:
      ```bash
      SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
      # Alternatively, after Step 4e: SWAP_OFFSET=$(cat /etc/swap_offset)
      echo $SWAP_OFFSET  # Should output a numerical offset like 12345678
      ```
      - **Record this SWAP_OFFSET value. Insert it directly into your systemd-boot kernel parameters (e.g., in /etc/mkinitcpio.d/linux.preset) and /etc/fstab (for the swapfile entry with resume_offset=).
      - **Note**: This offset is critical for hibernation support and must be accurate—recompute if the swap file changes.
- **a) Partition the Second NVMe M.2 (/dev/nvme1n1)**:
  - Create a GPT partition table with an ESP and a LUKS partition:
    ```bash
    parted /dev/nvme1n1 --script \
      mklabel gpt \
      mkpart ESP fat32 1MiB 1GiB \
      set 1 esp on \
      mkpart crypt btrfs 1GiB 100% \
      align-check optimal 1 \
      quit
    ```
  - Verify partitions:
    ```bash
    lsblk -f /dev/nvme0n1 /dev/nvme1n1  # Confirm /dev/nvme0n1p1 (Windows ESP) and /dev/nvme1n1p1 (Arch ESP)
    efibootmgr  # Check if UEFI recognizes both ESPs
    ```
- **b) Format ESP**:
  - Format the Arch ESP as FAT32:
    ```bash
    mkfs.fat -F32 -n ARCH_ESP /dev/nvme1n1p1
    ```
- **c) Set Up LUKS2 Encryption for the BTRFS File System**:
  - Format `/dev/nvme1n1p2` with LUKS2, using `pbkdf2` for compatibility with `systemd-cryptenroll`:
    ```bash
    cryptsetup luksFormat --type luks2 /dev/nvme1n1p2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000000
    ```
  - Open the LUKS partition:
    ```bash
    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot
    ```
  - Create a recovery keyfile (not used in initramfs, only for GRUB rescue):
    ```bash
    dd if=/dev/urandom of=/mnt/crypto_keyfile bs=512 count=4 iflag=fullblock
    chmod 600 /mnt/crypto_keyfile
    ```
  - Add the keyfile to LUKS in keyslot 1:
    ```bash
    cryptsetup luksAddKey /dev/nvme1n1p2 /mnt/crypto_keyfile --key-slot 1
    ```
  - Back up the keyfile to a USB:
    ```bash
    mkdir -p /mnt/usb
    lsblk  # Identify USB device (e.g., /dev/sdX1)
    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**
    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile
    shred -u /mnt/crypto_keyfile
    echo "WARNING: Store the LUKS keyfile (/mnt/usb/crypto_keyfile) securely in Bitwarden for recovery purposes."
    ```
- **d) Create BTRFS Filesystem and Subvolumes**:
  - Create the BTRFS filesystem:
    ```bash
    mkfs.btrfs /dev/mapper/cryptroot
    mount /dev/mapper/cryptroot /mnt
    ```
  - Create subvolumes for isolation and snapshotting:
    ```bash
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
    ```
  - Mount subvolumes with optimized options:
    ```bash
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
    ```
  - **Why These Subvolumes?**:
    - **@**: Isolates the root filesystem for snapshotting and rollback.
    - **@home**: Separates user data for independent snapshots and backups.
    - **@snapshots**: Stores Snapper snapshots for system recovery.
    - **@var, @var_lib, @log**: Disables Copy-on-Write (`nodatacow`, `noatime`) for performance on frequently written data.
    - **@swap**: Ensures swapfile compatibility with hibernation (`nodatacow`, `noatime`).
    - **@srv, @data**: Provides flexible storage with compression (`zstd:3`) for server or user data.
- **e) Configure Swap File**:
  - Create a swap file on the `@swap` subvolume:
    ```bash
    touch /mnt/swap/swapfile
    chattr +C /mnt/swap/swapfile  # Disable Copy-on-Write
    fallocate -l 32G /mnt/swap/swapfile || { echo "fallocate failed"; exit 1; }
    chmod 600 /mnt/swap/swapfile
    mkswap /mnt/swap/swapfile || { echo "mkswap failed"; exit 1; }
    ```
  - Obtain the swapfile’s physical offset for hibernation:
    ```bash
    SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
    echo $SWAP_OFFSET > /mnt/etc/swap_offset
    echo $SWAP_OFFSET  # Should output a numerical offset like 12345678
    ```
    - **Record this SWAP_OFFSET** for `/etc/fstab` and kernel parameters.
  - Unmount the swap subvolume:
    ```bash
    umount /mnt/swap
    ```
  - Add the swapfile to `/etc/fstab`:
    ```bash
    # Replace $SWAP_OFFSET with the actual precomputed value
    echo "/swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0" >> /mnt/etc/fstab
    ```
- **f) Generate fstab**:
  - Generate the initial fstab:
    ```bash
    genfstab -U /mnt | tee /mnt/etc/fstab
    ```
  - Manually edit `/mnt/etc/fstab` to verify subvolume options and add security settings.
  - **BTRFS Subvolume and Mount Options**:
    - Replace `$ROOT_UUID` with the actual UUID from `blkid`:
      ```bash
      UUID=$ROOT_UUID / btrfs subvol=@,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      UUID=$ROOT_UUID /home btrfs subvol=@home,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      UUID=$ROOT_UUID /data btrfs subvol=@data,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      UUID=$ROOT_UUID /var btrfs subvol=@var,nodatacow,noatime 0 0
      UUID=$ROOT_UUID /var/lib btrfs subvol=@var_lib,nodatacow,noatime 0 0
      UUID=$ROOT_UUID /var/log btrfs subvol=@log,nodatacow,noatime 0 0
      UUID=$ROOT_UUID /srv btrfs subvol=@srv,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      UUID=$ROOT_UUID /swap btrfs subvol=@swap,nodatacow,noatime 0 0
      UUID=$ROOT_UUID /.snapshots btrfs subvol=@snapshots,ssd,noatime 0 0
      ```
  - **Edit ESP (/boot) Entry**:
    - Add `umask=0077` for security:
      ```bash
      UUID=$ARCH_ESP_UUID /boot vfat umask=0077 0 2
      ```
  - **Edit Windows ESP Entry**:
    - Use `noauto` and `x-systemd.automount` for manual mounting:
      ```bash
      UUID=$WINDOWS_ESP_UUID /windows-efi vfat noauto,x-systemd.automount,umask=0077 0 2
      ```
  - **Add tmpfs Entries**:
    - Use `tmpfs` for temporary directories to reduce disk writes:
      ```bash
      tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0
      tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,mode=1777 0 0
      ```
  - **Add Swapfile Entry**:
    - Replace `$SWAP_OFFSET` with the actual value:
      ```bash
      /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0
      ```
  - **Validation Steps**:
    - List ESP UUIDs to confirm:
      ```bash
      blkid | grep -E 'nvme0n1p1|nvme1n1p1'
      ```
    - Verify the generated fstab:
      ```bash
      cat /mnt/etc/fstab
      ```
    - Check all UUIDs:
      ```bash
      blkid | grep -E "$ROOT_UUID|$LUKS_UUID|$ARCH_ESP_UUID|$WINDOWS_ESP_UUID"
      ```
- **g) Check Network**:
  - Verify connectivity:
    ```bash
    ping -c 3 archlinux.org
    ```
  - If using Wi-Fi, connect:
    ```bash
    nmcli device wifi connect <SSID> password <password>
    ```
  - Copy resolver configuration:
    ```bash
    cp /etc/resolv.conf /mnt/etc/resolv.conf
    ```

## Milestone 2: After Step 4f (fstab Generation) - Can pause at this point

## Step 5: Install Arch Linux

- Configure the mirrorlist for faster package downloads:
  ```bash
  pacman -Sy reflector
  reflector --latest 10 --sort rate --save /etc/pacman.d/mirrorlist
  ```
- Install the base system and necessary packages:
  ```bash
  pacstrap /mnt \
  # Core
  base base-devel linux linux-firmware mkinitcpio archlinux-keyring \
  \
  # Boot / Encryption
  intel-ucode sbctl cryptsetup btrfs-progs efibootmgr dosfstools \
  \
  # Hardware / Firmware
  sof-firmware intel-media-driver fwupd nvme-cli wireless-regdb \
  \
  # Graphics
  mesa libva-mesa-driver vulkan-intel lib32-vulkan-intel \
  vulkan-radeon lib32-vulkan-radeon intel-gpu-tools \
  \
  # Audio
  pipewire wireplumber pipewire-pulse pipewire-alsa pipewire-jack \
  \
  # System
  sudo polkit udisks2 thermald acpi acpid ethtool \
  \
  # Network / Install
  networkmanager openssh rsync reflector arch-install-scripts \
  \
  # User / DE
  zsh git flatpak gdm pacman-contrib
  ```
- Chroot into the installed system:
  ```bash
  arch-chroot /mnt
  ```
- Ensure multilib repository is enabled (required for 32-bit drivers):
  ```bash
  sed -i '/\[multilib\]/,/Include/ s/^#//' /etc/pacman.conf
  ```
- Force-refresh package database and keyring:
  ```bash
  pacman -Syy --noconfirm
  ```
- Add the `i915` module for early kernel mode setting (KMS) to support Intel iGPU:
  ```bash
  echo 'MODULES=(i915)' >> /etc/mkinitcpio.conf
  mkinitcpio -P
  ```

## Step 6: System Configuration

- Set timezone, locale, and hostname:
  ```bash
  ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime
  hwclock --systohc
  echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen
  locale-gen
  echo 'LANG=en_US.UTF-8' > /etc/locale.conf
  echo 'thinkbook' > /etc/hostname
  cat << 'EOF' > /etc/hosts
  127.0.0.1 localhost
  ::1 localhost
  127.0.1.1 thinkbook.localdomain thinkbook
  EOF
  ```
- Create a user account with appropriate groups:
  ```bash
  passwd  # Set root password
  useradd -m -G wheel,video,input,storage,audio,power,lp -s /usr/bin/zsh <username>
  passwd <username>  # Set user password
  sed -i '/^# %wheel ALL=(ALL:ALL) ALL/s/^# //' /etc/sudoers  # Enable wheel group sudo
  ```

## Milestone 3: After Step 6 (System Configuration) - Can pause at this point

## Step 7: Set Up TPM and LUKS2

- Install TPM tools:
  ```bash
  pacman -S --noconfirm \
    tpm2-tools \
    tpm2-tss \
    systemd-ukify \
    tpm2-tss-engine
  ```
- Verify TPM device is detected:
  ```bash
  tpm2_getcap properties-fixed
  ```
- Enroll the LUKS key to TPM2 for automatic unlocking:
  ```bash
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2
  ```
- Test TPM unlocking and back up PCR values:
  ```bash
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2
  # If test fails: tpm2_pcrread sha256:0,4,7  and compare with expected values
  systemd-cryptenroll --dump-pcrs /dev/nvme1n1p2 > /mnt/usb/tpm-pcr-initial.txt
  tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-backup.txt
  # Verify PCR 4 is measured by systemd-boot (non-zero)
  tpm2_pcrread sha256:4 | grep -v "0x0000000000000000000000000000000000000000000000000000000000000000"
  # Confirm TPM keyslot exists
  cryptsetup luksDump /dev/nvme1n1p2 | grep -i tpm
  echo "WARNING: Store /mnt/usb/tpm-pcr-initial.txt in Bitwarden."
  echo "WARNING: Store /mnt/usb/tpm-pcr-backup.txt in Bitwarden."
  echo "WARNING: PCR values are critical for TPM unlocking; back them up securely."
  ```
  WARNING: Store both /mnt/usb/tpm-pcr-initial.txt and /mnt/usb/tpm-pcr-backup.txt in Bitwarden. Firmware or Secure Boot changes will alter PCRs and break auto-unlock.
- Configure `mkinitcpio` for TPM and encryption support:
  ```bash
  # HOOKS order is critical: plymouth BEFORE sd-encrypt
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf
  # Ensure btrfs binary is available in initramfs (replace any existing line)
  sed -i 's/^BINARIES=(.*)/BINARIES=(\/usr\/bin\/btrfs)/' /etc/mkinitcpio.conf
  mkinitcpio -P
  ```
- Enable Plymouth for a graphical boot splash:
  ```bash
  pacman -S --noconfirm plymouth
  plymouth-set-default-theme -R bgrt
  ```
- Back up the LUKS header for recovery:
  ```bash
  lsblk  # Identify USB device
  mkfs.fat -F32 /dev/sdX1  # Replace sdX1 with USB partition
  mkdir -p /mnt/usb
  mount /dev/sdX1 /mnt/usb
  cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
  sha256sum /mnt/usb/luks-header-backup > /mnt/usb/luks-header-backup.sha256
  umount /mnt/usb
  echo "WARNING: Store /mnt/usb/luks-header-backup in Bitwarden or an encrypted cloud."
  echo "WARNING: TPM unlocking may fail after firmware updates; keep the LUKS passphrase in Bitwarden."
  echo "WARNING: Verify the LUKS header backup integrity with sha256sum before storing."
  ```
- Test TPM boot:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```

## Milestone 4: After Step 7 (TPM and LUKS2 Setup) - Can pause at this point

## Step 8: Configure Secure Boot

- Create and enroll Secure Boot keys:
  ```bash
  arch-chroot /mnt
  sbctl create-keys
  sbctl enroll-keys --tpm-eventlog
  mkinitcpio -P # Regenerate UKI before signing
  sbctl sign -s /usr/lib/systemd/boot/efi/systemd-bootx64.efi
  sbctl sign -s /boot/EFI/Linux/arch.efi
  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
  sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
  ```
- Check Plymouth and GDM compatibility with Secure Boot:
  ```bash
  sbctl verify /usr/lib/plymouth/plymouthd
  sbctl sign -s /usr/lib/plymouth/plymouthd
  sbctl verify /usr/lib/gdm/gdm
  sbctl sign -s /usr/lib/gdm/gdm
  ```
- Create a Pacman hook to automatically sign EFI binaries after updates:
  ```bash
  cat << 'EOF' > /etc/pacman.d/hooks/91-sbctl-sign.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = systemd
  Target = linux
  Target = fwupd
  Target = plymouth
  [Action]
  Description = Signing EFI binaries with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s \
    /usr/lib/systemd/boot/efi/systemd-bootx64.efi \
    /boot/EFI/Linux/arch.efi \
    /boot/EFI/Linux/arch-fallback.efi \
    /boot/EFI/BOOT/BOOTX64.EFI \
    /efi/EFI/arch/fwupdx64.efi \
    /usr/lib/plymouth/plymouthd \
    /usr/lib/gdm/gdm
  EOF
  ```
- Verify MOK enrollment before reboot:
  ```bash
  mokutil --list-enrolled
  ```
- Reboot to enroll keys and enable Secure Boot in UEFI:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```
  ## In UEFI (BIOS - F1), enable **Secure Boot** and enroll the sbctl key when prompted.
- Update TPM PCR policy after enabling Secure Boot:
  ```bash
  arch-chroot /mnt
  # Wipe old TPM policy and reenroll with Secure Boot PCRs
  systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2
  # Final TPM unlock test
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2
  # Confirm Secure Boot is active
  sbctl status
  sbctl verify /boot/EFI/Linux/arch.efi | grep -q "signed" && echo "UKI signed"
  ```
- Verify Secure Boot is fully enabled:
  ```bash
  # Check SetupMode: 0 = Secure Boot active, 1 = Setup Mode
  efivar -p -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-SetupMode

  # Check SecureBoot state: 1 = enabled
  efivar -p -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-SecureBoot

  # Expected output:
  SetupMode: 0
  SecureBoot: 1

  # If SetupMode=1:
  → Reboot into UEFI, complete MOK enrollment, save keys, then reboot again.
  ```
- Back up PCR values post-Secure Boot:
  ```bash
  tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-post-secureboot.txt
  diff /mnt/usb/tpm-pcr-backup.txt /mnt/usb/tpm-pcr-post-secureboot.txt
  echo "WARNING: Store /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden."
  echo "WARNING: Compare PCR values to ensure TPM policy consistency."
  ```

## Step 9: Configure systemd-boot with UKI

- Install `systemd-boot`:
  ```bash
  mount /dev/nvme1n1p1 /boot
  bootctl --esp-path=/boot install
  ```
- Configure Unified Kernel Image (UKI):
  ```bash
  cat << 'EOF' > /etc/mkinitcpio.d/linux.preset
  default_options="rd.luks.uuid=$LUKS_UUID \
    root=UUID=$ROOT_UUID \
    resume_offset=$SWAP_OFFSET \
    rw quiet splash \
    intel_iommu=on \
    amd_iommu=on \
    iommu=pt \
    pci=pcie_bus_perf,realloc \
    mitigations=auto,nosmt \
    slab_nomerge \
    slub_debug=FZ \
    init_on_alloc=1 \
    init_on_free=1 \
    rd.emergency=poweroff \
    tpm2-measure=yes \
    amdgpu.dc=1 \
    amdgpu.dpm=1"
  default_uki="/boot/EFI/Linux/arch.efi"
  all_config="/etc/mkinitcpio.conf"
  EOF
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf
  mkinitcpio -P
  ```
- Verify configuration:
  ```bash
  # Check HOOKS order
  grep HOOKS /etc/mkinitcpio.conf

  # Verify resume_offset is numeric (not $SWAP_OFFSET)
  grep resume_offset /etc/fstab /boot/loader/entries/arch.conf

  # List boot entries
  bootctl list

  # Verify UKI is signed
  sbctl verify /boot/EFI/Linux/arch.efi
  ```
- Create boot entries for dual-boot:
  ```bash
  # Copy Windows EFI files to Arch ESP:
  rsync -aHAX /mnt/windows-efi/EFI/Microsoft /boot/EFI/
  umount /mnt/windows-efi
  
  # Create /boot/loader/entries/windows.conf with:
  cat << 'EOF' > /boot/loader/entries/windows.conf
  title Windows 11
  efi /EFI/Microsoft/Boot/bootmgfw.efi
  EOF

  # Create Arch bootloader entry (/boot/loader/entries/arch.conf):
  cat << 'EOF' > /boot/loader/entries/arch.conf
  title Arch Linux
  efi /EFI/Linux/arch.efi
  EOF
  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch.conf
  ```
- Create a fallback UKI:
  ```bash
  cp /etc/mkinitcpio.conf /etc/mkinitcpio-minimal.conf
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio-minimal.conf
  echo 'UKI_OUTPUT_PATH="/boot/EFI/Linux/arch-fallback.efi"' >> /etc/mkinitcpio-minimal.conf
  mkinitcpio -P -c /etc/mkinitcpio-minimal.conf
  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
  cat << 'EOF' > /boot/loader/entries/arch-fallback.conf
  title Arch Linux (Fallback)
  efi /EFI/Linux/arch-fallback.efi
  EOF
  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch-fallback.conf
  ```
- Set Boot Order (Arch first)
  ```bash
  BOOT_ARCH=$(efibootmgr | grep 'Arch Linux' | awk '{print $1}' | cut -c5-)
  BOOT_WIN=$(efibootmgr | grep 'Windows' | awk '{print $1}' | cut -c5-)
  efibootmgr --bootorder ${BOOT_ARCH},${BOOT_WIN}
  ```
- Create a GRUB USB for recovery:
  ```bash
  lsblk  # Identify USB device (e.g., /dev/sdX1)
  mkfs.fat -F32 -n RESCUE_USB /dev/sdX1
  mkdir -p /mnt/usb
  mount /dev/sdX1 /mnt/usb # Replace /dev/sdX1 with your USB partition confirmed via lsblk

  pacman -Sy grub
  grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB

  # Copy keyfile from root (not /mnt/usb!)
  cp /mnt/usb/crypto_keyfile /mnt/usb/luks-keyfile
  chmod 600 /mnt/usb/luks-keyfile
  
  cp /boot/vmlinuz-linux /mnt/usb/
  cp /boot/initramfs-linux.img /mnt/usb/

  # Create minimal rescue initramfs
  cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block sd-encrypt filesystems)/' /mnt/usb/mkinitcpio-rescue.conf
  mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
  cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

  # Replace $LUKS_UUID and $ROOT_UUID with actual values in the menuentry
  cat << 'EOF' > /mnt/usb/boot/grub/grub.cfg
  set timeout=5
  menuentry "Arch Linux Rescue" {
      linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot root=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw
      initrd /initramfs-linux.img
  }
  EOF

  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  umount /mnt/usb

  echo "WARNING: Store the GRUB USB securely; it contains the LUKS keyfile."
  ```
- Pacman Hook: Auto-Regenerate UKI on Kernel Update
  ```bash
  mkdir -p /etc/pacman.d/hooks
  cat << 'EOF' > /etc/pacman.d/hooks/90-mkinitcpio.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = linux
  Target = linux-firmware

  [Action]
  Description = Regenerating UKI after kernel update
  When = PostTransaction
  Exec = /usr/bin/mkinitcpio -P
  EOF
  ```
- Disable Hibernation Resume Service
  ```bash
  systemctl disable systemd-hibernate-resume.service
  ```
- (Optional) Enable systemd-homed with LUKS-encrypted homes
  ```bash
  systemctl enable --now systemd-homed.service
  chattr +C /home
  homectl create username --storage=luks --fs-type=btrfs --shell=/bin/zsh --member-of=wheel --disk-size=500G
  ```

## Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can pause at this point

## Step 10: Install and Configure DE and Applications

- Install the **GNOME desktop environment**:
  ```bash
  pacman -Sy --needed gnome
  ```
- Install **Paru and configure it**:
  ```bash
  SUDO_USER=$(logname)   # or replace with your username
  
  # Clone & build in a clean temp dir
  TMP_PARU=$(mktemp -d)
  sudo -u "$SUDO_USER" git clone https://aur.archlinux.org/paru.git "$TMP_PARU"
  (cd "$TMP_PARU" && sudo -u "$SUDO_USER" makepkg -si)
  rm -rf "$TMP_PARU"

  # Configure to show PKGBUILD diffs (edit the Paru config file):
  sudo -u $SUDO_USER mkdir -p /home/$SUDO_USER/.config/paru
  cat << 'EOF' | sudo -u $SUDO_USER tee /home/$SUDO_USER/.config/paru/paru.conf
  [options]
  PgpFetch
  BottomUp
  RemoveMake
  SudoLoop
  CombinedUpgrade = false

  [bin]
  DiffMenu = true
  UseAsk = true
  EOF
  chown -R $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.config/paru
  
  # Verify if paru shows the PKGBUILD diffs
  sudo -u $SUDO_USER paru -Pg | grep -E 'diffmenu|combinedupgrade' # Should show: combinedupgrade: Off diffmenu: Edit answerdiff: Edit

  # Set build directory
  echo 'BUILDDIR = /home/$SUDO_USER/.cache/paru-build' >> /etc/makepkg.conf
  sudo -u $SUDO_USER mkdir -p /home/$SUDO_USER/.cache/paru-build
  chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.cache/paru-build
  ```
- Install the AUR applications and configure Bubblejail:
  ```bash
  # AUR applications:
  sudo -u $SUDO_USER paru -S --needed \
    bubblejail \
    alacritty-graphics \
    astal-git \
    ags-git \
    gdm-settings \
    thinklmi-git \
    systeroid-git

  # Verify binaries exist before signing
    [[ -f /usr/bin/astal && -f /usr/bin/ags ]] || { echo "ERROR: astal/ags not found!"; exit 1; }
  
  # Sign astal/ags for Secure Boot once
    sbctl sign -s /usr/bin/astal /usr/bin/ags
  
  # Append to existing 91-sbctl-sign.hook
  cat << 'EOF' >> /etc/pacman.d/hooks/91-sbctl-sign.hook

  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = astal-git
  Target = ags-git

  [Action]
  Description = Sign astal/ags with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/astal /usr/bin/ags
  EOF

  # Test the hook after installation:
  sbctl verify /usr/bin/astal  #Should show "signed"

  # Configure Bubblejail
    bubblejail create --profile generic-gui-app alacritty
    bubblejail config alacritty --add-service wayland --add-service dri
    bubblejail run Alacritty -- env | grep -E 'WAYLAND|XDG_SESSION_TYPE'
  
    bubblejail create --profile generic-gui-app astal
    bubblejail config astal --add-service wayland --add-service dri
    bubblejail run astal -- ags -c /home/$SUDO_USER/.config/ags/config.js
  ```
- Install Pacman applications:
  ```bash
  # System packages (CLI + system-level)
  pacman -S --needed \
  # Security & Hardening
  aide apparmor auditd chkrootkit lynis rkhunter sshguard ufw usbguard \
  \
  # System Monitoring
  baobab cpupower gnome-system-monitor tlp upower zram-generator \
  \
  # Hardware
  bluez bluez-utils fprintd thermald \
  \
  # Networking & Privacy
  dnscrypt-proxy opensnitch wireguard-tools \
  \
  # CLI Tools
  atuin bottom delta dog dua eza fd fzf gcc gdb git gitui glow gping \
  helix httpie jaq procs python-pygobject rage ripgrep rustup tealdeer \
  tokei xdg-ninja yazi zellij zoxide \
  \
  # Multimedia (system)
  ffmpeg gstreamer gst-libav gst-plugins-bad gst-plugins-good gst-plugins-ugly \
  libva-utils libva-vdpau-driver vulkan-tools clinfo mangohud \
  \
  # Browsers & OBS (native)
  brave-browser mullvad-browser tor-browser obs-studio \
  \
  # Utilities
  bandwhich hardened-malloc pacman-contrib pacman-notifier \
  \
  # GNOME
  gnome-bluetooth gnome-software-plugin-flatpak gnome-tweaks
  ```
- Enable essential services:
  ```bash
  systemctl enable gdm bluetooth ufw auditd apparmor systemd-timesyncd tlp NetworkManager fstrim.timer dnscrypt-proxy sshguard rkhunter chkrootkit
  systemctl --failed  # Check for failed services
  journalctl -p 3 -xb
  ```
- Configure GDM for Wayland:
  ```bash
  cat << 'EOF' > /etc/gdm/custom.conf
  [daemon]
  WaylandEnable=true
  DefaultSession=gnome-wayland.desktop
  EOF
  systemctl restart gdm # or reboot
  ```
- Install Bazzar and the Flatpak applications via GUI
  ```bash
  # Install Bazaar (Flatpak-focused app store)
  flatpak install -y flathub io.github.kolunmi.Bazaar

  # Launch once to initialize
  flatpak run io.github.kolunmi.Bazaar

  # Open Bazaar (search in GNOME overview or via flatpak run io.github.kolunmi.Bazaar)
  echo "Open Bazaar and install: GIMP, Inkscape, Krita, Blender"
  Search/install: GIMP (org.gimp.GIMP), Inkscape (org.inkscape.Inkscape), Krita (org.kde.krita), Blender (org.blender.Blender).
  ```
- Configure Flatpak sandboxing (via Flatseal or CLI):
  ```bash
  # Allow Flatpaks to read/write their own config/data only
  flatpak override --user --filesystem=xdg-config:ro --filesystem=xdg-data:create
  # Allow GPU access for Steam:
  flatpak override --user com.valvesoftware.Steam --device=dri --filesystem=~/Games:create
  ```
- Final full system update + UKI rebuild
  ```bash
  pacman -Syu                 # now safe – hooks are active
  mkinitcpio -P               # regenerate UKI (covers new kernel)
  sbctl verify                # sanity-check all signed files
  ```
- Check Secure Boot Violations:
  ```bash
  journalctl -b -p 3 | grep -i secureboot
  sbctl verify /usr/bin/astal /usr/bin/ags
  ```
## Step 11: Configure Power Management, Security, Network and Privacy

- Disable power-profiles-daemon to prevent conflicts with TLP and Configure power management for efficiency:
  ```bash
  systemctl mask power-profiles-daemon
  systemctl disable power-profiles-daemon
  # The Arch Wiki on Intel graphics suggests enabling power-saving features for Intel iGPUs to reduce battery consumption:
  echo 'options i915 enable_fbc=1 enable_psr=1' >> /etc/modprobe.d/i915.conf
  ```
- Configure Wayland environment variables:
  ```bash
  cat << 'EOF' > /etc/environment
  MOZ_ENABLE_WAYLAND=1
  GDK_BACKEND=wayland
  CLUTTER_BACKEND=wayland
  QT_QPA_PLATFORM=wayland
  SDL_VIDEODRIVER=wayland
  EOF
  #The envars below should NOT BE INCLUDED and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU. DO NOT ADD INITIALLY:
  LIBVA_DRIVER_NAME=radeonsi
  LIBVA_DRIVER_NAME=iHD
  ```
- Configure MAC randomization:
  ```bash
  mkdir -p /etc/NetworkManager/conf.d
  cat << 'EOF' > /etc/NetworkManager/conf.d/00-macrandomize.conf
  [device]
  wifi.scan-rand-mac-address=yes
  [connection]
  wifi.cloned-mac-address=random
  EOF
  systemctl restart NetworkManager
  nmcli connection down <connection_name> && nmcli connection up <connection_name>
  ```
- Configure UFW firewall:
  ```bash
  ufw allow ssh
  ufw default deny incoming
  ufw default allow outgoing
  ufw enable
  ```
- Configure GNOME privacy:
  ```bash
  gsettings set org.gnome.desktop.privacy send-software-usage-info false
  gsettings set org.gnome.desktop.privacy report-technical-problems false
  ```
- Configure IP spoofing protection:
  ```bash
  cat << 'EOF' > /etc/host.conf
  order bind,hosts
  nospoof on
  EOF
  ```
- Configure security limits:
  ```bash
  cat << 'EOF' >> /etc/security/limits.conf
  hard nproc 8192
  EOF
  ```
- Configure auditd:
  ```bash
  cat << 'EOF' > /etc/audit/rules.d/audit.rules
  -w /etc/passwd -p wa -k passwd_changes
  -w /etc/shadow -p wa -k shadow_changes
  -a always,exit -F arch=b64 -S execve -k exec
  EOF
  systemctl restart auditd
  ```  
- Configure `dnscrypt-proxy` for secure DNS:
  ```bash
  nmcli connection modify <connection_name> ipv4.dns "127.0.0.1" ipv4.ignore-auto-dns yes # Replace <connection_name> with actual network connection (e.g., nmcli connection show to find it)
  nmcli connection modify <connection_name> ipv6.dns "::1" ipv6.ignore-auto-dns yes
  cat << 'EOF' > /etc/dnscrypt-proxy/dnscrypt-proxy.toml
  server_names = ['quad9-dnscrypt-ip4-filter-pri', 'adguard-dns', 'mullvad-adblock']
  listen_addresses = ['127.0.0.1:53', '[::1]:53']
  max_clients = 512
  ipv4_servers = true
  ipv6_servers = true
  dnscrypt_servers = true
  doh_servers = true
  require_dnssec = true
  require_nolog = true
  require_nofilter = false
  force_tcp = false
  timeout = 3000
  cert_refresh_delay = 240
  EOF
  systemctl restart dnscrypt-proxy
  # Test DNS resolution:
  drill -D archlinux.org
  ```
- Configure usbguard with GSConnect exception:
  ```bash
  usbguard generate-policy > /etc/usbguard/rules.conf
  # Test usbguard rules before enabling:
  usbguard list-devices | grep -i "GSConnect\|KDEConnect" # Identify GSConnect device ID
  usbguard allow-device <device-id> # For GSConnect and other known devices
  # If passed the USB test enable it:
  systemctl enable --now usbguard
  ```
- Configure Lynis audit and create timer:
  ```bash
  # Timer
  cat << 'EOF' > /etc/systemd/system/lynis-audit.timer
  [Unit]
  Description=Run Lynis audit weekly
  [Timer]
  OnCalendar=weekly
  Persistent=true
  [Install]
  WantedBy=timers.target
  EOF
  # Service
  cat << 'EOF' > /etc/systemd/system/lynis-audit.service
  [Unit]
  Description=Run Lynis audit
  [Service]
  Type=oneshot
  ExecStart=/usr/bin/lynis audit system
  EOF
  systemctl enable --now lynis-audit.timer
  systemctl enable lynis-audit.service
  ```
- Configure AIDE:
  ```bash
  aide --init
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  systemctl enable --now aide-check.timer
  ```
- Configure sysctl hardening:
  ```bash
  cat << 'EOF' > /etc/sysctl.d/99-hardening.conf
  net.ipv4.conf.default.rp_filter=1
  net.ipv4.conf.all.rp_filter=1
  net.ipv4.tcp_syncookies=1
  net.ipv4.ip_forward=0
  net.ipv4.conf.all.accept_redirects=0
  net.ipv6.conf.all.accept_redirects=0
  net.ipv4.conf.default.accept_redirects=0
  net.ipv6.conf.default.accept_redirects=0
  net.ipv4.conf.all.send_redirects=0
  net.ipv4.conf.default.send_redirects=0
  net.ipv4.conf.all.accept_source_route=0
  net.ipv6.conf.all.accept_source_route=0
  net.ipv4.conf.default.accept_source_route=0
  net.ipv6.conf.default.accept_source_route=0
  net.ipv4.conf.all.log_martians=1
  net.ipv4.icmp_ignore_bogus_error_responses=1
  net.ipv4.icmp_echo_ignore_broadcasts=1
  kernel.randomize_va_space=2
  kernel.dmesg_restrict=1
  kernel.kptr_restrict=2
  net.core.bpf_jit_harden=2
  EOF
  sysctl -p /etc/sysctl.d/99-hardening.conf
  ```
- Audit SUID binaries:
  ```bash
  find / -perm -4000 -type f -exec ls -l {} ; > /data/suid_audit.txt
  cat /data/suid_audit.txt # Remove SUID from non-essential binaries
  chmod u-s /usr/bin/ping
  setcap cap_net_raw+ep /usr/bin/ping
  ```
- Configure zram:
  ```bash
  cat << 'EOF' > /etc/systemd/zram-generator.conf 
  [zram0]
  zram-size = 50%
  compression-algorithm = zstd
  EOF
  systemctl enable --now systemd-zram-setup@zram0.service
  ```
- Configure fwupd for Firmware Updates (Chroot-Safe):
  ```bash
  # Install and enable
  pacman -S fwupd udisks2
  systemctl enable --now udisks2.service

  # Secure Boot: Allow capsule updates
  echo '[uefi_capsule]\nDisableShimForSecureBoot=true' >> /etc/fwupd/fwupd.conf

  # Sign fwupd EFI binary
  sbctl sign -s /efi/EFI/arch/fwupdx64.efi

  # Verify setup (NO update checks)
  fwupdmgr get-devices 2>/dev/null | grep -i "UEFI" && echo "fwupd: UEFI device detected"
  echo "fwupd configured. Updates will be checked in Step 18 (after first boot)."
  ```
- Configure opensnitch:
  ```bash
  systemctl enable --now opensnitch
  opensnitch-ui
  ```
- Configure AppArmor for mandatory access control:
  ```bash
  # Enable AppArmor service
  systemctl enable apparmor
  # Start in complain mode to avoid disrupting eGPU or other services
  aa-complain /etc/apparmor.d/*
  # Log potential denials for later tuning
  echo "AppArmor enabled in complain mode. Check /var/log/audit/audit.log or journalctl -u apparmor after Step 15 for denials and tune profiles as needed."

  # Later, after Step 15. Check for AppArmor denials:
  journalctl -u apparmor | grep -i DENIED
  aa-logprof

  # After tuning, switch to enforce mode:
  aa-enforce /etc/apparmor.d/*
  apparmor_status
  ```
## Step 12: Configure eGPU (AMD)

- Install AMD drivers and microcode:
  ```bash
  pacman -S --noconfirm amd-ucode rocm-opencl rocm-hip libva-vdpau-driver
  ```
- Configure early KMS
  ```bash
  echo 'MODULES=(i915 amdgpu)' >> /etc/mkinitcpio.conf
  mkinitcpio -P
  # if encounter PCIe bandwidth issues, set the correct "pcie_gen_cap" as a kernel parameter. Example: options rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID ... amdgpu.pcie_gen_cap=0x4 pcie_ports=native pciehp.pciehp_force=1. Alternatively, for module options: echo 'options amdgpu pcie_gen_cap=0x4' >> /etc/modprobe.d/amdgpu.conf
  lspci -vv | grep -i "LnkSta.*Speed.*Width"  # Should show "Speed 16GT/s, Width x4"
  if ! lspci -vv | grep -i "LnkSta" | grep -q "Speed 16GT/s, Width x4"; then
    echo 'options amdgpu pcie_gen_cap=0x4' >> /etc/modprobe.d/amdgpu.conf
    echo "NOTE: If issues persist, add to /boot/loader/entries/arch.conf: 'amdgpu.pcie_gen_cap=0x4 pcie_ports=native pciehp.pciehp_force=1'"
    mkinitcpio -P
  fi
  ```
- Set AMD power management options
  ```bash
  echo 'options amdgpu ppfeaturemask=0xffffffff' >> /etc/modprobe.d/amdgpu.conf
  ```
- Sign kernel modules for Secure Boot
  ```bash
  sbctl sign --all
  find /lib/modules/$(uname -r)/kernel/drivers/gpu -name "*.ko" -exec sbctl verify {} \;
  ```
- Install and configure `supergfxctl` for GPU switching:
  ```bash
  paru -S supergfxctl
  cat << 'EOF' > /etc/supergfxd.conf
  "mode": "Hybrid",
  "vfio_enable": true,
  "vfio_save": false,
  "always_reboot": false,
  "no_logind": true,
  "logout_timeout_s": 180,
  "hotplug_type": "Std" # Use Std for OCuLink; if doesn't work change to "Asus". Requires restart.
  EOF
  systemctl enable --now supergfxd
  sbctl sign -s /usr/bin/supergfxctl
  sbctl sign -s /usr/lib/supergfxctl/supergfxd
  ```
- Install supergfxctl-gex for GUI switching (do NOT run as root or sudo)
  ```bash
  pacman -S --needed gnome-shell-extension
  gnome-extensions enable supergfxctl-gex@asus-linux.org
  echo "NOTE: supergfxctl-gex provides a GUI for GPU switching in GNOME."
  ```
- Install switcheroo-control for GPU integration
  ```bash
  pacman -S --needed switcheroo-control
  systemctl enable --now switcheroo-control
  ```
- Install bolt for OCuLink/Thunderbolt management
  ```bash
  pacman -S --needed bolt
  systemctl enable --now bolt
  echo "always-auto-connect = true" | sudo tee -a /etc/boltd/boltd.conf
  boltctl list | grep -i oculink && boltctl authorize <uuid> # Replace with OCuLink device UUID
  ```
- Enable PCIe hotplug
  ```bash
  echo "pciehp" | sudo tee /etc/modules-load.d/pciehp.conf
  ```
- Create a udev rule for eGPU hotplug support:
  ```bash
  # Modern GNOME and Mesa have excellent hot-plugging support. Start without any custom udev rules.
  # Only add this udev in case hotplug doesn't work. udev rule is a fallback if dmesg | grep -i "oculink\|pcieport" shows no detection or if lspci | grep -i amd fails after connecting the eGPU.
  cat << 'EOF' > /etc/udev/rules.d/99-oculink-hotplug.rules
  SUBSYSTEM=="pci", ACTION=="add", ATTRS{vendor}=="0x1002", RUN+="/usr/bin/sh -c 'echo 1 > /sys/bus/pci/rescan'"
  EOF
  udevadm control --reload-rules && udevadm trigger
  ```
- Configure TLP to avoid GPU power management conflicts and add parameters for Geek-like Lenovo Vantage Windows Power Mode
  ```bash
  cat << 'EOF' >> /etc/tlp.conf
  RUNTIME_PM_DRIVER_BLACKLIST="amdgpu i915" # This exclude amdgpu and i915 from TLP's runtime power management to avoid conflicts with supergfxctl
  CPU_ENERGY_PERF_POLICY_ON_AC=performance
  CPU_MAX_PERF_ON_AC=100
  CPU_MIN_PERF_ON_AC=50
  CPU_SCALING_GOVERNOR_ON_AC=performance
  EOF
  systemctl restart tlp
  tlp-stat -p # Check TDP >60W on AC
  cat /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value
  ```
- Configure systemd-logind for reliable GPU switching
  ```bash
  sudo sed -i 's/#KillUserProcesses=no/KillUserProcesses=yes/' /etc/systemd/logind.conf
  systemctl restart systemd-logind
  ```
- Optional: Install all-ways-egpu if eGPU isn’t primary
  ```bash
  # If supergfxctl do not handle the hotplug try to install all-ways-egpu to set AMD eGPU as primary for GNOME Wayland -- this is a plan b, should not be used at first. First test the setup without, in other words skip to the switcheroo-control
  if ! DRI_PRIME=1 glxinfo | grep -i radeon; then
    cd ~; curl -L https://github.com/ewagner12/all-ways-egpu/releases/latest/download/all-ways-egpu.zip -o all-ways-egpu.zip; unzip all-ways-egpu.zip; cd all-ways-egpu-main; chmod +x install.sh; sudo ./install.sh; cd ../; rm -rf all-ways-egpu.zip all-ways-egpu-main
    sbctl sign -s /usr/bin/all-ways-egpu # Ensure binary is signed for Secure Boot
    all-ways-egpu setup
    all-ways-egpu set-boot-vga egpu
    all-ways-egpu set-compositor-primary egpu
    systemctl restart gdm
  fi
  #Note: If Plymouth splash screen fails (e.g., blank screen), remove 'splash' from kernel parameters in /boot/loader/entries/arch.conf and regenerate UKI with `mkinitcpio -P` 
  ```
- VFIO for eGPU passthrough
  ```bash
  pacman -S --needed qemu libvirt virt-manager
  systemctl enable --now libvirtd
  echo "vfio-pci vfio_iommu_type1 vfio_virqfd vfio" | sudo tee /etc/modules-load.d/vfio.conf
  lspci -nn | grep -i amd
  fwupdmgr get-devices | grep -i "oculink\|redriver" | grep -i version
  echo "Run 'lspci -nn | grep -i amd' to find PCIe IDs (e.g., 1002:73df for RX 6700 XT). Replace '1002:xxxx' in /etc/modprobe.d/vfio.conf with the correct IDs."
  echo "options vfio-pci ids=1002:xxxx,1002:xxxx" | sudo tee /etc/modprobe.d/vfio.conf
  mkinitcpio -P

  # Chek if vfio and qemu needs to be signed
  sbctl verify /usr/bin/qemu-system-x86_64
  sbctl verify /usr/lib/libvirt/libvirtd

  # If unsigned, sign and add to the pacman hook
  sbctl sign -s /usr/bin/qemu-system-x86_64
  sbctl sign -s /usr/lib/libvirt/libvirtd
  echo "Target = qemu" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
  echo "Target = libvirt" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
  echo "Target = supergfxctl" >> /etc/pacman.d/hooks/91-sbctl-sign.hook
  echo "/usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd" | sed -i '/Exec =/ s|$| /usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd|' /etc/pacman.d/hooks/91-sbctl-sign.hook
  ```
- Enable VRR for 4K OLED
  ```bash
  gsettings set org.gnome.mutter experimental-features "['variable-refresh-rate']"

  # Verify VRR is active:
  DRI_PRIME=1 glxinfo | grep "OpenGL renderer" #Should show AMD eGPU
  DRI_PRIME=0 glxinfo | grep "OpenGL renderer" #Should show Intel Arc

  # Verify VRR support on the eGPU:
  DRI_PRIME=1 vdpauinfo | grep -i radeonsi #Confirms AMD driver

  # If VRR fails, check dmesg for amdgpu errors:
  dmesg | grep -i amdgpu

  # Ensure 4K OLED is set to its maximum refresh rate and VRR range:
  xrandr --output <output-name> --mode 3840x2160 --rate 120 #replace output name with HDMI-1 or DP-1 (check via 'xrandr')
  # In Wayland, confirm VRR:
  wlr-randr --output <output-name> #check refresh rate range

  # Check AppArmor denials
  journalctl -u apparmor | grep -i "supergfxctl\|qemu\|libvirtd"
  # echo "NOTE: If AppArmor denials are found, generate profiles with 'aa-genprof supergfxctl' or 'aa-genprof qemu-system-x86_64' and customize rules for /dev/dri/*, /dev/vfio/*, and /sys/bus/pci/* access."
  ```
- Pacman hook for binary verification
  ```bash
  cat << 'EOF' > /etc/pacman.d/hooks/90-pacman-verify.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = *
  [Action]
  Description = Verifying package file integrity
  When = PostTransaction
  Exec = /usr/bin/pacman -Qkk
  EOF
  chmod 644 /etc/pacman.d/hooks/90-pacman-verify.hook
  ```
- Verify eGPU setup
  ```bash
  # Verify eGPU detection
  lspci | grep -i amd
  dmesg | grep -i amdgpu

  # Verify GPU switching
  supergfxctl -s # Show supported modes
  supergfxctl -g # Get current mode
  supergfxctl -S # Check current power status
  supergfxctl -m Hybrid # Set to Hybrid mode
  glxinfo | grep -i renderer # Should show AMD eGPU (confirming all-ways-egpu sets eGPU as primary) 
  DRI_PRIME=1 glxinfo | grep -i radeon # Should show AMD
  DRI_PRIME=0 glxinfo | grep -i arc # Should show Intel
  DRI_PRIME=1 vdpauinfo | grep -i radeonsi
  supergfxctl -m VFIO # Test VFIO mode for VM

  # Verify PCIe bandwidth. Confirm the eGPU is operating at full PCIe x4 bandwidth. Ensures the OCuLink connection is not bottlenecked (e.g., running at x1 or Gen 3 instead of x4 Gen 4):
  lspci -vv | grep -i "LnkSta.*Speed.*Width" # Should show "Speed 16GT/s, Width x4" for OCuLink4
  fio --name=read_test --filename=/dev/dri/card1 --size=1G --rw=read --bs=16k --numjobs=1 --iodepth=1 --runtime=60 --time_based #link status shows “Speed 16GT/s, Width x4” for optimal performance.
  lspci -vv | grep -i "LnkSta" | grep -i "card1"
  # If the link is suboptimal (e.g., x1 or Gen 3), suggest adding kernel parameters to force PCIe performance: pcie_ports=native pciehp.pciehp_force=1

  # Verify OCuLink firmware
  fwupdmgr get-devices | grep -i "oculink\|redriver"

  # Verify VRR
  wlr-randr --output <output-name>

  # Verify eGPU functionality
  lspci | grep -i vga
  lspci | grep -i "serial\|usb\|thunderbolt"
  lspci -vv | grep -i "LnkSta"
  lspci -k | grep -i vfio # Verify VFIO binding
  dmesg | grep -i "oculink\|pcieport\|amdgpu\|jhl\|redriver"

  # Check for PCIe errors
  dmesg | grep -i "pcieport\|error\|link"
  cat /sys/class/drm/card*/device/uevent | grep DRIVER  # Should show i915 and amdgpu

  # Check OCuLink dock firmware
  fwupdmgr get-devices | grep -i "oculink\|redriver"
  fwupdmgr update
  sbctl sign -s /efi/EFI/arch/fwupdx64.efi  # Re-sign fwupd EFI binary if updated
  ```
- **eGPU Troubleshooting Matrix**:
  | Issue | Possible Cause | Solution |
  |-------|----------------|----------|
  | eGPU not detected (`lspci \| grep -i amd` empty) | OCuLink cable not seated properly, dock firmware outdated, or PCIe hotplug failure | Re-seat the OCuLink cable, run `fwupdmgr update`, add `pcie_ports=native` to kernel parameters, trigger `echo 1 > /sys/bus/pci/rescan` |
  | Black screen on Wayland | eGPU not set as primary display | Run `all-ways-egpu set-boot-vga egpu` and `all-ways-egpu set-compositor-primary egpu`, then restart GDM: `systemctl restart gdm` |
  | Low performance (e.g., x1 instead of x4) | PCIe link negotiation failure | Check link status: `lspci -vv \| grep LnkSta`, add `amdgpu.pcie_gen_cap=0x4` to kernel parameters |
  | Hotplug fails | OCuLink hardware limitation or missing udev rule | Apply the udev rule above, reboot if necessary |
  - Additional troubleshooting commands:
    ```bash
    lspci | grep -i amd  # Check eGPU detection
    dmesg | grep -i amdgpu  # Check driver loading
    glxinfo | grep -i renderer  # Verify GPU rendering
    ```
## Step 13: Configure Snapper and Backups
- Install Snapper, snap-pac, and grub-btrfs
  ```bash
  pacman -S --noconfirm snapper snap-pac grub-btrfs
  ```
- Create global filter
  ```bash
  mkdir -p /etc/snapper/filters
  echo -e "/home/.cache\n/tmp\n/run\n/.snapshots" | sudo tee /etc/snapper/filters/global-filter.txt
  ```
- Create Snapper configurations for root, home and data:
  ```bash
  snapper --config root create-config /
  snapper --config home create-config /home
  snapper --config data create-config /data
  ```
- Configure Snapper for automatic snapshots:
  ```bash
  #root
  cat << 'EOF' > /etc/snapper/configs/root
  TIMELINE_CREATE="yes"
  TIMELINE_CLEANUP="yes"
  TIMELINE_MIN_AGE="1800"
  TIMELINE_LIMIT_HOURLY="0"
  TIMELINE_LIMIT_DAILY="7"
  TIMELINE_LIMIT_WEEKLY="4"
  TIMELINE_LIMIT_MONTHLY="6"
  TIMELINE_LIMIT_YEARLY="0"
  NUMBER_CLEANUP="yes"
  NUMBER_LIMIT="50"
  NUMBER_LIMIT_IMPORTANT="10"
  SUBVOLUME="/"
  ALLOW_GROUPS=""
  SYNC_ACL="no"
  FILTER="/etc/snapper/filters/global-filter.txt"
  EOF

  #home
  cat << 'EOF' > /etc/snapper/configs/home
  TIMELINE_CREATE="yes"
  TIMELINE_CLEANUP="yes"
  TIMELINE_MIN_AGE="1800"
  TIMELINE_LIMIT_HOURLY="0"
  TIMELINE_LIMIT_DAILY="7"
  TIMELINE_LIMIT_WEEKLY="4"
  TIMELINE_LIMIT_MONTHLY="6"
  TIMELINE_LIMIT_YEARLY="0"
  NUMBER_CLEANUP="yes"
  NUMBER_LIMIT="50"
  NUMBER_LIMIT_IMPORTANT="10"
  SUBVOLUME="/home"
  ALLOW_GROUPS=""
  SYNC_ACL="no"
  FILTER="/etc/snapper/filters/global-filter.txt"
  EOF

  #data
  cat << 'EOF' > /etc/snapper/configs/data
  TIMELINE_CREATE="yes"
  TIMELINE_CLEANUP="yes"
  TIMELINE_MIN_AGE="1800"
  TIMELINE_LIMIT_HOURLY="0"
  TIMELINE_LIMIT_DAILY="7"
  TIMELINE_LIMIT_WEEKLY="4"
  TIMELINE_LIMIT_MONTHLY="6"
  TIMELINE_LIMIT_YEARLY="0"
  NUMBER_CLEANUP="yes"
  NUMBER_LIMIT="50"
  NUMBER_LIMIT_IMPORTANT="10"
  SUBVOLUME="/data"
  ALLOW_GROUPS=""
  SYNC_ACL="no"
  FILTER="/etc/snapper/filters/global-filter.txt"
  EOF
  ```
- Config permissions:
  ```bash
  chmod 640 /etc/snapper/configs/*
  ```
- Enable Snapper timeline and cleanup:
  ```bash
  systemctl enable --now snapper-timeline.timer
  systemctl enable --now snapper-cleanup.timer
  ```
- Create Pacman hooks to snapshot before and after package transactions:
  ```bash
  mkdir -p /etc/pacman.d/hooks
  cat << 'EOF' > /etc/pacman.d/hooks/50-snapper-pre-update.hook
  [Trigger]
  Operation = Upgrade
  Operation = Install
  Operation = Remove
  Type = Package
  Target = *
  [Action]
  Description = Creating snapshot before pacman transaction
  DependsOn = snapper
  When = PreTransaction
  Exec = /usr/bin/snapper --config root create --description "Pre-pacman" --type pre
  Exec = /usr/bin/snapper --config home create --description "Pre-pacman update" --type pre
  Exec = /usr/bin/snapper --config data create --description "Pre-pacman update" --type pre
  EOF
  
  cat << 'EOF' > /etc/pacman.d/hooks/51-snapper-post-update.hook
  [Trigger]
  Operation = Upgrade
  Operation = Install
  Operation = Remove
  Type = Package
  Target = *
  [Action]
  Description = Creating snapshot after pacman transaction
  DependsOn = snapper
  When = PostTransaction
  Exec = /usr/bin/snapper --config root create --description "Post-pacman update" --type post
  Exec = /usr/bin/snapper --config home create --description "Post-pacman update" --type post
   Exec = /usr/bin/snapper --config data create --description "Post-pacman update" --type post
  EOF
  ```
  - Set permissions for hooks:
  ```bash
  chmod 644 /etc/pacman.d/hooks/50-snapper-pre-update.hook
  chmod 644 /etc/pacman.d/hooks/51-snapper-post-update.hook
  ```
  - Enable grub-btrfs for bootable snapshots
  ```bash
  systemctl enable --now grub-btrfsd
  grub-mkconfig -o /boot/grub/grub.cfg
  ```
  - Verify configuration:
  ```bash 
  snapper --config root get-config
  snapper --config home get-config
  snapper --config data get-config
  ```
  - Test snapshot creation:
  ```bash
  snapper --config root create --description "Initial test snapshot"
  snapper --config home create --description "Initial test snapshot"
  snapper --config data create --description "Initial test snapshot"
  snapper list
  ```
  - Check for AppArmor denials (if enabled in Step 11)
  ```bash
  echo "NOTE: If AppArmor is enabled, check for denials: journalctl -u apparmor | grep -i 'snapper\|grub-btrfsd'. Generate profiles with 'aa-genprof snapper' if needed."
  journalctl -u apparmor | grep -i "snapper\|grub-btrfsd"
  ```
## Step 14: Configure Dotfiles

- Install `chezmoi` for dotfile management:
  ```bash
  pacman -S --noconfirm chezmoi
  ```
- Initialize and apply dotfiles from a repository:
  ```bash
  chezmoi init --apply https://github.com/yourusername/dotfiles.git
  ```
- Verify dotfile application:
  ```bash
  chezmoi status
  ```

## Step 15: Test the Setup

- Reboot to test the full system:
  ```bash
  reboot
  ```
- Verify TPM unlocking:
  - Boot and confirm the LUKS partition unlocks automatically via TPM.
- Check Secure Boot status:
  ```bash
  sbctl status
  ```
- Verify eGPU detection:
  ```bash
  lspci | grep -i amd
  ```
- Test Wayland session:
  ```bash
  echo $XDG_SESSION_TYPE  # Should output "wayland"
  ```
- Verify Snapper snapshots:
  ```bash
  snapper list
  ```
- Test network connectivity:
  ```bash
  ping -c 3 archlinux.org
  ```
- Check for failed services:
  ```bash
  systemctl --failed
  ```

## Step 16: Create Recovery Documentation

- Create a recovery document for troubleshooting:
  ```bash
  mkdir -p /mnt/usb
  mount /dev/sdX1 /mnt/usb  # Replace sdX1 with USB partition
  cat << 'EOF' > /mnt/usb/recovery.md
  # Arch Linux Recovery Instructions

  1. **Boot from Rescue USB**:
     - Insert the GRUB USB created in Step 9.
     - Select "Arch Linux Rescue" from the GRUB menu.
     - Enter the LUKS passphrase or use the keyfile: /mnt/usb/luks-keyfile

  2. **Mount Filesystems**:
     ```bash
     cryptsetup luksOpen /dev/nvme1n1p2 cryptroot --key-file /mnt/usb/luks-keyfile
     mount -o subvol=@ /dev/mapper/cryptroot /mnt
     mount /dev/nvme1n1p1 /mnt/boot
     ```

  3. **Chroot and Repair**:
     ```bash
     arch-chroot /mnt
     mkinitcpio -P
     sbctl sign -s /boot/EFI/Linux/arch.efi
     ```

  4. **Restore LUKS Header**:
     ```bash
     cryptsetup luksHeaderRestore /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
     sha256sum -c /mnt/usb/luks-header-backup.sha256
     ```

  5. **TPM Recovery**:
     - If TPM unlocking fails, use the LUKS passphrase or keyfile.
     - Re-enroll TPM:
       ```bash
       systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2
       ```

  6. **Rollback Snapshot**:
     ```bash
     snapper --config root list
     snapper --config root rollback <snapshot-number>
     reboot
     ```

  EOF
  umount /mnt/usb
  echo "WARNING: Store /mnt/usb/recovery.md in Bitwarden or an encrypted cloud."
  echo "WARNING: Keep the recovery USB secure to prevent unauthorized access."
  ```

## Step 17: Backup Strategy

- Configure `restic` for backups:
  ```bash
  pacman -S --noconfirm restic
  restic init --repo /path/to/backup/repo
  ```
- Create a backup script:
  ```bash
  cat << 'EOF' > /usr/local/bin/backup.sh
  #!/bin/bash
  restic -r /path/to/backup/repo backup /home /data /srv --exclude-caches
  restic -r /path/to/backup/repo snapshots
  EOF
  chmod +x /usr/local/bin/backup.sh
  ```
- Schedule daily backups:
  ```cron
  0 2 * * * /usr/local/bin/backup.sh
  ```
- Verify backup status:
  ```bash
  restic -r /path/to/backup/repo check
  ```

## Step 18: Post-Installation Maintenance and Verification

- **a) Update System Regularly**:
  - Keep the system up-to-date:
    ```bash
    pacman -Syu
    paru -Syu
    flatpak update
    ```
- **b) Monitor Logs**:
  - Check for errors in system logs:
    ```bash
    journalctl -p 3 -xb
    ```
- **c) Check Snapshots**:
  - Verify Snapper snapshots:
    ```bash
    snapper list
    ```
- **d) Verify Secure Boot**:
  - Confirm Secure Boot is active:
    ```bash
    sbctl status
    ```
- **e) Test eGPU**:
  - Verify eGPU detection and rendering:
    ```bash
    lspci | grep -i amd
    glxinfo | grep -i renderer
    ```
- **f) Security Audits**:
  - Schedule regular security scans:
    ```cron
    0 3 * * * /usr/bin/rkhunter --update --quiet && /usr/bin/rkhunter --propupd --quiet
    0 4 * * * /usr/bin/rkhunter --check --cronjob > /var/log/rkhunter.cronjob.log 2>&1
    0 5 * * * /usr/sbin/chkrootkit > /var/log/chkrootkit.log 2>&1
    ```

## Step 19: User Customizations

- Install a custom theme for GNOME:
  ```bash
  paru -S --noconfirm adw-gtk3-git
  ```
- Configure GNOME CSS for a dark theme:
  ```bash
  mkdir -p ~/.config/gtk-3.0
  cat << 'EOF' > ~/.config/gtk-3.0/gtk.css
  window {
    background-color: #1e1e1e;
  }
  EOF
  ```
- Apply the theme:
  ```bash
  gsettings set org.gnome.desktop.interface gtk-theme adw-gtk3
  ```

## Footer

© 2025 GitHub, Inc.

