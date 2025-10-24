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
    - For a swap file on a BTRFS subvolume, compute the physical offset for the `resume_offset` kernel parameter:
      ```bash
      SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
      echo $SWAP_OFFSET  # Should output a numerical offset like 12345678
      ```
      - **Record this SWAP_OFFSET** for kernel parameters and `/etc/fstab`.
      - **Note**: This offset is critical for hibernation support and must be accurate.
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
    mount /dev/sdX1 /mnt/usb
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
      # UUID=$ROOT_UUID / btrfs subvol=@,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      # UUID=$ROOT_UUID /home btrfs subvol=@home,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      # UUID=$ROOT_UUID /data btrfs subvol=@data,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      # UUID=$ROOT_UUID /var btrfs subvol=@var,nodatacow,noatime 0 0
      # UUID=$ROOT_UUID /var/lib btrfs subvol=@var_lib,nodatacow,noatime 0 0
      # UUID=$ROOT_UUID /var/log btrfs subvol=@log,nodatacow,noatime 0 0
      # UUID=$ROOT_UUID /srv btrfs subvol=@srv,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      # UUID=$ROOT_UUID /swap btrfs subvol=@swap,nodatacow,noatime 0 0
      # UUID=$ROOT_UUID /.snapshots btrfs subvol=@snapshots,ssd,noatime 0 0
      ```
  - **Edit ESP (/boot) Entry**:
    - Add `umask=0077` for security:
      ```bash
      # UUID=$ARCH_ESP_UUID /boot vfat umask=0077 0 2
      ```
  - **Edit Windows ESP Entry**:
    - Use `noauto` and `x-systemd.automount` for manual mounting:
      ```bash
      # UUID=$WINDOWS_ESP_UUID /windows-efi vfat noauto,x-systemd.automount,umask=0077 0 2
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
      # /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0
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
    base \
    base-devel \
    linux \
    linux-firmware \
    mkinitcpio \
    intel-ucode \
    zsh \
    btrfs-progs \
    sudo \
    cryptsetup \
    dosfstools \
    efibootmgr \
    networkmanager \
    mesa \
    libva-mesa-driver \
    pipewire \
    wireplumber \
    sof-firmware \
    vulkan-intel \
    lib32-vulkan-intel \
    pipewire-pulse \
    pipewire-alsa \
    pipewire-jack \
    archlinux-keyring \
    arch-install-scripts \
    intel-media-driver \
    sbctl \
    git \
    vulkan-radeon \
    lib32-vulkan-radeon \
    reflector \
    udisks2 \
    fwupd \
    openssh \
    rsync \
    pacman-contrib \
    polkit \
    flatpak \
    gdm \
    acpi \
    acpid \
    thermald \
    intel-gpu-tools \
    nvme-cli \
    wireless-regdb \
    ethtool
  ```
- Chroot into the installed system:
  ```bash
  arch-chroot /mnt
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
  systemd-cryptenroll --dump-pcrs /dev/nvme1n1p2 > /mnt/usb/tpm-pcr-initial.txt
  tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-backup.txt
  echo "WARNING: Store /mnt/usb/tpm-pcr-initial.txt in Bitwarden."
  echo "WARNING: Store /mnt/usb/tpm-pcr-backup.txt in Bitwarden."
  echo "WARNING: PCR values are critical for TPM unlocking; back them up securely."
  ```
- Configure `mkinitcpio` for TPM and encryption support:
  ```bash
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems keyboard)/' /etc/mkinitcpio.conf
  echo 'BINARIES=(/usr/bin/btrfs)' >> /etc/mkinitcpio.conf
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
  mkinitcpio -P
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
- Reboot to enroll keys and enable Secure Boot in UEFI:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```
  - In UEFI, enable **Secure Boot** and select the enrolled keys.
- Update TPM PCR policy after enabling Secure Boot:
  ```bash
  arch-chroot /mnt
  systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2
  sbctl status
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
- Create boot entries for dual-boot:
  ```bash
  rsync -aHAX /mnt/windows-efi/EFI/Microsoft /boot/EFI/
  umount /mnt/windows-efi
  cat << 'EOF' > /boot/loader/entries/windows.conf
  title Windows 11
  efi /EFI/Microsoft/Boot/bootmgfw.efi
  EOF
  cat << 'EOF' > /boot/loader/entries/arch.conf
  title Arch Linux
  efi /EFI/Linux/arch.efi
  EOF
  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch.conf
  ```
- Create a fallback UKI:
  ```bash
  cp /etc/mkinitcpio.conf /etc/mkinitcpio-minimal.conf
  sed -i 's/HOOKS=(.*)/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt resume filesystems)/' /etc/mkinitcpio-minimal.conf
  echo 'UKI_OUTPUT_PATH="/boot/EFI/Linux/arch-fallback.efi"' >> /etc/mkinitcpio-minimal.conf
  mkinitcpio -P -c /etc/mkinitcpio-minimal.conf
  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
  cat << 'EOF' > /boot/loader/entries/arch-fallback.conf
  title Arch Linux (Fallback)
  efi /EFI/Linux/arch-fallback.efi
  EOF
  sed -i 's/\/boot\/EFI/\/efi/' /boot/loader/entries/arch-fallback.conf
  ```
- Create a GRUB USB for recovery:
  ```bash
  lsblk  # Identify USB device (e.g., /dev/sdX1)
  mkfs.fat -F32 -n RESCUE_USB /dev/sdX1
  mkdir -p /mnt/usb
  mount /dev/sdX1 /mnt/usb
  pacman -Sy grub
  grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB
  cp /mnt/usb/crypto_keyfile /mnt/usb/luks-keyfile
  chmod 600 /mnt/usb/luks-keyfile
  cp /boot/vmlinuz-linux /mnt/usb/
  cp /boot/initramfs-linux.img /mnt/usb/
  # Replace $LUKS_UUID and $ROOT_UUID with actual values in the menuentry
  cat << 'EOF' > /mnt/usb/boot/grub/grub.cfg
  set timeout=5
  menuentry "Arch Linux Rescue" {
      linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot root=UUID=$ROOT_UUID rw
      initrd /initramfs-linux.img
  }
  EOF
  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  umount /mnt/usb
  echo "WARNING: Store the GRUB USB securely; it contains the LUKS keyfile."
  ```

## Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can pause at this point

## Step 10: Install and Configure DE and Applications

- Update the system to ensure the latest packages:
  ```bash
  pacman -Syu
  ```
- Install the **GNOME desktop environment** and additional applications:
  ```bash
  pacman -S --needed gnome
  paru -S --needed \
    bubblejail \
    alacritty-graphics \
    astal-git \
    ags-git \
    thinklmi
  pacman -S --needed \
    gnome-tweaks \
    gnome-software-plugin-flatpak \
    bluez \
    bluez-utils \
    ufw \
    apparmor \
    tlp \
    cpupower \
    upower \
    systemd-timesyncd \
    zsh \
    sshguard \
    rkhunter \
    chkrootkit \
    lynis \
    usbguard \
    aide \
    pacman-notifier \
    mullvad-browser \
    brave-browser \
    tor-browser \
    bitwarden \
    helix \
    zellij \
    yazi \
    blender \
    krita \
    gimp \
    gcc \
    gdb \
    rustup \
    python-pygobject \
    git \
    vala \
    gjs \
    xdg-ninja \
    libva-vdpau-driver \
    zram-generator \
    ripgrep \
    fd \
    eza \
    gstreamer \
    gst-plugins-good \
    gst-plugins-bad \
    gst-plugins-ugly \
    ffmpeg \
    gst-libav \
    fprintd \
    dnscrypt-proxy \
    systeroid-git \
    rage \
    zoxide \
    jaq \
    atuin \
    gitui \
    glow \
    delta \
    tokei \
    dua \
    tealdeer \
    fzf \
    procs \
    gping \
    dog \
    httpie \
    bottom \
    bandwhich \
    gnome-bluetooth \
    opensnitch \
    baobab \
    gnome-system-monitor \
    hardened-malloc \
    wireguard-tools \
    vulkan-tools \
    libva-utils \
    clinfo \
    mangohud \
    obs-studio \
    inkscape
  ```
- Enable essential services:
  ```bash
  systemctl enable gdm bluetooth ufw auditd apparmor systemd-timesyncd tlp NetworkManager fstrim.timer dnscrypt-proxy sshguard rkhunter chkrootkit
  systemctl --failed  # Check for failed services
  ```
- Configure GDM for Wayland:
  ```bash
  cat << 'EOF' > /etc/gdm/custom.conf
  [daemon]
  WaylandEnable=true
  DefaultSession=gnome-wayland.desktop
  EOF
  ```

## Step 11: Configure Power Management, Security, and Privacy

- Configure power management for efficiency:
  ```bash
  systemctl mask power-profiles-daemon
  echo 'options i915 enable_fbc=1 enable_psr=1' >> /etc/modprobe.d/i915.conf
  ```
- Configure Wayland environment variables:
  ```bash
  cat << 'EOF' > /etc/environment
  MOZ_ENABLE_WAYLAND=1
  GDK_BACKEND=wayland
  CLUTTER_BACKEND=wayland
  QT_QPA_PLATFORM=wayland
  EOF
  ```
- Configure `dnscrypt-proxy` for secure DNS:
  ```bash
  cat << 'EOF' > /etc/dnscrypt-proxy/dnscrypt-proxy.toml
  server_names = ['cloudflare', 'quad9-dnscrypt-filter-pri']
  listen_addresses = ['127.0.0.1:53']
  max_clients = 250
  ipv4_servers = true
  ipv6_servers = false
  dnscrypt_servers = true
  doh_servers = true
  require_dnssec = true
  require_nolog = true
  require_nofilter = false
  force_tcp = false
  timeout = 5000
  cert_refresh_delay = 240
  EOF
  systemctl restart dnscrypt-proxy
  ```
- Configure AppArmor for mandatory access control:
  ```bash
  systemctl enable apparmor
  aa-enforce /etc/apparmor.d/*
  ```
- Configure UFW firewall:
  ```bash
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ssh
  ufw enable
  ```

## Step 12: Configure eGPU (AMD)

- Install AMD drivers and microcode:
  ```bash
  pacman -S --noconfirm \
    amd-ucode \
    rocm-opencl \
    rocm-hip \
    libva-vdpau-driver
  echo 'MODULES=(i915 amdgpu)' >> /etc/mkinitcpio.conf
  mkinitcpio -P
  echo 'options amdgpu ppfeaturemask=0xffffffff' >> /etc/modprobe.d/amdgpu.conf
  ```
- Install and configure `supergfxctl` for GPU switching:
  ```bash
  paru -S supergfxctl-git
  cat << 'EOF' > /etc/supergfxd.conf
  "mode": "Hybrid",
  "vfio_enable": true,
  "vfio_save": false,
  "always_reboot": false,
  "no_logind": true,
  "logout_timeout_s": 180,
  "hotplug_type": "Std"
  EOF
  systemctl enable --now supergfxd
  ```
- Create a udev rule for eGPU hotplug support:
  ```bash
  cat << 'EOF' > /etc/udev/rules.d/99-oculink-hotplug.rules
  SUBSYSTEM=="pci", ACTION=="add", ATTRS{vendor}=="0x1002", RUN+="/usr/bin/sh -c 'echo 1 > /sys/bus/pci/rescan'"
  EOF
  udevadm control --reload-rules && udevadm trigger
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

- Install Snapper for BTRFS snapshots:
  ```bash
  pacman -S --noconfirm \
    snapper \
    snap-pac
  ```
- Create Snapper configurations for root and home:
  ```bash
  snapper -c root --create-config / --type btrfs
  snapper -c home --create-config /home --type btrfs
  ```
- Configure Snapper for automatic snapshots:
  ```bash
  cat << 'EOF' > /etc/snapper/configs/root
  TIMELINE_CREATE="yes"
  TIMELINE_CLEANUP="yes"
  TIMELINE_MIN_AGE="1800"
  TIMELINE_HOURLY="5"
  TIMELINE_DAILY="7"
  TIMELINE_WEEKLY="0"
  TIMELINE_MONTHLY="0"
  TIMELINE_YEARLY="0"
  NUMBER_CLEANUP="yes"
  NUMBER_LIMIT="50"
  NUMBER_LIMIT_IMPORTANT="10"
  EOF
  cp /etc/snapper/configs/root /etc/snapper/configs/home
  ```
- Enable Snapper timeline and cleanup:
  ```bash
  systemctl enable --now snapper-timeline.timer
  systemctl enable --now snapper-cleanup.timer
  ```
- Create Pacman hooks to snapshot before and after package transactions:
  ```bash
  mkdir -p /etc/pacman.d/hooks
  cat << 'EOF' > /etc/pacman.d/hooks/50-bootbackup.hook
  [Trigger]
  Operation = Upgrade
  Operation = Install
  Operation = Remove
  Type = Package
  Target = *
  [Action]
  Description = Creating snapshot before pacman transaction
  Depends = snapper
  When = PreTransaction
  Exec = /usr/bin/snapper --config root --description "pacman" --type pre
  EOF
  cat << 'EOF' > /etc/pacman.d/hooks/50-bootbackup-post.hook
  [Trigger]
  Operation = Upgrade
  Operation = Install
  Operation = Remove
  Type = Package
  Target = *
  [Action]
  Description = Creating snapshot after pacman transaction
  Depends = snapper
  When = PostTransaction
  Exec = /usr/bin/snapper --config root --description "pacman" --type post
  EOF
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

