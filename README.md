# Secure Arch Installation for an Intel Lenovo ThinkBook using an AMD eGPU via OCuLink

## Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)

- This guide provides a **comprehensive action plan** for installing and configuring **Arch Linux** on a **Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H** with **Intel iGPU (Arc 140T)**, no dGPU, using **GNOME Wayland**, **BTRFS**, **LUKS2**, **TPM2**, **AppArmor**, **systemd-boot with Unified Kernel Image (UKI)**, **Secure Boot**, **run0** and an **OCuP4V2 OCuLink GPU Dock ReDriver with an AMD eGPU**.
- The laptop has **two M.2 NVMe slots**; we will install **Windows 11 Pro** on one slot (`/dev/nvme0n1`) for BIOS and firmware updates, and **Arch Linux** on the second slot (`/dev/nvme1n1`).
- **Observation**: The `linux-hardened` kernel is avoided due to complexities with eGPU setup and performance penalties. Instead, we manually incorporate security enhancements inspired by `linux-hardened`, such as kernel parameters for memory safety and mitigations. In the future linux-hardened and hardened-malloc can be explored.
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
- Test the USB by rebooting and selecting it in the **BIOS boot menu** (press `F1`).
- Verify network connectivity in the live environment:
  ```bash
  ping -c 3 archlinux.org
  ```
- If Wi-Fi is needed, configure it:
  ```bash
  ip link
  rfkill
  iwctl device list
  # If the device or its corresponding adapter is turned off, power it on:
  iwctl device <device> set-property Powered on
  iwctl adapter <adapter> set-property Powered on
  # Scan for networks and list the available networks:
  iwctl station <device> scan # command produces no output
  iwctl station <device> get-networks
  # Connect to the desired network:
  iwctl station <device> connect <SSID>
  ping archlinux.org
  ```
- Console Font and Keyboard Setup
  ```bash
  setfont ter-132b; loadkeys us
  # Improves ISO usability
  ```
- Verify the boot mode
  ```bash
  # To verify the boot mode, check the UEFI bitness:
  cat /sys/firmware/efi/fw_platform_size
  # If the system did not boot in the mode you desired (UEFI vs BIOS), refer to your motherboard's manual.
  # Expected: If the command returns 64, the system is booted in UEFI mode and has a 64-bit x64 UEFI.
  ```
- Update the System Clock
  ```bash
  timedatectl
  ```
## Step 4: Pre-Arch Installation Steps

- Boot from the **Arch Live USB**.
- **Pre-computation and Pre-determination of System Identifiers**:
  - **LUKS for rd.luks.uuid and Partition UUID**:
    - After encrypting `/dev/nvme1n1p2` with LUKS, retrieve its UUID:
      ```bash
      LUKS_UUID=$(cryptsetup luksUUID --header /dev/nvme1n1p2)
      echo $LUKS_UUID  # Should output a UUID like a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8
      ```
      - **Record this UUID** for use in `/etc/crypttab` and kernel parameters (`rd.luks.uuid=...`).
    - Get the partition UUID (rarely used):
      ```bash
      PART_UUID=$(blkid -s PARTUUID -o value /dev/nvme1n1p2)
      echo $PART_UUID  # Should output a UUID like 123e4567-e89b-12d3-a456-426614174000
      ```
      - **Record this UUID** for kernel parameters and `/etc/crypttab` mappings.
  - **Root Filesystem UUID**:
    - After creating the BTRFS filesystem on `/dev/mapper/cryptroot`, obtain its UUID:
      ```bash
      ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
      echo $ROOT_UUID  # Should output a UUID like 48d0e960-1b5e-4f2c-8caa-...
      ```
      - **Record this UUID** for the bootloader (`root=UUID=...`) and `/etc/fstab`.
- **a) Partition the Second NVMe M.2 (/dev/nvme1n1)**:
  - Check optimal sector size (should be 512 for most NVMe; 4096 for some)
    ```bash
    cat /sys/block/nvme1n1/queue/logical_block_size  # Expected: 512 or 4096
    cat /sys/block/nvme1n1/queue/physical_block_size
    # Review your partitioning scheme: This creates a 1GiB ESP and full-disk encrypted root. Adjust sizes if needed (e.g., for multi-partition setups).
    ```
  - NVMe Sanitize:
    ```bash
    nvme sanitize /dev/nvme1 --sanact=0x02  # Block erase (quick, no overwrite)
    nvme sanitize-log /dev/nvme1  # Monitor progress
    partprobe  # Reload partition table (clears old Windows remnants)
    ```
  - Create a GPT partition table with an ESP and a LUKS partition:
    ```bash
    fdisk /dev/nvme1n1
    # # At fdisk: g, n (1, +1G), t (1, EF), n (2, default), t (2, 83), p, w
    g (create new GPT partition table)
    n (new partition), 1 (partition number), default first sector, +1G (size for ESP)
    t (change type), 1 (partition), EF (EFI System)
    n (new partition), 2 (partition number), default first sector, default last sector (use remainder)
    t (change type), 2 (partition), 83 (Linux filesystem—default, but confirm)
    p (print table to verify)
    w (write changes and exit)
    fdisk -l /dev/nvme1n1
    ```
  - Verify partitions:
    ```bash
    lsblk -f /dev/nvme0n1 /dev/nvme1n1  # Confirm /dev/nvme0n1p1 (Windows ESP) and /dev/nvme1n1p1 (Arch ESP)
    fdisk -l # This should list the partitions in case the command above didn't return any outputs
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
    # (REPLACED) cryptsetup luksFormat --type luks2 /dev/nvme1n1p2 --pbkdf pbkdf2 --pbkdf-force-iterations 500000 *GRUB not supporting argon2id only applies if GRUB itself is unlocking the drive (e.g., to read an encrypted /boot partition, which you don't have).
    cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --hash sha512 --iter-time 5000 --key-size 512 --pbkdf argon2id --sector-size 4096 /dev/nvme1n1p2
    ```
  - Open the LUKS partition:
    ```bash
    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot
    ```
  - (OPTIONAL) Add dm-integrity for tampering detection (wiki recommends for high security; ~10% perf hit):
    ```bash
    cryptsetup open --integrity hmac-sha256 /dev/mapper/cryptroot cryptintegrity # If adding integrity
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
  - Backup the keyfile to a USB:
    ```bash
    mkdir -p /mnt/usb
    lsblk  # Identify USB device (e.g., /dev/sdX1)
    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**
    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile
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
    mount -o subvol=@,compress=zstd:3,ssd,space_cache=v2 /dev/mapper/cryptroot /mnt
    mkdir -p /mnt/{boot,windows-efi,.snapshots,home,data,var,var/lib,var/log,swap,srv}
    mount /dev/nvme1n1p1 /mnt/boot
    mount /dev/nvme0n1p1 /mnt/windows-efi
    mount -o subvol=@home,compress=zstd:3,ssd,space_cache=v2 /dev/mapper/cryptroot /mnt/home
    mount -o subvol=@data,compress=zstd:3,ssd,space_cache=v2 /dev/mapper/cryptroot /mnt/data
    mount -o subvol=@var,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var
    mount -o subvol=@var_lib,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var/lib
    mount -o subvol=@log,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/var/log
    mount -o subvol=@srv,compress=zstd:3,ssd,space_cache=v2 /dev/mapper/cryptroot /mnt/srv
    mount -o subvol=@swap,nodatacow,compress=no,noatime /dev/mapper/cryptroot /mnt/swap
    mount -o subvol=@snapshots,ssd,noatime /dev/mapper/cryptroot /mnt/.snapshots
    ```
  - **Why These Subvolumes?**:
    - **@**: Isolates the root filesystem for snapshotting and rollback.
    - **@home**: Separates user data for independent snapshots and backups.
    - **@snapshots**: Stores Snapper snapshots for system recovery.
    - **@var**, @var_lib, @log**: Disables Copy-on-Write (`nodatacow`, `noatime`) for performance on frequently written data.
    - **@swap**: Ensures swapfile compatibility with hibernation (`nodatacow`, `noatime`).
    - **@srv, @data**: Provides flexible storage with compression (`zstd:3`) for server or user data.
- **e) Configure Swap File**:
  - Create a swap file on the `@swap` subvolume:
    ```bash
    touch /mnt/swap/swapfile
    truncate -s 0 /mnt/swap/swapfile
    chattr +C /mnt/swap/swapfile  # Disable Copy-on-Write
    (REPLACED WITH TRUNCATE + DD) fallocate -l 32G /mnt/swap/swapfile || { echo "fallocate failed"; exit 1; } # DO NOT EXECUTE
    dd if=/dev/zero of=/mnt/swap/swapfile bs=1M count=32768 status=progress
    chmod 600 /mnt/swap/swapfile
    mkswap /mnt/swap/swapfile || { echo "mkswap failed"; exit 1; }
    swapon /mnt/swap/swapfile
    ```
  - Obtain the swapfile’s physical offset for hibernation:
    ```bash
    SWAP_OFFSET=$(btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile | awk '{print $NF}')
    echo $SWAP_OFFSET > /mnt/etc/swap_offset # Save for later use
    echo "SWAP_OFFSET: $SWAP_OFFSET"  # Record this number. Should output a numerical offset like 12345678
    ```
    - **Record this SWAP_OFFSET value. Insert it directly into your systemd-boot kernel parameters (e.g., in /etc/mkinitcpio.d/linux.preset) and /etc/fstab (for the swapfile entry with resume_offset=).
    - **Note**: This offset is critical for hibernation support and must be accurate—recompute if the swap file changes.
  - BTRFS OFFICIAL VERIFICATION
    ```bash
    btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile > /dev/null \
      && echo "Swapfile 100 % BTRFS-compliant" \
      || { echo "FATAL: map-swapfile failed"; exit 1; }
    btrfs property get /mnt/swap/swapfile compression | grep -q none \
      || { echo "FATAL: compression still on"; exit 1; }
    ```
  - Add to fstab (REPLACE $SWAP_OFFSET with the computed value)
    ```bash
    grep -q swapfile /mnt/etc/fstab || cat <<EOF >> /mnt/etc/fstab
    /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0
    EOF
    ```
  - Unmount the swap subvolume:
    ```bash
    swapon --show | grep swapfile && swapoff /mnt/swap/swapfile
    umount /mnt/swap
    echo "Swap subvolume unmounted – you are DONE"
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
      UUID=$ROOT_UUID /var btrfs subvol=@var,nodatacow,compress=no,noatime 0 0
      UUID=$ROOT_UUID /var/lib btrfs subvol=@var_lib,nodatacow,compress=no,noatime 0 0
      UUID=$ROOT_UUID /var/log btrfs subvol=@log,nodatacow,compress=no,noatime 0 0
      UUID=$ROOT_UUID /srv btrfs subvol=@srv,compress=zstd:3,ssd,noatime,space_cache=v2 0 0
      UUID=$ROOT_UUID /swap btrfs subvol=@swap,nodatacow,compress=no,noatime 0 0
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
      SWAP_OFFSET_VALUE=$(cat /mnt/etc/swap_offset) # Retrieve the saved value
      grep -q "[/]swap/swapfile" /mnt/etc/fstab || cat <<EOF >> /mnt/etc/fstab
      /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0
      EOF
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
- Enable parallel downloads
  ```bash
  sed -i 's/^#ParallelDownloads/ParallelDownloads/' /etc/pacman.conf
  ```
- Install the base system and necessary packages:
  ```bash
  pacstrap /mnt \
  # Core
  base base-devel linux linux-lts linux-firmware mkinitcpio archlinux-keyring \
  \
  # Boot / Encryption
  intel-ucode sbctl cryptsetup btrfs-progs efibootmgr dosfstools systemd-boot \
  \
  # Hardware / Firmware
  sof-firmware intel-media-driver fwupd nvme-cli wireless-regdb \
  \
  # Graphics
  mesa libva-mesa-driver mesa-demos vulkan-intel lib32-vulkan-intel \
  vulkan-radeon lib32-vulkan-radeon intel-gpu-tools \
  \
  # Audio
  pipewire wireplumber pipewire-pulse pipewire-alsa pipewire-jack \
  \
  # System
  sudo polkit udisks2 thermald acpi acpid ethtool namcap \
  \
  # Network / Install
  networkmanager openssh rsync reflector arch-install-scripts \
  \
  # User / DE
  zsh git jq flatpak gdm pacman-contrib devtools nano
  ```
- Create Gentoo prep directories (In case you want to migrate to Gentoo in the future):
  ```bash
  mkdir -p /mnt/etc/gentoo-prep  
  touch /mnt/etc/gentoo-prep/packages-mapping.md  
  echo "# Arch to Gentoo Package Mapping" >> /mnt/etc/gentoo-prep/packages-mapping.md  
  echo "- base -> sys-apps/baselayout" >> /mnt/etc/gentoo-prep/packages-mapping.md  
  # Add more as you install, e.g., after pacstrap: pacman -Qeq >> /mnt/etc/gentoo-prep/arch-packages.txt

  # Gentoo Preparation: Document System-Wide Build Settings for Portage
  # Create a dedicated file for system-wide CFLAGS (optimizations)
  echo 'CFLAGS="-march=native -O2 -pipe"' > /mnt/etc/gentoo-prep/cflags.txt
  echo "Documented CFLAGS/CXXFLAGS for Intel Core Ultra 7 255H."

  # Create a dedicated file for critical USE flags (features)
  # These flags are based on your plan (systemd, AppArmor, Wayland, GNOME, etc.)
  echo 'systemd btrfs luks tpm gnome wayland apparmor pipewire zstd' > /mnt/etc/gentoo-prep/desired-use-flags.txt
  echo "Documented critical USE flags for a secure, modern Gentoo desktop."

  # Gentoo Preparation: Document Detailed Hardware Profile (Highly Recommended)
  # Capture full hardware details, especially PCI devices for the eGPU/OCuLink
  echo "Saved detailed PCI/eGPU hardware list."
  ```  
- Chroot into the installed system:
  ```bash
  arch-chroot /mnt
  ```
- Initialize Git for /etc (This tracks all /etc changes for easy merge into Gentoo):
  ```bash
  pacman -S --noconfirm git etckeeper  
  etckeeper init  
  etckeeper commit "Initial Arch config"
  ```
- Document Detailed Hardware Profile (Useful for Gentoo migration):  
  ```bash
  # Capture PCI Devices (Most Critical for eGPU/NVMe)
  # The -nnk flags show the numerical ID, device name, and the kernel driver in use.
  lspci -nnk > /etc/gentoo-prep/lspci-nnk.txt
  echo "Saved detailed PCI hardware list (lspci-nnk.txt)."

  # Capture USB Devices (For peripherals and controllers)
  # The -vt flags show a detailed tree of all USB devices and drivers.
  lsusb -vt > /etc/gentoo-prep/lsusb-vt.txt
  echo "Saved detailed USB hardware list (lsusb-vt.txt)."

  # Capture Block Devices (For all disks and partitions)
  # The -f and -o flags are useful for documenting BTRFS/LUKS device paths.
  lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,UUID,MODEL,ROTA > /etc/gentoo-prep/lsblk.txt
  echo "Saved block device list (lsblk.txt)."
  
  # Capture CPU Details (Though CFLAGS are already noted, this is comprehensive)
  lscpu > /etc/gentoo-prep/lscpu.txt
  echo "Saved CPU details (lscpu.txt)."

  echo "All critical hardware information for Gentoo migration has been saved to /etc/gentoo-prep/."
  ``` 
- Ensure multilib repository is enabled (required for 32-bit drivers):
  ```bash
  sed -i '/\[multilib\]/,/Include/ s/^#//' /etc/pacman.conf
  ```
- Force-refresh package database and keyring:
  ```bash
  pacman -Sy --noconfirm
  pacman-key --init
  pacman-key --populate archlinux
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
  timedatectl set-local-rtc 1 --adjust-system-clock
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
  read -p "Enter your username: " username

  # Create user with Zsh as default shell
  useradd -m -G wheel,video,input,storage,audio,power,lp -s /usr/bin/zsh "$username"

  # Set passwords
  passwd  # root
  passwd "$username"
  ```
- Enable sudo
  ```bash
  echo "%wheel ALL=(ALL:ALL) ALL" | tee /etc/sudoers.d/wheel
  chmod 440 /etc/sudoers.d/wheel   # optional but good practice
  ```
- Enable NetworkManager
  ```bash
  systemctl enable NetworkManager
  ```
- TTY console
  ```bash
  echo "KEYMAP=us" > /etc/vconsole.conf
  echo "FONT=ter-v16n" >> /etc/vconsole.conf
  ```
- Enable polkit caching (run0 15-min password reuse)
  ```bash
  mkdir -p /etc/polkit-1/rules.d
  tee /etc/polkit-1/rules.d/49-run0-cache.rules > /dev/null <<'EOF'
  polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
   });
   EOF
  ```
- Shell Configuration — Add to ~/.zshrc or ~/.bashrc
  ```bash
  cat << 'EOF' >> /home/$username/.zshrc
  # Load fzf if available
  if command -v fzf >/dev/null 2>&1; then
    source <(fzf --zsh)
  fi

  # AUR wrapper: force paru, block yay:
  if command -v paru >/dev/null 2>&1; then
    alias yay='paru'
  else
    alias yay='echo -e "\nERROR: paru not installed. Run: sudo pacman -S --needed paru\n"; false'
  fi

  # Block 'yay' via pacman
  pacman() {
  for arg in "$@"; do
    if [[ "$arg" == "yay" ]] || [[ "$arg" == "yay-bin" ]]; then
      echo -e "\nERROR: Do not install 'yay'. This system uses 'paru' only.\n"
      return 1
    fi
  done
  command pacman "$@"
  }
  
  # Modern CLI tool alias:
  if [[ $- == *i* ]]; then
    alias sysctl='systeroid'
    alias grep='rg'
    alias find='fd'
    alias ls='eza  --icons --git'
    alias cat='bat --style=plain'
    alias du='dua'
    alias man='tldr'
    alias ps='procs'
    alias dig='dog'
    alias curl='http'
    alias btop='btm'
    alias iftop='bandwhich'
    alias fix-tpm='sudo systemctl start tpm-reenroll.service && journalctl -u tpm-reenroll.service -f'

  # zoxide: use 'z' and 'zi' (no autojump alias needed)
  if command -v zoxide >/dev/null 2>&1; then
    eval "$(zoxide init zsh)"
  fi
  fi

  # Safe update alias
  alias update='paru -Syu'
  echo "Run 'update' weekly. Use 'paru -Syu' for full control."
  EOF

  # Set ownership and permissions
  chown "$username:$username" "/home/$username/.zshrc"
  chmod 644 "/home/$username/.zshrc"
  ```
- Document kernel config upfront (for potential Gentoo migration):
  ```bash
  # Save the kernel configuration script as a reusable tool
  tee /usr/local/bin/save-kernel-config.sh > /dev/null << 'EOF'
  #!/usr/bin/env bash
  set -euo pipefail

  KERNEL_VERSION=$(uname -r)
  CONFIG_DIR="/etc/kernel"
  CONFIG_FILE="${CONFIG_DIR}/config-${KERNEL_VERSION}"
  mkdir -p "$CONFIG_DIR"

  echo "Saving kernel config for ${KERNEL_VERSION}..."

  if [[ -f /proc/config.gz ]] && zcat /proc/config.gz > "$CONFIG_FILE" 2>/dev/null; then
    echo "Success: Extracted from /proc/config.gz → $CONFIG_FILE"
  elif [[ -f "/usr/lib/modules/${KERNEL_VERSION}/build/.config" ]]; then
    cp "/usr/lib/modules/${KERNEL_VERSION}/build/.config" "$CONFIG_FILE"
    echo "Success: Copied from build dir → $CONFIG_FILE"
  else
    echo "Error: Kernel config not found."
    echo "   • pacman -S linux-headers"
    echo "   • OR: modprobe configs && zcat /proc/config.gz > $CONFIG_FILE"
    echo "   • Tip: Enable CONFIG_IKCONFIG_PROC=y in kernel"
    exit 1
  fi

  chmod 644 "$CONFIG_FILE"

  echo "Verifying key features..."
  for opt in "BTRFS_FS" "DM_CRYPT" "NVME_CORE"; do
    if grep -q "^CONFIG_${opt}=[ym]" "$CONFIG_FILE"; then
      echo "   $opt: enabled"
    else
      echo "   $opt: NOT enabled"
    fi
  done

  echo "Kernel config saved: $CONFIG_FILE"
  EOF

  chmod +x /usr/local/bin/save-kernel-config.sh
  save-kernel-config.sh
  ```  
## Milestone 3: After Step 6 (System Configuration) - Can pause at this point

## Step 7: Backup the LUKS header for recovery
  ```bash
  echo "=== LUKS Header Backup ==="
  echo "Insert a USB drive (will be FORMATTED)"
  echo "WARNING: ALL DATA ON THE USB WILL BE ERASED!"
  mkdir -p /mnt/usb
  lsblk  # Identify USB device
  mkfs.fat -F32 /dev/sdX1  # Replace sdX1 with USB partition
  mount /dev/sdX1 /mnt/usb
  cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
  sha256sum /mnt/usb/luks-header-backup > /mnt/usb/luks-header-backup.sha256
  sync
  umount /mnt/usb
  echo "WARNING: Store /mnt/usb/luks-header-backup in Bitwarden or an encrypted cloud."
  echo "WARNING: TPM unlocking may fail after firmware updates; keep the LUKS passphrase in Bitwarden."
  echo "WARNING: Verify the LUKS header backup integrity with sha256sum before storing."
  ```

## Milestone 4: After Step 7 (Back up the LUKS header for recovery) - Can pause at this point

## Step 8: Configure Boot, UKI, Secure Boot, and Hooks (Inside chroot)

- Install TPM tools:
  ```bash
  pacman -S --noconfirm tpm2-tools tpm2-tss systemd-ukify plymouth 
  ```
- Configure Unified Kernel Image (UKI):
  ```bash
  # Dynamic Resume Offset Calculation (REQUIRED for BTRFS swapfile)
  RESUME_OFFSET=$(awk '$2 == "/swap/swapfile" {print $1}' /etc/fstab | \
    xargs btrfs inspect-internal map-swapfile -r /swap/swapfile 2>/dev/null)
  if [[ -z "$RESUME_OFFSET" ]]; then
      echo "ERROR: resume_offset not found – check swapfile and fstab!"
      exit 1
  fi
  echo "Detected resume_offset = $RESUME_OFFSET"
    
  # Explicit TPM2 auto-unlock via crypttab.initramfs
  # The sd-encrypt hook looks for this file and uses the tpm2-device=auto option.
  echo "cryptroot UUID=$LUKS_UUID none tpm2-device=auto,discard" > /etc/crypttab.initramfs
  echo "Created /etc/crypttab.initramfs for TPM auto-unlock (with TRIM)."

  # Update HOOKS in mkinitcpio.conf (Run this to ensure the final state is correct)
  HOOKS order:
  # - systemd early
  # - microcode for UKI early loading
  # - kms for graphics
  # - plymouth BEFORE sd-encrypt → graphical unlock prompt
  # - no fsck, no btrfs, no keyboard/keymap/consolefont bloat
  sed -i 's/^HOOKS=.*/HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole plymouth block sd-encrypt filesystems resume)/' /etc/mkinitcpio.conf
  echo "Updated /etc/mkinitcpio.conf HOOKS."

  # Configure linux.preset (defines the kernel command line for UKI)
  # rd.luks.uuid is now optional due to crypttab.initramfs, simplifying the cmdline.

  # Main Preset (linux)
  cat > /etc/mkinitcpio.d/linux.preset << EOF
  default_uki="/boot/EFI/Linux/arch.efi"
  all_config="/etc/mkinitcpio.conf"
  default_options="root=UUID=$ROOT_UUID rootflags=subvol=@ resume_offset=$RESUME_OFFSET rw quiet splash \
  intel_iommu=on amd_iommu=on iommu=pt pci=pcie_bus_perf,realloc \
  mitigations=auto,nosmt slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 \
  rd.emergency=poweroff amdgpu.dc=1 amdgpu.dpm=1"
  EOF
  echo "Created /etc/mkinitcpio.d/linux.preset."

  # LTS preset (atomic copy, just rename the UKI)
  sed "s/arch\.efi/arch-lts\.efi/g" /etc/mkinitcpio.d/linux.preset > /etc/mkinitcpio.d/linux-lts.preset
  echo "Created /etc/mkinitcpio.d/linux-lts.preset."

  # Fallback (identical options, different UKI name)
  sed "s/arch\.efi/arch-fallback\.efi/g" /etc/mkinitcpio.d/linux.preset > /etc/mkinitcpio.d/linux-fallback.preset
  echo "Created /etc/mkinitcpio.d/linux-fallback.preset"

  # Plymouth set the default theme:
  plymouth-set-default-theme -R bgrt
  echo "Plymouth + BGRT theme set"

  # Generate UKI
  # Arch Wiki order REQUIRED: mkinitcpio -P -> bootctl install -> sbctl sign
  mkinitcpio -P
  echo "Generated arch.efi, arch-lts.efi, arch-fallback.efi"

  # Install `systemd-boot`:
  # Creates /boot/loader/, installs systemd-bootx64.efi.
  bootctl --esp-path=/boot install
  
  # Secure Boot keys (only once)
  if ! sbctl status | grep -q "Installed: Yes"; then
      sbctl create-keys
      sbctl enroll-keys -m -f
      echo "sbctl keys created and enrolled (incl. Microsoft keys)"
  fi

  # Secure Boot Signing (bootloader and UKIs)
  sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
  sbctl sign -s /boot/EFI/Linux/arch*.efi
  echo "Signed Bootloader and all UKIs for Secure Boot."

  # Create systemd-boot entry for LTS kernel
  cat > /boot/loader/entries/arch-lts.conf << 'EOF'
  title   Arch Linux (LTS Kernel)
  efi     /EFI/Linux/arch-lts.efi
  EOF

  # Fallback boot entry
  cat > /boot/loader/entries/arch-fallback.conf << EOF
  title   Arch Linux (Fallback)
  efi     /EFI/Linux/arch-fallback.efi
  EOF

  # Set a fast boot menu timeout (e.g., 3 seconds, or menu-hidden for fastest boot)
  bootctl set-timeout menu-hidden
  echo "Set systemd-boot timeout hidden. Pressing and holding a key (the Space bar is commonly cited and the most reliable)."

  # Set Boot Order – main Arch → LTS → Fallback → Windows (robust & future-proof)
  efibootmgr --bootorder \
    $(efibootmgr | grep -E 'Arch Linux( |$)' | grep -v 'LTS' | grep -v 'Fallback' | cut -c5-),\
    $(efibootmgr | grep 'LTS Kernel' | cut -c5-),\
    $(efibootmgr | grep 'Fallback' | cut -c5-),\
    $(efibootmgr | grep -i windows | cut -c5-) \
    2>/dev/null || echo "Boot order set (some entries may be missing – this is fine)"

  # Create Pacman hooks to automatically sign EFI binaries after updates:
  cat << 'EOF' > /etc/pacman.d/hooks/90-uki-sign.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = linux*
  Target = systemd
  Target = mkinitcpio
  Target = plymouth

  [Action]
  Description = Rebuild UKI and sign with Secure Boot
  When = PostTransaction
  Exec = /usr/bin/bash -c 'mkinitcpio -P; bootctl update && sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI /boot/EFI/Linux/arch*.efi 2>/dev/null || true'
  EOF

  # Enable paccache.timer
  systemctl enable paccache.timer

  # Verification Checks
  grep HOOKS /etc/mkinitcpio.conf
  echo -e "\nBoot entries:"
  bootctl list | grep -E "(title|efi)"
  echo -e "\nresume_offset in presets:"
  grep resume_offset /etc/mkinitcpio.d/linux*.preset
  
  #If you get a black screen, to debug:
  # Reboot.
  # Hold Space at boot → press 'e' → remove 'splash' or add 'i915.enable_guc=0' (Intel iGPU issue).
  # If issues arise after connecting the eGPU, try amdgpu.dc=0.
  ```
- Reboot to enroll keys and enable Secure Boot in UEFI:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```
  ## In UEFI (BIOS - F1), enable **Secure Boot** and enroll the sbctl key when prompted. You may need to reboot twice: once to enroll, once to activate.

## Step 9: TPM Auto-Healing, Recovery USB, Windows Entry & Final Archive (Live System)

- Update TPM PCR policy after enabling Secure Boot:
  ```bash
  # Boot back into Arch ISO
  arch-chroot /mnt

  # Generate stable TPM public key (once only)
  TPM_PUBKEY="/etc/tpm2-ukey.pem"
  if [ ! -f "$TPM_PUBKEY" ]; then
    echo "Generating TPM public key..."
    tpm2_createek --ek-context /tmp/ek.ctx --key-algorithm rsa --public /tmp/ek.pub
    tpm2_readpublic -c /tmp/ek.ctx -o "$TPM_PUBKEY"
    rm /tmp/ek.*
    echo "TPM public key saved to $TPM_PUBKEY"
  fi

  # Raw PCR + Public-Key Enrollment - OCreate the systemd service file
  cat > /etc/systemd/system/tpm-reenroll.service << 'EOF'
  [Unit]
  Description=Re-enroll TPM2 policy if PCRs changed
  Documentation=man:systemd-cryptenroll(1)

  # a. Wait until the LUKS device is unlocked and mapped
  After=systemd-cryptsetup@cryptroot.service
  Requires=systemd-cryptsetup@cryptroot.service

  # b. Also wait for TPM device
  Requires=tpm2.target
  After=tpm2.target

  [Service]
  Type=oneshot
  RemainAfterExit=yes

  # c. Use the *mapped* device (safe, always exists after unlock)
  ExecStart=/usr/bin/bash -c '
  set -euo pipefail

  LUKS_DEV="/dev/mapper/cryptroot"
  TPM_PUB="/etc/tpm2-ukey.pem"

  # d. Test current policy
  if systemd-cryptenroll --tpm2-device=auto --tpm2-public-key="$TPM_PUB" --test "$LUKS_DEV" >/dev/null 2>&1; then
    echo "TPM policy valid. No action needed."
    exit 0
  fi

  echo "TPM policy mismatch detected. Re-enrolling with current PCRs..."

  # e. Wipe old TPM slot and re-enroll
  systemd-cryptenroll "$LUKS_DEV" --wipe-slot=tpm2
  systemd-cryptenroll "$LUKS_DEV" \
    --tpm2-device=auto \
    --tpm2-pcrs=7+11 \
    --tpm2-public-key="$TPM_PUB" \
    --tpm2-pcrs-bank=sha256
  
  echo "TPM re-enrollment complete. Auto-unlock restored."
  '

  [Install]
  WantedBy=multi-user.target
  EOF

  # f. Re-enroll command
  ExecStartPost=/usr/bin/bash -c 'systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-public-key="$TPM_PUB" --tpm2-pcrs=7+11 "$LUKS_DEV"'
  
  # Reload daemon and enable the service
  systemctl daemon-reload
  systemctl enable --now tpm-reenroll.service

  # Verify
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM unlock test PASSED"
 
  # Final TPM unlock test
  systemd-cryptenroll --tpm2-device=auto --test "$TPM_DEV" && echo "TPM unlock test PASSED"
  # Should return 0 and print "Unlocking with TPM2... success".

  # Confirm Secure Boot is active
  sbctl status
  # Expected:
  ✓ Secure Boot: Enabled
  ✓ Setup Mode: Disabled
  ✓ Signed: all files
  sbctl verify /boot/EFI/Linux/arch.efi | grep -q "signed" && echo "UKI signed"
  ```
- Backup PCR values post-Secure Boot:
  ```bash
  mount /dev/sdX1 /mnt/usb  # Replace with your USB
  tpm2_pcrread sha256:7,11 > /mnt/usb/tpm-pcr-post-secureboot.txt
  diff /mnt/usb/tpm-pcr-backup.txt /mnt/usb/tpm-pcr-post-secureboot.txt || echo "PCR 7 changed (expected)"
  echo "WARNING: Store /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden."
  echo "WARNING: Compare PCR values to ensure TPM policy consistency."
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
  ```
- Create a GRUB USB for recovery:
  ```bash
  lsblk  # Identify USB device (e.g., /dev/sdX1)
  read -p "Enter USB partition (e.g. /dev/sdb1): " USB_PART
  mkfs.fat -F32 -n RESCUE_USB /dev/sdX1 # Make sure to enter the USB ID in use replacing the placeholder "/dev/sdX1"

  mkdir -p /mnt/usb
  mount /dev/sdX1 /mnt/usb # Replace /dev/sdX1 with your USB partition confirmed via lsblk

  pacman -Sy grub
  grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB --recheck

  # Copy kernel + initramfs
  cp /crypto_keyfile /mnt/usb/luks-keyfile
  chmod 600 /mnt/usb/luks-keyfile
  cp /boot/vmlinuz-linux /mnt/usb/
  cp /boot/initramfs-linux.img /mnt/usb/initramfs-linux.img

  # Copy AMD firmware for offline recovery
  echo "Copying AMD firmware to recovery USB..."
  mkdir -p /mnt/usb/firmware
  cp -r /lib/firmware/amdgpu /mnt/usb/firmware/

  # Generate minimal rescue initramfs (no plymouth, resume)
  cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
  sed -i 's/HOOKS=(.*/HOOKS=(base systemd autodetect modconf block sd-encrypt btrfs filesystems keyboard)/' /mnt/usb/mkinitcpio-rescue.conf
  mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
  cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

  # Copy LUKS keyfile
  cp /crypto_keyfile /mnt/usb/luks-keyfile 2>/dev/null || \
  echo "Warning: No keyfile found. Using passphrase only."
  chmod 600 /mnt/usb/luks-keyfile 2>/dev/null || true

  # GRUB config (Replace $LUKS_UUID and $ROOT_UUID with actual values in the menuentry)
  cat << EOF > /mnt/usb/boot/grub/grub.cfg
  set timeout=5
  menuentry "Arch Linux Rescue" {
    insmod part_gpt
    insmod fat
    insmod luks
    insmod luks2
    linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot:allow-discards --key-file=/luks-keyfile root=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw
    initrd /initramfs-linux.img
  }
  EOF

  # Sign GRUB bootloader
  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  shred -u /crypto_keyfile # This may fail and you will need to enter the chroot, mount everything, then wipe
  umount /mnt/usb
  
  echo "WARNING: Store the GRUB USB securely; it contains the LUKS keyfile."
  ```
- Full LUKS+UKI+TPM config snapshot - archive-system-config.sh (helpful in case of a Gentoo migration)
  ```bash
  # Usage: sudo ./archive-system-config.sh [keep-staging]
  set -euo pipefail

  # --- Config ---------------------------------------------------------
  ARCHIVE_ROOT="/etc/system-config-archive"
  STAGING_DIR="${ARCHIVE_ROOT}/staging_$(date +%Y%m%d_%H%M%S)"
  ARCHIVE_NAME="arch_luks_uki_config_$(date +%Y%m%d).tar.gz"
  FINAL_ARCHIVE="${ARCHIVE_ROOT}/${ARCHIVE_NAME}"

  # Optional: keep staging dir for debugging
  KEEP_STAGING="${1:-}"

  # --- Helpers --------------------------------------------------------
  log() { echo "[$(date +%H:%M:%S)] $*"; }
  die() { log "ERROR: $*"; exit 1; }

  # --- Main -----------------------------------------------------------
  log "Creating system configuration archive..."

  mkdir -p "$STAGING_DIR"
  log "Staging directory: $STAGING_DIR"

  # Kernel & Boot
  log "Copying mkinitcpio & bootloader config..."
  cp -v /etc/mkinitcpio.conf            "$STAGING_DIR/" || true
  for preset in /etc/mkinitcpio.d/*.preset; do
  [[ -f "$preset" ]] && cp -v "$preset" "$STAGING_DIR/"
  done
  cp -v /boot/loader/loader.conf        "$STAGING_DIR/" || true
  cp -v /etc/pacman.d/hooks/90-uki-sign.hook "$STAGING_DIR/" || true

  # Filesystem & Encryption
  log "Copying fstab & crypttab..."
  cp -v /etc/fstab                      "$STAGING_DIR/" || true
  cp -v /etc/crypttab                   "$STAGING_DIR/" || true

  # TPM / Security (sensitive!)
  log "Copying TPM reenroll service (PEM excluded)..."
  cp -v /etc/systemd/system/tpm-reenroll.service "$STAGING_DIR/" || true
  # DO NOT copy private key! Store hash instead:
  if [[ -f /etc/tpm2-ukey.pem ]]; then
    sha256sum /etc/tpm2-ukey.pem > "$STAGING_DIR/tpm2-ukey.pem.sha256"
    log "   tpm2-ukey.pem: hash saved (private key excluded)"
  fi

  # Kernel config 
  log "Running kernel config saver..."
  /usr/local/bin/save-kernel-config.sh
  KERNEL_CONFIG="/etc/kernel/config-$(uname -r)"
  [[ -f "$KERNEL_CONFIG" ]] || die "Kernel config not generated"
  cp -v "$KERNEL_CONFIG" "$STAGING_DIR/"

  # Archive + Verify
  log "Creating compressed archive..."
  tar -C "$STAGING_DIR" --sort=name --owner=0 --group=0 --mtime='2025-01-01' \
    -czf "$FINAL_ARCHIVE" .

  log "Verifying archive integrity..."
  gzip -t "$FINAL_ARCHIVE" || die "Corrupted archive!"

  # Checksum 
  sha256sum "$FINAL_ARCHIVE" > "${FINAL_ARCHIVE}.sha256"
  log "Checksum: ${FINAL_ARCHIVE}.sha256"

  # Cleanup
  if [[ -z "$KEEP_STAGING" ]]; then
    rm -rf "$STAGING_DIR"
    log "Staging directory removed."
  else
    log "Staging directory preserved: $STAGING_DIR"
  fi

  log "Full system config archive saved:"
  log "   → $FINAL_ARCHIVE"
  log "   → ${FINAL_ARCHIVE}.sha256"

  chmod +x /usr/local/bin/archive-system-config.sh
  archive-system-config.sh
  ```
- Migration Gentoo Final Checklist
  ```bash
  # Verify all files exist
  ls -R /etc/gentoo-prep/
  ls /etc/kernel/config-*
  ls /etc/system-config-archive/*.tar.gz

  # Commit etckeeper
  etckeeper commit "Final config before first boot"

  # Backup archive off-system
  cp /etc/system-config-archive/*.tar.gz /path/to/backup/
  ```
- Exit chroot:
  ```bash
  exit
  ```
- Final reboot into encrypted system:
  ```bash
  umount -R /mnt
  reboot
  ```
- Verify
  ```bash
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM unlock test PASSED"
  sbctl status
  ```
- (Optional) Enable systemd-homed with LUKS-encrypted homes
  ```bash
  systemctl enable --now systemd-homed.service
  chattr +C /home
  
  # Example user
  read -p "Create homed user? (y/N): " CREATE_HOMED
  if [[ "$CREATE_HOMED" =~ ^[Yy]$ ]]; then
    read -p "Username: " USERNAME
    homectl create "$USERNAME" \
      --storage=luks \
      --fs-type=btrfs \
      --shell=/bin/zsh \
      --member-of=wheel \
      --disk-size=100G
  fi
  ```
## Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can pause at this point

## Step 10: Install and Configure DE and Applications

- Install the **GNOME desktop environment**:
  ```bash
  # Install Gnome
  pacman -S --needed gnome
  ```
- Install **Paru and configure it**:
  ```bash   
  # Clone & build in a clean temp dir
  TMP_PARU=$(mktemp -d)
  git clone --depth 1 https://aur.archlinux.org/paru.git "$TMP_PARU"
  (
    cd "$TMP_PARU" || exit 1
  
  # Build the package (creates the .pkg.tar.zst file)
  makepkg -s
  
  # NAMCAP AUDIT (Insert Check Here)
  echo "--- Running namcap audit on the built paru package ---"
  # Audits the built package. The || true allows the script to continue on warnings.
  namcap paru-*.pkg.tar.zst || true
  
  # Install the audited package
  pacman -U paru-*.pkg.tar.zst --noconfirm
  )
  rm -rf "$TMP_PARU"

  # Configure to show PKGBUILD diffs (edit the Paru config file):
  mkdir -p /home/arch/.config/paru
  cat << 'EOF' > /home/arch/.config/paru/paru.conf
  [options]
  PgpFetch
  BottomUp
  RemoveMake
  SudoLoop
  EditMenu = true
  CombinedUpgrade = false

  [bin]
  DiffMenu = true
  UseAsk = true
  Chroot = true
  EOF
  chown -R arch:arch /home/arch/.config/paru
  
  # Verify if paru shows the PKGBUILD diffs
  paru -Pg | grep -E 'diffmenu|combinedupgrade|editmenu' # Should show: combinedupgrade: Off diffmenu: Edit editmenu: Edit

  # Set build directory
  echo 'BUILDDIR = /home/arch/.cache/paru-build' >> /etc/makepkg.conf
  sudo -p /home/arch/.cache/paru-build
  chown arch:arch /home/arch/.cache/paru-build
  ```
- Install Pacman applications:
  ```bash
  # System packages (CLI + system-level)
  pacman -S --needed \
  # Security & Hardening
  aide apparmor auditd bitwarden chkrootkit lynis rkhunter sshguard ufw usbguard \
  \
  # System Monitoring
  baobab cpupower gnome-system-monitor logwatch tlp upower zram-generator \
  \
  # Hardware
  bluez bluez-utils fprintd thermald \
  \
  # Networking & Privacy
  dnscrypt-proxy opensnitch wireguard-tools \
  \
  # CLI Tools
  atuin bat bottom broot delta dog dua eza fd fzf gcc gdb git gitui glow gping \
  helix httpie hyfetch procs python-pygobject rage ripgrep rustup starship tealdeer \
  tokei xdg-ninja yazi zellij zoxide zsh-autosuggestions \
  \
  # Multimedia (system)
  ffmpeg gstreamer gst-libav gst-plugins-bad gst-plugins-good gst-plugins-ugly \
  libva-utils libva-vdpau-driver vulkan-tools clinfo mangohud \
  \
  # Browsers & OBS (native)
  brave-browser mullvad-browser tor-browser obs-studio \
  \
  # Utilities
  bandwhich pacman-notifier \
  \
  # GNOME
  gnome-bluetooth gnome-software-plugin-flatpak gnome-tweaks
  ```
- Enable essential services:
  ```bash
  systemctl enable gdm bluetooth ufw auditd apparmor systemd-timesyncd tlp fstrim.timer dnscrypt-proxy sshguard rkhunter chkrootkit logwatch.timer
  systemctl --failed  # Check for failed services
  journalctl -p 3 -xb
  ```
- Install Rebos (NixOS-like repeatability for any Linux distro.)
  ```bash
  # Pre-reqs (Rust + Cargo; already in base-devel)
  rustup default stable

  # Install latest from GitLab upstream
  cargo install --git https://gitlab.com/Oglo12/rebos.git rebos

  # Verify
  rebos --version  # Should show latest (e.g., v0.x as of 2025)
  which rebos      # /home/$USER/.cargo/bin/rebos

  # Add to PATH if needed (add to ~/.zshrc)
  echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
  source ~/.zshrc

  # Init for your system (tracks pacman/AUR history)
  rebos init

  # Generate initial manifest (from your current install)
  rebos gen base
  git add ~/.config/rebos/base.toml
  git commit -m "Initial Rebos manifest"

  # Optional: Custom config (BTRFS, eGPU, etc.)
  mkdir -p ~/.config/rebos
  cat > ~/.config/rebos/base.toml << 'EOF'
  name = "arch-secure-egpu"
  description = "Hardened Arch + BTRFS + LUKS2 + TPM2 + AppArmor + eGPU"
  bootloader = "systemd-boot"
  kernel = "linux"
  extra_packages = ["supergfxctl", "bolt", "apparmor"]  # Your eGPU/MAC deps
  EOF

  # First backup/snapshot
  rebos backup create --name "post-install-$(date +%Y%m%d)"
  ```
- Install the AUR applications:
  ```bash
  # AUR applications:
  paru -S --needed \
    apparmor.d-git \
    alacritty-graphics \
    astal-git \
    ags-git \
    gdm-settings \
    thinklmi-git \
    systeroid-git \
    run0-sudo-shim-git

  # Verify ThinkLMI for BIOS settings
  sudo thinklmi  # Check BIOS settings (e.g., Secure Boot, TPM). 

  # Verify binaries exist before signing
    [[ -f /usr/bin/astal && -f /usr/bin/ags ]] || { echo "ERROR: astal/ags not found!"; exit 1; }
  
  # Sign astal/ags for Secure Boot once
  sbctl sign -s /usr/bin/astal /usr/bin/ags

  # Sign run0-sudo-shim for sudo replacement
  sbctl sign -s /usr/bin/sudo
  echo "run0-sudo-shim installed and signed"
  
  # Append Astal/AGS to existing 90-uki-sign.hook
  if ! grep -q "Target = astal-git" /etc/pacman.d/hooks/90-uki-sign.hook; then
  cat << 'EOF' >> /etc/pacman.d/hooks/90-uki-sign.hook

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
  fi
  
  # Test the hook after installation:
  sbctl verify /usr/bin/astal  #Should show "signed"

  # Auto-re-sign hook for run0-sudo-shim
  sudo tee /etc/pacman.d/hooks/90-run0-shim-sign.hook <<'EOF'
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = run0-sudo-shim-git

  [Action]
  Description = Sign the sudo shim for Secure Boot
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/sudo
  EOF

  # Test the run0-sudo-shim
  sudo -v && echo "polkit cache OK"
  fix-tpm && echo "TPM script OK"
  sbctl verify /usr/bin/sudo && echo "Secure Boot OK"
  type sudo && echo "shim is in place"
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
  # Install Bazaar (Flatpak-focused app store) and Flatseal
  flatpak install -y flathub io.github.kolunmi.Bazaar com.github.tchx84.Flatseal

  # Launch once to initialize
  flatpak run io.github.kolunmi.Bazaar

  # Open Bazaar (search in GNOME overview or via flatpak run io.github.kolunmi.Bazaar)
  echo "Open Bazaar (via GNOME overview or 'flatpak run io.github.kolunmi.Bazaar') and install: GIMP (org.gimp.GIMP), Inkscape (org.inkscape.Inkscape), Krita (org.kde.krita), Blender (org.blender.Blender), GDM Settings (io.github.realmazharhussain.GdmSettings), Lollypop (org.gnome.Lollypop). Use Flatseal (com.github.tchx84.Flatseal) to fine-tune per-app permissions (e.g., add --filesystem=home:rw for Blender if needed)."
  ```
- Configure Flatpak sandboxing (via Flatseal or CLI):
  ```bash
  # Allow Flatpaks to read/write their own config/data only
  flatpak override --user --filesystem=xdg-config:ro --filesystem=xdg-data:create
  # Allow GPU access for Steam:
  flatpak override --user com.valvesoftware.Steam --device=dri --filesystem=~/Games:create
  ```
- Setup Automated System/AUR Updates
  ```bash
  
  # Create a service and timer for automated paru (AUR/System) updates
  cat << EOF | sudo tee /etc/systemd/system/paru-update.service
  [Unit]
  Description=Paru and System Update
  Wants=network-online.target
  After=network-online.target

  [Service]
  Type=oneshot
  ExecStart=/usr/bin/paru --noconfirm -Syu
  User=%i
  # Remember to replace your_username with the actual username you set up in Step 6.
  User=your_username 
  EOF

  cat << EOF | sudo tee /etc/systemd/system/paru-update.timer
  [Unit]
  Description=Runs paru-update.service daily

  [Timer]
  # Run at 03:00 (3 AM) daily
  OnCalendar=daily
  # Wait up to 15 minutes to prevent all systems hitting the mirror at once
  RandomizedDelaySec=15min
  Persistent=true

  [Install]
  WantedBy=timers.target
  EOF

  # Enable and start the paru timer
  sudo systemctl enable paru-update.timer
  sudo systemctl start paru-update.timer
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
  sudo tee /etc/environment > /dev/null <<'EOF'
  # WAYLAND (FORCE HIGH-PERFORMANCE)
  MOZ_ENABLE_WAYLAND=1
  GDK_BACKEND=wayland
  CLUTTER_BACKEND=wayland
  QT_QPA_PLATFORM=wayland
  SDL_VIDEODRIVER=wayland
  ELECTRON_OZONE_PLATFORM_HINT=auto
  XDG_SESSION_TYPE=wayland

  # PATH HARDENING (SYSTEM-WIDE ONLY)
  # User paths ($HOME/.local/bin) added in ~/.zshrc
  PATH=/usr/local/bin:/usr/bin:/bin
  EOF
  #The envars below should NOT BE INCLUDED and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU. DO NOT ADD INITIALLY:
  LIBVA_DRIVER_NAME=radeonsi
  LIBVA_DRIVER_NAME=iHD

  cat >> ~/.zshrc <<'EOF'
  # XDG BASE DIRECTORIES (FHS COMPLIANT)
  export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
  export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
  export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
  export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

  # USER PATH: ~/.local/bin (paru, scripts)
  [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && PATH="$HOME/.local/bin:$PATH"

  # WAYLAND GUARD (REINFORCE)
  export XDG_SESSION_TYPE=wayland
  EOF

  # Add to ~/.profile (sourced by login shells & display managers)
  cat >> ~/.profile <<'EOF'
  # XDG Base Dirs
  export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
  export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
  export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
  export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

  # PATH
  [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && PATH="$HOME/.local/bin:$PATH"
  EOF
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
  CONN=$(nmcli -t -f NAME,TYPE connection show --active | grep wifi | cut -d: -f1)
  [[ -n "$CONN" ]] && nmcli connection modify "$CONN" ipv4.dns "127.0.0.1"
  [[ -n "$CONN" ]] && nmcli connection modify "$CONN" ipv6.dns "::1" ipv6.ignore-auto-dns yes
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
  dog archlinux.org
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
  #!/usr/bin/env bash
  set -euo pipefail

  AUDIT_FILE="/data/suid_audit.txt"
  mkdir -p "$(dirname "$AUDIT_FILE")"

  # Find SUID files, skip special filesystems
  find / -xdev -type f -perm -u+s 2>/dev/null > "$AUDIT_FILE"

  # Example: remove SUID from ping and give capability instead
  PING_BIN="/usr/bin/ping"
  if [[ -f "$PING_BIN" ]]; then
    chmod u-s "$PING_BIN"
    setcap cap_net_raw+ep "$PING_BIN"
  fi
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
- Enable FSP in COMPLAIN mode
  ```bash
  # This activates the *complete* AppArmor.d policy (1000+ profiles)
  # DO NOT use aa-complain on /etc/apparmor.d/* — that's legacy.
  
  # Enable service
  sudo systemctl enable --now apparmor

  # Enable the upstream-sync timer (weekly profile updates)
  sudo systemctl enable --now apparmor.d-update.timer
  
  # Load Full System Policy in COMPLAIN mode
  sudo just fsp-complain   # from the apparmor.d build dir (installed to /usr/share/apparmor.d)

  # Warm cache for boot-time performance (critical for UKI + Secure Boot)
  sudo apparmor_parser -r /usr/share/apparmor.d/*

  # Restart to apply everything
  sudo systemctl restart apparmor

  echo "AppArmor FSP is now in COMPLAIN mode."
  echo "Use system normally for 1–2 days, then check denials:"
  echo "  journalctl -u apparmor | grep DENIED"
  echo "  sudo aa-logprof"
  echo "NEXT STEPS (after eGPU setup + normal use):"
  echo "  1. Use system normally for 1–2 days"
  echo "  2. Check denials:"
  echo "       journalctl -u apparmor | grep -i DENIED"
  echo "       ausearch -m avc -ts recent | tail -20"
  echo "  3. Tune interactively:"
  echo "       sudo aa-logprof"
  echo "       sudo aa-genprof <binary>  # e.g., astal, supergfxctl, obs-studio"
  echo "  4. After tuning → ENFORCE:"
  echo "       sudo just fsp-enforce"
  echo " Note: Full AppArmor.d policy will be enforced in Step 18j via 'just fsp-enforce
  echo "       sudo systemctl restart apparmor"
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
  # If probe error -22: Try kernel param 'amdgpu.noretry=0' in /etc/mkinitcpio.d/linux.preset, then mkinitcpio -P
  supergfxctl -m Integrated  # Fallback to iGPU if eGPU fails
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
- (DEPRECATED - Fallback Only) Create a udev rule for eGPU hotplug support:
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
- (DEPRECATED - Fallback Only) Install all-ways-egpu if eGPU isn’t primary
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
  echo "1. Run: lspci -nn | grep -i amd"
  echo "2. Example output: 1002:73df [AMD Radeon RX 6700 XT]"
  echo "3. Edit /etc/modprobe.d/vfio.conf and replace 1002:xxxx with real IDs"
  echo "4. Then: mkinitcpio -P && reboot"
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
  echo "Target = qemu" >> /etc/pacman.d/hooks/90-uki-sign.hook
  echo "Target = libvirt" >> /etc/pacman.d/hooks/90-uki-sign.hook
  echo "Target = supergfxctl" >> /etc/pacman.d/hooks/90-uki-sign.hook
  echo "Target = rebos" >> /etc/pacman.d/hooks/90-uki-sign.hook
  echo "Exec = /usr/bin/sbctl sign -s /home/*/.*cargo/bin/rebos" >> /etc/pacman.d/hooks/90-uki-sign.hook
  sed -i '/Exec =/ s|$| \/usr\/bin\/qemu-system-x86_64 \/usr\/lib\/libvirt\/libvirtd|' /etc/pacman.d/hooks/90-uki-sign.hook
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

  # Log denials to a file for review
  journalctl -u apparmor | grep -i DENIED > /var/log/apparmor-denials.log

  # DO NOT ENFORCE YET — FSP is in COMPLAIN mode
  # Denials will be logged to /var/log/apparmor-denials.log
  # Note: Full AppArmor.d policy will be enforced in Step 18j via 'just fsp-enforce
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

  **Note:** Switch modes before testing:
  # Hybrid: `supergfxctl -m Hybrid` → `DRI_PRIME=1 glxinfo | grep renderer`
  # VFIO: `supergfxctl -m VFIO` → `lspci -k | grep vfio`
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

  # (Optional) Check OCuLink dock firmware - Firmware Update may be better performed in Step 18
  fwupdmgr get-devices | grep -i "oculink\|redriver"
  (DO NOT EXEXECUTE) fwupdmgr update - echo "fwupd upgrade moved to Step 18 for BIOS/firmware updates."
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
- Install Snapper and snap-pac
  ```bash
  pacman -S --noconfirm snapper snap-pac
  ```
- Create global filter
  ```bash
  mkdir -p /etc/snapper/filters
  echo -e "/home/.cache\n/tmp\n/run\n/.snapshots\n.nobackup" | sudo tee /etc/snapper/filters/global-filter.txt
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
  Exec = /usr/bin/snapper --config root create --description "Pre-pacman update" --type pre
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
  - Create Rebos pacman hook for updates
  ```bash
  cat > /etc/pacman.d/hooks/99-rebos-gen.hook << 'EOF'
  [Trigger]
  Operation=Upgrade
  Type=Package
  Target=rebos

  [Action]
  Description=Regenerate Rebos manifest after updates
  When=PostTransaction
  # NOTE: Replace 'your_username' with the actual username that installed Rebos via Cargo.
  Exec=/usr/bin/runuser -u your_username -- /home/your_username/.cargo/bin/rebos gen base
  EOF
  ```
  - Set permissions for hooks:
  ```bash
  chmod 644 /etc/pacman.d/hooks/50-snapper-pre-update.hook
  chmod 644 /etc/pacman.d/hooks/51-snapper-post-update.hook
  chmod 644 /etc/pacman.d/hooks/99-rebos-gen.hook
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
  echo "NOTE: If AppArmor is enabled, check for denials: journalctl -u apparmor | grep -i 'snapper'. Generate profiles with 'aa-genprof snapper' if needed."
  journalctl -u apparmor | grep -i "snapper"
  ```
## Step 14: Configure Dotfiles

- Install `chezmoi` for dotfile management:
  ```bash
  # Install chezmoi
  pacman -S --noconfirm chezmoi
  ```
- Initialize and apply dotfiles from a repository:
  ```bash
  chezmoi init --apply https://github.com/yourusername/dotfiles.git
  ```
- Run doctor as user
  ```bash
  chezmoi doctor || echo "chezmoi OK"
  ```
- Verify dotfile application:
  ```bash
  chezmoi status
  ```
- Backup existing configurations
  ```bash
  cp -r ~/.zshrc ~/.config/gnome ~/.config/alacritty ~/.config/gtk-4.0 ~/.config/gtk-3.0 ~/.local/share/backgrounds ~/.config/gnome-backup ~/.config/rebos
  ```
- Add user-specific dotfiles
  ```bash
  chezmoi add ~/.zshrc ~/.config/zsh
  dconf dump /org/gnome/ > ~/.config/gnome-settings.dconf
  dconf dump /org/gnome/shell/extensions/ > ~/.config/gnome-shell-extensions.dconf
  flatpak override --user --export > ~/.config/flatpak-overrides
  chezmoi add ~/.config/gnome-settings.dconf ~/.config/gnome-shell-extensions.dconf ~/.config/flatpak-overrides
  chezmoi add -r ~/.config/alacritty ~/.config/helix ~/.config/zellij ~/.config/yazi ~/.config/atuin ~/.config/git ~/.config/astal
  chezmoi add -r ~/.config/gtk-4.0 ~/.config/gtk-3.0 ~/.local/share/gnome-shell/extensions ~/.local/share/backgrounds
  chezmoi add ~/.config/rebos
  ```
- Add system-wide configurations
  ```bash
  sudo chezmoi add /etc/pacman.conf /etc/paru.conf /etc/pacman.d/hooks
  sudo chezmoi add /etc/audit/rules.d/audit.rules /etc/security/limits.conf /etc/sysctl.d/99-hardening.conf
  sudo chezmoi add /etc/NetworkManager/conf.d/00-macrandomize.conf /etc/dnscrypt-proxy/dnscrypt-proxy.toml /etc/usbguard/rules.conf
  sudo chezmoi add /etc/snapper/configs /etc/snapper/filters/global-filter.txt
  sudo chezmoi add /etc/modprobe.d/i915.conf /etc/modprobe.d/amdgpu.conf /etc/supergfxd.conf
  sudo chezmoi add /etc/udev/rules.d/99-oculink-hotplug.rules /etc/modules-load.d/pciehp.conf /etc/modules-load.d/vfio.conf
  sudo chezmoi add /etc/mkinitcpio.conf /etc/mkinitcpio.d/linux.preset
  sudo chezmoi add /boot/loader/entries/arch.conf /boot/loader/entries/arch-fallback.conf /boot/loader/entries/windows.conf
  sudo chezmoi add /etc/fstab /etc/environment /etc/gdm/custom.conf /etc/systemd/zram-generator.conf /etc/systemd/logind.conf /etc/host.conf
  sudo chezmoi add /etc/systemd/system/lynis-audit.timer /etc/systemd/system/lynis-audit.service
  sudo chezmoi add /etc/systemd/system/btrfs-balance.timer /etc/systemd/system/btrfs-balance.service
  sudo chezmoi add /etc/systemd/system/arch-news.timer /etc/systemd/system/arch-news.service
  sudo chezmoi add /etc/systemd/system/paccache.timer /etc/systemd/system/paccache.service
  sudo chezmoi add /etc/systemd/system/maintain.timer /etc/systemd/system/maintain.service
  sudo chezmoi add /etc/systemd/system/astal-widgets.service
  sudo chezmoi add /etc/pacman.d/hooks/90-uki-sign.hook
  sudo chezmoi add /usr/local/bin/maintain.sh /usr/local/bin/toggle-theme.sh /usr/local/bin/check-arch-news.sh
  sudo chezmoi add /etc/mkinitcpio-arch-fallback.efi.conf
  sudo chezmoi add /etc/pacman.d/hooks/90-mkinitcpio-uki.hook
  sudo chezmoi add /etc/tlp.conf
  sudo chezmoi add /etc/boltd/boltd.conf
  sudo chezmoi add /etc/locale.conf /etc/vconsole.conf
  sudo chezmoi add /etc/pacman.d/mirrorlist
  sudo chezmoi add -r /etc/dnscrypt-proxy/
  sudo chezmoi add /etc/just/fsp.conf 2>/dev/null || true
  sudo chezmoi add -r /etc/apparmor.d/local/
  sudo chezmoi add /etc/gentoo-prep/
  ```
- Export package lists for reproducibility
  ```bash
  pacman -Qqe > ~/explicitly-installed-packages.txt
  pacman -Qqm > ~/aur-packages.txt
  flatpak list --app > ~/flatpak-packages.txt
  chezmoi add ~/explicitly-installed-packages.txt ~/aur-packages.txt ~/flatpak-packages.txt
  ```
- Backup Secure Boot and TPM data to USB (replace /dev/sdX1 with your USB partition, confirm via lsblk)
  ```bash
  lsblk
  sudo mkfs.fat -F32 -n BACKUP_USB /dev/sdX1
  sudo mkdir -p /mnt/usb
  sudo mount /dev/sdX1 /mnt/usb
  sudo cp -r /etc/sbctl /mnt/usb/sbctl-keys
  sudo cp /var/lib/tpm-pcr-initial.txt /mnt/usb/ 2>/dev/null || true
  sudo umount /mnt/usb
  echo "WARNING: Store /mnt/usb/sbctl-keys, /mnt/usb/tpm-pcr-initial.txt, and /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden or an encrypted cloud."
  ```
- Version control with chezmoi
  ```bash
  chezmoi cd
  git init
  git remote add origin # Skip if not using a remote repository
  git add .
  git commit -m "Add user and system configurations for Lenovo ThinkBook Arch setup"
  git push origin main # Skip if not using a remote repository
  ```
- Apply configurations and set permissions
  ```bash
  chezmoi apply
  sudo chmod 640 /etc/snapper/configs/*
  ```
- Test and validate
  ```bash
  chezmoi diff # Should show no differences if applied successfully
  dconf load /org/gnome/ < ~/.config/gnome-settings.dconf
  dconf load /org/gnome/shell/extensions/ < ~/.config/gnome-shell-extensions.dconf
  zsh -i # Ensure no errors in ~/.zshrc
  systemctl list-timers --all # Verify lynis-audit.timer, btrfs-balance.timer, etc.
  systemctl status maintain.service
  cat ~/explicitly-installed-packages.txt # Check for expected packages
  cat ~/aur-packages.txt # Check for AUR packages
  cat ~/flatpak-packages.txt # Check for Flatpak apps
  ```
- Document recovery steps in Bitwarden (store UEFI password, LUKS passphrase, keyfile location, MOK password):
  ```bash
  a. Boot from Arch Linux Rescue USB.
  b. Mount root: cryptsetup luksOpen /dev/nvme1n1p2 cryptroot
  c. Mount subvolumes: mount -o subvol=@ /dev/mapper/cryptroot /mnt
  d. Chroot: arch-chroot /mnt
  e. Use /mnt/usb/luks-keyfile, /mnt/usb/luks-header-backup, or Bitwarden-stored header/passphrase for recovery.
  ```
- Troubleshooting
  ```bash
  If chezmoi apply fails: chezmoi doctor; journalctl -xe
  If a file is missing: verify path, create if needed (e.g., touch /etc/modprobe.d/amdgpu.conf)
  If git push fails: check remote setup (git remote -v)

  # Check AppArmor logs
  journalctl -u apparmor | grep -i chezmoi || echo "No AppArmor denials for chezmoi"
  ```
## Step 15: Test the Setup

- Reboot to test the full system:
  ```bash
  echo "Verifying bootloader configuration before reboot"
  bootctl status | grep -i "systemd-boot" || echo "Error: systemd-boot not installed"
  ls /boot/loader/entries/arch.conf /boot/loader/entries/arch-fallback.conf /boot/loader/entries/windows.conf || echo "Error: Boot entries missing"
  sbctl verify /boot/EFI/systemd/systemd-bootx64.efi || { echo "Signing bootloader"; sbctl sign -s /boot/EFI/systemd/systemd-bootx64.efi; }
  sbctl verify /boot/EFI/BOOT/BOOTX64.EFI || { echo "Signing bootloader"; sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI; }
  echo "Rebooting to test systemd-boot. Press F1 to access the boot menu and confirm Arch and Windows entries."
  reboot
  ```
- Verify TPM unlocking:
  ```bash
  # Boot and confirm the LUKS partition unlocks automatically via TPM.
  echo "After reboot, checking TPM unlock logs"
  journalctl -b | grep -i "systemd-cryptsetup.*tpm2" || echo "Warning: TPM unlock not confirmed"

  # Check the PCRs you actually enrolled (0, 4, 7)
  tpm2_pcrread sha256:7,11 > /tmp/tpm-pcr-current.txt

  # Mount USB to read the backup file
  echo "Please insert your backup USB drive..."
  sleep 5 # Give yourself time to plug it in

  # Find the USB, e.g., /dev/sdb1 (use lsblk to confirm)
  lsblk 
  read -p "Enter the USB partition (e.g., /dev/sdb1): " USB_PART
  mkdir -p /mnt/usb
  mount "$USB_PART" /mnt/usb

  # Diff against the correct file on the USB
  echo "Comparing current PCRs with the backup from Step 8..."
  diff /tmp/tpm-pcr-current.txt /mnt/usb/tpm-pcr-post-secureboot.txt || echo "Warning: TPM PCR values differ (This is expected if you've updated firmware/bootloader since Step 8)"

  # Clean up
  umount /mnt/usb
  rmdir /mnt/usb
  ```
- Check Secure Boot status:
  ```bash
  sbctl status
  mokutil --sb-state
  ```
- Verify eGPU detection:
  ```bash
  lspci | grep -i amd
  dmesg | grep -i amdgpu
  # Manually test module loading
  modprobe -r amdgpu
  modprobe amdgpu
  echo $?  # Should return 0
  # Check Wayland/Mutter logs for graphics errors (Wayland equivalent of glamor)
  journalctl -b | grep -i -E "mutter|gnome-shell|amdgpu" | grep -i -E "fail|error"
  ls /sys/class/drm/card*
  DRI_PRIME=1 glxinfo | grep "OpenGL renderer" || echo "Warning: GLX test failed, trying Vulkan"
  DRI_PRIME=1 vulkaninfo --summary | grep deviceName
  systemctl status supergfxd
  supergfxctl -s
  sbctl verify /lib/modules/*/kernel/drivers/gpu/drm/amd/amdgpu.ko || { echo "Signing amdgpu module"; sbctl sign -s /lib/modules/*/kernel/drivers/gpu/drm/amd/amdgpu.ko; }
  ```
- Test hibernation
  ```bash
  echo "Verifying swapfile configuration"
  swapon --show
  btrfs inspect-internal map-swapfile /swap/swapfile
  filefrag -v /swap/swapfile | grep "extents found: 1" || echo "Warning: Swapfile is fragmented" # Ensure no fragmentation
  systemctl hibernate
  echo "After resuming, checking hibernation logs"
  dmesg | grep -i "hibernate|swap"
  ```
- Test Wayland session:
  ```bash
  echo $XDG_SESSION_TYPE  # Should output "wayland"
  grep WaylandEnable /etc/gdm/custom.conf

  # Verify Mutter is running as the Wayland compositor
  ps aux | grep -i mutter | grep -v grep || echo "Error: Mutter not running"

  # Check if GNOME is using Wayland for rendering
  gsettings get org.gnome.mutter experimental-features  # Should include Wayland-related features

  # Test Wayland rendering with a simple GNOME application
  GDK_BACKEND=wayland gnome-calculator &  # Launch a Wayland-native app
  sleep 2
  killall gnome-calculator
  ```
- Verify Snapper snapshots:
  ```bash
  for config in root home data; do
    snapper --config "$config" create --description "Test snapshot"
    snapper --config "$config" list
  done
  ```
- Test Timers
  ```bash
  systemctl list-timers --all | grep -E "paru-update|paccache|snapper-timeline|snapper-cleanup|fstrim|lynis-audit"
  journalctl -u paru-update.timer
  journalctl -u paccache.timer
  journalctl -u snapper-timeline.timer
  journalctl -u fstrim.timer
  journalctl -u lynis-audit.timer
  systemctl start paru-update.service snapper-timeline.service fstrim.service lynis-audit.service
  ```
- Test network connectivity:
  ```bash
  ping -c 3 archlinux.org
  nslookup archlinux.org
  systemctl status dnscrypt-proxy
  ```
- Check for failed services:
  ```bash
  systemctl --failed
  systemctl --failed | awk '/failed/ {print $2}' | xargs -I {} journalctl -u {} -n 50  ```
- Verify AppArmor.d full-system policy (FSP) is active
  ```bash
  echo "=== AppArmor.d FSP Status ==="
  aa-status | head -20

  # Check if FSP is loaded from /usr/share/apparmor.d
  if [ -d /usr/share/apparmor.d ] && command -v just >/dev/null; then
    echo "✓ apparmor.d FSP detected"
    just fsp-status || echo "Warning: FSP not fully loaded"
  else
    echo "✗ apparmor.d not installed or 'just' command missing"
  fi

  # Show loaded profiles count
  aa-status | grep -E "(profiles are loaded|enforce|complain)" || echo "No profiles loaded"

  # Log recent denials (FSP logs to same audit)
  ausearch -m avc -ts recent | tail -10 || echo "No recent AVC denials"

  # Confirm cache is enabled
  grep -q "cache-loc = /etc/apparmor.d/cache" /etc/apparmor/parser.conf && \
    echo "✓ AppArmor cache enabled" || echo "✗ Cache not configured"

  echo "Note: Full AppArmor.d policy will be enforced in Step 18j via 'just fsp-enforce'."
  ```
- Test AUR builds with /tmp (no noexec)
  ```bash
  mount | grep /tmp | grep -v noexec || echo "Error: /tmp mounted with noexec"
  # The paru command succeeding is the test. No need to sign the binary.
  paru -S --builddir ~/.cache/paru_build --noconfirm hello-world-bin
  ```
- AppArmor Tuning Milestone (Run After Normal Use)
  ```bash
  echo "=== APARMOR TUNING ==="
  echo "Use system normally (eGPU, browsers, OBS, AGS) for 1–2 hours."
  echo "Then run:"

  sudo ausearch -m avc -ts boot | audit2allow
  sudo aa-logprof

  # For AGS/Astal:
  sudo aa-genprof astal
  # → In another terminal: astal -- ags -c ~/.config/ags/config.js
  # → Exercise UI, then Ctrl+C and finish aa-genprof

  echo "Repeat for: ags, supergfxctl, boltctl, qemu-system-x86_64"

  echo "After tuning: reboot and verify no denials in journalctl -u apparmor"
  ```
- Validate run0
  ```
  # Validate run0 (Polkit-based sudo replacement)
  # This tests:
  #   • Polkit rule grants wheel group access
  #   • Authentication is cached (~15 min)
  #   • Cache clears on reboot (expected)
  echo "Testing run0 inside chroot..."

  # First use: should prompt for password
  run0 whoami
  # → Expected: Polkit prompt → outputs "root"

  # Second use: should use cached credentials (no prompt)
  run0 id
  # → Expected: **no prompt**, outputs UID/GID

  # Note: Full cache behavior (including timeout) is only observable
  #       after first boot with a display manager (GDM).
  #       In chroot, caching is limited but rule application is verified.
  echo "run0 validation complete in chroot."
  echo "After first boot, re-test: run0 whoami → run0 id (no prompt) → reboot → run0 whoami (prompt again)"
  ```
- (DEPRECATED) Verify fwupd. # Updating the BIOS is better placed in Step 18.
  ```bash
  echo "fwupd tests moved to Step 18 for BIOS/firmware updates."
  ```
- (Optional) Test Windows boot.
  ```bash
  echo "Reboot and select Windows from the boot menu (F12 or Enter). Verify Windows boots correctly."
  sbctl verify /boot/EFI/Microsoft/Boot/bootmgfw.efi || { echo "Signing Windows bootloader"; sbctl sign -s /boot/EFI/Microsoft/Boot/bootmgfw.efi; }
  ```
## Step 16: Create Recovery Documentation

- Document UEFI password, LUKS passphrase, keyfile location, MOK password, and recovery steps in Bitwarden.
  ```bash
  echo "Store UEFI password, LUKS passphrase, keyfile location, and MOK password in Bitwarden."
  read -p "Confirm that UEFI password, LUKS passphrase, keyfile location, and MOK password are stored in Bitwarden (y/n): " confirm
  [ "$confirm" = "y" ] || { echo "Error: Please store credentials in Bitwarden before proceeding."; exit 1; }
  ```
- TPM Seal breaks
  ```bash
  # Enter LUKS passphrase (Stored in Bitwarden)
  # Run one automated command
  sudo tpm-seal-fix
  # echo "This re-measures the current boot state and re-enrolls TPM automatically."
  # echo "No manual PCR reading. No key regeneration. Just one line."
  ```
- Prepare and verify USB
  ```bash
  echo "Available devices:"
  lsblk -d -o NAME,SIZE,TYPE,MOUNTPOINT
  read -p "Enter USB partition (e.g., sdb1): " usb_dev
  [ -b "/dev/$usb_dev" ] || { echo "Error: /dev/$usb_dev not found"; exit 1; }
  echo "WARNING: Formatting /dev/$usb_dev will erase all data."
  read -p "Continue? (y/n): " confirm
  [ "$confirm" = "y" ] || { echo "Aborted."; exit 1; }
  # The formatting command must be run as root
  sudo mkfs.fat -F32 -n RECOVERY_USB /dev/$usb_dev || echo "Warning: USB formatting failed"
  sudo mkdir -p /mnt/usb
  sudo mount /dev/$usb_dev /mnt/usb
  ```
- Verify existing backups
  ```bash
  [ -f /mnt/usb/luks-keyfile ] || { echo "Error: /mnt/usb/luks-keyfile not found"; exit 1; }
  [ -f /mnt/usb/luks-header-backup ] || { echo "Error: /mnt/usb/luks-header-backup not found"; exit 1; }
  ```
- Backup LUKS header and Secure Boot keys
  ```bash
  [ -f /mnt/usb/luks-header-backup ] && { echo "Warning: /mnt/usb/luks-header-backup exists. Overwrite? (y/n): "; read confirm; [ "$confirm" = "y" ] || exit 1; }
  cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
  sha256sum /mnt/usb/luks-header-backup > /mnt/usb/luks-header-backup.sha256
  cp -r /etc/sbctl /mnt/usb/sbctl-keys
  sudo chmod -R 600 /mnt/usb/sbctl-keys
  ```
- Create a recovery document for troubleshooting:
  ```bash
  [ -f /mnt/usb/luks-keyfile ] && [ -f /mnt/usb/luks-header-backup ] || { echo "Error: Required files missing"; exit 1; }
  cat << 'EOF' > /mnt/usb/recovery.md
  # Arch Linux Recovery Instructions

  a. **Boot from Rescue USB**:
   - Insert the GRUB USB created in Step 9 or an Arch Linux ISO USB.
   - For GRUB USB: Select "Arch Linux Rescue" from the GRUB menu.
   - For Arch ISO: Boot into the Arch environment.
   - Enter the LUKS passphrase or use the keyfile: /mnt/usb/luks-keyfile # OR use recovery keyfile from USB/Bitwarden
  # LUKS passphrase
  cryptsetup luksOpen /dev/nvme1n1p2 cryptroot

  # OR use recovery keyfile from USB/Bitwarden
  cryptsetup luksOpen /dev/nvme1n1p2 cryptroot --key-file /path/to/crypto_keyfile

  b. **Mount Filesystems**:
   cryptsetup luksOpen /dev/nvme1n1p2 cryptroot --key-file /mnt/usb/luks-keyfile
   mount -o subvol=@ /dev/mapper/cryptroot /mnt
   mount -o subvol=@home /dev/mapper/cryptroot /mnt/home
   mount -o subvol=@data /dev/mapper/cryptroot /mnt/data
   mount /dev/nvme1n1p1 /mnt/boot

  c. **Chroot and Repair**:
   arch-chroot /mnt
   mkinitcpio -P
   sbctl sign -s /boot/EFI/Linux/arch.efi
   journalctl -u apparmor | grep -i DENIED
   sbctl status

  d. **Restore LUKS Header**:
   cryptsetup luksHeaderRestore /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
   sha256sum -c /mnt/usb/luks-header-backup.sha256

  e. **TPM Recovery**:
   - If TPM unlocking fails, use the LUKS passphrase or keyfile.
   - Wipe old TPM keyslot(s)
  ```bash
  mapfile -t TPM_SLOTS < <(cryptsetup luksDump /dev/nvme1n1p2 --dump-json-metadata \
    | jq -r '.tokens[] | select(.type == "systemd-tpm2") | .keyslots[]')

  for slot in "${TPM_SLOTS[@]}"; do
    echo "Wiping TPM keyslot $slot..."
    systemd-cryptenroll /dev/nvme1n1p2 --wipe-slot="$slot" || true
  done

  # Verify
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM OK"
  sbctl status | grep -q "Enabled" && echo "Secure Boot OK"

  f. **Rollback Snapshot**:
   - List snapshots:
   snapper --config root list
   - Identify the desired snapshot number from the output (e.g., 42).
   - Roll back:
   snapper --config root rollback 42
   - Repeat for home and data subvolumes:
   snapper --config home list
   snapper --config home rollback <snapshot-number>
   snapper --config data list
   snapper --config data rollback <snapshot-number>
   reboot

  g. **Verify and unmount USB**
  [ -f /mnt/usb/recovery.md ] || { echo "Error: Failed to create /mnt/usb/recovery.md"; exit 1; }
  [ -d /mnt/usb/sbctl-keys ] || { echo "Error: /mnt/usb/sbctl-keys not found"; exit 1; }
  sha256sum /mnt/usb/recovery.md > /mnt/usb/recovery.md.sha256
  cat /mnt/usb/recovery.md
  sudo umount /mnt/usb
  echo "WARNING: Store /mnt/usb/recovery.md, /mnt/usb/luks-header-backup, /mnt/usb/sbctl-keys, and their checksums in Bitwarden or an encrypted cloud."
  echo "WARNING: Keep the recovery USB secure to prevent unauthorized access."

  - Check USB contents
  lsblk | grep $usb_dev
  sudo mount /dev/$usb_dev /mnt/usb
  ls /mnt/usb/recovery.md /mnt/usb/recovery.md.sha256 /mnt/usb/luks-keyfile /mnt/usb/luks-header-backup /mnt/usb/sbctl-keys
  sha256sum -c /mnt/usb/recovery.md.sha256
  sha256sum -c /mnt/usb/luks-header-backup.sha256
  sudo umount /mnt/usb

  - Verify Bitwarden storage (manual)
  echo "WARNING: Store UEFI password, LUKS passphrase, /mnt/usb/luks-keyfile location, MOK password, /mnt/usb/recovery.md, /mnt/usb/luks-header-backup, /mnt/usb/sbctl-keys, and their checksums in Bitwarden or an encrypted cloud. Keep the recovery USB secure."
  read -p "Confirm all credentials and USB contents are stored in Bitwarden (y/n): " confirm
  [ "$confirm" = "y" ] || { echo "Error: Please store all data in Bitwarden."; exit 1; }
  ```
## Step 17: Backup Strategy

- Local Snapshots:
  ```bash
  # Managed by Snapper for @, @home, @data, excluding /var, /var/lib, /log, /tmp, /run.
  ```
- Install `restic` for backups:
  ```bash
  sudo pacman -S --noconfirm restic
  ```
- Verify & sign binary for Secure Boot
  ```bash
  sbctl verify /usr/bin/restic || sbctl sign -s /usr/bin/restic
  ```
- Pacman hook (auto-sign on updates)
  ```bash
  if ! grep -q "Target = restic" /etc/pacman.d/hooks/90-uki-sign.hook 2>/dev/null; then
    sudo tee -a /etc/pacman.d/hooks/90-uki-sign.hook >/dev/null <<'EOF'

  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = restic
  [Action]
  Description = Sign restic binary with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/restic
  EOF
  fi
  ```
- Excludes File:
  ```bash
  sudo mkdir -p /etc/restic
  sudo tee /etc/restic/excludes.txt >/dev/null <<'EOF'
  /tmp/*
  /var/cache/*
  /var/tmp/*
  /proc/*
  /sys/*
  /dev/*
  /run/*
  /mnt/*
  /media/*
  /lost+found/*
  /.swap/*
  /home/*/.cache
  /home/*/.local/share/Trash
  /home/*/.thumbnails
  /.snapshots
  */.snapshots
  /etc/pacman.d/mirrorlist*
  /etc/machine-id
  /var/log/journal/*
  /var/lib/libvirt/images/*
  /var/lib/flatpak/repo/*
  /var/lib/pacman/sync/*
  /home/*/.npm
  /home/*/.gradle
  /home/*/.cargo
  EOF
  ```
- Create a backup script:
  ```bash
  sudo tee /usr/local/bin/restic-backup.sh >/dev/null <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail

  # ----- CONFIGURATION (EDIT ONCE) -----
  REPO="/mnt/backup/restic-repo"          # <-- CHANGE TO YOUR MOUNTPOINT / SFTP URL
  HOSTNAME="$(hostname)"
  TAG="thinkbook"
  # -------------------------------------

  export RESTIC_CACHE_DIR="/var/cache/restic"
  export RESTIC_COMPRESSION="auto"

  # Ensure bitwarden session is active
  if ! bw status | grep -q '"status":"unlocked"'; then
    echo "Bitwarden CLI not unlocked – trying to unlock..."
    bw unlock --raw > /dev/null || { echo "Failed to unlock Bitwarden"; exit 1; }
  fi

  # Prevent concurrent runs
  exec 200>/var/lock/restic-backup.lock
  flock -n 200 || { echo "Another restic backup is already running"; exit 1; }

  # Unlock any stale locks
  restic unlock

  # Backup
  restic backup \
    --verbose \
    --one-file-system \
    --tag="$TAG" \
    --hostname="$HOSTNAME" \
    --exclude-caches \
    --exclude-if-present .nobackup \
    --exclude-file=/etc/restic/excludes.txt \
    /home /data /srv /etc

  # Prune
  restic forget \
    --keep-last 10 \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 6 \
    --keep-yearly 3 \
    --prune

  # Quick integrity check (5 GiB subset)
  restic check --read-data-subset=5G
  EOF
  sudo chmod +x /usr/local/bin/restic-backup.sh
  ```
- Create a Rebos backup script
  ```bash
  sudo tee /usr/local/bin/rebos-backup.sh > /dev/null <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail

  REBOS_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/rebos"
  BACKUP_NAME="weekly-$(date +%Y%m%d-%H%M%S)"
  LOG="/var/log/rebos-backup.log"

  echo "[$(date)] Starting Rebos backup: $BACKUP_NAME" | tee -a "$LOG"

  # Ensure rebos is in PATH
  export PATH="$HOME/.cargo/bin:$PATH"

  # Regenerate manifest from current system state
  rebos gen base --output "$REBOS_CONFIG/base.toml" | tee -a "$LOG"

  # Commit to local git (if initialized)
  if [ -d "$REBOS_CONFIG/.git" ]; then
    cd "$REBOS_CONFIG"
    git add base.toml
    git commit -m "Auto: weekly system manifest - $BACKUP_NAME" || echo "No changes to commit" | tee -a "$LOG"
  fi

  # Create named backup
  rebos backup create --name "$BACKUP_NAME" | tee -a "$LOG"

  # Prune old backups: keep last 8 weekly + 4 monthly
  rebos backup prune --keep-last 8 --keep-tagged monthly:4 | tee -a "$LOG"

  echo "[$(date)] Rebos backup completed: $BACKUP_NAME" | tee -a "$LOG"
  EOF

  sudo chmod +x /usr/local/bin/rebos-backup.sh
  ```  
- Systemd Service & Timer:
  ```bash
  sudo tee /etc/systemd/system/restic-backup.service >/dev/null <<'EOF'
  [Unit]
  Description=Restic incremental backup
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/restic-backup.sh
  Nice=19
  IOSchedulingClass=best-effort
  ProtectSystem=strict
  ProtectHome=false
  PrivateTmp=true
  EOF

  sudo tee /etc/systemd/system/restic-backup.timer >/dev/null <<'EOF'
  [Unit]
  Description=Daily restic backup
  Requires=restic-backup.service

  [Timer]
  OnCalendar=*-*-* 02:30:00
  RandomizedDelaySec=5m
  Persistent=true
  Unit=restic-backup.service

  [Install]
  WantedBy=timers.target
  EOF
  ```
- Enable Timers Services
  ```bash
  sudo systemctl enable --now restic-backup.timer
  ```
- Weekly full repo check
  ```bash
  sudo tee /etc/systemd/system/restic-check.service >/dev/null <<'EOF'
  [Unit]
  Description=Restic repository integrity check
  After=network-online.target

  [Service]
  Type=oneshot
  ExecStart=/usr/bin/restic check
  Nice=19
  EOF

  sudo tee /etc/systemd/system/restic-check.timer >/dev/null <<'EOF'
  [Unit]
  Description=Weekly restic repo check

  [Timer]
  OnCalendar=Sun *-*-* 03:00:00
  Persistent=true
  Unit=restic-check.service

  [Install]
  WantedBy=timers.target
  EOF

  sudo systemctl enable --now restic-check.timer
  ```
- First-run initialization (interactive)
  ```bash
  echo "=== RESTIC REPOSITORY INITIALIZATION ==="
  read -p "Enter full repository path (local dir or sftp:user@host:/path): " REPO
  sudo sed -i "s|^REPO=.*|REPO=\"$REPO\"|" /usr/local/bin/restic-backup.sh

  echo "You must now initialize the repository. The user running the service MUST own this repository."
  echo "If running as root (default for system service), use: sudo restic init --repo \"$REPO\""
  echo "If running as your user (recommended for Bitwarden), use: restic init --repo \"$REPO\""
  
  # Init repo (ask for secondary key file for offline recovery)
  restic init --repo "$REPO"
  echo "Save the repository password in Bitwarden (item: restic-repo)."
  read -p "Create a secondary key file for offline recovery? (y/N): " sec
  if [[ $sec =~ ^[Yy]$ ]]; then
    SECONDARY_KEY="/root/restic-secondary-key.txt"
    restic key add --new-password-file "$SECONDARY_KEY"
    echo "Store $SECONDARY_KEY securely (offline USB, encrypted vault)."
  fi
- Test + Notes
  ```bash
  echo "Running a quick test backup..."
  /usr/local/bin/restic-backup.sh && echo "Test backup succeeded!"
  systemctl list-timers --all
  journalctl -u restic-backup.timer -n 20
  journalctl -u rebos-backup.service -n 20
  rebos backup list

  # Restic provides **off-site / incremental** backups of /home, /data, /srv, /etc.
  # Check status any time:  restic snapshots --repo <path>
  # Restore example:
  # restic restore --target /tmp/restore latest --path /home/user/Documents
  # Weekly integrity: systemctl status restic-check.timer
  ```
## Step 18: Post-Installation Maintenance and Verification

- **a) Update System Regularly**:
  - Keep the system up-to-date:
    ```bash
    pacman -Syu --noconfirm || echo "pacman failed"
    paru -Syu --noconfirm || echo "paru failed"
    flatpak update -y || echo "flatpak failed"
    ```
- **b) Monitor Logs**:
  - Check for errors in system logs:
    ```bash
    journalctl -p 3 -xb
    journalctl -b -p err --since "1 hour ago"
    ```
- **c) Check Snapshots**:
  - Verify Snapper snapshots:
    ```bash
    snapper list
    snapper status 0..1
    ```
- **d) Verify Secure Boot**:
  - Confirm Secure Boot is active:
    ```bash
    sbctl status
    sbctl verify
    mokutil --sb-state
    ```
- **e) Test eGPU**:
  - Verify eGPU detection and rendering:
    ```bash
    lspci | grep -i amd
    DRI_PRIME=1 glxinfo | grep renderer
    supergfxctl -g
    DRI_PRIME=1 glxgears -info | grep "GL_RENDERER"
    ```
- **f) Firmware Updates**:
  ```bash

  fwupdmgr refresh --force
  fwupdmgr get-updates
  fwupdmgr update
  # After fwupdmgr update
  echo "WARNING: Firmware updates (BIOS, eGPU dock) will change TPM PCR values."
  echo "TPM auto-unlock will fail on next boot. You MUST enter your LUKS passphrase."
  echo "Firmware updated—TPM PCRs changed. Re-enrolling TPM..."
  echo "After booting, re-enroll the TPM:"
  echo "  systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2"
  echo "  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2"
  echo "WARNING: Firmware updates change PCRs. TPM auto-unlock fails once; enter passphrase."
  echo "If TPM fails (e.g., Secure Boot change):"
  echo "1. Enter LUKS Passphrase."
  echo "2. Run the automated fix script: sudo tpm-seal-fix"
  tpm2_pcrread sha256:7,11 > /etc/tpm-pcr-post-firmware.txt  # Backup new PCRs
  reboot
  ```
- **g) TPM seal breaks Maintenance**:
  ```bash
  # If the TPM seal breaks (e.g., hook failure). Update the permanent policy file (captures new PCRs 7 and 11)
  # Run **only** when you know PCR 7 or 11 changed:
  #   • Firmware/BIOS update
  #   • Secure Boot DB change
  #   • UKI rebuilt with different cmdline
  
  sudo tpm-seal-fix
  
  # The script re-measures the *current* UKI into PCR 11 automatically
  # (systemd-stub does this on every boot) and re-enrolls the LUKS
  # keyslot against the same public key + PCR 7+11.
  ```
- **h) Security Audit**:
  ```bash
  lynis audit system > /root/lynis-report-$(date +%F).txt
  rkhunter --check --sk > /root/rkhunter-report-$(date +%F).log
  aide --check | grep -v "unchanged" > /root/aide-report-$(date +%F).txt
  ```
- **i) Adopt AppArmor.d for Full-System Policy and Automation (executed this one after a few months only)**:
  ```bash
  # Enable early policy caching (required for boot-time FSP)
  sudo mkdir -p /etc/apparmor.d/cache
  sudo sed -i '/^#.*cache-loc/s/^#//' /etc/apparmor/parser.conf
  sudo sed -i 's|.*cache-loc.*|cache-loc = /etc/apparmor.d/cache|' /etc/apparmor/parser.conf

  # Check timer status
  systemctl status apparmor.d-update.timer

  # Check timer last run
  journalctl -u apparmor.d-update.service -n 20

  # Confirm profiles are cached
  ls /etc/apparmor.d/cache/ | wc -l   # Should show 1000+ files
  aa-status | grep "profiles are loaded" | head -1

  # Tune from logs (run after normal usage)
  echo "Use the system for a while, then run:"
  echo "  sudo aa-logprof   # interactive"
  echo "  sudo aa-genprof <binary>   # for new apps"

  # Switch to enforced mode once satisfied
  read -p "Ready to enforce AppArmor.d FSP? (y/N): " confirm_fsp
  [[ $confirm_fsp =~ ^[Yy]$ ]] || exit 1
  sudo just fsp-enforce
  sudo apparmor_parser -r /usr/share/apparmor.d/*
  sudo systemctl restart apparmor
  aa-status | grep -E "(profiles are in enforce mode|complain)"
  echo "AppArmor FSP is now ENFORCED."

  # Confirm no stray vanilla profiles interfere
  if [ -f /etc/appamor.d/disable ] || ls /etc/apparmor.d/*.conf >/dev/null 2>&1; then
    echo "Warning: Legacy profiles in /etc/apparmor.d/ — consider removing or disabling."
  fi
  # echo "AppArmor.d FSP is now ENFORCED.

  # Warm cache on boot (critical for UKI + Secure Boot)
  sudo mkdir -p /etc/systemd/system/apparmor.service.d
  sudo tee /etc/systemd/system/apparmor.service.d/cache-warm.conf > /dev/null <<'EOF'
  [Service]
  ExecStartPre=/usr/bin/apparmor_parser -r /usr/share/apparmor.d/*
  EOF

  # (Optional) Add user-specific tunables
  sudo mkdir -p /etc/apparmor.d/tunables/local
  echo '@{XDG_RUNTIME_DIR}=/run/user/@{UID}' | sudo tee /etc/apparmor.d/tunables/local/xdg.conf
  sudo apparmor_parser -r /etc/apparmor.d/tunables/*

  # Reboot to apply cache & early load
  echo "Rebooting in 10 seconds to apply AppArmor.d cache..."
  sleep 10
  reboot
  ```
- **j) Gentoo Migration: How to Use This Later**:
  ```bash
  # On Gentoo system:
  tar -xzf arch_luks_uki_config_*.tar.gz -C /tmp/arch-config

  # Kernel
  cp /tmp/arch-config/config-* /usr/src/linux/.config
  cd /usr/src/linux
  make olddefconfig

  # USE flags
  cat /etc/gentoo-prep/desired-use-flags.txt >> /etc/portage/make.conf

  # Packages
  # Use arch-packages.txt + mapping to build @world
  ```
- **k) Final Reboot & Lock**:
  ```bash
  mkinitcpio -P
  
  # Sign only unsigned EFI binaries
  sbctl sign -s $(sbctl verify | grep "not signed" | awk '{print $1}')

  sbctl verify
  echo "System locked and ready. Final reboot recommended."
  reboot
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
- Backup Monitor in Astal
  ```bash
  // ~/.config/ags/widgets/backup-status.ts
  import { Widget, Service, Utils } from 'astal/gtk3';
  import Systemd from 'gi://AstalSystemd';

  const systemd = Systemd.get_default();

  export default () => Widget.Box({
    className: "backup-status",
    spacing: 8,
    children: [
        Widget.Icon({
            icon: "backup-symbolic",
        }),
        Widget.Label({
            label: systemd.unit("restic-backup.service")
                .bind("ActiveState")
                .as(state => {
                    if (state === "active") return "✓ Running";
                    if (state === "inactive") return "✓ Idle";
                    if (state === "failed") return "✗ Failed";
                    return "? Unknown";
                }),
        }),
        Widget.Button({
            label: "Run",
            onClicked: () => Utils.execAsync("systemctl start restic-backup.service"),
        }),
    ],
  });
  ```
- Logwatch
  ```bash
  // ~/.config/ags/widgets/logwatch.ts
  import { Widget, Utils } from 'astal/gtk3';

  export default () => Widget.Box({
    className: "logwatch",
    spacing: 6,
    children: [
      Widget.Icon({ icon: "security-high-symbolic" }),
      Widget.Label({
        label: Utils.execAsync(["journalctl", "-p", "err", "-n", "1", "--no-pager"])
          .then(out => out.trim() || "No errors")
          .catch(() => "Error"),
      }),
    ],
  });
  ```
