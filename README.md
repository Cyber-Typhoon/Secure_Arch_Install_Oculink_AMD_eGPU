# Secure Arch Installation for an Intel Lenovo ThinkBook using an AMD eGPU via OCuLink

## Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)

- This guide provides a **comprehensive action plan** for installing and configuring **Arch Linux** on a **Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H** with **Intel iGPU (Arc 140T)**, no dGPU, using **GNOME Wayland**, **BTRFS**, **LUKS2**, **TPM2**, **AppArmor**, **systemd-boot with Unified Kernel Image (UKI)**, **Secure Boot**, **run0** and an **OCuP4V2 OCuLink GPU Dock ReDriver with an AMD eGPU**.
- The laptop has **two M.2 NVMe slots**; we will install **Windows 11 Pro** on one slot (`/dev/nvme0n1`) for BIOS and firmware updates, and **Arch Linux** on the second slot (`/dev/nvme1n1`).
- **Observation**: The `linux-hardened` kernel and hardened malloc are avoided due to complexities with eGPU setup, performance penalties, more specific linux-hardened does not support hibernation, hardened malloc will make games crash randomly and Firefox's browsers performance will significantly decrease because replacemant of jemalloc which is highly optimized for browser rendering. Instead, we manually incorporate security enhancements inspired by `linux-hardened`, such as kernel parameters for memory safety and mitigations. If desired, post-installation, linux-hardened and hardened malloc can be explored.
- **Attention**: Commands involving `dd`, `mkfs`, `cryptsetup`, `parted`, and `efibootmgr` can **destroy data** if executed incorrectly. **Re-read each command multiple times** to confirm the target device/partition is correct. Test **LUKS and TPM unlocking** thoroughly before enabling **Secure Boot**, and verify **Secure Boot** functionality before configuring the **eGPU**.
- Unfortunatelly this CPU doesn't support Intel Total Memory Encryption because it isn't a vPRO model. In case you have a vPRO Intel CPU activate the TME in the BIOS.

## Step 1: Verify Hardware

- Access the **UEFI BIOS** by pressing `F1` at boot:
  - Enable **TPM 2.0** (Security Chip) under the Security menu.
  - Enable **Intel VT-d** (IOMMU) for improved eGPU and virtualization support.
  - Set a **strong UEFI BIOS password** (at least 12 characters, mid case, numbers, and symbols).
  - **Store the UEFI BIOS password in Bitwarden** or another secure password manager.
  - Temporarily disable **Secure Boot** in the UEFI settings to simplify initial setup.
  - Reset to **Setup Mode** in the BIOS.
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
- Configure Windows to use UTC time (prevents dual-boot time drift):
  ```powershell
  # In Windows (Administrator PowerShell):
  reg add "HKLM\System\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /d 1 /t REG_DWORD /f
  
  # Restart Time service to apply
  net stop w32time && net start w32time
  
  echo "Windows now uses UTC (matches Linux hardware clock)"
  ```
- Enable **tamper protection** and **real-time protection**:
  - Navigate to **Settings > Windows Security > Virus & Threat Protection** and enable both.
- Back up the **Windows EFI partition UUID** for dual-boot compatibility:
  ```powershell
  # Insert a USB drive (e.g., E:)
  # CMD
  mountvol Z: /S
  robocopy Z:\ E:\EFI-Backup /MIR /XJ /XF BCD* /R:0 /W:0 # Replace E: with the USB drive letter
  bcdedit /export E:\EFI-Backup\BCD-Backup # Replace E: with the USB drive letter
  mountvol Z: /D
  # Powershell (Identify first in the Disk Management which is the Windows Disk, it might be 0 or 1, in this example is 1)
  Get-Partition -DiskNumber 1 -PartitionNumber 1 | Select-Object -ExpandProperty Guid | Out-File E:\windows-esp-uuid.txt # Replace E: with the USB drive letter
  ```
- **WARNING**: Store `E:\EFI-Backup` and `E:\windows-esp-uuid.txt` securely in **Bitwarden** or an encrypted cloud service.
- **WARNING**: Ensure the USB drive is encrypted or physically secure to prevent unauthorized access to the EFI backup.

## Milestone 1: After Step 2 (Windows Installation) - Can pause at this point

## Step 3: Prepare Installation Media

- Download the latest **Arch Linux ISO** from https://archlinux.org/download/.
- Verify the ISO signature to ensure integrity:
  - Follow instructions on the Arch Linux website for `gpg` verification.
  - Example:
    ```bash
    # Windows Powershell
    Get-FileHash .\archlinux-2026.02.01-x86_64.iso -Algorithm SHA256
    # Linux
    gpg --keyserver-options auto-key-retrieve --verify archlinux-<version>-x86_64.iso.sig

    # Compare to Arch Download page
    ```
- Create a bootable USB drive:
  - Use **Rufus** in Windows, selecting **DD mode** for reliable writing. The alternatives are KDE ISO Image Writer and USBImager but Rufus should be a good option here.
  - **Avoid Ventoy** and **Balena Etcher** due to potential trackers and reliability issues.
- Test the USB by rebooting and selecting it in the **BIOS boot menu** (press `F1`).
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
  ```
- Verify network connectivity in the live environment:
  ```bash
  ping -c 3 archlinux.org
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
- Before proceeding with partitioning, identify which drive is which. Windows Disk 0/1 numbering does NOT match Linux device names.
  ```bash  
   # List all disks
   lsblk -o NAME,SIZE,MODEL,FSTYPE,LABEL,MOUNTPOINT
   
   # Identify Windows drive (look for EFI + NTFS partitions)
   fdisk -l | grep -A 10 "Disk /dev/nvme"
   
   # Note the device names:
   # - Windows drive: /dev/nvmeXn1 (has EFI partition ~260MB, NTFS partition)
   # - Empty Arch drive: /dev/nvmeYn1 (no partitions)

  **VERIFY BEFORE PROCEEDING**:
   - If Windows is on `/dev/nvme0n1` and empty drive is `/dev/nvme1n1`:
     **Follow Step 4 exactly as written**
   
   - If Windows is on `/dev/nvme1n1` and empty drive is `/dev/nvme0n1`:
     **SWAP all device names in Step 4**:
     - Replace `/dev/nvme1n1` → `/dev/nvme0n1` (for Arch)
     - Avoid touching `/dev/nvme0n1` → `/dev/nvme1n1` (Windows)

  **Double-check before any destructive command**:
   # Before running parted or cryptsetup, verify disk is empty:
   lsblk /dev/nvmeXn1   # Should show no partitions if new drive
  ```
## Step 4: Pre-Arch Installation Steps

- **a) Partition the Second NVMe M.2 (/dev/nvme1n1)**:
  - Check optimal sector size (should be 512 for most NVMe; 4096 for some)
    ```bash
    cat /sys/block/nvme1n1/queue/logical_block_size  # Expected: 512 or 4096
    cat /sys/block/nvme1n1/queue/physical_block_size
    # Review your partitioning scheme: This creates a 1GiB ESP and full-disk encrypted root. Adjust sizes if needed (e.g., for multi-partition setups).
    ```
  - NVMe Sanitize:
    ```bash
    # If sanitize doesn't work use the format command only:
    nvme sanitize /dev/nvme1 --sanact=0x02  # Block erase (quick, no overwrite)
    nvme sanitize-log /dev/nvme1  # Monitor progress
    partprobe  # Reload partition table (clears old Windows remnants)

    # Alternatice to sanitize, format:
    nvme format /dev/nvme1n1 -l 0
    ```
  - Create a GPT partition table with an ESP and a LUKS partition:
    ```bash
    fdisk /dev/nvme1n1
    # # At fdisk: g, n (1, +1G), t (1, EF), n (2, default), t (2, 83), p, w
    g (create new GPT partition table)
    n (new partition), 1 (partition number), default first sector, +1G (size for ESP)
    t (change type), 1 (partition), EF (EFI System)
    n (new partition), 2 (partition number), default first sector, default last sector (use remainder)
    t (change type), 2 (partition), linux (Linux filesystem—default, but confirm)
    p (print table to verify)
    w (write changes and exit)
    fdisk -l /dev/nvme1n1
    ```
  - Verify partitions:
    ```bash
    lsblk -f /dev/nvme0n1 /dev/nvme1n1  # Confirm /dev/nvme0n1p1 (Windows ESP) 
    fdisk -l # This should list the partitions in case the command above didn't return any outputs
    efibootmgr  # Check if UEFI recognizes Windows boot
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
    # PBKDF choice is irrelevant to GRUB because boot is via UKI; systemd unlocks LUKS.
    # Use this first command if your threat model isn't aggresive, if it is use the alternative:
    cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --hash sha512 --iter-time 5000 --key-size 512 --pbkdf argon2id --sector-size 4096 /dev/nvme1n1p2
    # (OPTIONAL ALTERNATIVE) Add dm-integrity for tampering detection (wiki recommends for high security; ~10% perf hit), for a gaming laptop this is a skip, use the command above:
    cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --hash sha512 --iter-time 5000 --key-size 512 --pbkdf argon2id --integrity hmac-sha256 /dev/mapper/cryptroot cryptintegrit --sector-size 4096 /dev/nvme1n1p2
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
  - Backup the keyfile to a USB:
    ```bash
    mkdir -p /mnt/usb
    lsblk  # Identify USB device (e.g., /dev/sdX1)
    mount /dev/sdX1 /mnt/usb # **Replace sdX1 with USB partition confirmed via lsblk previously executed**
    cp /mnt/crypto_keyfile /mnt/usb/crypto_keyfile
    # "WARNING: Store the LUKS keyfile (/mnt/usb/crypto_keyfile) securely in Bitwarden for recovery purposes."
    ```
  - **LUKS for rd.luks.uuid and Partition UUID**:
    - After encrypting `/dev/nvme1n1p2` with LUKS, retrieve its UUID:
      ```bash
      LUKS_UUID=$(cryptsetup luksUUID /dev/nvme1n1p2)
      echo $LUKS_UUID  # Should output a UUID like a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8
      ```
      - **Record this UUID** for use in `/etc/crypttab` and kernel parameters (`rd.luks.uuid=...`).
    - Get the partition UUID (rarely used):
      ```bash
      PART_UUID=$(blkid -s PARTUUID -o value /dev/nvme1n1p2)
      echo $PART_UUID  # Should output a UUID like 123e4567-e89b-12d3-a456-426614174000
      ```
      - **Record this UUID** for kernel parameters and `/etc/crypttab` mappings.
- **d) Create BTRFS Filesystem and Subvolumes**:
  - Create the BTRFS filesystem:
    ```bash
    mkfs.btrfs /dev/mapper/cryptroot
    mount /dev/mapper/cryptroot /mnt
    ```
  - **Root Filesystem UUID**:
    - After creating the BTRFS filesystem on `/dev/mapper/cryptroot`, obtain its UUID:
      ```bash
      ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
      echo $ROOT_UUID  # Should output a UUID like 48d0e960-1b5e-4f2c-8caa-...
      ```
      - **Record this UUID** for the bootloader (`root=UUID=...`) and `/etc/fstab`.
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
    mkdir -p /mnt/var/lib
    mkdir -p /mnt/var/log
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
  - Set a qgroup limit (e.g., 100GB) on the @snapshots subvolume
    ```bash
    btrfs quota enable /mnt
    btrfs qgroup create 0/1 /mnt/.snapshots        # 0/1 is an arbitrary but safe ID
    btrfs qgroup limit 100G 0/1 /mnt/.snapshots
    # Verify
    btrfs qgroup show /mnt
    # NOTE: Btrfs qgroup limits persist via filesystem metadata.
    # Do NOT add qgroup rules to /etc/fstab.
    ```
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
    mkdir -p /mnt/etc
    echo $SWAP_OFFSET > /mnt/etc/swap_offset # Save for later use
    echo "SWAP_OFFSET: $SWAP_OFFSET"  # Record this number. Should output a numerical offset like 12345678
    ```
    - **Record this SWAP_OFFSET value**. Insert it directly into your systemd-boot kernel parameters (e.g., in /etc/mkinitcpio.d/linux.preset) and /etc/fstab (for the swapfile entry with resume_offset=).
    - **Note**: This offset is critical for hibernation support and must be accurate—recompute if the swap file changes.
  - BTRFS OFFICIAL VERIFICATION
    ```bash
    btrfs inspect-internal map-swapfile -r /mnt/swap/swapfile > /dev/null \
      && echo "Swapfile 100 % BTRFS-compliant" \
      || { echo "FATAL: map-swapfile failed"; exit 1; }
    ```
  - Add to fstab (REPLACE $SWAP_OFFSET with the computed value)
    ```bash
    grep -q swapfile /mnt/etc/fstab || cat <<EOF >> /mnt/etc/fstab
    /swap/swapfile none swap defaults,discard=async,noatime,resume_offset=$SWAP_OFFSET 0 0
    EOF
    ```
  - Validate the swap subvolume:
    ```bash
    swapon --show | grep swapfile && swapoff /mnt/swap/swapfile
    ```
- **f) Generate fstab**:
  - Generate the initial fstab:
    ```bash
    genfstab -U /mnt | tee /mnt/etc/fstab
    ```
  - **Record the Arch and Windows UUID**:
  - List ESP UUIDs to confirm:
    ```bash
    blkid | grep -E 'nvme0n1p1|nvme1n1p1'
    ```
  - **Remove the generic pacstrap fstab, we already generated the correct one**:
    ```bash
    rm /mnt/etc/fstab.pacnew
    ```
  - Manually edit with nano `/mnt/etc/fstab` to verify subvolume options and add security settings.
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
      UUID=$ARCH_ESP_UUID /boot vfat defaults,noatime,umask=0077,dmask=0077,fmask=0077 0 2
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
    - Verify the generated fstab:
      ```bash
      cat /mnt/etc/fstab
      ```
- **g) Address some potential little pitfalls**:
  - Verify connectivity:
    ```bash
    ping -c 3 archlinux.org
    ```
  - Copy resolver configuration:
    ```bash
    cp /etc/resolv.conf /mnt/etc/resolv.conf
    ```
  - Create vconsole.conf that might be requested by the pacstrap:
    ```bash
    # Create a minimal vconsole.conf (optional):
    echo "KEYMAP=us" > /mnt/etc/vconsole.conf
    echo "FONT=ter-v16n" >> /mnt/etc/vconsole.conf
    ```
  - Observations
    ```bash
    # Eventually we might see the following excuting the pacstrap:
    # "Secureboot key directory doesn't exist, not signing! " --> It can be safely ignored, the Secure Boot is addressed later
    ```
## Milestone 2: After Step 4f (fstab Generation) - Can pause at this point

## Step 5: Install Arch Linux

- Configure the mirrorlist for faster package downloads:
  ```bash
  pacman -Sy reflector
  reflector --country "United States" --country "Canada" --latest 15 --protocol https --sort rate --save /etc/pacman.d/mirrorlist
  #change country to wherever you are at the moment
  ```
- Enable parallel downloads
  ```bash
  sed -i 's/^#ParallelDownloads/ParallelDownloads/' /etc/pacman.conf
  ```
- Install the base system and necessary packages:
  ```bash
  pacstrap /mnt \
  # Core
  base base-devel linux linux-lts linux-firmware mkinitcpio archlinux-keyring pacman-contrib \
  \
  # Boot / Encryption
  intel-ucode sbctl cryptsetup tpm2-tools tpm2-tss tpm2-abrmd btrfs-progs efibootmgr dosfstools \
  \
  # Hardware / Firmware
  sof-firmware intel-media-driver fwupd nvme-cli wireless-regdb \
  \
  # Graphics
  mesa mesa-demos mesa-utils vulkan-intel intel-compute-runtime \
  vulkan-radeon vulkan-icd-loader lib32-vulkan-icd-loader vdpauinfo xorg-xwayland intel-gpu-tools lact-libadwaita \
  \
  # Audio
  pipewire wireplumber pipewire-pulse pipewire-alsa pipewire-jack alsa-utils alsa-firmware rtkit gst-plugin-pipewire \
  \
  # System
  sudo polkit udisks2 thermald acpi acpid ethtool namcap dmidecode apparmor \
  \
  # Network / Install
  networkmanager openssh rsync reflector arch-install-scripts iwd \
  \
  # User / DE
  zsh git jq flatpak pacman-contrib devtools micro man-db man-pages
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
- Initialize apparmor service:
  ```bash
  systemctl enable apparmor
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
  pacman -Syu --noconfirm
  pacman-key --init
  pacman-key --populate archlinux
  ```
- Add the `xe` and `i915` module for early kernel mode setting (KMS) to support Intel iGPU:
  ```bash
  # Load 'xe' first. 'i915' is kept as a fallback but likely won't bind to the iGPU if xe claims it.
  echo 'MODULES=(xe i915)' >> /etc/mkinitcpio.conf
  mkinitcpio -P
  ```

## Step 6: System Configuration

- Set timezone, locale, and hostname:
  ```bash
  ln -sf /usr/share/zoneinfo/America/Los_Angeles /etc/localtime
  hwclock --systohc
  # Force the system to treat the hardware clock as UTC (Production Standard)
  timedatectl set-local-rtc 0 --adjust-system-clock
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
  username="Enter your username"

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

  # Enforce 440 permissions (Read-only for owner/group) for best practice security.
  chown root:root /etc/sudoers
  chmod 440 /etc/sudoers
  echo "Secured /etc/sudoers permissions (440)."
  ```
- Enable essential services
  ```bash
  systemctl enable NetworkManager
  systemctl enable systemd-timesyncd                   
  systemctl enable bluetooth                  
  systemctl enable thermald               
  systemctl enable acpid                  
  systemctl enable fwupd-refresh.timer    
  systemctl enable paccache.timer  
  ```
- Configure PipeWire audio latency (prevents robotic/delayed audio):
  ```bash
  # Create PipeWire quantum config to fix browser video audio issues
  mkdir -p /home/$USERNAME/.config/pipewire/pipewire.conf.d
  cat > /home/$USERNAME/.config/pipewire/pipewire.conf.d/99-latency.conf <<'EOF'
  context.properties = {
    default.clock.rate          = 48000
    default.clock.allowed-rates = [ 44100 48000 88200 96000 ]
    # NOTE (Feb 2026): PipeWire 1.6+ has improved adaptive scheduling.
    # This quantum override fixes browser audio crackling but may be unnecessary on newer PipeWire.
    # If experiencing latency or XRuns, consider removing these override below and relying on auto-scheduling:
    default.clock.quantum       = 800
    default.clock.min-quantum   = 512
    default.clock.max-quantum   = 1024
  }
  EOF

  # Fix ownership (critical - file must be owned by the user):
  chown -R $USERNAME:$USERNAME /home/$USERNAME/.config/pipewire

  # Verify it was created correctly:
  ls -la /home/$USERNAME/.config/pipewire/pipewire.conf.d/99-latency.conf
  # Should show: -rw-r--r-- 1 username username ...
 
  echo "PipeWire latency configured (prevents robotic audio in browsers)"
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
- NetworkManager Configuration (tells NetworkManager to prefer iwd over the default wpa_supplicant)
  ```bash
  mkdir -p /etc/NetworkManager/conf.d
  cat <<EOF > /etc/NetworkManager/conf.d/wifi-backend.conf
  [device]
  wifi.backend=iwd # Do not manually enable iwd.service with systemctl enable. NetworkManager will automatically start and manage the iwd daemon when needed.
  wifi.scan-rand-mac-address=yes
  wifi.iwd.autoconnect=yes


  [connection]
  wifi.cloned-mac-address=stable
  ethernet.cloned-mac-address=random
  EOF

  # Ensure iwd uses the same randomization logic internally
  mkdir -p /etc/iwd
  cat <<EOF > /etc/iwd/main.conf
  [General]
  AddressRandomization=network
  AddressRandomizationRange=full
  EOF
  ```
- Shell Configuration — Add to ~/.zshrc or ~/.bashrc
  ```bash
  cat << 'EOF' >> /home/$username/.zshrc
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

  # Modern CLI tools alias:
  if [[ $- == *i* ]]; then
  alias dig='dog'
  alias btop='btm'
  alias iftop='bandwhich --immediate --tree'
  alias cd='z'

  # Ignore trivial & sensitive commands
  setopt HIST_IGNORE_SPACE
  setopt HIST_REDUCE_BLANKS
  export HISTSIZE=5000
  export SAVEHIST=5000
  export HISTFILE=~/.zsh_history

  # Don't record obvious secrets
  export HISTIGNORE="*password*:*token*:*secret*:*--key*"

  # Optional: make sudo preserve these aliases when need
  # Trailing space make it happen
  alias sudo='sudo '
  fi

  # Safe update alias
  alias update='update-system'
  # echo "Run 'update' weekly. Use 'paru -Syu' for full control."
  # NOTE: The following are now system-wide tools, not aliases:
  # - fix-tpm  -> /usr/local/bin/fix-tpm (script)
  # - yay      -> /usr/local/bin/yay (symlink to paru)
  # - sysctl/systeroid -> separate tools (no alias, use each for this purpose)

  # Completion 

  autoload -Uz compinit
  compinit

  zstyle ':completion:*' menu select
  zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
  zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"

  source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
  source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

  # Suggestion color (Srcery stone color)
  ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=#918175"

  source /home/zureta/.config/broot/launcher/bash/br
  # Note: XDG variables and PATH are handled by ~/.profile on login.
  # We append PATH here as a fallback for non-login interactive shells.
  [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && export PATH="$PATH:$HOME/.local/bin"

  # ─── Srcery Welcome Banner ─────────────────────────────────────────────────────
  # Paste into ~/.zshrc — call _welcome at the very END of the file so all
  # aliases (update, paru, etc.) are already defined when it runs.
  # ───────────────────────────────────────────────────────────────────────────────

  _welcome() {
    # ── Srcery palette via standard ANSI codes ──────────────────────────────────
    local reset=$'\e[0m'
    local yellow=$'\e[33m'         # Srcery Yellow       #FBB829  warm amber
    local bright_white=$'\e[97m'   # Srcery Bright White  #FCE8C3 cream
    local bright_black=$'\e[90m'   # Srcery Bright Black  #918175 muted stone
    local cyan=$'\e[36m'           # Srcery Cyan          #0AAEB3 cool teal
    local bright_cyan=$'\e[96m'    # Srcery Bright Cyan   #2BE4D0 electric
    local green=$'\e[32m'          # Srcery Green         #519F50  forest
    local orange=$'\e[38;5;202m'   # Srcery Orange        #FF5F00  xterm 202

    # ── Dynamic values ──────────────────────────────────────────────────────────
    local date_str
    date_str=$(date '+%A, %B %d, %Y')

    # ── Helpers ─────────────────────────────────────────────────────────────────
    # _tool new old  — prints "  new  instead of  old"
    _tool() {
      printf "  ${bright_cyan}%-6s${reset}${bright_black}instead of  ${reset}${bright_black}%s${reset}\n" "$1" "$2"
    }

    # ── Layout ──────────────────────────────────────────────────────────────────
    local stripe="${yellow}▪▪▪${reset}"
    local rule="${bright_black}────────────────────────────────${reset}"
    local sep="${bright_black} · ${reset}"

    print "  ${stripe}  ${bright_white}Welcome back!${reset}  ${stripe}"
    print "  ${rule}"
    printf "  ${bright_black}%-6s${reset}${cyan}%s${reset}\n" "Date" "$date_str"
    print "  ${rule}"
    _tool "rg"    "grep"
    _tool "eza"   "ls"
    _tool "bat"   "cat"
    _tool "dua"   "du and ncdu"
    _tool "procs" "ps"
    print "  ${rule}"
    print "  ${bright_black}run ${reset}${orange}update${reset}${bright_black} to update the system${reset}"
  }

  # Call at end of .zshrc — after aliases, after PATH, after everything.
  _welcome

  # ─── Reproducible Packages ────────────────────────────────────────────────────────────
  repropkg() {
    local pkg="$1"
    shift
    local ver=$(pacman -Q "$pkg" | awk '{print $2}')
    local file
    # Try x86_64 first, then any
    file=$(ls /var/cache/pacman/pkg/${pkg}-${ver}-x86_64.pkg.tar.zst \
              /var/cache/pacman/pkg/${pkg}-${ver}-any.pkg.tar.zst 2>/dev/null | head -1)
    if [[ -z "$file" ]]; then
      echo "==> ERROR: could not find cached package for ${pkg}-${ver}"
      return 1
    fi
    repro "$@" "$file"
  }

  # ─── Starship ────────────────────────────────────────────────────────────
  eval "$(starship init zsh)" 

  # ─── fzf ────────────────────────────────────────────────────────────

  if command -v fzf >/dev/null 2>&1; then
    source <(fzf --zsh)
  fi

  # ─── zoxide ─────────────────────────────────────────────────────────

  if command -v zoxide >/dev/null 2>&1; then
    eval "$(zoxide init zsh)"
    alias cd='z'
  fi
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
  echo "WARNING: ALL DATA ON THE USB WILL BE ERASED! "
  mkdir -p /mnt/usb
  lsblk  # Identify USB device
  mkfs.fat -F32 /dev/sdX1  # Replace sdX1 with USB partition
  mount /dev/sdX1 /mnt/usb
  cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/usb/luks-header-backup
  sha256sum /mnt/usb/luks-header-backup > /mnt/usb/luks-header-backup.sha256
  sync
  umount /mnt/usb
  echo "WARNING: Store /mnt/usb/luks-header-backup in Bitwarden or an encrypted cloud."
  echo "WARNING: Primary LUKS passphrase must be stored offline (paper or password manager)."
  echo "WARNING: TPM unlocking may fail after firmware updates; keep the LUKS passphrase in Bitwarden."
  echo "WARNING: Verify the LUKS header backup integrity with sha256sum before storing."
  ```

## Milestone 4: After Step 7 (Back up the LUKS header for recovery) - Can pause at this point

## Step 8: Configure Boot, UKI, Secure Boot, and Hooks (Last Step Inside chroot)

- Install TPM tools:
  ```bash
  pacman -S --noconfirm tpm2-tools tpm2-tss systemd-ukify plymouth 
  ```
- Capture variables:
  ```bash
  LUKS_UUID=$(cryptsetup luksUUID /dev/nvme1n1p2)
  ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
  ```
- Configure Unified Kernel Image (UKI):
  ```bash
  # Dynamic Resume Offset Calculation (REQUIRED for BTRFS swapfile)
  RESUME_OFFSET=$(btrfs inspect-internal map-swapfile -r /swap/swapfile)
  if [[ -z "$RESUME_OFFSET" ]]; then
      echo "ERROR: resume_offset not found – check swapfile and fstab! "
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
  sed -i 's/^HOOKS=.*/HOOKS=(systemd keyboard autodetect microcode modconf kms sd-vconsole plymouth block sd-encrypt filesystems resume)/' /etc/mkinitcpio.conf
  echo "Updated /etc/mkinitcpio.conf HOOKS."

  # Configure linux.preset (defines the kernel command line for UKI)
  # rd.luks.uuid is now optional due to crypttab.initramfs, simplifying the cmdline.
  # LUKS configuration is intentionally not passed via kernel parameters.
  # TPM auto-unlock is handled exclusively via /etc/crypttab.initramfs + sd-encrypt hook.

  # This creates the standard file that UKI builders (like ukify) use by default
  mkdir -p /etc/kernel
  cat << EOF > /etc/kernel/cmdline
  root=UUID=$ROOT_UUID rootflags=subvol=@ resume=UUID=$ROOT_UUID resume_offset=$RESUME_OFFSET rw quiet splash intel_iommu=on amd_iommu=on iommu=pt pci=pcie_bus_perf randomize_kstack_offset=on hash_pointers=always mitigations=auto page_alloc.shuffle=1 vsyscall=none debugfs=off vdso32=0 proc_mem.force_override=never kfence.sample_interval=100 rd.systemd.show_status=auto rd.udev.log_priority=3 lsm=landlock,lockdown,yama,integrity,apparmor,bpf lockdown=integrity i915.force_probe=!7d51 xe.force_probe=7d51 xe.enable_psr=0 split_lock_detect=off systemd.stub_measured_sections=0
  EOF
  # Double check if the $ROOT_UUID and $RESUME_OFFSET are numerical and not variables.

  # Main Preset (linux)
  tee /etc/mkinitcpio.d/linux.preset > /dev/null << EOF
  PRESETS=('default')
  ALL_kver="/boot/vmlinuz-linux"
  default_uki="/boot/EFI/Linux/arch.efi"
  all_config="/etc/mkinitcpio.conf"
  EOF
  echo "Created /etc/mkinitcpio.d/linux.preset."
  # Monitor after Kernel 6.15+ remove xe.force_low_latency=1 and xe.enable_psr=0. These were used to prevent the iGPU idle state causing pop-up asking to close (force to quit) applications like Steam and Brave. 
  # Remove any i915.* parameters. Xe driver is default and stable for Meteor Lake (Core Ultra 7 255H) on kernel 6.12+.
  # No xe.force_probe needed. i915 is kept in MODULES (line 2985) as fallback only.
  # Mesa 26.0+ includes BTI prefetch for Intel ANV (better Arc 140T Vulkan performance) and ACO compiler for RadeonSI (faster AMD shader compile).
  # If when we start using the laptop we experience random freezes add i915.enable_dc=0, test if resolves, if not update intel_idle.max_cstate=1. Source: https://wiki.archlinux.org/title/Intel_graphics#Crash/freeze_on_low_power_Intel_CPUs
  # i915.enable_psr=0 → prevents random black screens on Meteor Lake OLED panels
  # pcie_bus_perf,realloc=1 → required for stable >200 W power delivery over OCuLink
  # processor.max_cstate=1 intel_idle.max_cstate=1 → stops random freezes when eGPU is plugged
  # add this after iommu,strict=1 in case AMD eGPU has some issues amdgpu.dcdebugmask=0x4 amdgpu.gpu_recovery=1 amdgpu.noretry=0 \
  # consider adding intel_iommu=igfx_off if you run into problems using the Xe iGPU for display and the AMD eGPU for rendering
  # hardened_usercopy=1 - Mostly redundant on modern kernels
  # slab_debug=P - Performance hit + little real desktop benefit
  # pti=on - Already auto-managed
  # iommu.strict=1 - Breaks some DMA paths (esp. eGPU edge cases) - “Enable iommu.strict=1 only if DMA misbehavior is observed.”
  # intel_idle.max_cstate=2 - Power + thermal penalty
  # Hibernation is intentionally unavailable until Step 15
  # systemd.stub_measured_sections=0 --> opt-out for systemd-stub’s TPM measurements of the UKI sections (PCR 11). If we decide to use PCR 11 on the TPM2 we need to remove this.
  

  # LTS preset (atomic copy, just rename the UKI)
  sed "s/arch\.efi/arch-lts\.efi/g" /etc/mkinitcpio.d/linux.preset > /etc/mkinitcpio.d/linux-lts.preset
  echo "Created /etc/mkinitcpio.d/linux-lts.preset."
  # It should have something like this:
  # PRESETS=('default')
  # ALL_kver="/boot/vmlinuz-linux-lts"
  # all_config="/etc/mkinitcpio.conf"
  # default_uki="/boot/EFI/Linux/arch-lts.efi"

  # Fallback (identical options, different UKI name)
  sed "s/arch\.efi/arch-fallback\.efi/g" /etc/mkinitcpio.d/linux.preset > /etc/mkinitcpio.d/linux-fallback.preset
  echo "Created /etc/mkinitcpio.d/linux-fallback.preset"
  # It should have something like this:
  # PRESETS=('default')
  # ALL_kver="/boot/vmlinuz-linux"
  # all_config="/etc/mkinitcpio.conf"
  # default_uki="/boot/EFI/Linux/arch-fallback.efi"

  # Plymouth set the default theme:
  plymouth-set-default-theme -R bgrt
  echo "Plymouth + BGRT theme set"

  # Configure Plymouth Defaults (HiDPI and fast boot)
  cat > /etc/plymouth/plymouthd.conf << EOF
  [Daemon]
  Theme=bgrt
  ShowDelay=0
  DeviceScale=2  # Uncommented for HiDPI (e.g., 4K/Retina); test post-install regenerate the initramfs "mkinitcpio -p"
  EOF
  echo "Configured Plymouth for immediate display (ShowDelay=0) and HiDPI (DeviceScale=2)."

  # Kernel Hardening: Blacklist Unused Modules
  # Hardware-specific check:
  lsmod | grep -E 'firewire|pcspkr|cramfs|hfs|btusb'
  # Create a configuration file
  cat > /etc/modprobe.d/99-local-blacklist.conf <<EOF
  # Prevents the PC speaker module (for system beep)
  install pcspkr /bin/true
  # Blacklist legacy filesystems if not needed
  install cramfs /bin/true
  install hfs /bin/true
  install hfsplus /bin/true
  blacklist firewire_core
  EOF

  # Generate UKI
  # Arch Wiki order REQUIRED: mkinitcpio -P -> bootctl install -> sbctl sign
  mkinitcpio -P
  echo "Generated arch.efi, arch-lts.efi, arch-fallback.efi"

  # Double-check after mkinitcpio -P that no stray rd.luks.* crept in:
  grep -i rd.luks /boot/loader/entries/*.conf  # should return nothing
  grep -i rd.luks /etc/mkinitcpio.d/*.preset   # should return nothing
  strings /boot/EFI/Linux/arch.efi | grep "resume_offset=" # should return the custom entries

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
  # This creates or overwrites the loader.conf with the hidden menu setting
  cat << EOF > /boot/loader/loader.conf
  timeout 0
  console-mode max
  editor no
  EOF
  echo "Set systemd-boot timeout hidden. Pressing and holding a key (the Space bar is commonly cited and the most reliable)."

  # Create Pacman hooks to automatically sign EFI binaries after updates:
  mkdir -p /etc/pacman.d/hooks
  cat << 'EOF' > /etc/pacman.d/hooks/90-uki-sign.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = linux*
  Target = linux-firmware
  Target = systemd
  Target = mkinitcpio
  Target = plymouth

  [Action]
  Description = Rebuild UKI and sign with Secure Boot
  When = PostTransaction
  Exec = /usr/bin/bash -c 'mkinitcpio -P; bootctl update && sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI /boot/EFI/Linux/arch*.efi 2>/dev/null || true'
  EOF

  # Verification Checks
  grep HOOKS /etc/mkinitcpio.conf
  echo -e "\nBoot entries:"
  bootctl list | grep -E "(title|efi)"
  echo -e "\nresume_offset in presets:"
  grep resume_offset /etc/mkinitcpio.d/linux*.preset
  sbctl verify
  # **MUST show all signed** (✓)
  # If ANY show "✗ Not signed" 
  # sbctl sign -s $path
  
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

## Step 9: TPM Seal, Recovery USB, Windows Entry & Final Archive (newly installed, booted Arch Linux OS, not the USB installer)
- Warning Log with your username not root.
- Save-kernel-config.sh (for archive script)
  ```bash
  sudo tee /usr/local/bin/save-kernel-config.sh > /dev/null << 'EOF'
  #!/bin/bash
  set -e
  KERNEL_VERSION=$(uname -r)
  mkdir -p /etc/kernel
  if [ -f /proc/config.gz ]; then
    zcat /proc/config.gz > /etc/kernel/config-${KERNEL_VERSION}
    echo "Kernel config saved from /proc/config.gz"
  elif [ -f /boot/config-${KERNEL_VERSION} ]; then
    cp /boot/config-${KERNEL_VERSION} /etc/kernel/config-${KERNEL_VERSION}
    echo "Kernel config saved from /boot"
  else
    echo "Kernel config not found"
    exit 1
  fi
  EOF
  sudo chmod +x /usr/local/bin/save-kernel-config.sh
  ```
- Update TPM PCR policy after enabling Secure Boot:
  ```bash
  # Generate stable TPM public key (once only)
  TPM_PUBKEY="/etc/tpm2-ukey.pem"
  if [ ! -f "$TPM_PUBKEY" ]; then
    echo "Generating TPM public key..."
    sudo tpm2_createek --ek-context /tmp/ek.ctx --key-algorithm rsa --public /tmp/ek.pub
    sudo tpm2_readpublic -c /tmp/ek.ctx -f pem -o "$TPM_PUBKEY"
    sudo rm /tmp/ek.*
    sudo chmod 644 "$TPM_PUBKEY"
    echo "TPM public key saved to $TPM_PUBKEY"
  fi

  # Create TPM Seal Script
  sudo tee /usr/local/bin/tpm-seal > /dev/null << EOF
  #!/usr/bin/env bash
  set -euo pipefail

  LUKS_DEV="/dev/disk/by-uuid/${LUKS_UUID}"
  TPM_PUBKEY="/etc/tpm2-ukey.pem"

  if ! test -f "$TPM_PUBKEY"; then
    echo "ERROR: TPM key missing at $TPM_PUBKEY"
    exit 1
  fi

  echo "Sealing LUKS to TPM PCRs 7..."

  systemd-cryptenroll "$LUKS_DEV" \
    --wipe-slot=tpm2 \
    --tpm2-device=auto \
    --tpm2-pcrs=7 \
    --tpm2-public-key="$TPM_PUBKEY"

  echo "TPM sealing complete."
  EOF
  sudo chmod +x /usr/local/bin/tpm-seal

  # Create fix-tpm
  sudo tee /usr/local/bin/fix-tpm > /dev/null << EOF
  #!/usr/bin/env bash
  set -euo pipefail

  LUKS_DEV="/dev/disk/by-uuid/${LUKS_UUID}"

  echo "Re-enrolling TPM2 LUKS unlock..."

  sudo touch /etc/allow-tpm-reenroll

  if sudo systemctl start tpm-reenroll.service; then
    echo "Re-enrollment triggered"
  else
    echo "Re-enrollment failed"
    sudo rm -f /etc/allow-tpm-reenroll
    exit 1
  fi

  sudo rm -f /etc/allow-tpm-reenroll

  echo ""
  echo "=== Recent TPM Re-enrollment Logs ==="
  sudo journalctl -u tpm-reenroll.service -n 20 --no-pager

  # Dump the LUKS_DEV token
  DUMP=$(sudo /usr/bin/cryptsetup luksDump "$LUKS_DEV")

  echo "Verify TPM2 token enrollment..."
  if echo "$DUMP | /usr/bin/grep -q "systemd-tpm2"; then
  echo ""
    echo "TPM unlock test PASSED"
  else
  echo ""
    echo "TPM unlock test FAILED"
    exit 1
  fi
  EOF
  sudo chmod +x /usr/local/bin/fix-tpm
  
  # TPM metadata (for documentation)
  sudo tee /etc/tpm-policy-info.txt << EOF
  PCRs: 7
  Hash: sha256 (auto-selected by modern systemd)
  Sealed: $(date)
  SecureBoot: Enabled
  LUKS UUID: ${LUKS_UUID}
  ROOT UUID: ${ROOT_UUID}
  EOF

  # Final TPM Policy Sealing
  # Wipe any existing TPM enrollment (safe even if none exists):
  echo "Wiping any existing TPM slot..."
  sudo systemd-cryptenroll /dev/nvme1n1p2 --wipe-slot=tpm2 2>/dev/null || echo "No existing TPM slot to wipe"

  # Run the seal:
  echo "Running TPM seal..."
  sudo tpm-seal

  # Test it (a slot should show tpm2):
  sudo systemd-cryptenroll /dev/nvme1n1p2
  # It should display 3 layers of protection:
  #  Slot 0: Passphrase (Mental backup).
  #  Slot 1: Keyfile on USB (Digital backup).
  #  Slot 2: TPM2 (Daily Driver. Hands-free unlock).
  
  # Raw PCR + Public-Key Enrollment - Create the tpm-reenroll systemd service file that will be a wrapper of TPM Seal Script
  sudo tee /etc/systemd/system/tpm-reenroll.service > /dev/null << 'EOF'
  [Unit]
  Description=Re-enroll TPM2 policy if PCRs changed
  ConditionPathExists=/etc/allow-tpm-reenroll
  Documentation=man:systemd-cryptenroll(1)

  # Wait until the LUKS device is unlocked and mapped
  After=cryptsetup.target

  # Also wait for TPM device
  Requires=tpm2.target
  After=tpm2.target

  [Service]
  Type=oneshot
  RemainAfterExit=yes

  # Execute the TPM Seal 
  ExecStart=/usr/bin/systemd-cryptenroll /dev/disk/by-uuid/"TYPE_LUKS_UUID" \
    --wipe-slot=tpm2 \
    --tpm2-device=auto \
    --tpm2-pcrs=7 \

  # Automatic cleanup of the trigger file
  ExecStartPost=/usr/bin/rm -f /etc/allow-tpm-reenroll
  
  [Install]
  WantedBy=multi-user.target
  EOF

  # Enable the service:
  sudo systemctl daemon-reload
  sudo systemctl enable tpm-reenroll.service
  echo "tpm-reenroll service created and enabled"

  # Current Workflow:
  # touch /etc/allow-tpm-reenroll
  # systemctl start tpm-reenroll.service
  # rm /etc/allow-tpm-reenroll

  # Main Arch Entry
  sudo tee /boot/loader/entries/arch.conf > /dev/null << 'EOF'
  title   Arch Linux
  efi     /EFI/Linux/arch.efi
  EOF
  echo "Main Arch boot entry created."

  # Windows Entry (if /windows-efi mount exists from install)
  sudo mkdir -p /boot/EFI
  sudo mkdir -p /mnt/windows-efi
  sudo mount /dev/nvme0n1p1 /mnt/windows-efi
  if [ -d "/mnt/windows-efi/EFI/Microsoft" ]; then
    sudo rsync -aHAX /mnt/windows-efi/EFI/Microsoft /boot/EFI/
    sudo tee /boot/loader/entries/windows.conf > /dev/null << 'EOF'
  title   Windows 11
  efi     /EFI/Microsoft/Boot/bootmgfw.efi
  EOF
    echo "Windows boot entry created."
  fi
  sudo umount /mnt/windows-efi 2>/dev/null || true
  sudo rm -rf /mnt/windows-efi

  # Before moving to the efibootmgr check the Linux and Microsoft boot are created (arch.efi inside the Linux folder and the microsof boot inside the Microsoft folder)
  ls -R /boot/EFI | less
  
  # Set Boot Order – main Arch 
  echo "Setting Arch Linux as default boot..."
  sudo bootctl set-default arch.conf
  echo "Default boot entry set"
  # Verify the motherboard order
  sudo efibootmgr
  
  # Verify the TPM Seal one last time using the physical device
  if sudo sbctl verify /boot/EFI/Linux/arch.efi | \grep -q "signed"; then
    echo "UKI is properly signed"
  else
    echo "UKI signature verification unclear - check manually"
  fi

  # Confirm Secure Boot is active
  sbctl status
  # Expected:
  ✓ Secure Boot: Enabled
  ✓ Setup Mode: Disabled
  ✓ Signed: all files
  ```
- Backup PCR values post-Secure Boot:
  ```bash
  sudo mount /dev/sdX1 /mnt/usb  # Replace with your USB
  sudo tpm2_pcrread sha256:7 | sudo tee /mnt/usb/tpm-pcr-post-secureboot.txt > /dev/null
  sudo \cat /mnt/usb/tpm-pcr-post-secureboot.txt
  echo "WARNING: Store /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden."
  echo "WARNING: Compare PCR values to ensure TPM policy consistency."
  ```
- Create a GRUB USB for recovery:
  ```bash
  lsblk  # Identify USB device (e.g., /dev/sdX1)
  read "USB_PART?Enter USB partition (e.g. /dev/sda1): "
  sudo umount -l /dev/sda1
  sudo mkfs.fat -F32 -n RESCUE_USB /dev/$USB_PART 

  sudo mount /dev/sda1 /mnt/usb
  sudo mkdir -p /mnt/usb
  sudo mount /dev/sdX1 /mnt/usb # Replace /dev/sdX1 with your USB partition confirmed via lsblk

  sudo pacman -Sy grub
  sudo grub-install --target=x86_64-efi --efi-directory=/mnt/usb --bootloader-id=RescueUSB --recheck

  # Copy kernel + initramfs
  sudo cp /crypto_keyfile /mnt/usb/luks-keyfile
  sudo chmod 600 /mnt/usb/luks-keyfile
  sudo cp /boot/vmlinuz-linux /mnt/usb/
  sudo cp /boot/initramfs-linux.img /mnt/usb/initramfs-linux.img

  # Copy AMD firmware for offline recovery
  echo "Copying AMD firmware to recovery USB..."
  sudo mkdir -p /mnt/usb/firmware
  sudo cp -rL /lib/firmware/amdgpu /mnt/usb/firmware/

  # Generate minimal rescue initramfs (no plymouth, resume)
  sudo cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
  sudo sed -i 's/HOOKS=(.*/HOOKS=(base systemd autodetect modconf block sd-encrypt btrfs filesystems keyboard)/' /mnt/usb/mkinitcpio-rescue.conf
  sudo mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
  sudo cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

  # GRUB config (Replace $LUKS_UUID and $ROOT_UUID with actual values in the menuentry)
  sudo tee /mnt/usb/boot/grub/grub.cfg > /dev/null << EOF
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
  sudo cp /mnt/usb/EFI/RescueUSB/grubx64.efi /mnt/usb/EFI/BOOT/BOOTX64.EFI
  sudo sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  sudo shred -u /crypto_keyfile # This may fail and you will need to enter the chroot, mount everything, then wipe
  sudo umount /mnt/usb
  
  echo "WARNING: Store the GRUB USB securely; it contains the LUKS keyfile."

  # To use the USB to boot, insert the USB, press F12, select the USB to boot. It should request the Passphrase, in the moment check if the USB didn't unplug because it is protected and requires to enter the paswweor again.
  # In the grub prompt enter the following:
  # chainloader (hd1,gpt1)/EFI/Linux/arch.efi
  # boot
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

  sudo mkdir -p "$STAGING_DIR"
  log "Staging directory: $STAGING_DIR"

  # Kernel & Boot
  log "Copying mkinitcpio & bootloader config..."
  sudo cp -v /etc/mkinitcpio.conf            "$STAGING_DIR/" || true
  for preset in /etc/mkinitcpio.d/*.preset; do
  [[ -f "$preset" ]] && cp -v "$preset" "$STAGING_DIR/"
  done
  sudo cp -v /boot/loader/loader.conf        "$STAGING_DIR/" || true
  sudo cp -v /etc/pacman.d/hooks/90-uki-sign.hook "$STAGING_DIR/" || true

  # Filesystem & Encryption
  log "Copying fstab & crypttab..."
  sudo cp -v /etc/fstab                      "$STAGING_DIR/" || true
  sudo cp -v /etc/crypttab                   "$STAGING_DIR/" || true

  # TPM / Security (sensitive!)
  log "Copying TPM reenroll service (PEM excluded)..."
  sudo cp -v /etc/systemd/system/tpm-reenroll.service "$STAGING_DIR/" || true
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
  sudo cp -v "$KERNEL_CONFIG" "$STAGING_DIR/"

  # Archive + Verify
  log "Creating compressed archive..."
  tar -C "$STAGING_DIR" --sort=name --owner=0 --group=0 --mtime='2025-01-01' --exclude=/etc/shadow \
    -czf "$FINAL_ARCHIVE" .

  log "Verifying archive integrity..."
  gzip -t "$FINAL_ARCHIVE" || die "Corrupted archive! "

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

  sudo chmod +x /usr/local/bin/archive-system-config.sh
  sudo archive-system-config.sh
  ```
- Migration Gentoo Final Checklist
  ```bash
  # Verify all files exist
  sudo ls -R /etc/gentoo-prep/
  sudo ls /etc/kernel/config-*
  sudo ls /etc/system-config-archive/*.tar.gz

  # Commit etckeeper
  sudo etckeeper commit "Final config before first boot"

  # Backup archive off-system
  sudo cp /etc/system-config-archive/*.tar.gz /path/to/backup/
  ```
- Final reboot into encrypted system:
  ```bash
  sudo umount -R /mnt
  reboot
  ```
- Verify
  ```bash
  sudo sbctl status
  ```
- Check Windows
  ```bash
  # Reboot to Windows and verify it boots
  # Then reboot to Linux to continue
  # REMEMBER: If something get strange this is the sequence to get thing right: fix-tpm (if is only the passphrase coming in every login try this first, if doesn't fix continue) --> **Check if BIOS (F1) is in Reset to Setup Mode** --> sudo sbctl enroll-keys -m --> sudo sbctl sign-all -g --> sudo sbctl verify --> efibootmgr (Linux Boot Manager First) --> **Reboot Turn Secure Boot On** --> fix-tpm
  ```
## Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can pause at this point

## Step 10: Install and Configure DE and Applications

  set -euo pipefail

- Install the **GNOME desktop environment**:
  ```bash
  # Update the System
  sudo pacman -Syu
  
  # Core Desktop Environment (Shell, Compositor, Login Manager)
  sudo pacman -S --needed mutter gnome-shell gdm gnome-control-center gnome-session gnome-settings-daemon \

  # Install Essential Tools
  nautilus gnome-keyring gnome-backgrounds xdg-user-dirs-gtk xdg-desktop-portal-gnome xdg-desktop-portal-gtk localsearch libadwaita xdg-utils glycin-gtk4 gnome-power-manager webp-pixbuf-loader \

  # GNOME Adwaita, Orchis and Papirus
  adw-gtk-theme gnome-themes-extra adwaita-fonts adwaita-icon-theme orchis-theme papirus-icon-theme
  ```
- Create ~/Music, Pictures, Documents, Downloads, Desktop, Videos, Public, Git, Games etc. (for Lollypop, etc) (NO SUDO)
  ```bash
  sudo chown -R username:username /home/username # Replace "username" with your username
  xdg-user-dirs-update 
  ```
- Install **Paru and configure it**:
  ```bash   
  # Clone & build in a clean temp dir
  mkdir -p /tmp/paru-build
  git clone --depth 1 https://aur.archlinux.org/paru.git /tmp/paru-build
  
  # Build the package (creates the .pkg.tar.zst file)
  (
  cd /tmp/paru-build || exit 1
  makepkg -src --noconfirm
  
  # NAMCAP AUDIT (Insert Check Here)
  echo "--- Running namcap audit on the built paru package ---"
  # Audits the built package. The || true allows the script to continue on warnings.
  if command -v namcap >/dev/null; then
    echo "--- Running namcap audit ---"
    namcap PKGBUILD || true
    namcap paru-*.pkg.tar.zst || true
  fi
  
  # Install the audited package
  sudo pacman -U --noconfirm paru-*.pkg.tar.zst
  )
  rm -rf /tmp/paru-build  

  # Configure to show PKGBUILD diffs (edit the Paru config file):
  mkdir -p ~/.config/paru
  \cat << 'EOF' > ~/.config/paru/paru.conf
  [options]
  PgpFetch
  BottomUp
  RemoveMake
  CleanAfter
  SudoLoop
  UpgradeMenu

  # Use 'CombinedUpgrade' if you want Repo and AUR updates in one list. 
  # Keep it commented out if you prefer to see them separately. Recommended.
  # CombinedUpgrade

  [bin]
  # If you install 'bat', uncomment this for beautiful diffs:
  # Pager = bat
  EOF
    
  # Verify if paru shows the PKGBUILD diffs
  paru -Pg | grep -E 'diffmenu|combinedupgrade|editmenu' || true # Should show: combinedupgrade: Off diffmenu: Edit editmenu: Edit

  # Set build directory
  mkdir -p ~/.cache/paru-build
  echo 'BuildDir = /home/'"$USER"'/.cache/paru-build' >> ~/.config/paru/paru.conf

  # Create yay → paru symlink for AUR helper script compatibility
  sudo ln -sf /usr/bin/paru /usr/local/bin/yay
  echo "Created /usr/local/bin/yay → paru symlink (AUR script compatibility)"
  ```
- Install Pacman applications:
  ```bash
  # System packages (CLI + system-level)
  sudo pacman -S --needed \
  # Security & Hardening
  audit arch-audit lynis sshguard ufw usbguard \
  \
  # System Monitoring
  gnome-system-monitor gnome-disk-utility tlp upower zram-generator libappindicator smartmontools \
  \
  # Hardware
  bluez bluez-utils cups fprintd \
  \
  # Networking & Privacy
  dnscrypt-proxy dnsutils opensnitch wireguard-tools proton-vpn-gtk-app reflector dnsmasq \
  \
  # CLI Tools
  atuin bat bandwhich bottom broot cmake extra-cmake-modules git-delta dog dua-cli eza fd fzf gcc gdb gitui glow gping \
  helix httpie fastfetch macchina linux-docs nasm procs python-gobject rage ripgrep rustup starship systeroid tealdeer \
  yazi zoxide zsh-autosuggestions zsh-syntax-highlighting zsh-history-substring-search wl-clipboard \
  \
  # Multimedia (system)
  ffmpeg gstreamer gst-libav gst-plugins-bad gst-plugins-good gst-plugins-ugly \
  libva-utils vulkan-tools clinfo wine 7zip exfatprogs \
  \
  # Browsers, Email-Client and Virtual Machine (Make sure to set in the Tor application to perform automatic updates)
  torbrowser-launcher thunderbird virt-manager libvirt qemu-desktop \
  \
  # Games
  steam mangohud gamemode lib32-gamemode gamescope goverlay lib32-alsa-plugins lib32-giflib lib32-gst-plugins-base-libs lib32-gtk3 libjpeg-turbo lib32-libjpeg-turbo \
  lib32-libva lib32-mpg123 lib32-ocl-icd lib32-openal lib32-libpulse lib32-libxcomposite lib32-libxinerama lib32-vulkan-intel lib32-vulkan-radeon libxslt mpg123 openal protontricks winetricks \
  \
  # Fonts (Emoji/symbol coverage + CJK support)
  # Core system + fallback
  noto-fonts noto-fonts-cjk noto-fonts-emoji \
  # UI / system fonts
  cantarell-fonts inter-font ttf-roboto otf-ipaexfont ttf-liberation \
  # Coding fonts
  ttf-jetbrains-mono-nerd ttf-cascadia-code-nerd otf-commit-mono-nerd \
  # Symbols / icons fallback  
  ttf-nerd-fonts-symbols-mono \
  # Language support
  ttf-croscore \
  \
  # GNOME Extras
  gnome-bluetooth-3.0 gnome-tweaks gnome-shell-extensions gnome-firmware gnome-browser-connector gnome-shell-extension-appindicator gnome-font-viewer gnome-menus \
  gvfs gvfs-afc gvfs-smb gvfs-mtp gvfs-gphoto2 gvfs-wsdd libgsf qt6-wayland qt5-wayland nautilus-share gst-thumbnailers evolution-data-server gnome-software
  ```
- Permanently allow the bandwhich binary its required privileges (Assign capabilities):
  ```bash
  sudo setcap cap_sys_ptrace,cap_dac_read_search,cap_net_raw,cap_net_admin+ep /usr/bin/bandwhich
  ```
- Privacy measure to prevent laptop location identification:
  ```bash
  sudo systemctl mask geoclue.service
  ```
- Font rendering (subpixel + hinting):
  ```bash
  fc-cache -fv
  gsettings set org.gnome.desktop.interface font-antialiasing 'rgba'
  gsettings set org.gnome.desktop.interface font-hinting 'slight'
  ```
- Enable essential services:
  ```bash
  sudo systemctl enable gdm.service bluetooth ufw systemd-timesyncd libvirtd.service tlp fprintd fstrim.timer sshguard systemd-oomd upower.service cups.service
  sudo systemctl --failed  # Check for failed services
  sudo usermod -aG libvirt $USER
  sudo journalctl -p 3 -xb
  ```
- Install the AUR applications:
  ```bash
  # AUR applications:
  paru -S --needed \
    aide \
    amdgpu_top-tui-bin \
    apparmor.d-git \
    wezterm-git \
    fresh-editor-bin \
    folder-color-nautilus \
    libva-vdpau-driver \
    gst-plugins-rs-git \
    brave-bin \
    kanagawa-icon-theme-git \
    kanagawa-gtk-theme-git \
    nautilus-open-any-terminal \
    nautilus-copy-path \
    nautilus-admin-gtk4 \
    needrestart \
    rose-pine-cursor \
    rose-pine-gtk-theme-full \
    stylepak-git \
    run0-sudo-shim-git \
    wluma \
    xdg-ninja
  # Update linker cache (Requires Sudo)
  sudo ldconfig
  ```
- Sign the fwupd and run0-sudo-shim
  ```bash
  # Sign fwupd EFI binary for Secure Boot (once; hook handles updates)
  if [[ -f /usr/lib/fwupd/efi/fwupdx64.efi ]]; then
    sudo sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi 2>/dev/null || true
    echo "fwupd EFI signed for Secure Boot"
  else
    echo "WARNING: fwupd EFI binary not found – install fwupd first"
  fi

  # Create separate hook for fwupd signing
  cat << 'EOF' | sudo tee /etc/pacman.d/hooks/91-fwupd-sign.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = fwupd

  [Action]
  Description = Sign fwupd EFI for Secure Boot
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi
  Depends = sbctl
  EOF

  # Test fwupd signing
  sudo sbctl verify /usr/lib/fwupd/efi/fwupdx64.efi  # Should show "signed"

  # For run0-sudo-shim: No Secure Boot signing needed (userspace ELF)
  if command -v sudo >/dev/null 2>&1 && [[ "$(sudo --version 2>/dev/null | head -n1)" == *"run0-sudo-shim"* ]]; then
  echo "run0-sudo-shim is in place"
  sudo -v && echo "polkit cache OK (15-min reuse for run0)"
  else
  echo "ERROR: run0-sudo-shim not installed – install via paru -S run0-sudo-shim-git"
  fi
  ```
- Configure GDM for Wayland:
  ```bash
  cat << 'EOF' | sudo tee /etc/gdm/custom.conf
  [daemon]
  WaylandEnable=true
  DefaultSession=gnome.desktop
  EOF
  sudo systemctl restart gdm
  # and reboot (start working on Gnome) -- This is the point that you start seeing your Desktop Environment
  ```
- Edit the Wezterm Visuals (this is basics, just to move forward, later can make more aesthetic udpates):
  ```bash
  # The "Super" Pro-Tip for GNOME
  # Since you are on GNOME, there is a "hidden" feature that makes resizing terminals 10x faster than hunting for a 1-pixel border:
  # Hold the Super key (Windows key).
  # Middle-Click (or right-click) anywhere inside the terminal window and drag.
  # The window will resize from whichever corner is closest to your cursor.
  # CTRL + SHIFT + C = Copy || CTRL + SHIFT + V = PASTE

  # Optimized WezTerm Setup for Arch (Wayland + Intel ARL)
  mkdir -p ~/.config/wezterm

  if [[ ! -f ~/.config/wezterm/wezterm.lua ]]; then
    cat <<'EOF' > ~/.config/wezterm/wezterm.lua
  -- Pull in the wezterm API
  local wezterm = require 'wezterm'

  -- This will hold the configuration.
  local config = wezterm.config_builder()

  -- Fonts & Rendering
  config.font = wezterm.font_with_fallback({
  --  { family = "JetBrains Mono", weight = "Regular" },
    { family = "JetBrainsMono Nerd Font Mono", scale = 1.0 },
  --  { family = "JetBrainsMono NFM", scale = 1.0 },
    { family = "Symbols Nerd Font Mono", scale = 1.0 },
    "Noto Color Emoji",
  })

  config.font_size           = 12.5
  config.line_height         = 1.14
  -- config.harfbuzz_features   = { 'liga', 'calt', 'ss01', 'ss02', 'ss03', 'ss04', 'ss05' }
  config.harfbuzz_features = { 'liga', 'calt' }

  -- Changing the initial geometry for new windows:
  config.initial_cols = 146
  config.initial_rows = 39

  -- Suppress the "Font problem" notification toast globally
  -- config.warn_about_missing_glyphs = false

  -- Appearance (Srcery Theme & No Translucency)
  config.color_scheme = 'Srcery (Gogh)'

  -- "RESIZE" keeps the ability to grab edges.
  config.window_decorations = "INTEGRATED_BUTTONS|RESIZE"
  -- config.tab_bar_at_bottom = true
  -- config.use_fancy_tab_bar = false
  config.tab_and_split_indices_are_zero_based = true
  -- config.integrated_title_button_color = "Cyan"
  -- config.integrated_title_button_style = "Gnome"

  -- Adjust Cursor Animation 
  config.default_cursor_style = 'BlinkingBar'

  -- Add Tab Number
  config.show_tab_index_in_tab_bar = true

  -- Performance / Backend
  config.front_end = "WebGpu"
  -- config.front_end = "OpenGL"
  config.webgpu_power_preference = "HighPerformance"

  -- Dim inactive panes
  config.inactive_pane_hsb = {
   saturation = 0.85,
   brightness = 0.75,
   } 
  
  -- Adjust Borders
  config.window_padding = {
    left = 2,
    right = 2,
    top = 1,
    bottom = 1,
  } 

  config.window_frame = {
    border_top_height   = '3px',
    border_left_width   = '3px',
    border_right_width  = '3px',
    border_bottom_height = '3px',
    border_top_color    = '#2C78BF',
    border_left_color   = '#2C78BF',
    border_right_color  = '#2C78BF', 
    border_bottom_color = '#2C78BF',
    inactive_titlebar_bg = '#1c1b19',
    active_titlebar_bg   = '#2d2c29',
  }

  return config
  EOF
    echo "WezTerm configuration created successfully!"
  else
    echo "WezTerm config already exists – skipping to protect your settings."
  fi
  ```
- Enable Brave hardware video accelaration (for WebRTC/screen sharing) and Steam running with high-performance flags:
  ```bash
  # Copy Brave .desktop to local override
  mkdir -p ~/.local/share/applications
  cp /usr/share/applications/brave-browser.desktop ~/.local/share/applications/

  # Add our successful Wayland and Hardware Acceleration flags to all Exec lines
  sed -i 's|Exec=/usr/bin/brave-browser|Exec=env LIBVA_DRIVER_NAME=iHD /usr/bin/brave-browser --ozone-platform=wayland --enable-features=VaapiVideoDecoder,VaapiVideoEncoder,VaapiVideoEncodeAccelerator,CanvasOopRasterization --disable-features=UseChromeOSDirectVideoDecoder|g' ~/.local/share/applications/brave-browser.desktop

  echo "Brave Wayland & GPU optimizations permanently enabled!"
  
  # Verify at brave://gpu → Video Acceleration section

  # Add performance flags to Steam itself
  sed -i 's|Exec=/usr/bin/steam|Exec=/usr/bin/steam -noverifyfiles -nobootstrapupdate -skipmovies -nofriendsui|g' \
    ~/.local/share/applications/steam.desktop  
  ```
- Install Mullvad Browser (Updates are going to be managed via browser):
  ```bash
  # Download the Linux .tar.xz file: https://mullvad.net/en/download/browser/linux-x86_64/latest
  # Verify the file's signature
  gpg --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org
  gpg --fingerprint --fingerprint torbrowser@torproject.org
  # Double-check that you have the correct key, visit the Tor Browser website: https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/#618e1a509a4f4d3dbea11b7651b26f71
  # Sign it with your own key
  gpg --gen-key
  # Enter your "Real name" (use a fake name if you want to be anonymous) and an "Email address" and enter "O". Then enter a password and click on OK.
  gpg --sign-key torbrowser@torproject.org
  # You will see a long message with some revoked keys and in the end it shows the following:
  # pub  rsa4096/4E2C6E8793298290
  #   created: 2014-12-15  expires: 2027-07-15  usage: C   
  #   trust: unknown       validity: unknown
  # Primary key fingerprint: EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290
  #
  #   Tor Browser Developers (signing key) <torbrowser@torproject.org>
  # This key is due to expire on 2027-07-15.
  # Are you sure that you want to sign this key with your
  # key "xxx <xxx@xxx.xx>" (xxx)
  # Enter "y" to sign it and then enter your pgp key password.
  # Extract the download:
  #  Open the Downloads folder.
  #  Right click on mullvad-browser-linux-x86_64-X.X.X.tar.xz.
  #  Click on Extract Here (Ubuntu) or Extract (Fedora).
  # Make sure to place the signature file and the browser install file in the same folder.
  # Verify the Mullvad Browser
  # Navigate into the folder where the files are with the cd command and then run the following command:
  gpg --verify mullvad-browser-*.asc
  # Starting the Mullvad Browser
  #  Open the Downloads folder.
  #  Open the decompressed mullvad-browser-linux-x86_64-X.X.X folder.
  #  Open the mullvad-browser folder.
  #  Open the Browser folder.
  #  Right-click on start-mullvad-browser.
  #  Click on Run as a Program.  
  ```
- Install Flatseal and the Flatpak applications via GUI
  ```bash
  # Install Flatseal
  flatpak remote-add --if-not-exists --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  flatpak install --user -y flathub com.github.tchx84.Flatseal
  sudo flatpak remote-delete flathub

  # Launch Gnome Software once to initialize
  # Open Gnome Software (search in GNOME overview)
  echo "Install: GIMP (org.gimp.GIMP), GDM Settings (io.github.realmazharhussain.GdmSettings), Lollypop (org.gnome.Lollypop), Mixx (org.mixxx.Mixxx), Logseq (com.logseq.Logseq), Calculator (org.gnome.Calculator), Camera (org.gnome.Snapshot), Characters (org.gnome.Characters), Disk Usage Analyzer (org.gnome.baobab), Document Scanner (org.gnome.SimpleScan), Document Viewer (org.gnome.Papers), Fonts (org.gnome.font-viewer), Image Viewer (org.gnome.Loupe), Logs (org.gnome.Logs), Dconf Editor (ca.desrt.dconf-editor), Bustle (org.freedesktop.Bustle), Eyedropper (com.github.finefindus.eyedropper), Obfuscate (com.belmoussaoui.Obfuscate), Extension Manager (com.mattjakeman.ExtensionManager), File Roller (org.gnome.FileRoller), LibreOffice (org.libreoffice.LibreOffice), Scopebuddy GUI (io.github.rfrench3.scopebuddy-gui), Passwords and Keys (org.gnome.seahorse.Application), Protonmail-Bridge (ch.protonmail.protonmail-bridge), Resources (net.nokyan.Resources) and Video Player (org.gnome.Showtime). Use Flatseal (com.github.tchx84.Flatseal) to fine-tune per-app permissions (e.g., add --filesystem=home:rw for Lollypop if needed)."
  ```
- Configure Flatpak sandboxing (via Flatseal or CLI):
  ```bash
  # Allow Flatpaks to read/write their own config/data only
  flatpak override --user --filesystem=xdg-config:ro --filesystem=xdg-data:create
  flatpak override --user --socket=wayland --socket=x11
  # Enable GPU device access for video players. For Example: Showtime
  # In Flatseal, select org.gnome.Showtime, then:
  # Devices → Enable GPU access (checkbox)
  # This grants /dev/dri/* access inside the sandbox
  # Rely on Flatpak's bubblewrap sandbox for application isolation instead.
  # Flatpak GUI - Test
  ```
- Install Theme Extensions for Flatpak via stylepak
  ```bash
  # Install themes system-wide (for all users) and for the current user
  sudo ./stylepak install-system # Run system install with Sudo
  ./stylepak install-user # Run user install (no sudo)

  # Clear the theme storage cache to ensure the new themes are picked up
  ./stylepak clear-cache
  ```
- Configure GTK4/Libadwaita Overrides for Flatpak Themes
  ```bash
  # Allow user Flatpak apps to READ the host user's GTK4 config (e.g., custom CSS)
  flatpak override --user --filesystem=xdg-config/gtk-4.0:ro

  # Optional: Allow system-installed Flatpak apps to READ the host system's GTK4 config
  sudo flatpak override --filesystem=xdg-config/gtk-4.0:ro
  ```
- Clear some Orphan Packages:
  ```bash
  paru -Qdt
  sudo paru -Rs $LIST_THE_ORPHAN_PACKAGES
  ```
- Make Terminal Applications Icons Like Helix and Micro to open looking your Terminal
  ```bash
  paru -S xdg-terminal-exec
  cat <<EOF > ~/.config/xdg-terminals.list
    org.wezfurlong.wezterm.desktop
    org.gnome.Console.desktop
  EOF

  # Valdiate
  ls /usr/share/applications/ | grep wezterm
  grep "Categories" /usr/share/applications/org.wezfurlong.wezterm.desktop

  # Setting the Default in GNOME
  gsettings set org.gnome.desktop.default-applications.terminal exec 'wezterm'
  ```
- (OPTIONAL/RECOMMENDED) Using Fresh Text Editor CLI as the Default Text Editor. If we don't do this install the Gnome Text Editor Flatpak Applications for this purporse.
  ```bash
  # Create the Desktop Entry
  cat <<EOF > ~/.local/share/applications/fresh.desktop
  [Desktop Entry]
  Name=Fresh
  Comment=Quick CLI Text Editor
  GenericName=Text Editor
  # This assumes 'fresh' is in your PATH (e.g., /usr/bin/fresh)
  Exec=fresh %F
  # Important: This tells GNOME to use your new WezTerm handler
  Terminal=true
  Type=Application
  Icon=text-editor
  Categories=Utility;TextEditor;Development;
  MimeType=text/plain;
  Keywords=text;editor;cli;fresh;
  StartupNotify=false
  EOF

  # Update the Desktop Database
  update-desktop-database ~/.local/share/applications/

  # Making it the "Default" for .txt files
  xdg-mime default fresh.desktop text/plain
  ```  
- Install Extensions from extensions.gnome.org using Extension Manager application flatpak
  ```bash
  # GNOME Extension Compatibility Note (GNOME 50 - March 2026):
  # Some extensions may break with GNOME 50 release. Check compatibility at:
  # https://extensions.gnome.org/local/
  # Affected extensions typically include: AppIndicator, Dash to Dock, custom themes.
  # Wait for extension updates if GNOME Shell crashes after 'pacman -Syu' to GNOME 50.
  
  echo "Install GSConnect from https://extensions.gnome.org/extension/1319/gsconnect/ using Extension Manager"  
  echo "Install Just Perfection from https://extensions.gnome.org/extension/3843/just-perfection/ using Extension Manager
  echo "Install User Themes from https://extensions.gnome.org/extension/19/user-themes/ using Extension Manager"
  echo "Install Caffeine from https://extensions.gnome.org/extension/517/caffeine/ using Extension Manager"
  echo "Install AppIndicator and KStatusNotifier from https://extensions.gnome.org/extension/615/appindicator-support/ using Extension Manager"
  echo "Install ArcMenu from ¨https://extensions.gnome.org/extension/3628/arcmenu/¨ using Extension Manager"
  echo "Install Dash to Dock from ¨https://extensions.gnome.org/extension/307/dash-to-dock/¨ using Extension Manager"
  echo "Install Open Bar from ¨https://extensions.gnome.org/extension/6580/open-bar/¨ using Extension Manager"
  echo "Install Privacy Quick Settings from ¨https://github.com/stuarthayhurst/privacy-menu-extension¨ using Extension Manager"
  echo "Install Clipboard Indicator from ¨https://extensions.gnome.org/extension/779/clipboard-indicator/¨ using Extension Manager"
  echo "Install Removable Drive Menu from ¨https://extensions.gnome.org/extension/7/removable-drive-menu/¨ using Extension Manager"
  echo "After installing via Extension Manager, enable it and Log Out and Log back in"
  ```
- Enroll fingerprint if device has a reader
  ```bash
  if fprintd-enroll -f list | grep -q "no devices"; then
    echo "No fingerprint reader detected"
  else
    echo "Fingerprint reader found! Run 'fprintd-enroll' to set it up (optional)"
  fi
  # If fingerprint doesn't work try to install the libfprint from AUR. # DO NOT use thinkfinger (legacy).
  # Install the TOD framework and the V2 Goodix driver
  # paru -S libfprint-tod libfprint-2-tod1-goodix-v2

  # You MUST restart the service to load the new driver
  # sudo systemctl restart fprintd

  # Check if fprintd now "sees" the hardware
  # fprintd-list $USER
  ```
- (OPTIONAL NOT RECOMMENDED) Setup Automated System/AUR Updates
  ```bash
  # === SYSTEM-WIDE TEMPLATED AUTO-UPDATE (FUNCTIONAL, BUT HAS SECURITY TRADE-OFF) ===
  cat << 'EOF' | sudo tee /etc/systemd/system/paru-update@.service
  [Unit]
  Description=Paru and System Update for %i
  Wants=network-online.target
  After=network-online.target

  [Service]
  Type=oneshot
  # WARNING: Using --noconfirm for AUR packages bypasses the PKGBUILD review, which is a security risk.
  # This setting prioritizes full automation over security review.
  ExecStart=/usr/bin/paru -Syu --noconfirm
  User=%i
  WorkingDirectory=/home/%i
  StandardOutput=journal
  StandardError=journal
  # Give time for large AUR builds
  TimeoutSec=30min
  EOF

  cat << 'EOF' | sudo tee /etc/systemd/system/paru-update.timer
  [Unit]
  Description=Runs paru-update@<user>.service daily

  [Timer]
  OnCalendar=*-*-* 03:00:00
  RandomizedDelaySec=15min
  Persistent=true
  Unit=paru-update@%i.service

  [Install]
  WantedBy=timers.target
  EOF

  # === ENABLE FOR CURRENT USER ===
  sudo systemctl daemon-reload
  sudo systemctl enable "paru-update@$USER.service"
  sudo systemctl enable --now paru-update.timer

  # === VERIFY ===
  sudo systemctl list-unit-files | grep paru-update
  sudo systemctl status "paru-update@$USER.service"
  ```
- Suppress font duplication/clutter in UIs (hides variants without uninstalling):
  ```bash
  # Create the rule
  sudo tee /etc/fonts/conf.d/99-hide-variants.conf <<'EOF'
  
  <?xml version="1.0"?>
  <!DOCTYPE fontconfig SYSTEM "fonts.dtd">

  <fontconfig>

  <!-- ════════════════════════════════════════════════════════════════
     PART 1: HIDE NERD FONT PROPORTIONAL AND PROPO VARIANTS
     Merged into one block (cleaner than two separate blocks).

     Both the base "Nerd Font" (proportional, no monospace enforcement)
     and "Nerd Font Propo" (v3 rename of same thing) are hidden.
     Only "Nerd Font Mono" remains visible in pickers.

     OPTIONAL: If you use Nerd icons in proportional GUI contexts
        (e.g., Waybar), comment out the base "Nerd Font" patterns
        (every second line below) and keep only the "Propo" patterns.
     ════════════════════════════════════════════════════════════════ -->

  <selectfont>
  <rejectfont>

    <!-- JetBrains Mono (ttf-jetbrains-mono-nerd) -->
    <pattern><patelt name="family"><string>JetBrainsMono Nerd Font Propo</string></patelt></pattern>
    <pattern><patelt name="family"><string>JetBrainsMono Nerd Font</string></patelt></pattern>
    <pattern><patelt name="family"><string>JetBrainsMonoNL Nerd Font Mono</string></patelt></pattern>
    <pattern><patelt name="family"><string>JetBrainsMonoNL Nerd Font Propo</string></patelt></pattern>
    <pattern><patelt name="family"><string>JetBrainsMonoNL Nerd Font</string></patelt></pattern>
          
    <!-- Cascadia Code → renamed CaskaydiaCove (ttf-cascadia-code-nerd) -->
    <pattern><patelt name="family"><string>CaskaydiaCove Nerd Font Propo</string></patelt></pattern>
    <pattern><patelt name="family"><string>CaskaydiaCove Nerd Font</string></patelt></pattern>
    
    <!-- Commit Mono → renamed Commit (otf-commit-mono-nerd) -->
    <pattern><patelt name="family"><string>CommitMono Nerd Font Propo</string></patelt></pattern>
    <pattern><patelt name="family"><string>CommitMono Nerd Font</string></patelt></pattern>
    
    <!-- Symbols Only (ttf-nerd-fonts-symbols-mono) -->
    <pattern><patelt name="family"><string>Symbols Nerd Font Propo</string></patelt></pattern>
    <pattern><patelt name="family"><string>Symbols Nerd Font</string></patelt></pattern>
    
  </rejectfont>
  </selectfont>


  <!-- ════════════════════════════════════════════════════════════════
     PART 2: ALIAS REDIRECTS — complete set for all 14 Nerd fonts
     When any app requests a font by its hidden base proportional name,
     redirect to the Mono variant. Ensures WezTerm, Helix, Starship,
     and dotfiles copied from other machines resolve correctly.
     ════════════════════════════════════════════════════════════════ -->

  <alias>
    <family>JetBrainsMono Nerd Font</family>
    <prefer><family>JetBrainsMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>CaskaydiaCove Nerd Font</family>
    <prefer><family>CaskaydiaCove Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>CommitMono Nerd Font</family>
    <prefer><family>CommitMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Symbols Nerd Font</family>
    <prefer><family>Symbols Nerd Font Mono</family></prefer>
  </alias>

  </fontconfig>

  # Rebuild cache
  fc-cache -fv

  # Validate, all three should return zero output if the config is working:
  fc-list : family | grep "Nerd Font" | grep -v "Mono" | grep -v "Propo"
  fc-list | grep -i "propo"
  fc-list | grep -i "condensed"

  # These should still show your 14 Mono entries:
  fc-list | grep -i "nerd font mono"
  ```
- Final full system update + UKI rebuild
  ```bash
  sudo pacman -Syu                 # now safe – hooks are active
  sudo mkinitcpio -P               # regenerate UKI (covers new kernel)
  # REQUIRED: Manually sign the newly created UKI, as mkinitcpio -P does not trigger the Pacman hook.
  sudo sbctl sign -s /boot/EFI/Linux/*.efi /boot/EFI/Linux/*.EFI 2>/dev/null || true
  sudo sbctl verify                # sanity-check all signed files
  ```
- Check Secure Boot Violations:
  ```bash
  sudo journalctl -b -p 3 | grep -i secureboot
  ```
## Step 11: Configure Power Management, Security, Network and Privacy

- Disable power-profiles-daemon to prevent conflicts with TLP and Configure power management for efficiency:
  ```bash
  sudo systemctl mask power-profiles-daemon
  sudo systemctl disable power-profiles-daemon
  # Intel iGPU Power Saving
  # NOTE: enable_psr (Panel Self Refresh) is omitted to prevent screen flickering on OLED/High-Refresh displays.
  # The Arch Wiki on Intel graphics suggests enabling power-saving features for Intel iGPUs to reduce battery consumption:
  echo 'options xe force_probe=7d51' | sudo tee -a /etc/modprobe.d/xe.conf
  sudo mkinitcpio -P
  ```
- Default deny incoming network via firewall (ufw):
  ```bash
  # Disables the SSH daemon and stops it immediately, removing the risk
  sudo systemctl disable --now sshd
  # Blocks all incoming connections by default (including port 22, ping, etc.)
  sudo ufw default deny incoming
  # Allows the laptop to connect to the internet, servers, etc. (required)
  sudo ufw default allow outgoing
  # Allow DHCP explicitly (prevents edge cases)
  sudo ufw allow out 67,68/udp
  # Explicitly allow loopback (defensive clarity)
  sudo ufw allow in on lo
  # Allow VPN interfaces (wg0 for WireGuard, proton0 for ProtonVPN native)
  sudo ufw allow in on wg0
  sudo ufw allow in on proton0
  # Replace '51413' with the actual port number from your torrent client.
  sudo ufw allow 51413/tcp
  sudo ufw allow 51413/udp
  # GSConnect / KDE Connect (Required for phone pairing)
  sudo ufw allow 1714:1764/udp
  sudo ufw allow 1714:1764/tcp
  # Enables the firewall and applies the rules
  sudo ufw enable

  - **NOTE: VPN Kill Switch and Split Tunneling are handled natively by ProtonVPN.**
  UFW manages incoming traffic only. All outgoing traffic is allowed by default.
  Use ProtonVPN's built-in features for outgoing traffic control:
  - **Kill Switch**: Enable in ProtonVPN GUI → Settings → Connection → Kill Switch.
    This blocks all traffic if the VPN drops unexpectedly, preventing IP leaks.
  - **Split Tunneling**: Configure in ProtonVPN GUI → Settings → Connection → 
    Split Tunneling. Use this to exclude specific applications from the VPN tunnel:
    - **VPN-hostile websites**: Exclude your browser temporarily to access sites
      that block VPN traffic.
    - **Gaming**: Exclude your game launcher (Steam, Lutris) to bypass VPN latency
      and get full ISP speed. Re-enable after gaming sessions.
  - The outgoing `allow out on wg0` and `allow out on proton0` rules are intentionally
    absent — ProtonVPN manages its own routing internally.
  ```
- Configure Wayland environment variables:
  ```bash
  # System-wide environment
  sudo tee /etc/environment > /dev/null <<'EOF'
  MOZ_ENABLE_WAYLAND=1
  QT_QPA_PLATFORM="wayland;xcb"
  ELECTRON_OZONE_PLATFORM_HINT=auto
  EOF
  # For Proton: PROTON_USE_WINED3D=1 env if DX12 issues.

  # PATH HARDENING (SYSTEM-WIDE ONLY)
  # # Avoid global PATH overrides to prevent breaking admin tools.
  # User paths ($HOME/.local/bin) added in ~/.zshrc
  #The envars below should NOT BE INCLUDED and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU. DO NOT ADD INITIALLY:
  # LIBVA_DRIVER_NAME=radeonsi
  # LIBVA_DRIVER_NAME=iHD

  # Login shell profile
  cat >> ~/.profile <<'EOF'

  # XDG Base Directories (FHS Compliant)
  export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
  export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
  export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
  export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

  # USER PATH: Appended for security (prevents PATH hijacking)
  [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && export PATH="$PATH:$HOME/.local/bin"

  # Default editor (optional but recommended)
  export EDITOR=fresh

  EOF

  # Zsh login router
  cat > ~/.zprofile <<'EOF'
  # Source common profile for login shells
  [[ -f ~/.profile ]] && source ~/.profile
  EOF

  # Interactive shell (minimal)
  cat >> ~/.zshrc <<'EOF'

  # Note: XDG variables and PATH are handled by ~/.profile on login.
  # We append PATH here as a fallback for non-login interactive shells.
  [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && export PATH="$PATH:$HOME/.local/bin"

  EOF

  echo "Step 11 complete. Log out and log back in to apply changes."
  ```
- Edit MAC randomization:
  ```bash
  # Remove the fragmented files
  sudo rm -f /etc/NetworkManager/conf.d/wifi-backend.conf
  sudo rm -f /etc/NetworkManager/conf.d/00-macrandomize.conf

  # Create the one 'Master' network config
  sudo tee /etc/NetworkManager/conf.d/99-hardened-network.conf > /dev/null <<'EOF'
  [device]
  wifi.backend=iwd
  wifi.scan-rand-mac-address=yes
  wifi.iwd.autoconnect=yes

  [connection]
  # 'random' generates a new MAC every time you connect (Max Privacy)
  # 'stable' generates one random MAC per SSID (Best for Home/Work stability)
  wifi.cloned-mac-address=random
  ethernet.cloned-mac-address=random
  EOF

  # Restart to apply
  sudo systemctl restart NetworkManager
  ```
- Configure GNOME privacy:
  ```bash
  gsettings set org.gnome.desktop.privacy remember-recent-files false
  gsettings set org.gnome.desktop.privacy report-technical-problems false
  ```
- Configure PAM security limits:
  ```bash
  sudo mkdir -p /etc/security/limits.d
  sudo tee /etc/security/limits.d/99-desktop-limits.conf > /dev/null <<'EOF'
  # Process/Thread limits Prevents build failures/crashes)
  * soft nproc 65536
  * hard nproc 65536

  # Massive headroom for Proton/Gaming without tool breakage
  * soft nofile 8192
  * hard nofile 131072

  # Ensure root can always recover the system
  root soft nproc unlimited
  root hard nproc unlimited
  EOF
  ```
- Configure auditd:
  ```bash
  sudo tee /etc/audit/rules.d/99-security.rules > /dev/null <<'EOF'
  ## Delete all existing rules
  -D

  ## Buffer & failure handling (16k for high‑thread CPU)
  -b 32768
  -f 0

  ## Identity & authentication files
  -w /etc/passwd      -p wa -k identity
  -w /etc/shadow      -p wa -k identity
  -w /etc/group       -p wa -k identity
  -w /etc/gshadow     -p wa -k identity
  -w /etc/sudoers     -p wa -k sudoers
  -w /etc/sudoers.d/  -p wa -k sudoers

  ## System configuration & network
  -w /etc/hosts          -p wa -k network
  -w /etc/resolv.conf    -p wa -k network
  -w /etc/hostname       -p wa -k network
  -w /etc/fstab          -p wa -k storage
  -w /etc/crypttab       -p wa -k crypto

  ## Kernel, boot & modules
  -w /boot/              -p wa -k boot
  -w /usr/lib/modules/   -p wa -k modules

  ## Security frameworks
  -w /etc/apparmor/      -p wa -k apparmor
  -w /etc/apparmor.d/    -p wa -k apparmor
  -w /etc/usbguard/rules.conf -p wa -k usbguard

  ## Privilege‑escalation (64‑ and 32‑bit)
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo        -k priv_esc
  -a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo        -k priv_esc
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/systemd-run -k priv_esc
  -a always,exit -F arch=b32 -S execve -F path=/usr/bin/systemd-run -k priv_esc
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec      -k priv_esc
  -a always,exit -F arch=b32 -S execve -F path=/usr/bin/pkexec      -k priv_esc

  ## Filesystem mounts (eGPU / USB monitoring)
  -a always,exit -F arch=b64 -S mount   -F exe=/usr/bin/mount  -k mounts
  -a always,exit -F arch=b64 -S umount2 -F exe=/usr/bin/umount -k mounts
  -a always,exit -F arch=b32 -S mount   -F exe=/usr/bin/mount  -k mounts
  -a always,exit -F arch=b32 -S umount2 -F exe=/usr/bin/umount -k mounts

  ## Time changes (for forensic timeline)
  -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
  -a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time_change
  -w /etc/localtime -p wa -k time_change

  ## Immutable flag (enable only after you’ve verified the rule set)
  # -e 2
  EOF

  # Start the auditd service:
  sudo systemctl enable --now auditd 

  # Load the rules
  sudo augenrules --load

  # Verify they are active and syntactically correct
  sudo auditctl -l | grep -i error && echo "ERROR" || echo "Audit rules loaded"

  # Ensure the daemon starts on boot (if not already)
  sudo systemctl enable --now auditd

  # After the reload, test a couple of events:
  # sudo usage
  sudo true
  sudo ausearch -k priv_esc | tail -n 5

  # mount monitoring (plug a USB stick or disconnect the eGPU)
  sudo ausearch -k mounts | tail -n 5

  # auditd.conf final output
  #
  # This file controls the configuration of the audit daemon
  #

  local_events = yes
  write_logs = yes
  log_file = /var/log/audit/audit.log
  log_group = root
  log_format = ENRICHED
  flush = INCREMENTAL_ASYNC
  freq = 50
  max_log_file = 8
  num_logs = 5
  priority_boost = 4
  name_format = NONE
  ##name = mydomain
  max_log_file_action = ROTATE
  space_left = 75
  space_left_action = SYSLOG
  verify_email = yes
  action_mail_acct = root
  admin_space_left = 50
  admin_space_left_action = SUSPEND
  disk_full_action = SUSPEND
  disk_error_action = SUSPEND
  report_interval = 0
  use_libwrap = yes
  ##tcp_listen_port = 60
  tcp_listen_queue = 5
  tcp_max_per_addr = 1
  ##tcp_client_ports = 1024-65535
  tcp_client_max_idle = 0
  transport = TCP
  krb5_principal = auditd
  ##krb5_key_file = /etc/audit/audit.key
  distribute_network = no
  q_depth = 8192
  overflow_action = SYSLOG
  max_restarts = 10
  plugin_dir = /etc/audit/plugins.d
  end_of_event_timeout = 2

  # Final suid-audit output
  #!/usr/bin/env bash
  set -euo pipefail

  AUDIT_DIR="/var/lib/suid-audit"
  LOG_DIR="/var/log/suid-audit"

  BASELINE="$AUDIT_DIR/baseline.txt"
  CURRENT="$AUDIT_DIR/current.txt"
  LOG="$LOG_DIR/audit.log"

  mkdir -p "$AUDIT_DIR" "$LOG_DIR"
  chmod 700 "$AUDIT_DIR" "$LOG_DIR"

  log() {
      echo "$(date '+%F %T') - $*" | tee -a "$LOG"
  }

  log "Starting SUID/SGID audit..."

  # Scan entire system safely (no -xdev blind spots)  
  find / \
    \( -path "/.snapshots" -o -path "/home/.snapshots" -o -path "/data/.snapshots" \
       -o -path "/var/lib/repro" \
       -o -path /proc -o -path /sys -o -path /dev -o -path /run \
       -o -path /tmp -o -path /var/tmp \) -prune \
    -o -type f \( -perm -4000 -o -perm -2000 \) -print \
    2>/dev/null | sort > "$CURRENT"

  # First run → create baseline
  if [[ ! -f "$BASELINE" ]]; then
      cp "$CURRENT" "$BASELINE"
      chmod 600 "$BASELINE"
      log "Baseline created at $BASELINE"
      exit 0
  fi

  # Detect new entries (safe, no diff parsing bugs)
  NEW=$(comm -13 "$BASELINE" "$CURRENT")

  if [[ -z "$NEW" ]]; then
      log "No new SUID/SGID binaries detected."
  else
      log "New SUID/SGID binaries detected! "

      while IFS= read -r file; do
          [[ -z "$file" ]] && continue

          if ! pacman -Qo "$file" &>/dev/null; then
              log "CRITICAL: Unowned SUID/SGID binary: $file"
          else
              log "Package-owned SUID/SGID added: $file"
          fi
      done <<< "$NEW"
  fi

  log "Audit completed."
  ```  
- Configure `dnscrypt-proxy` for secure DNS:
  ```bash
  #!/usr/bin/env bash
  set -euo pipefail

  echo "=== Installing prerequisites ==="
  sudo pacman -S --needed dnscrypt-proxy dnsutils

  echo "=== Freeing Port 53 ==="
  # Stop systemd-resolved so dnscrypt-proxy can bind to port 53 safely
  sudo systemctl disable --now systemd-resolved || true

  echo "=== Disabling NetworkManager DNS Control ==="
  sudo mkdir -p /etc/NetworkManager/conf.d
  printf "[main]\ndns=none\nsystemd-resolved=false\n" | sudo tee /etc/NetworkManager/conf.d/90-custom-dns.conf > /dev/null
  sudo systemctl restart NetworkManager

  echo "=== Setting static resolv.conf ==="
  sudo rm -f /etc/resolv.conf
  printf "nameserver 127.0.0.1\n" | sudo tee /etc/resolv.conf > /dev/null

  echo "=== Configuring dnscrypt-proxy ==="
  sudo tee /etc/dnscrypt-proxy/dnscrypt-proxy.toml > /dev/null << 'EOF'
  server_names = ['quad9-dnscrypt-ip4-filter-pri', 'mullvad-adblock']
  listen_addresses = ['127.0.0.1:53', '[::1]:53']
  max_clients = 250
  ipv4_servers = true
  ipv6_servers = false
  dnscrypt_servers = true
  doh_servers = false
  require_dnssec = true
  require_nolog = true
  require_nofilter = false
  force_tcp = false
  timeout = 2000
  lb_strategy = 'p2'
  netprobe_timeout = 5
  keepalive = 30
  cache = true
  cache_size = 4096
  cache_min_ttl = 2400
  cache_max_ttl = 86400
  cache_neg_min_ttl = 60
  EOF

  echo "=== Enabling Service ==="
  sudo systemctl enable --now dnscrypt-proxy

  echo "=== Creating Helper Scripts ==="
  sudo tee /usr/local/bin/portal-login > /dev/null << 'EOF'
  #!/usr/bin/env bash
  gateway=$(ip route | awk '/default/ {print $3; exit}')
  printf "nameserver %s\n" "${gateway:-192.168.1.1}" | sudo tee /etc/resolv.conf > /dev/null
  echo "Captive portal mode: DNS → ${gateway:-192.168.1.1}. Run portal-restore when done."
  EOF

  sudo tee /usr/local/bin/portal-restore > /dev/null << 'EOF'
  #!/usr/bin/env bash
  printf "nameserver 127.0.0.1\n" | sudo tee /etc/resolv.conf > /dev/null
  echo "DNS restored → dnscrypt-proxy (127.0.0.1)"
  EOF

  sudo tee /usr/local/bin/dns-status > /dev/null << 'EOF'
  #!/usr/bin/env bash
  echo "=== DNS Status ==="
  echo -n "Current DNS: "
  grep ^nameserver /etc/resolv.conf
  echo ""
  if systemctl is-active dnscrypt-proxy --quiet; then
      echo "dnscrypt-proxy: RUNNING"
  else
      echo "dnscrypt-proxy: DOWN"
  fi
  echo ""
  echo "Listening sockets (port 53):"
  ss -lnptu | grep ':53' || echo "Nothing listening on port 53"
  EOF

  sudo tee /usr/local/bin/dns-help > /dev/null << 'EOF'
  #!/usr/bin/env bash
  echo "=== DNS System Help ==="
  echo "Active stack: dnscrypt-proxy → resolv.conf → 127.0.0.1"
  echo ""
  echo "Commands:"
  echo "  portal-login    Captive portal mode (hotel/airport wifi)"
  echo "  portal-restore  Restore dnscrypt-proxy after portal login"
  echo "  dns-status      Show current DNS state"
  echo "  dns-help        Show this help"
  echo ""
  echo "Restart dnscrypt:  sudo systemctl restart dnscrypt-proxy"
  echo "Check logs:        journalctl -u dnscrypt-proxy -f"
  EOF

  sudo chmod +x /usr/local/bin/portal-login /usr/local/bin/portal-restore /usr/local/bin/dns-status /usr/local/bin/dns-help

  echo "=== DNS Configuration Complete ==="
  # Note: dnscrypt-proxy runs permanently. ProtonVPN kill switch and split tunneling
  # are handled natively via the ProtonVPN GUI — not via UFW or DNS scripts.
  # See: ProtonVPN GUI → Settings → Connection → Kill Switch / Split Tunneling
  ```
- Check if there is a VPN or DNS leak:
  ```bash
  # Verify (check IP and no leaks)
  dns-status # Should show running
  \dig archlinux.org #should see this in the last rows SERVER: 127.0.0.1#53(127.0.0.1)
  # Run https://www.dnsleaktest.com/ should show Quad9 or Mullvad DNS
  ```
- Harden Bluetooth Connections:
  ```bash
  # Bluetooth Hardening (Balanced for Daily Use)
  # Backup first:
  sudo cp /etc/bluetooth/main.conf /etc/bluetooth/main.conf.backup 2>/dev/null || true

  # Apply balanced hardening (uncomment and update the following):
  sudo fresh /etc/bluetooth/main.conf

  [General]
  DiscoverableTimeout=0
  ControllerMode=dual
  Privacy=network/on
  JustWorksRepairing=always

  [Policy]
  ReconnectAttempts=5
  ReconnectIntervals=1,2,4,8
  AutoEnable=true

  # Restart Bluetooth:
  sudo systemctl restart bluetooth

  # Verify:
  bluetoothctl show

  # Test your devices:
  # - Bluetooth mouse/keyboard should work
  # - Headphones should reconnect
  # - GSConnect should reconnect after suspend
  ```
- Harden CUPS (Printer Attack Surface):
  ```bash
  # Create backup directory
  BACKUP_DIR="/root/cups-backups"
  sudo mkdir -p "$BACKUP_DIR"

  # Backup existing configs
  sudo cp /etc/cups/cupsd.conf "$BACKUP_DIR/cupsd.conf.$(date +%F-%H%M%S)"
  sudo cp /etc/cups/printers.conf "$BACKUP_DIR/printers.conf.$(date +%F-%H%M%S)" 2>/dev/null || true

  # Ensure CUPS service exists and is running
  sudo systemctl enable --now cups.service

  # Disable printer discovery daemon (major historical attack vector)
  sudo systemctl disable --now cups-browsed.service 2>/dev/null || true

  # Lock down remote access using official CUPS API
  sudo cupsctl \
    --no-share-printers \
    --no-remote-admin \
    --no-remote-any

  # Enforce discovery disabled in configuration
  CONF="/etc/cups/cupsd.conf"

  if sudo grep -Eq '^[[:space:]]*Browsing' "$CONF"; then
    sudo sed -i 's/^[[:space:]]*Browsing.*/Browsing Off/' "$CONF"
  else
    echo "Browsing Off" | sudo tee -a "$CONF" >/dev/null
  fi

  if sudo grep -Eq '^[[:space:]]*BrowseLocalProtocols' "$CONF"; then
    sudo sed -i 's/^[[:space:]]*BrowseLocalProtocols.*/BrowseLocalProtocols none/' "$CONF"
  else
    echo "BrowseLocalProtocols none" | sudo tee -a "$CONF" >/dev/null
  fi

  # Restart CUPS
  sudo systemctl restart cups.service

  # Check listening ports
  ss -tulpn | grep 631
  # Correct result:
  # 127.0.0.1:631
  # [::1]:631

  # Check discovery daemon
  systemctl status cups-browsed --no-pager
  # Expected:
  # inactive (dead)
  # disabled
  # Unit cups-browsed.service could not be found.
  ```
- Configure Lynis audit and log management:
  ```bash
  # Directory setup
  sudo mkdir -p /var/log/lynis
  sudo chown root:root /var/log/lynis
  sudo chmod 700 /var/log/lynis

  # Timer
  sudo tee /etc/systemd/system/lynis-audit.timer > /dev/null <<'EOF'
  [Unit]
  Description=Run Lynis audit weekly

  [Timer]
  OnCalendar=weekly
  Persistent=true
  RandomizedDelaySec=30min

  [Install]
  WantedBy=timers.target
  EOF

  # Service
  sudo tee /etc/systemd/system/lynis-audit.service > /dev/null <<'EOF'
  [Unit]
  Description=Run Lynis security audit
  After=network-online.target
  ConditionVirtualization=!container

  [Service]
  Type=oneshot
  User=root

  ExecStart=/usr/bin/lynis audit system --cronjob \
    --auditor "Automated Audit" \
    --logfile /var/log/lynis/lynis.log \
    --report-file /var/log/lynis/lynis-report.dat

  StandardOutput=journal
  StandardError=journal

  ProtectSystem=full
  ProtectHome=true
  PrivateTmp=true
  ReadWritePaths=/var/log/lynis

  TimeoutStartSec=15min
  EOF

  # Logrotate
  sudo tee /etc/logrotate.d/lynis > /dev/null <<'EOF'
  /var/log/lynis/lynis.log /var/log/lynis/lynis-report.dat {
      weekly
      rotate 52
      compress
      delaycompress
      missingok
      notifempty
      create 0600 root root
  }
  EOF

  # Enable
  sudo systemctl daemon-reload
  sudo systemctl enable --now lynis-audit.timer

  # Initial run
  echo "Running initial Lynis audit..."
  sudo lynis audit system --cronjob \
    --auditor "Initial Manual Audit" \
    --logfile /var/log/lynis/lynis.log \
    --report-file /var/log/lynis/lynis-report.dat

  # Valdiate
  # Files exist
  sudo ls -l /var/log/lynis/

  # Check your Hardening Index (The "Score")
  sudo grep "Hardening index" /var/log/lynis/lynis.log

  # Timer is active
  systemctl list-timers lynis-audit.timer
  
  echo ""
  echo "Lynis configured and running!"
  echo ""
  echo "View reports:"
  echo "  Full log:    less /var/log/lynis/lynis.log"
  echo "  Warnings:    grep -i warning /var/log/lynis/lynis.log"
  echo "  Score:       grep -i 'hardening index' /var/log/lynis/lynis.log"
  echo ""
  echo "Timer status:"
  systemctl list-timers lynis-audit.timer --no-pager
  ```
- Configure AIDE (File Integrity Monitoring):
  ```bash
  # Backup original config
  sudo cp /etc/aide.conf /etc/aide.conf.bak 2>/dev/null || true

  # Clean, hardened config
  sudo tee /etc/aide.conf > /dev/null <<'EOF'
  database_in=file:/var/lib/aide/aide.db.gz
  database_out=file:/var/lib/aide/aide.db.new.gz

  gzip_dbout=yes
  report_ignore_changed_attrs=b
  report_force_attrs=u+g
  warn_dead_symlinks=yes

  SecGroup = p+i+n+u+g+s+m+c+acl+xattrs+sha512

  /boot        SecGroup
  /etc         SecGroup
  /usr/bin     SecGroup
  /usr/sbin    SecGroup
  /usr/lib     SecGroup
  /var/lib     SecGroup

  /etc/apparmor.d SecGroup
  /etc/systemd    SecGroup
  /etc/ssh        SecGroup
  /etc/sudoers.d  SecGroup

  !/var/lib/aide
  !/var/lib/pacman/sync
  !/var/lib/systemd/coredump
  !/var/lib/systemd/timesync
  !/var/lib/flatpak
  !/var/lib/docker
  !/var/log
  !/var/tmp
  !/var/cache
  !/var/spool
  !/.snapshots
  !/home/.snapshots
  !/data/.snapshots
  !/tmp
  !/proc
  !/sys
  !/dev
  !/run
  !/home
  EOF

  # Validate config
  echo "Validating AIDE configuration..."
  sudo aide --config-check
  if [ $? -ne 0 ]; then
    echo "Config error"
    exit 1
  fi
  echo "Config valid"

  # Initialize database
  echo "Initializing AIDE database (5-15 min)..."
  sudo aide --init
  if sudo [ ! -f /var/lib/aide/aide.db.new.gz ]; then
    echo "ERROR: AIDE initialization failed"
  else
    echo "Database exists"
  fi
  sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  echo "Database initialized"

  # Smart service 
  sudo tee /etc/systemd/system/aidecheck.service > /dev/null <<'EOF'
  [Unit]
  Description=AIDE File Integrity Check
  After=multi-user.target

  [Service]
  Type=oneshot
  ExecStart=/bin/sh -c 'if [ -f /var/lib/aide/.update-needed ]; then echo "Running AIDE Update..."; /usr/bin/aide --update; RET=$?; if [ -f /var/lib/aide/aide.db.new.gz ]; then mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; rm -f /var/lib/aide/.update-needed; echo "Baseline updated."; else echo "AIDE update failed with code $RET"; exit $RET; fi; else echo "Running AIDE Integrity Check..."; /usr/bin/aide --check; fi'
  
  StandardOutput=journal
  StandardError=journal
  ProtectSystem=full
  ProtectHome=true
  PrivateTmp=true
  ReadWritePaths=/var/lib/aide

  SuccessExitStatus=0 4
  EOF

  # Daily timer
  sudo tee /etc/systemd/system/aidecheck.timer > /dev/null <<'EOF'
  [Unit]
  Description=Run AIDE daily

  [Timer]
  OnCalendar=daily
  Persistent=true
  RandomizedDelaySec=1h

  [Install]
  WantedBy=timers.target
  EOF

  # Non-blocking pacman hook
  sudo mkdir -p /etc/pacman.d/hooks
  sudo tee /etc/pacman.d/hooks/99-aide-update.hook > /dev/null <<'EOF'
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Operation = Remove
  Type = Package
  Target = *

  [Action]
  Description = Flag AIDE database update needed
  When = PostTransaction
  Exec = /usr/bin/touch /var/lib/aide/.update-needed
  EOF

  # Enable
  sudo systemctl daemon-reload
  sudo systemctl enable --now aidecheck.timer

  echo ""
  echo "AIDE configured!"
  echo ""
  echo "Verification:"
  echo "  ls -lh /var/lib/aide/aide.db.gz"
  echo "  systemctl status aidecheck.timer"
  echo "  sudo systemctl start aidecheck.service"
  echo "  journalctl -u aidecheck.service -n 30"
  ```
- Configure sysctl hardening:
  ```bash
  # Backup current settings
  systeroid -a | sudo tee /root/sysctl-backup-$(date +%F).txt > /dev/null

  # Apply the config
  sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
  # === NETWORK HARDENING ===
  # Use "loose" mode to avoid breaking VPNs, Docker, multi-homed setups
  net.ipv4.conf.default.rp_filter=2
  net.ipv4.conf.all.rp_filter=2
  net.ipv4.tcp_syncookies=1
  net.ipv4.ip_forward=1                # updated to 1 from 0 for USB tethering/hotspot/VMs
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
  net.ipv4.conf.default.log_martians=1
  net.ipv4.icmp_ignore_bogus_error_responses=1
  net.ipv4.icmp_echo_ignore_broadcasts=1
  net.ipv4.tcp_rfc1337=1
  net.ipv4.ping_group_range=0 2147483647
  # net.ipv6.conf.all.autoconf=0                          # USED IN SERVER ONLY 
  # net.ipv6.conf.default.autoconf=0                      # USED IN SERVER ONLY
  # net.ipv6.conf.all.accept_ra=0                         # USED IN SERVER ONLY
  # net.ipv6.conf.default.accept_ra=0                     # USED IN SERVER ONLY
  # net.ipv6.conf.default.accept_ra_rt_info_max_plen=0    # USED IN SERVER ONLY
  # net.ipv6.conf.all.router_solicitations=0              # USED IN SERVER ONLY
  # net.ipv6.conf.default.router_solicitations=0          # USED IN SERVER ONLY
  # net.ipv6.conf.all.use_tempaddr=2                      # USED IN SERVER ONLY
  # net.ipv6.conf.default.use_tempaddr=2                  # USED IN SERVER ONLY
  net.core.netdev_max_backlog=4096
  net.core.bpf_jit_harden=2

  # === CORE KERNEL HARDENING (Post-Boot) ===
  kernel.randomize_va_space=2
  kernel.dmesg_restrict=1
  kernel.kptr_restrict=2
  kernel.kexec_load_disabled=1
  kernel.nmi_watchdog=0
  kernel.perf_event_paranoid=3
  kernel.yama.ptrace_scope=1           # Safer for debuggers (Wine/Proton)
  vm.unprivileged_userfaultfd = 0      # Disable dangerous userfaultfd
  dev.tty.ldisc_autoload = 0           # Disable tty line discipline autoloading
  dev.tty.legacy_tiocsti = 0           # Disable TIOCSTI (key injection)
  kernel.sysrq=244                     # Enable REISUB emergency recovery (desktop-appropriate)
  # kernel.warn_limit = 10             # Reboot on excessive warnings. DO NOT enable warn/oops limits on desktop (can cause random reboots)
  # kernel.oops_limit = 10             # Reboot on excessive oopses. DO NOT enable warn/oops limits on desktop (can cause random reboots)

  # === COMPATIBILITY HARDENING ===
  # kernel.unprivileged_bpf_disabled=1 # Block unprivileged BPF exploits (use sudo for tracing tools if needed). Set to 0 only if specific games/anti-cheat require it.
  # kernel.modules_disabled=0          # MUST BE 0 for eGPU/WiFi (Default is fine, but ensures we don't accidentally disable it). Default is 0, no need to set explicitly.

  # === SANDBOXING (Flatpak/Steam) ===
  user.max_user_namespaces=32768       # REQUIRED for sandboxing (Flatpak, Steam, Chrome)

  # === FILE SYSTEM PROTECTIONS ===
  fs.protected_symlinks=1
  fs.protected_hardlinks=1
  fs.protected_fifos=2                 # Strong protection for FIFOs
  fs.protected_regular=2               # Strong protection for regular files
  fs.suid_dumpable=0
  fs.file-max=2097152                  # High limit for Steam/Gaming

  # === GAMING / MEMORY TUNING ===
  vm.max_map_count=2147483642
  vm.swappiness=10
  vm.vfs_cache_pressure=50
  vm.compaction_proactiveness=0
  vm.watermark_scale_factor=500
  vm.watermark_boost_factor=0
  # vm.min_free_kbytes=131072
  vm.page_lock_unfairness=1
  vm.zone_reclaim_mode=0
  # kernel.sched_nr_migrate=128        # Not available on modern kernel
  kernel.split_lock_mitigate=0         # May improve frametimes in some Proton / DXVK titles. Disable if you experience instability

  # === I/O SMOOTHNESS (Smoothness/Latency) ===
  vm.dirty_bytes=100000000
  vm.dirty_background_bytes=50000000
  vm.dirty_writeback_centisecs=1500

  # === SWAP (Hibernation Readahead) ===
  vm.page-cluster=3
  EOF

  # === SYSTEROID VALIDATION: Audit for misses, explanations, and interactive review ===
  # Requires: systeroid + linux-docs package
  # NOTE: sysctl is NOT aliased; systeroid is used only for audit/inspection
  echo "=== Auditing hardening config with systeroid ==="

  # Parse & validate sysctl config file (NO enforcement)
  sudo systeroid -p /etc/sysctl.d/99-hardening.conf

  # Search for key hardening categories (check for misses/overrides)
  # - Network: Ensure RP filters, redirects, etc., applied
  sudo systeroid -r '^net\.(ipv4|ipv6)\.conf.*(rp_filter|accept_redirects|send_redirects|accept_source_route|log_martians|accept_ra)' -e
  # - Kernel core: Verify restrictions like dmesg, ptrace
  sudo systeroid -r '^(kernel\.(randomize_va_space|dmesg_restrict|kptr_restrict|kexec_load_disabled|yama\.ptrace_scope)|vm\.unprivileged_userfaultfd|dev\.tty\.(ldisc_autoload|legacy_tiocsti))' -e
  # - FS/Sandbox: Spot protected_* or namespaces issues
  sudo systeroid -r '^(fs\.protected_(symlinks|hardlinks|fifos|regular)|user\.max_user_namespaces)' -e

  # Explain a sample param (e.g., for gaming compatibility review)
  sudo systeroid --explain kernel.yama.ptrace_scope  # Safer for Wine/Proton; adjust if needed
  # Or batch-explain network ones: sudo systeroid -r 'net.ipv4.*rp_filter' --explain -e

  # Interactive TUI audit (optional, but recommended for full review)
  # Launch filtered to security sections; search '/', explain with '?', save tweaks with 's'
  sudo systeroid-tui --section kernel --query "hardening" --save-path /tmp/hardening-audit.conf
  # Review output file if tweaks needed, then merge back to 99-hardening.conf

  # Quick diff: Compare loaded system config vs. runtime (spot overrides)
  sudo systeroid --system -n > /tmp/sys-loaded.txt  # Loaded names/values
  sudo systeroid -A -n > /tmp/sys-runtime.txt       # Current runtime
  echo "Differences (should be minimal/expected):"
  sudo diff /tmp/sys-loaded.txt /tmp/sys-runtime.txt || true  # Any mismatches? Investigate
  sudo rm -f /tmp/sys-{loaded,runtime}.txt      # Cleanup

  echo "=== Audit complete. Review outputs above for gaps (e.g., add IPv6 martians if missing). ==="

  # Apply if validation passes (or reboot for full effect)
  sudo sysctl --system
  sudo etckeeper commit "Final sysctl hardening: secure, compatible, gaming-optimized"
  ```
- MGLRU + THP madvise:
  ```bash
  # MGLRU status:
  cat /sys/kernel/mm/lru_gen/enabled # f it outputs 0x0007: MGLRU is already fully enabled and managed by the kernel. You do not need to touch it.

  # Create the Configuration:
  sudo tee /etc/tmpfiles.d/10-memory-tuning.conf > /dev/null <<'EOF'
  # /etc/tmpfiles.d/10-memory-tuning.conf
  # Description: Mitigate latency spikes by tuning Transparent Huge Pages (THP).
  # MGLRU is intentionally omitted as modern kernels handle it dynamically.

  # Set THP to 'madvise' (Only use Huge Pages when an app specifically requests them)
  w /sys/kernel/mm/transparent_hugepage/enabled           - - - - madvise

  # Disable THP defragmentation (Eliminates the CPU stall when the kernel forces RAM defrag)
  w /sys/kernel/mm/transparent_hugepage/khugepaged/defrag - - - - 0

  # Set shared memory (shmem) to advise (Safe default for Vulkan/OpenGL gaming)
  w /sys/kernel/mm/transparent_hugepage/shmem_enabled     - - - - advise
  EOF

  # Apply the settings immediately without rebooting:
  sudo systemd-tmpfiles --create

  # Verify
  cat /sys/kernel/mm/transparent_hugepage/enabled
  # Expected output: always [madvise] never

  cat /sys/kernel/mm/transparent_hugepage/khugepaged/defrag
  # Expected output: 0
  ```
- Audit SUID binaries:
  ```bash
  # Install the audit script
  sudo install -Dm755 /dev/stdin /usr/local/sbin/suid-audit <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail

  AUDIT_DIR="/var/lib/suid-audit"
  LOG_DIR="/var/log/suid-audit"

  BASELINE="$AUDIT_DIR/baseline.txt"
  CURRENT="$AUDIT_DIR/current.txt"
  LOG="$LOG_DIR/audit.log"

  mkdir -p "$AUDIT_DIR" "$LOG_DIR"
  chmod 700 "$AUDIT_DIR" "$LOG_DIR"

  log() {
      echo "$(date '+%F %T') - $*" | tee -a "$LOG"
  }

  log "Starting SUID/SGID audit..."

  # Scan entire system safely (no -xdev blind spots)
  find / \
    \( -path "/.snapshots" -o -path "/home/.snapshots" -o -path "/data/.snapshots" \) -prune -o \
    -type d \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \) -prune \
    -o -type f \( -perm -4000 -o -perm -2000 \) -print \
    2>/dev/null | sort > "$CURRENT"

  # First run → create baseline
  if [[ ! -f "$BASELINE" ]]; then
      cp "$CURRENT" "$BASELINE"
      chmod 600 "$BASELINE"
      log "Baseline created at $BASELINE"
      exit 0
  fi

  # Detect new entries (safe, no diff parsing bugs)
  NEW=$(comm -13 "$BASELINE" "$CURRENT")

  if [[ -z "$NEW" ]]; then
      log "No new SUID/SGID binaries detected."
  else
      log "New SUID/SGID binaries detected! "

      while IFS= read -r file; do
          [[ -z "$file" ]] && continue

          if ! pacman -Qo "$file" &>/dev/null; then
              log "CRITICAL: Unowned SUID/SGID binary: $file"
          else
              log "ℹ️ Package-owned SUID/SGID added: $file"
          fi
      done <<< "$NEW"
  fi

  log "Audit completed."
  EOF

  # Hardened systemd automation
  # Service
  sudo tee /etc/systemd/system/suid-audit.service > /dev/null <<'EOF'
  [Unit]
  Description=Audit SUID/SGID Binaries
  After=local-fs.target

  [Service]
  Type=oneshot
  ExecStart=/usr/local/sbin/suid-audit

  # Hardening
  ProtectSystem=strict
  ProtectHome=read-only
  PrivateTmp=yes
  NoNewPrivileges=yes
  ReadWritePaths=/var/lib/suid-audit /var/log/suid-audit
  EOF

  # Timer
  sudo tee /etc/systemd/system/suid-audit.timer > /dev/null <<'EOF'
  [Unit]
  Description=Periodic SUID/SGID Audit

  [Timer]
  OnBootSec=10min
  OnUnitActiveSec=7d
  Persistent=true

  [Install]
  WantedBy=timers.target
  EOF

  # Enable
  sudo systemctl daemon-reload
  sudo systemctl enable --now suid-audit.timer

  # Initialize baseline
  sudo systemctl start suid-audit.service

  # Fix ping (modern best practice)
  PING_BIN="$(command -v ping)"

  sudo chmod u-s "$PING_BIN"
  sudo setcap cap_net_raw+ep "$PING_BIN"

  # Verify
  getcap "$PING_BIN"
  # Expected:
  # /usr/bin/ping cap_net_raw=ep

  # You DO NOT need constant maintenance.
  # Only update baseline when:
  #  • You install new software introducing SUID
  #      ◦ Example: docker, wireshark, virtualization tools
  # When that happens:
  # sudo cp /var/lib/suid-audit/current.txt /var/lib/suid-audit/baseline.txt 
  ```
- Configure zram:
  ```bash
  echo "Step: Removing conflicting ZRAM services..."

  for svc in zramswap.service zram-config.service tlp-zram.service systemd-swap.service; do
      sudo systemctl disable --now "$svc" 2>/dev/null || true
      sudo systemctl mask "$svc" 2>/dev/null || true
  done

  echo "Step: Creating ZRAM configuration..."

  sudo tee /etc/systemd/zram-generator.conf > /dev/null <<'EOF'
  [zram0]
  zram-size = min(ram / 2, 8192)
  compression-algorithm = zstd
  swap-priority = 100
  EOF

  echo "Step: Configuring kernel memory parameters..."

  sudo tee /etc/sysctl.d/99-zram-optimize.conf > /dev/null <<'EOF'
  # === ZRAM Memory Optimization ===
  # Overrides gaming-only values from 99-hardening.conf

  # Swappiness: Aggressive ZRAM use
  # Tunable: adjust to 60 (conservative) or 100 (maximum) if needed
  vm.swappiness=80

  # Page clustering: Disable for ZRAM (essential!)
  vm.page-cluster=0
  EOF

  echo "Step: Applying configurations..."

  sudo systemctl daemon-reload
  sudo sysctl --system
  sudo systemctl enable --now systemd-zram-setup@zram0.service

  echo ""
  echo "=== CONFIGURATION COMPLETE ==="
  echo ""

  echo "ZRAM Status:"
  zramctl
  echo ""

  echo "Swap Status:"
  swapon --show
  echo ""

  echo "Kernel Settings:"
  echo "  vm.swappiness = $(sysctl -n vm.swappiness)"
  echo "  vm.page-cluster = $(sysctl -n vm.page-cluster)"
  echo ""

  echo "Memory:"
  free -h
  echo ""

  echo "Setup Complete! "
  echo ""
  echo "Configuration Summary:"
  echo "  ZRAM: min(50% RAM, 8GB) with zstd compression"
  echo "  ZRAM Priority: 100 (used before disk swap)"
  echo "  Swappiness: 80 (tunable in /etc/sysctl.d/99-zram-optimize.conf)"
  echo "  Page Cluster: 0 (optimized for ZRAM)"
  echo "  THP: Left at system default (stable baseline)"
  echo ""
  echo "Reboot recommended for full effect"
  echo ""
  ```
- Configure systemd-oomd for desktop responsiveness
  ```bash
  echo "Step: Enabling systemd-oomd..."
  sudo systemctl enable --now systemd-oomd.service

  echo "Step: Configuring user.slice for OOM protection..."

  sudo mkdir -p /etc/systemd/system/user.slice.d

  sudo tee /etc/systemd/system/user.slice.d/10-oomd.conf > /dev/null <<'EOF'
  [Slice]
  # Enable memory pressure-based OOM killing for user applications
  # This protects system responsiveness by killing memory-hungry apps
  ManagedOOMMemoryPressure=kill

  # Threshold: 80% (balanced for gaming + desktop responsiveness)
  # - 60% = very responsive (Fedora default)
  # - 80% = balanced (gaming-friendly, recommended)
  # - 90% = too late (system already freezing)
  ManagedOOMMemoryPressureLimit=80%

  # Enable swap-based fallback protection
  ManagedOOMSwap=kill
  EOF

  echo "Step: Configuring global oomd defaults..."

  sudo mkdir -p /etc/systemd/oomd.conf.d

  sudo tee /etc/systemd/oomd.conf.d/10-defaults.conf > /dev/null <<'EOF'
  [OOM]
  # Default memory pressure limit (used if slice not configured)
  DefaultMemoryPressureLimit=80%

  # Require sustained pressure before acting (prevents false kills during game loads)
  DefaultMemoryPressureDurationSec=10s

  # Swap usage limit (secondary safety net)
  # With ZRAM, keep this HIGH (90%) to avoid premature kills
  # ZRAM compresses data, so swap % is misleading
  SwapUsedLimit=90%
  EOF

  echo "Step: Applying configuration..."

  sudo systemctl daemon-reload
  sudo systemctl restart systemd-oomd

  echo ""
  echo "=== CONFIGURATION COMPLETE ==="
  echo ""

  echo "systemd-oomd Status:"
  systemctl status systemd-oomd --no-pager | head -n 5
  echo ""

  echo "user.slice OOM Configuration:"
  systemctl show user.slice | grep ManagedOOM
  echo ""

  echo "Global OOM Settings:"
  sudo oomctl | head -n 10
  echo ""

  echo "PSI (Pressure Stall Information) Status:"
  cat /proc/pressure/memory
  echo ""

  echo "Current Swap State:"
  swapon --show
  echo ""

  echo "Setup Complete! "
  echo ""
  echo "Configuration Summary:"
  echo "  systemd-oomd: Active and monitoring"
  echo "  Primary trigger: PSI (memory pressure) - ZRAM-aware"
  echo "  user.slice: Kill enabled at 80% pressure"
  echo "  Duration: 10 seconds (prevents false kills)"
  echo "  Swap limit: 90% (secondary safety net)"
  echo "  system.slice: Protected (won't kill system services)"
  echo ""
  echo " Expected Behavior:"
  echo "  - Under heavy load: background apps killed first"
  echo "  - System stays responsive during memory exhaustion"
  echo "  - Games protected (user.slice priorities)"
  echo "  - No full system freezes or swap thrashing"
  ```
- Configure udisk for Firmware Updates:
  ```bash
  # Enable services
  echo "Enabling services..."
  sudo systemctl enable --now udisks2.service

  # Backup existing config (if it exists)
  if [[ -f /etc/fwupd/fwupd.conf ]]; then
      sudo cp /etc/fwupd/fwupd.conf /etc/fwupd/fwupd.conf.backup
      echo "✓ Backed up existing fwupd.conf"
  fi

  # Create drop-in configuration (BEST PRACTICE - survives package updates)
  echo "Creating Secure Boot configuration..."
  sudo mkdir -p /etc/fwupd/fwupd.conf.d

  sudo tee /etc/fwupd/fwupd.conf.d/99-secureboot.conf > /dev/null <<'EOF'
  # Secure Boot configuration for self-signed keys (sbctl)
  # Disables shim verification (not needed with sbctl)
  [uefi_capsule]
  DisableShimForSecureBoot=true
  EOF

  echo "✓ Created /etc/fwupd/fwupd.conf.d/99-secureboot.conf"

  # Sign fwupd EFI binary with sbctl
  echo "Signing fwupd EFI binary..."
  if [[ -f /usr/lib/fwupd/efi/fwupdx64.efi ]]; then
      sudo sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi
      echo "✓ Signed fwupdx64.efi"
  else
      echo "⚠ Warning: fwupdx64.efi not found (may appear after first fwupd run)"
  fi

  # Verification (NO UPDATES)
  echo ""
  echo "=== Verification ==="
  echo ""

  # Check services
  echo "Services:"
  systemctl is-active udisks2.service && echo "  ✓ udisks2: active" || echo "  ✗ udisks2: inactive"
  systemctl is-active fwupd.service && echo "  ✓ fwupd: active" || echo "  ℹ fwupd: inactive (normal, starts on-demand)"
  echo ""

  # Check for UEFI devices (don't fail if none found)
  echo "UEFI Devices:"
  if fwupdmgr get-devices 2>/dev/null | grep -i "UEFI" > /dev/null; then
      fwupdmgr get-devices 2>/dev/null | grep -i "UEFI" | head -3
      echo "  ✓ UEFI device detected"
  else
      echo "  ℹ No UEFI devices detected yet (normal before first boot)"
      echo "  ℹ Ensure 'UEFI Capsule Updates' enabled in BIOS"
  fi
  echo ""

  # Verify sbctl signing
  echo "Secure Boot Signing:"
  if sbctl verify 2>/dev/null | grep -q "fwupdx64.efi"; then
      sbctl verify 2>/dev/null | grep "fwupdx64.efi"
  else
      echo "  ℹ fwupdx64.efi signing will be verified after first fwupd run"
  fi
  echo ""

  echo "✅ fwupd configuration complete! "
  echo ""
  echo "📝 Configuration Summary:"
  echo "  - Packages: fwupd, udisks2"
  echo "  - Services: enabled and running"
  echo "  - Secure Boot: configured for sbctl (no shim)"
  echo "  - Config: /etc/fwupd/fwupd.conf.d/99-secureboot.conf"
  echo ""
  echo "⚠ IMPORTANT: Firmware updates will be checked in Step 18"
  echo "  (after first successful boot and system validation)"
  echo ""

  # Commit to etckeeper
  sudo etckeeper commit "fwupd: Configured for Secure Boot UEFI updates"
  ```
- Configure opensnitch:
  ```bash
  echo "=== Installing OpenSnitch (Application Firewall) ==="
  echo ""
  echo "⚠️  First 1-2 hours will have connection prompts"
  echo "   This is normal - you're building your baseline"
  echo ""
  read "confirm?Install OpenSnitch? (yes/NO): "
  echo ""

  if [[ "$confirm" != "yes" ]]; then
      echo "Skipping OpenSnitch installation"
      echo ""
      echo "ℹ️  You can add this later if needed"
      exit 0
  fi

  # Configure eBPF backend (SIMPLE - safe mutation only)
  echo "Optimizing backend for eBPF..."

  CONFIG_FILE="/etc/opensnitchd/default-config.json"

  if [[ -f "$CONFIG_FILE" ]] && grep -q '"ProcMonitorMethod"' "$CONFIG_FILE"; then
      # Safe: file exists AND key exists - just update value
      sudo sed -i 's/"ProcMonitorMethod": *"[^"]*"/"ProcMonitorMethod": "ebpf"/' "$CONFIG_FILE"
      echo "✓ Set eBPF backend in config"
  else
      # Skip if file/key missing - let user verify in GUI
      echo "ℹ️  eBPF config skipped - verify in GUI settings"
  fi

  # Enable daemon
  echo "Enabling OpenSnitch daemon..."
  sudo systemctl enable --now opensnitchd.service

  # Configure GUI autostart
  echo "Configuring GUI autostart..."
  mkdir -p ~/.config/autostart
  cp /usr/share/applications/opensnitch_ui.desktop ~/.config/autostart/ 2>/dev/null || {
      tee ~/.config/autostart/opensnitch-ui.desktop > /dev/null <<'EOF'
  [Desktop Entry]
  Type=Application
  Name=OpenSnitch UI
  Exec=opensnitch-ui
  Hidden=false
  NoDisplay=false
  X-GNOME-Autostart-enabled=true
  EOF 
  }

  # Launch GUI now
  echo "Launching OpenSnitch GUI..."
  opensnitch-ui &
  sleep 2

  # Verification
  echo ""
  echo "=== Verification ==="
  if systemctl is-active --quiet opensnitchd.service; then
      echo "  ✓ opensnitchd daemon: active"
  else
      echo "  ✗ opensnitchd daemon: failed"
      exit 1
  fi

  if pgrep -x opensnitch-ui > /dev/null; then
      echo "  ✓ opensnitch-ui: running"
  else
      echo "  ⚠️  opensnitch-ui: not running (will start on login)"
  fi

  echo ""
  echo "✅ OpenSnitch installed successfully! "
  echo ""
  echo "📝 CRITICAL NEXT STEPS:"
  echo ""
  echo "1. GUI is now open (system tray icon)"
  echo ""
  echo "2. In GUI Preferences, VERIFY:"
  echo "   - Default action: ALLOW (learning mode)"
  echo "   - Backend: eBPF (for best performance)"
  echo "     If not eBPF, change it manually in settings"
  echo ""
  echo "3. Use your system normally:"
  echo "   - Open Firefox, Steam, ProtonVPN, etc."
  echo "   - Allow trusted apps: 'Allow → Process → Always'"
  echo "   - Deny suspicious connections"
  echo ""
  echo "4. Common first prompts (usually safe to allow):"
  echo "   - /usr/bin/firefox"
  echo "   - /usr/bin/steam"
  echo "   - /usr/bin/steamwebhelper"
  echo "   - /usr/bin/NetworkManager"
  echo "   - Your VPN client"
  echo "   - Proton/Wine processes"
  echo ""
  echo "5. Golden rules:"
  echo "   ❌ Don't click 'Allow All'"
  echo "   ❌ Don't switch to 'Deny by default'"
  echo "   ❌ Don't overthink every prompt"
  echo "   ✅ Trust known binaries (/usr/bin/...)"
  echo "   ⚠️  Be careful with /tmp or unknown paths"
  echo ""
  echo "=== ROLLBACK ==="
  echo ""
  echo "Temporary disable:"
  echo "  sudo systemctl stop opensnitchd"
  echo ""
  echo "Remove completely:" 
  echo "  sudo systemctl disable --now opensnitchd"
  echo "  sudo pacman -Rns opensnitch"
  echo "  rm -rf ~/.config/opensnitch"
  echo ""
  echo "=== YOUR NETWORK STACK ==="
  echo ""
  echo "Layer 1: UFW (packet filtering)"
  echo "Layer 2: ProtonVPN (routing/privacy)"
  echo "Layer 3: dnscrypt-proxy (DNS privacy)"
  echo "Layer 4: OpenSnitch (app control) ← NEW"
  echo ""
  echo "✅ Clean architecture - complementary layers"
  echo ""

  # Commit to etckeeper
  sudo etckeeper commit "OpenSnitch: Application firewall (simple learning mode)"

  echo "🎯 Start using your system normally to build your baseline!"
  echo ""
  echo "Evaluate after 3 days - keep if adds value, remove if too annoying."
  ```
- Enable Apparmor in COMPLAIN mode
  ```bash
  # Parser Configuration (Drop-in approach - survives updates)
  echo "Setting up optimized parser config..."
  sudo mkdir -p /etc/apparmor/parser.conf.d
  sudo mkdir -p /var/cache/apparmor

  sudo tee /etc/apparmor/parser.conf.d/99-apparmor-performance.conf > /dev/null <<'EOF'
  write-cache
  cache-loc /var/cache/apparmor
  Optimize=compress-fast
  EOF

  echo "✓ Parser configured"

  # Enable AppArmor Service (NO timer - AUR package doesn't include it)
  echo ""
  echo "Enabling AppArmor service..."
  sudo systemctl enable --now apparmor.service
  echo "✓ Service enabled"

  # Clean up duplicate profiles (AUR package creates these)
  echo ""
  echo "Checking for duplicate profiles..."

  DUPLICATES=(
      "brave" "chrome" "chromium" "element-desktop" "epiphany" 
      "firefox" "flatpak" "foliate" "loupe" "msedge" "nautilus" 
      "opera" "plasmashell" "signal-desktop" "slirp4netns" 
      "systemd-coredump" "thunderbird" "transmission" 
      "unix-chkpwd" "virtiofsd"
  )

  FOUND_DUPLICATES=false
  for app in "${DUPLICATES[@]}"; do
      if [[ -f "/etc/apparmor.d/$app" ]] && [[ -f "/etc/apparmor.d/${app}.apparmor.d" ]]; then
          FOUND_DUPLICATES=true
          break
      fi
  done

   if $FOUND_DUPLICATES; then
      echo "⚠️  Found duplicate profiles - cleaning up..."
      sudo mkdir -p /etc/apparmor.d/duplicates_backup
    
      for app in "${DUPLICATES[@]}"; do
          if [[ -f "/etc/apparmor.d/$app" ]] && [[ -f "/etc/apparmor.d/${app}.apparmor.d" ]]; then
              sudo mv "/etc/apparmor.d/$app" "/etc/apparmor.d/duplicates_backup/" 2>/dev/null
              echo "  Moved duplicate: $app"
          fi
      done
      echo "✓ Duplicates backed up to /etc/apparmor.d/duplicates_backup/"
  else
      echo "✓ No duplicate profiles found"
  fi

  # Set all profiles to COMPLAIN mode
  echo ""
  echo "Setting all profiles to COMPLAIN mode..."
  echo "(This may take a moment for 2000+ profiles)"

  sudo aa-complain /etc/apparmor.d/* 2>&1 | grep -E "^(Setting|ERROR)" | tail -20

  echo "✓ Profiles set to complain mode"

  # Restart AppArmor to load all profiles
  echo ""
  echo "Restarting AppArmor service..."
  sudo systemctl restart apparmor.service
  echo "✓ Service restarted"

  # Regenerate UKI and sign (mkinitcpio hook not needed)
  echo ""
  echo "Regenerating Unified Kernel Image..."
  sudo mkinitcpio -P

  echo ""
  echo "Signing all EFI binaries..."
  sudo sbctl sign-all

  echo "✓ UKI rebuilt and signed"

  # Verification
  echo ""
  echo "=== Verification ==="
  echo ""

  # Service status
  if systemctl is-active --quiet apparmor.service; then
      echo "✓ apparmor.service: active"
  else
      echo "✗ apparmor.service: FAILED"
      exit 1
  fi

  # Profile status
  echo ""
  echo "AppArmor Profile Status:"
  TOTAL=$(sudo aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
  COMPLAIN=$(sudo aa-status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}')
  ENFORCE=$(sudo aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')

  echo "  Total profiles loaded: $TOTAL"
  echo "  Profiles in complain mode: $COMPLAIN"
  echo "  Profiles in enforce mode: $ENFORCE"

  # Commit to etckeeper
  echo ""
  sudo etckeeper commit "AppArmor.d: Configured $TOTAL profiles in COMPLAIN mode (Step 11 base)"

  # Initial Summary
  echo ""
  echo "✅ AppArmor.d Base Configuration Complete! "
  echo ""
  echo "📊 Current Status:"
  echo "  - $TOTAL profiles loaded and active"
  echo "  - $COMPLAIN in COMPLAIN mode (learning)"
  echo "  - $ENFORCE in ENFORCE mode (defaults)"
  echo "  - Parser optimized for performance"
  echo "  - UKI rebuilt and signed"
  echo ""
  ```
- Apparmor Gaming Fix Service
  ```bash
  sudo tee /usr/local/bin/apparmor-gaming-fix > /dev/null << 'EOF'
  #!/usr/bin/env bash
  # Enforce disabled state for AppArmor profiles that break gaming
  # Removed -e temporarily to handle grep return codes manually
  set -uo pipefail

  GAMING_BLOCKERS=("steam" "fbwrap" "unprivileged_userns")
  PROFILES_FIXED=0

  /usr/bin/mkdir -p /etc/apparmor.d/disable

  for profile in "${GAMING_BLOCKERS[@]}"; do
      if [[ -f "/etc/apparmor.d/$profile" ]]; then
          # Use [[:space:]] to be whitespace-agnostic and 
          # use an if-statement to handle the grep exit code safely
          if /usr/bin/aa-status 2>/dev/null | /usr/bin/grep -qE "^[[:space:]]+$profile$"; then
              /usr/bin/logger -t apparmor-gaming-fix "NOTICE: $profile was active, disabling..."
              /usr/bin/ln -sf "/etc/apparmor.d/$profile" "/etc/apparmor.d/disable/$profile"
              /usr/bin/apparmor_parser -R "/etc/apparmor.d/$profile" 2>/dev/null || true
              ((PROFILES_FIXED++))
          fi
      fi
  done

  if [[ $PROFILES_FIXED -gt 0 ]]; then
      /usr/bin/logger -t apparmor-gaming-fix "Successfully re-disabled $PROFILES_FIXED profiles."
  else
      /usr/bin/logger -t apparmor-gaming-fix "System clean: Gaming profiles already disabled."
  fi

  # Explicitly exit 0 so systemd is happy
  exit 0
  EOF
  
  sudo tee /etc/systemd/system/apparmor-gaming-fix.service > /dev/null << 'EOF'
  [Unit]
  Description=Re-enforce AppArmor gaming profile exclusions
  Documentation=man:apparmor(7)
  After=apparmor.service
  Requires=apparmor.service

  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/apparmor-gaming-fix
  RemainAfterExit=yes

  [Install]
  WantedBy=multi-user.target
  EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now apparmor-gaming-fix.service
  ```
- Increase Audit Backlog for AppArmor Complain Mode
  ```bash
  echo "Increasing audit backlog for AppArmor learning phase..."

  # AppArmor with 2000+ profiles in complain mode generates
  # massive log volume. Default backlog (8192-16384) is too small.

  # Create main audit rules file if it doesn't exist
  if [[ ! -f /etc/audit/rules.d/audit.rules ]]; then
    sudo tee /etc/audit/rules.d/audit.rules > /dev/null <<'EOF'
  # Audit Rules Configuration
  # Generated during Arch Fortress installation

  # AppArmor Complain Mode - Increase Backlog
  # 2040+ profiles in complain mode = massive log volume
  # Default: 8192-16384 → New: 131072
  -b 131072
  EOF
  else
      # Append to existing file
      sudo tee -a /etc/audit/rules.d/audit.rules > /dev/null <<'EOF'
  # AppArmor Complain Mode - Increase Backlog
  # 2040+ profiles generate massive log volume
  -b 131072
  EOF
  fi

  # Apply immediately
  sudo auditctl -b 131072 -r 0

  # Reload all rules
  sudo augenrules --load > /dev/null 2>&1

  # Verify
  CURRENT_BACKLOG=$(sudo auditctl -s | grep backlog_limit | awk '{print $2}')

  if [[ "$CURRENT_BACKLOG" == "131072" ]]; then
      echo "✓ Audit backlog increased to 131072"
  else
      echo "  Audit backlog: $CURRENT_BACKLOG (expected 131072)"
      echo "   This is non-critical, system will work fine"
  fi

  echo ""
  echo "NOTE: 'Old style watch rules are slower' warnings are normal"
  echo "      and can be ignored (legacy audit rule format)"
  ```
- Systemd Service Hardening Phase 1 and 2 (3 will be after eGPU)
  ```bash
  #!/bin/bash
  # Phase 1: Disable Unused Services
  DISABLED_COUNT=0

  # Bluetooth - KEEP for GSConnect
  echo "ℹ️  Keeping bluetooth.service (GSConnect requires Bluetooth)"
  echo "   (You can disable manually later if you remove GSConnect)"

  # CUPS - Check if already removed
  if systemctl list-unit-files cups.service &>/dev/null; then
      if ! lpstat -p 2>/dev/null | grep -q "printer"; then
          echo "✓ Disabling cups.service (no printer configured)"
          sudo systemctl disable --now cups.service cups.socket cups.path 2>/dev/null || true
          ((DISABLED_COUNT++))
      else
          echo "ℹ️  Printer detected, keeping CUPS enabled"
      fi
  else
      echo "ℹ️  CUPS not installed (already removed)"
  fi

  # IIO Sensor Proxy - KEEP for auto-brightness
  echo "ℹ️  Keeping iio-sensor-proxy.service (auto-brightness functionality)"

  # Libvirt - KEEP if VMs might be used
  echo "ℹ️  Keeping libvirt services (VM infrastructure)"

  # Bolt - KEEP for Thunderbolt ports
  echo "ℹ️  Keeping bolt.service (ThinkBook has Thunderbolt 4 ports)"

  echo ""
  echo "Phase 1 complete: $DISABLED_COUNT service groups disabled"

  # Verification
  echo ""
  echo "Verification:"
  systemctl --failed | grep -E "cups|iio|libvirt" && echo "⚠️  Some services failed!" || echo "✓ No failed services"

  # Commit
  sudo etckeeper commit "Systemd: Phase 1 - Disabled $DISABLED_COUNT unused services"

  # Phase 2: Low-Risk Service Hardening

  # Create drop-in directories
  sudo mkdir -p /etc/systemd/system/{thermald,acpid,rtkit-daemon}.service.d

  # thermald (CRITICAL: NO ProtectKernelTunables - thermal management must work!)
  echo "Hardening thermald.service (thermal-safe)..."
  sudo tee /etc/systemd/system/thermald.service.d/harden.conf > /dev/null <<'EOF'
  [Service]
  # Thermal management - MUST be able to write to /sys for cooling control
  # CRITICAL: NO ProtectKernelTunables (would break thermal management)
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  NoNewPrivileges=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  RestrictRealtime=yes
  MemoryDenyWriteExecute=yes
  RestrictAddressFamilies=AF_UNIX AF_NETLINK
  # AF_NETLINK required for thermal zone monitoring
  EOF

  # acpid (ACPI events - relaxed hardening for event scripts)
  echo "Hardening acpid.service (relaxed for event scripts)..."
  sudo tee /etc/systemd/system/acpid.service.d/harden.conf > /dev/null <<'EOF'
  [Service]
  # ACPI event handling - needs flexibility for event scripts
  # Use 'full' instead of 'strict' to allow /etc/acpi script execution
  ProtectSystem=full
  ProtectHome=yes
  PrivateTmp=yes
  NoNewPrivileges=yes
  RestrictAddressFamilies=AF_UNIX AF_NETLINK
  # AF_NETLINK required for hardware events
  # ProtectKernelModules removed - acpi scripts may need it
  EOF

  # rtkit-daemon (audio realtime priority)
  echo "Hardening rtkit-daemon.service..."
  sudo tee /etc/systemd/system/rtkit-daemon.service.d/harden.conf > /dev/null <<'EOF'
  [Service]
  # Realtime audio priority daemon
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  NoNewPrivileges=yes
  ProtectKernelTunables=yes
  MemoryDenyWriteExecute=yes
  RestrictAddressFamilies=AF_UNIX
  # RestrictRealtime NOT set - needs realtime for audio
  EOF

  # Apply changes
  sudo systemctl daemon-reload

  # Restart services with verification
  echo ""
  echo "Restarting services to apply hardening..."
  for svc in thermald acpid rtkit-daemon; do
      if systemctl is-active --quiet $svc; then
          echo "  Restarting $svc..."
          sudo systemctl restart $svc
          sleep 1
          if systemctl is-active --quiet $svc; then
              echo "    ✓ $svc active and hardened"
          else
              echo "    ✗ $svc FAILED - rolling back!"
              sudo rm /etc/systemd/system/$svc.service.d/harden.conf
              sudo systemctl daemon-reload
              sudo systemctl start $svc
          fi
      else
          echo "  ℹ️  $svc not running (OK)"
      fi
  done

  # Comprehensive verification
  echo ""
  echo "=== Verification ==="

  # Security scores
  echo "Security scores (lower is better):"
  systemd-analyze security thermald acpid rtkit-daemon 2>/dev/null | \
      grep -E "^(thermald|acpid|rtkit)" || echo "Services hardened"

  # Thermal functionality
  echo ""
  echo "Thermal system check:"
  if ls /sys/class/thermal/thermal_zone*/temp > /dev/null 2>&1; then
      echo "  ✓ Thermal zones accessible"
      # Check if thermald can read temps
      temp_file=$(ls /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
      if [[ -r "$temp_file" ]]; then
          temp=$(($(cat $temp_file) / 1000))
          echo "  ✓ Current CPU temp: ${temp}°C"
      fi
  else
      echo "  ✗ Thermal zones NOT accessible (ERROR!)"
  fi

  # ACPI functionality
  echo ""
  echo "ACPI system check:"
  if systemctl status acpid --no-pager -l | grep -q "active"; then
      echo "  ✓ ACPI daemon active"
  else
      echo "  ✗ ACPI daemon failed"
  fi

  # Audio functionality
  echo ""
  echo "Audio system check:"
  if pactl info > /dev/null 2>&1; then
      echo "  ✓ Audio system working (rtkit functional)"
  else
      echo "  ⚠️  Audio check failed (might not be critical)"
  fi

  # Commit
  sudo etckeeper commit "Systemd: Phase 2 - Hardened thermald, acpid, rtkit-daemon (thermal-safe)"

  echo ""
  echo "✅ Phase 2 Complete!"
  echo ""
  echo "IMPORTANT: Monitor temps during first gaming session"
  echo "  Install lm_sensors if needed: sudo pacman -S lm_sensors"
  echo "  Then run: sensors"
  ```
- Check for TME support (If your CPU support it and is active in the BIOS this is a check)
  ```bash
  dmesg | grep -i "Memory Encryption"
  # If you see "TME: enabled", your RAM is encrypted against physical extraction.
  ```
- Remove GRUB is not in use
  ```bash
  sudo pacman -Rns grub
  ```
## Step 12: Configure eGPU (AMD)

- Install AMD drivers and microcode:
  ```bash
  pacman -S --noconfirm amd-ucode rocm-opencl rocm-hip
  ```
- amdgpu Module configuration and early KMS
  ```bash
  # === AMD eGPU: Full recommended amdgpu module configuration ===
  sudo tee /etc/modprobe.d/amdgpu.conf <<'EOF'
  # Enable ALL PowerPlay features (fan curves, overclocking, power limits, zero-RPM, etc.)
  options amdgpu ppfeaturemask=0xffffffff

  # Force PCIe Gen4 max capability (most Thunderbolt 4/5 enclosures are Gen4 x4)
  # 0x80000 = advertise Gen4 support up to Gen4, driver will negotiate down if needed
  options amdgpu pcie_gen_cap=0x80000

  # (OPTIONAL - START WITHOUT) Better hot-plug handling on Thunderbolt/USB4 (fixes black screen on plug-in for many)
  # options amdgpu dcdebugmask=0x4

  # (OPTIONAL - START WITHOUT) Recommended for stability with most eGPU enclosures
  # options amdgpu vm_update_mode=3

  # Optional: enable RAS (error correction/reporting) on RDNA2/RDNA3 — harmless if unsupported
  options amdgpu ras_enable=1
  EOF

  # If experiencing AMD eGPU reset issues (black screen after suspend/hotplug):
  # Uncomment and test reset methods (kernel 7.0+ has improved reset handling):
  # options amdgpu reset_method=2    # BACO (Bus Alive, Chip Off) - most stable
  # options amdgpu reset_method=3    # Mode1 (display reset only)
  # See: https://wiki.archlinux.org/title/AMDGPU#Reset_methods

  # === Early KMS: load xe (iGPU), i915 (fallback), and amdgpu at boot ===
  sudo sed -i '/^MODULES=/d' /etc/mkinitcpio.conf
  echo 'MODULES=(xe i915 amdgpu)' | sudo tee -a /etc/mkinitcpio.conf

  # Regenerate initramfs so everything loads early (critical for eGPU at login screen)
  sudo mkinitcpio -P

  # Optional but very useful: add these kernel parameters
  # Especially important if you still don’t get full 16 GT/s ×4 after the above
  # Example line to add to your bootloader entry:
  # options rd.luks.uuid=$LUKS_UUID root=UUID=$ROOT_UUID ... amdgpu.pcie_gen_cap=0x80000 pcie_ports=native pciehp.pciehp_force=1.
  # Alternatively, for module options: echo 'options amdgpu pcie_gen_cap=0x80000' | sudo tee -a /etc/modprobe.d/amdgpu.conf
  # Essential for reliable PCIe hotplug on Lenovo/OCuLink
  # pcie_ports=native          # Use native PCIe port driver (bypasses BIOS quirks)
  # pciehp.pciehp_force=1      # Force-enable hotplug polling on all slots
  # pcie_aspm=off              # Disable ASPM (power saving) to prevent link drops
  # pci=nomsi                  # Fallback if MSI interrupts fail on hot-add
  ```
- Sign kernel modules for Secure Boot
  ```bash
  sbctl sign --all
  find /lib/modules/$(uname -r)/kernel/drivers/gpu -name "*.ko" -exec sbctl verify {} \;
  reboot

  # After Reboot
  # Validate AMD GPU once connected (Should output "AMD Radeon ...")
  DRI_PRIME=1 glxinfo | grep renderer

  # After setup, verify with (should show "Speed 16GT/s (ok), Width x4"). If stuck at lower, tweak pcie_gen_cap to 0x40000
  lspci -vv -s $(lspci | awk '/VGA.*AMD/{print $1}') | grep LnkSta
  ```
- Configure TLP to avoid GPU power management conflicts and add parameters for Geek-like Lenovo Vantage Windows Power Mode
  ```bash
  # === AUTOMATION: Performance Profile Switching (AC vs. Battery) ===
  # Disable tlp-rdw,it can fight with manual governor settings
  sudo systemctl mask tlp-rdw

  # Create the shell script to toggle the performance mode (run as root by udev)
  sudo tee /usr/local/bin/thinklmi-power-switcher << 'EOF'
  #!/bin/bash

  # Without this, fast AC plug/unplug storms can run the script multiple times
  LOCKFILE="/var/run/thinklmi-switcher.lock"
  # Simple flock to prevent overlapping runs
  exec 200>"$LOCKFILE"
  flock -n 200 || exit 0
    
  # Path to the ThinkLMI file
  PERF_MODE_PATH="/sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value"

  # Check if the path exists (ensure kernel module is loaded)
  if [ ! -f "$PERF_MODE_PATH" ]; then
    echo "ThinkLMI performance_mode path not found: $PERF_MODE_PATH" >&2
    exit 1
  fi

  case "$1" in
    ac)
        # Max performance (Geek Mode) when plugged in (docked)
        echo "Setting ThinkLMI to extreme_performance (AC Power)"
        echo "extreme_performance" > "$PERF_MODE_PATH"
        if [ "$(cat "$PERF_MODE_PATH")" != "extreme_performance" ]; then
           echo "Failed to set extreme_performance: Check dmesg or valid_values." >&2
           logger -t thinklmi-switcher "Failed to set extreme_performance ($(date))"
           exit 1
        fi
        logger -t thinklmi-switcher "Set to extreme_performance ($(date))"
        ;;
    battery)
        # Quiet Mode for maximum battery life when unplugged
        echo "Setting ThinkLMI to quiet_mode (Battery Power)"
        echo "quiet_mode" > "$PERF_MODE_PATH"
        if [ "$(cat "$PERF_MODE_PATH")" != "quiet_mode" ]; then
           echo "Failed to set quiet_mode: Check dmesg or valid_values." >&2
           logger -t thinklmi-switcher "Failed to set quiet_mode ($(date))"
           exit 1
        fi
        logger -t thinklmi-switcher "Set to quiet_mode ($(date))"
        ;;
    *)
        echo "Usage: $0 {ac|battery}" >&2
        exit 1
        ;;
  esac
  EOF

  # Make the script executable
  sudo chmod +x /usr/local/bin/thinklmi-power-switcher

  # Create the udev rule to trigger the script on AC status change
  sudo tee /etc/udev/rules.d/99-thinklmi-power.rules << 'EOF'
  # When AC adapter status changes to 'online' (1)
  SUBSYSTEM=="power_supply", KERNEL=="AC*", ATTR{online}=="1", ACTION=="change", RUN+="/bin/sh -c 'sleep 0.5; /usr/local/bin/thinklmi-power-switcher ac'"

  # When AC adapter status changes to 'offline' (0)
  SUBSYSTEM=="power_supply", KERNEL=="AC*", ATTR{online}=="0", ACTION=="change", RUN+="/usr/local/bin/thinklmi-power-switcher battery"
  EOF

  # Reload udev rules to make the change active immediately
  sudo udevadm control --reload-rules

  # Execute the script once to set the initial state (based on current power status)
  # This will find the current power state and apply the corresponding profile.
  AC_STATUS=""
  if [ -f /sys/class/power_supply/AC*/online ]; then
    AC_STATUS=$(cat /sys/class/power_supply/AC*/online 2>/dev/null | head -1)
  elif command -v upower >/dev/null 2>&1; then
    AC_STATUS=$(upower -i /org/freedesktop/UPower/devices/line_power_AC*/online 2>/dev/null | grep -q "yes" && echo "1" || echo "0")
  else
    echo "Warning: No reliable AC probe available; skipping initial set." >&2
    exit 0
  fi

  if [ "$AC_STATUS" = "1" ]; then
    sudo /usr/local/bin/thinklmi-power-switcher ac
  else
    sudo /usr/local/bin/thinklmi-power-switcher battery
  fi

  # === Configure TLP for auto-switching and eGPU compatibility ===
  
  # Create the proper drop-in directory (once)
  sudo mkdir -p /etc/tlp.d

  # Write your custom overrides safely (this will never be overwritten by pacman updates)
  sudo tee /etc/tlp.d/99-thinkbook-egpu.conf << 'EOF'
  # === GPU: Prevent TLP from touching runtime PM (critical for OCuLink eGPU hotplug) ===
  RUNTIME_PM_BLACKLIST="amdgpu xe i915"     # xe = Intel Arc iGPU (Core Ultra), amdgpu = eGPU

  # === Maximum performance on AC (mimics Lenovo Vantage "Extreme Performance") ===
  CPU_SCALING_GOVERNOR_ON_AC=performance
  CPU_ENERGY_PERF_POLICY_ON_AC=performance

  # Quieter/Slower on Battery (Consistent with ThinkLMI 'quiet_mode')
  CPU_SCALING_GOVERNOR_ON_BAT=powersave
  CPU_ENERGY_PERF_POLICY_ON_BAT=balance_power

  # === Do not fight with Lenovo's native battery charge control ===
  # (TLP has ignored vendor-specific thresholds by default since 2023, but being explicit is fine)
  START_CHARGE_THRESH_BAT0=""
  STOP_CHARGE_THRESH_BAT0=""
  
  EOF

  # Apply
  sudo systemctl restart tlp

  # === Performance Mode: Auto-Switching via UDEV ===

  # LIST available modes on your specific hardware (e.g., quiet_mode, balanced, extreme_performance)
  echo "Available Lenovo Power Modes:"
  cat /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/valid_values

  # If want to set manually one time the "Extreme Performance" profile
  # This is the Linux equivalent of Lenovo Vantage's "Geek Power Mode"
  # echo extreme_performance | sudo tee /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value

  # VERIFY the change
  echo "Current Active Mode:"
  tlp-stat -s            # Should show "performance" governor
  tlp-stat -p            # PL1/PL2 should be high (60–120 W depending on cooling)
  tlp-stat -g            # Confirm runtime PM blacklist applied
  cat /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value

  # Manual Option in case don't want to automate with UDEV
  # Manual GUI button to toggle the mode on demand, create a desktop entry or a simple custom GNOME extension that runs the following commands:
  # Extreme Performance:
  # pkexec /bin/sh -c 'echo extreme_performance > /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value'
  # Quiet Mode:
  # pkexec /bin/sh -c 'echo quiet_mode > /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value'
  # [Desktop Entry]
  # Name=ThinkLMI Extreme Performance
  # Exec=pkexec /bin/sh -c 'echo extreme_performance > /sys/class/firmware-attributes/thinklmi/attributes/performance_mode/current_value'
  # Icon=performance-high
  # Type=Application
  ```
- Install switcheroo-control for GPU integration
  ```bash
  pacman -S --needed switcheroo-control
  systemctl enable --now switcheroo-control
  ```
- Explicit IOMMU group check for eGPU isolation
  ```bash
  for d in /sys/kernel/iommu_groups/*/devices/*; do
    n=${d#*/iommu_groups/*}; n=${n%%/*}
    printf 'IOMMU Group %s ' "$n"
    lspci -nns "${d##*/}"
  done | grep -i amd
  ```
- Configure systemd-logind for reliable GPU switching
  ```bash
  # Enable KillUserProcesses for clean eGPU switching
  # WARNING: This will close background apps (Discord, Spotify) on logout
  # If you want them to persist, set to 'no' (but may cause eGPU issues)
  sudo sed -i 's/#KillUserProcesses=no/KillUserProcesses=yes/' /etc/systemd/logind.conf
  systemctl restart systemd-logind
  ```
- Install bolt for Thunderbolt 4 management (OCuLink usually bypasses this)
  ```bash
  pacman -S --needed bolt
  systemctl enable --now bolt
  # Configure auto-connection for Thunderbolt devices
  # (Note: OCuLink typically appears as raw PCIe and doesn't use bolt/Thunderbolt security)
  sudo mkdir -p /etc/boltd
  echo "always-auto-connect = true" | sudo tee -a /etc/boltd/boltd.conf
  
  # Check for devices (Use this only if connecting via USB4/TB4 port)
  boltctl list

  # If a device shows as 'unauthorized', copy its UUID:
  # grep -i oculink
  # boltctl authorize <uuid>
  ```
- Enable VRR for 4K OLED
  ```bash
  # === Enable VRR in GNOME Mutter (Wayland) ===
  # VRR Configuration (GNOME 50+ - March 2026)
  # VRR is now stable and enabled by default in Settings > Displays > Refresh Rate
  # Verify VRR capability:
  gnome-randr | grep -i variable || xrandr --prop | grep -i vrr

  # If VRR doesn't auto-enable, force with:
  # gsettings set org.gnome.mutter experimental-features "['variable-refresh-rate']"

  # NOTE: Actual VRR range configuration is handled via GNOME Control Center
  # (Settings -> Displays) after this flag is enabled.

  # === Verify PRIME Offload (iGPU vs. eGPU) ===
  echo "--- OpenGL (glxinfo) Verification ---"
  # Verify iGPU (Intel Arc) is the default:
  DRI_PRIME=0 glxinfo | grep "OpenGL renderer" #Should show Intel Arc
  # Verify eGPU (AMD) is selected for offload:
  DRI_PRIME=1 glxinfo | grep "OpenGL renderer" #Should show AMD eGPU
  
  echo "--- Vulkan (vulkaninfo) Verification ---"
  # Vulkan is the modern standard; ensure it sees the eGPU
  # Install 'vulkan-tools' package if 'vulkaninfo' is not found.
  # Output should list your AMD eGPU (e.g., 'AMD Radeon RX 7900 XT')
  # Verify VRR support on the eGPU:
  DRI_PRIME=1 vulkaninfo | grep "deviceName"

  # Check video decode capabilities
  echo "--- Video Acceleration Check (VDPau/Radeonsi) ---"
  DRI_PRIME=1 vdpauinfo | grep -i radeonsi 

  # If VRR fails, check dmesg for amdgpu errors:
  dmesg | grep -i amdgpu

  # === Confirm Display Settings (Wayland) ===
  # The following is a Wayland-native check tool (wlr-randr) often useful,
  # but configuration must be done in GNOME Control Center for Mutter.
  echo "--- Wayland Refresh Rate Check ---"
  # Check if wlr-randr is available and confirm refresh rate range:
  if command -v wlr-randr &> /dev/null; then
    wlr-randr
  else
    echo "wlr-randr not found. Check display settings in GNOME Control Center."
  fi
  # Ensure 4K OLED is set to its maximum refresh rate and VRR range in the GUI:
  # Launch 'gnome-control-center' (Settings) -> Displays -> Resolution/Refresh Rate
  # Set the desired resolution and confirm the refresh rate (e.g., 120Hz) is available.

  # === Check AppArmor Denials (Crucial for VFIO/Passthrough) ===
  echo "--- AppArmor Denial Checks ---"
  # Check AppArmor denials specifically related to systems that touch PCI/GPU resources
  journalctl -u apparmor | grep -i "supergfxctl\|qemu\|libvirtd\|amdgpu"
  
  # Log denials to a file for review
  journalctl -u apparmor | grep -i DENIED > /var/log/apparmor-denials.log
  # echo "NOTE: If AppArmor denials are found, generate profiles with 'aa-genprof qemu-system-x86_64' and customize rules for /dev/dri/*, /dev/vfio/*, and /sys/bus/pci/* access."

  # DO NOT ENFORCE YET — FSP is in COMPLAIN mode
  # Denials will be logged to /var/log/apparmor-denials.log
  # Note: Full AppArmor.d policy will be enforced in later Step 18 via 'just fsp-enforce
  ```
- Enable gamemoded
  ```bash
  # Enable GameMode
  systemctl --user enable --now gamemoded

  # Usage and Conflicts
  echo "GameMode enabled. Use 'gamemoderun' prefix for performance uplift."
  # Launch example for Steam:
  # Launch Options: gamemoderun %command%

  echo "ALERT: GameMode is not recommended alongside advanced schedulers like Ananicy-cpp. Ananicy-cpp is not used in the plan at the momment"
  echo "Choose one: simple performance via GameMode, or complex system-wide tuning via Ananicy-cpp."
  echo "If using dual monitors with mixed refresh rates (e.g., 144Hz + 60Hz), GameMode can help AMD eGPU power management by running scripts to toggle rates (reduces idle VRAM clock/power draw). You would need to create a script for this."
  ```
- Configure LACT for GPU Control
  ```bash
  # Enable LACT daemon
  sudo systemctl enable --now lactd

  # Open GUI (after reboot into graphical environment)
  lact

  # Recommended LACT Settings for Gaming:

  # Power Profile: 3dmark or VR (max performance)
  # Power Limit: Max (depends on dock cooling - monitor temps)
  # Performance Level: high or manual
  # Fan Curve: Aggressive (eGPU docks have limited cooling)
  # Clock Limits: Leave at max unless thermal throttling
  # VRAM Clock: Max
  # VRR: Enable (if not auto-detected)
  ```
- Create MangoHud Configuration
  ```bash
  mkdir -p ~/.config/MangoHud
  cat > ~/.config/MangoHud/MangoHud.conf << 'EOF'
  ############
  # DISPLAY
  ############
  # Position: top-left is safest for OLED (avoids bottom burn-in)
  position=top-left
  font_size=24
  no_small_font

  # OLED-friendly colors (avoid pure white, use slight gray)
  text_color=E0E0E0
  gpu_color=95E095
  cpu_color=95E0E0
  vram_color=95A0E0
  ram_color=E0E095
  fps_color=E0E095

  # Background opacity (0-100, lower = less burn-in risk)
  background_alpha=0.4

  ############
  # METRICS
  ############
  # Core stats
  fps
  fps_sampling_period=500
  fps_color_change
  fps_value=30,60

  # GPU
  gpu_stats
  gpu_temp
  gpu_core_clock
  gpu_mem_clock
  gpu_power
  gpu_load_change
  gpu_load_value=50,90
  vram
  amdgpu_voltage

  # CPU  
  cpu_stats
  cpu_temp
  cpu_mhz
  cpu_load_change
  cpu_load_value=50,90
  core_load

  # Memory
  ram
  swap

  # Frame timing (critical for diagnosing stutters)
  frame_timing=1
  frametime
  histogram

  # 1% and 0.1% lows (critical for smoothness perception)
  fps_metrics=avg,0.01,0.1

  ############
  # FPS LIMITING
  ############
  # For 240Hz OLED with VRR: limit to 237 fps (240 - 3)
  # This prevents tearing while staying in VRR range
  fps_limit=237

  # Use 'early' method for lower latency (recommended for competitive)
  # Use 'late' for smoother frame pacing (recommended for single-player)
  fps_limit_method=early

  # Toggle FPS limit on/off with Shift_R+F1
  toggle_fps_limit=Shift_R+F1

  ############
  # LOGGING
  ############
  # Benchmark logging
  output_folder=/home/$USER/Documents/mangohud_logs
  log_duration=30
  toggle_logging=Shift_R+F2
  upload_log=F5

  ############
  # OTHER
  ############
  # Show MangoHud version
  version

  # Vsync indicator (shows when vsync is forced)
  vsync=0

  # Engine version (useful for debugging)
  engine_version
  wine

  # Hotkeys
  toggle_hud=Shift_R+F12
  reload_cfg=Shift_R+F4
  EOF
  ```
- Configure gaming environment variables:
  ```bash
  mkdir -p ~/.config/environment.d
  cat > ~/.config/environment.d/50-gaming.conf <<'EOF'
  # AMD Mesa shader cache (centralized location)
  # Note: ACO is the default RADV compiler on modern Mesa;
  # no explicit RADV_PERFTEST flags are required.
  MESA_SHADER_CACHE_DIR=$HOME/.cache/mesa_shader_cache
  MESA_SHADER_CACHE_MAX_SIZE=10G
  EOF
  
  echo "✓ Gaming environment variables configured (session-wide)"
  echo "  Shader cache: ~/.cache/mesa_shader_cache (10GB max)"
  echo "  ACO: default RADV compiler on modern Mesa (no forcing needed)"
  ```
- Performance optimization template (for Gamesopce add to Steam)
  ```bash
  # Template: For regular gaming (without gamescope, light games or native desktop resolution)
  # MANGOHUD_CONFIG="cpu_stats,cpu_temp,gpu_stats,gpu_temp,vram,ram,fps_limit=117,frame_timing" LD_BIND_NOW=1 MESA_VK_DEVICE_SELECT=amd gamemoderun mangohud %command%

  # Templates for gamescope gaming (with eGPU)
  # Template 1: Native 4K 240Hz (for games that can hit >100 fps)
  # Steam Launch Options:
  # MESA_VK_DEVICE_SELECT=amd LD_BIND_NOW=1 gamemoderun gamescope -W 3840 -H 2160 -w 3840 -h 2160 -r 240 --adaptive-sync --mangoapp -- %command%
  
  # Template 2: 1440p → 4K Upscale (for demanding games)
  # Uses FSR to upscale 1440p to 4K (better performance)
  # MESA_VK_DEVICE_SELECT=amd LD_BIND_NOW=1 gamemoderun gamescope -w 2560 -h 1440 -W 3840 -H 2160 -r 240 --fsr-sharpness 3 --adaptive-sync --mangoapp -- %command%

  # Template 3: 1080p → 4K Upscale (for very demanding games)
  # Uses FSR to upscale 1080p to 4K (best performance)
  # MESA_VK_DEVICE_SELECT=amd LD_BIND_NOW=1 gamemoderun gamescope -w 1920 -h 1080 -W 3840 -H 2160 -r 240 --fsr-sharpness 3 --adaptive-sync --mangoapp -- %command%

  # Template 4: High Refresh Priority (for competitive games)
  # 1080p native, max refresh, low latency
  # MESA_VK_DEVICE_SELECT=amd LD_BIND_NOW=1 gamemoderun gamescope -w 1920 -h 1080 -W 1920 -H 1080 -r 240 --adaptive-sync --immediate-flips --mangoapp -- %command%
  
  # Verify Gaming Settings
  sysctl -a | grep vm.swappiness # (should be 10)
  cat /sys/kernel/mm/transparent_hugepage/enabled # (madvise)
  DRI_PRIME=1 glxgears # (eGPU: uncapped FPS → vblank disabled)
  # Games: Add vblank_mode=0 to Steam launch options if needed (overrides drirc).
  # Revert if tearing bothers you: rm ~/.drirc && chezmoi forget ~/.drirc.

  # Gamescope Flags Explained:
  # -w/-h: Game internal resolution
  # -W/-H: Display output resolution
  # -r: Refresh rate cap (use 240 for max)
  # --adaptive-sync: Enable VRR (better than -r for variable fps)
  # --fsr-sharpness: 0-20, higher = sharper (3-5 recommended for upscaling)
  # --mangoapp: MangoHud overlay (don't use mangohud wrapper with gamescope)
  # --immediate-flips: Lower latency (may cause tearing without VRR)
  ```
- Configure FPS Limiting Strategy
  ```bash
  For 240Hz OLED with VRR:
  Option A: Let VRR Handle It (Recommended for most games)

  Don't set FPS limit
  Let game run uncapped within VRR range
  Smoother experience with variable frame times

  Option B: Cap at 237 FPS (For consistency)

  Prevents exceeding VRR max (240Hz)
  Avoids VSync fallback and tearing
  Use MangoHud: fps_limit=237 + fps_limit_method=early

  Option C: Cap at Half Refresh (For demanding games)

  Cap at 120 fps for 240Hz display
  Guarantees smooth frame pacing
  Use MangoHud: fps_limit=120 + fps_limit_method=late

  In-Game vs MangoHud vs Gamescope:

  In-game FPS limit (best): Use if available, lowest latency
  MangoHud (fps_limit_method=early): Good latency, works everywhere
  Gamescope (-r flag): Adds latency, use only for VRR ceiling
  ```
- (OPTIONAL - FALLBACK IF HOT PLUG DOES NOT WORK) Install and configure `supergfxctl` for GPU switching:
  ```bash
  # TEST FIRST HOT-PLUG THE eGPU - IF IT WORKS SKIP THIS OPTIONAL ITEM.
  paru -S supergfxctl
  # Enable the service FIRST (it will auto-generate a working default config)
  sudo systemctl enable --now supergfxd
  # Override only the options we need
  sudo mkdir -p /etc/supergfxd.conf.d
  sudo tee /etc/supergfxd.conf.d/99-egpu.conf <<'EOF'
  {
  "mode": "Hybrid",
  "vfio_enable": false,  # CRITICAL: Must be false for AMD eGPU Hybrid mode
  "vfio_save": false,
  "always_reboot": false,
  "no_logind": false,
  "logout_timeout_s": 180,
  "hotplug_type": "Std"  # Standard hotplug works well for OCuLink/TB4/5
  }
  EOF

  # Install the profile script for desktop environment compatibility (Wayland/Gnome)
  sudo supergfxctl --install-profile-script

  # Fallback to iGPU if eGPU fails
  supergfxctl -m Integrated  

  # Secure Boot signing for the binaries
  # Note: sbctl can sign multiple files in one call.
  sbctl sign -s /usr/bin/supergfxctl /usr/lib/supergfxd

  # Reboot to apply all changes (KMS, modprobe, and supergfxd)
  sudo reboot

  # If probe error -22: Try kernel param 'amdgpu.noretry=0' in /etc/mkinitcpio.d/linux.preset, then mkinitcpio -P
  # hotplug_type use Std for OCuLink; if doesn't work change to "Asus". Requires restart.
  ```
- (OPTIONAL - FALLBACK IF HOT PLUG DOES NOT WORK) Install supergfxctl-gex for GUI switching
  ```bash
  # GUI Installation of supergfxctl-gex
  echo "NOTE: supergfxctl-gex is installed via the GNOME Extensions website, not the AUR."
  # GUI installation
  echo "--------------------------------------------------------------------------------"
  echo "MANUAL STEP REQUIRED:"
  echo "1. Log into your GNOME desktop session."
  echo "2. Open your web browser and navigate to: https://extensions.gnome.org/extension/5344/supergfxctl-gex/"
  echo "3. Toggle the switch to 'ON' to install and enable the extension."
  echo "4. After installation, log out and log back in (or press Alt+F2, then 'r', then Enter) to see the GUI icon."
  echo "--------------------------------------------------------------------------------"
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
- (OPTIONAL NOT RECOMMENDED) VFIO for eGPU passthrough
  ```bash
  > **99.9 % of people reading this guide should SKIP this entire section.**
  >
  > If you just want to game on Linux with your AMD OCuLink eGPU → **you already have the best possible setup** with `chgpu` in hybrid/dedicated/egpu mode + ThinkLMI automation.
  >
  > VFIO passthrough on AMD in 2025 still means:
  > - You lose **all** native Linux use of the eGPU
  > - No hot-plug (must cold-plug + reboot every time)
  > - AMD reset bug is only ~90 % solved (still needs vendor-reset or bleeding-edge patches)
  > - You will spend 10–40 hours debugging instead of gaming
  >
  > Only do this if you absolutely need near-native Windows performance in a VM and accept the above trade-offs.

  # If you still want to proceed → follow the official Arch Wiki page exactly:  
  # https://wiki.archlinux.org/title/PCI_passthrough_via_OVMF

  # Do **not** follow any random script that blacklists `amdgpu` globally — it will break your daily driver.

  # VFIO for eGPU passthrough (AMD OCuLink focus)
  pacman -S --needed qemu virt-manager 
  systemctl enable --now libvirtd

  # Load VFIO modules
  echo "vfio-pci vfio_iommu_type1 vfio_virqfd vfio" | sudo tee /etc/modules-load.d/vfio.conf

  # Check IOMMU groups (essential for isolation; script from ArchWiki)
  cat << 'EOF' | sudo tee /usr/local/bin/check-iommu-groups.sh
  #!/bin/bash
  shopt -s nullglob
  for g in $(find /sys/kernel/iommu_groups/* -maxdepth 0 -type d | sort -V); do
    echo "IOMMU Group ${g##*/}:"
    for d in $g/devices/*; do
        echo -e "\t$(lspci -nns ${d##*/})"
    done;
  done
  EOF
  sudo chmod +x /usr/local/bin/check-iommu-groups.sh
  echo "Run: sudo check-iommu-groups.sh to verify eGPU isolation (GPU/audio should be alone)."
  sudo check-iommu-groups.sh | grep -i amd  # Quick preview

  # Guide for IDs + auto-detect AMD eGPU
  echo "1. Run: lspci -nn | grep -i amd"
  echo "2. Example output: 1002:73df [AMD Radeon RX 6700 XT]"
  echo "3. Edit /etc/modprobe.d/vfio.conf below with real IDs (vendor:device for GPU + audio)."
  lspci -nn | grep -i amd
  fwupdmgr get-devices | grep -i "oculink\|redriver" | grep -i version

  # Blacklist AMD driver (prevents host claiming eGPU; OCuLink-specific)
  echo "blacklist amdgpu" | sudo tee /etc/modprobe.d/blacklist-amdgpu.conf
  echo "softdep amdgpu pre: vfio-pci" | sudo tee -a /etc/modprobe.d/vfio.conf

  # Auto-generate vfio-pci IDs
  GPU_IDS=$(lspci -nn | grep -i amd | grep VGA | awk '{print $3}' | sed 's/\://g' | head -1)
  AUDIO_IDS=$(lspci -nn | grep -i amd | grep Audio | awk '{print $3}' | sed 's/\://g' | head -1)
  echo "options vfio-pci ids=${GPU_IDS:-1002:xxxx},${AUDIO_IDS:-1002:xxxx}" | sudo tee /etc/modprobe.d/vfio.conf
  echo "Auto-detected IDs: GPU=${GPU_IDS:-TBD}, Audio=${AUDIO_IDS:-TBD}. Edit if wrong."
  echo "4. Then: mkinitcpio -P && reboot"
  mkinitcpio -P

  # Optional: vendor-reset for AMD reset bug
  echo "For AMD eGPU reset issues: paru -S vendor-reset-dkms-git"
  echo "Add 'vendor_reset' to MODULES in /etc/mkinitcpio.conf, then mkinitcpio -P."

  # Optional: Resizable BAR udev rule for Code 43
  cat << 'EOF' | sudo tee /etc/udev/rules.d/01-amd-bar.rules
  ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x1002", ATTR{resource0_resize}="14"
  ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x1002", ATTR{resource2_resize}="8"
  EOF
  echo "For Resizable BAR/Code 43: Unplug/replug eGPU or reboot."

  # Optional: BIOS hangs note
  echo "If guest hangs: BIOS — disable Re-Size BAR, enable SR-IOV, set Initiate Graphic Adapter=IGD."

  # Sign binaries if unsigned
  for bin in /usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd /usr/bin/supergfxctl; do
    if ! sbctl verify "$bin" | grep -q "signed"; then
      sbctl sign -s "$bin"
      echo "Signed $bin."
    else
      echo "$bin already signed."
    fi
  done

  # Append structured hook
  if ! grep -q "Target = supergfxctl" /etc/pacman.d/hooks/90-uki-sign.hook 2>/dev/null; then 
  cat << 'EOF' | sudo tee -a /etc/pacman.d/hooks/90-uki-sign.hook

  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = qemu
  Target = libvirt
  Target = supergfxctl

  [Action]
  Description = Sign VFIO/eGPU binaries with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/qemu-system-x86_64 /usr/lib/libvirt/libvirtd /usr/bin/supergfxctl
  Depends = sbctl
  EOF
    echo "Added structured signing hook."
  else
    echo "Signing hook already exists."
  fi
  ```
- Systemd Service Hardening Phase 3 (post eGPU)
  ```bash
  echo "=== Phase 3: udisks2 Hardening ==="
  echo "⚠️  TEST THOROUGHLY after this one!"
  echo ""

  sudo mkdir -p /etc/systemd/system/udisks2.service.d

  sudo tee /etc/systemd/system/udisks2.service.d/harden.conf > /dev/null <<'EOF'
  [Service]
  # Disk management needs device access but can be restricted
  ProtectSystem=strict
  ProtectHome=read-only
  PrivateTmp=yes
  NoNewPrivileges=yes
  ProtectKernelTunables=yes
  ProtectControlGroups=yes
  RestrictSUIDSGID=yes
  # Note: Needs device access for eGPU/USB mounting
  # ProtectKernelModules=no (may load filesystem modules)
  EOF

  sudo systemctl daemon-reload
  sudo systemctl restart udisks2.service

  echo ""
  echo "⚠️  CRITICAL: Test eGPU hotplug NOW!"
  echo "   1. Unplug OCuLink"
  echo "   2. Plug back in"
  echo "   3. Verify eGPU detected"
  echo ""
  echo "If broken, rollback:"
  echo "   sudo rm /etc/systemd/system/udisks2.service.d/harden.conf"
  echo "   sudo systemctl daemon-reload"
  echo "   sudo systemctl restart udisks2.service"
  ```
- Verify eGPU setup
  ```bash
  # Verify eGPU detection
  lspci | grep -i amd
  dmesg | grep -i amdgpu

  # (DEPRECATED) Verify GPU switching
  # supergfxctl -s # Show supported modes
  # supergfxctl -g # Get current mode
  # supergfxctl -S # Check current power status
  # supergfxctl -m Hybrid # Set to Hybrid mode
  glxinfo | grep -i renderer # Should show AMD eGPU (confirming all-ways-egpu sets eGPU as primary)

  **Note:** Switch modes before testing:
  # Hybrid: `supergfxctl -m Hybrid` → `DRI_PRIME=1 glxinfo | grep renderer`
  # VFIO: `supergfxctl -m VFIO` → `lspci -k | grep vfio`
  DRI_PRIME=1 glxinfo | grep -i radeon # Should show AMD
  DRI_PRIME=0 glxinfo | grep -i arc # Should show Intel
  DRI_PRIME=1 vdpauinfo | grep -i radeonsi
  # (DEPRECATED) supergfxctl -m VFIO # Test VFIO mode for VM

  # Verify PCIe bandwidth. Confirm the eGPU is operating at full PCIe x4 bandwidth. Ensures the OCuLink connection is not bottlenecked (e.g., running at x1 or Gen 3 instead of x4 Gen 4):
  lspci -vv | grep -i "LnkSta.*Speed.*Width" # Should show "Speed 16GT/s, Width x4" for OCuLink4
  # (DEPRECATED) fio --name=read_test --filename=/dev/dri/card1 --size=1G --rw=read --bs=16k --numjobs=1 --iodepth=1 --runtime=60 --time_based #link status shows “Speed 16GT/s, Width x4” for optimal performance.
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
  # (DEPRECATED) lspci -k | grep -i vfio # Verify VFIO binding
  dmesg | grep -i "oculink\|pcieport\|amdgpu\|jhl\|redriver"

  # Check for PCIe errors
  dmesg | grep -i "pcieport\|error\|link"
  cat /sys/class/drm/card*/device/uevent | grep DRIVER  # Should show xe and amdgpu

  # (Optional) Check OCuLink dock firmware - Firmware Update may be better performed in Step 18
  fwupdmgr get-devices | grep -i "oculink\|redriver"
  (DO NOT EXECUTE) fwupdmgr update - echo "fwupd upgrade moved to Step 18 for BIOS/firmware updates."
  ```
- **eGPU Troubleshooting Matrix**:
  | Issue | Possible Cause | Solution |
  |-------|----------------|----------|
  | eGPU not detected (`lspci \| grep -i amd` empty) | OCuLink cable not seated properly, dock firmware outdated, or PCIe hotplug failure | Re-seat the OCuLink cable, run `fwupdmgr update`, add `pcie_ports=native` to kernel parameters, trigger `echo 1 > /sys/bus/pci/rescan` |
  | Black screen on Wayland | eGPU not set as primary display | Run `all-ways-egpu set-boot-vga egpu` and `all-ways-egpu set-compositor-primary egpu`, then restart GDM: `systemctl restart gdm` |
  | Low performance (e.g., x1 instead of x4) | PCIe link negotiation failure | Check link status: `lspci -vv \| grep LnkSta`, add `amdgpu.pcie_gen_cap=0x4` to kernel parameters |
  | Flickering | AMD flickering issue | Add: `amdgpu.dcdebugmask=0x10` to kernel parameters |
  | Hotplug fails | OCuLink hardware limitation or missing udev rule | Apply the udev rule above, reboot if necessary |
  - Additional troubleshooting commands:
    ```bash
    lspci | grep -i amd  # Check eGPU detection
    dmesg | grep -i amdgpu  # Check driver loading
    glxinfo | grep -i renderer  # Verify GPU rendering
    ```
  - DIAGNOSTIC: Check IOMMU groups after connecting eGPU
    ```bash
    find /sys/kernel/iommu_groups/ -type l | sort | grep 1002:

    # CONDITIONAL FIX: If the AMD GPU is not in its own group:
    # Get the AMD GPU PCI ID (e.g., from 'lspci -nnk'): 1002:xxxx
    # Add the following to linux.preset default_options:
    # vfio-pci.ids=1002:xxxx
    ```
  - (Optional) If for some reason the Oculink performance has some latency issues consider adding some script for setpci like CachyOS does - https://wiki.cachyos.org/features/cachyos_settings/#helper-scripts
    ```bash
    #!/usr/bin/env sh
    # This script is designed to improve the performance and reduce audio latency
    # for sound cards by setting the PCI latency timer to an optimal value of 80
    # cycles. It also resets the default value of the latency timer for other PCI
    # devices, which can help prevent devices with high default latency timers from
    # causing gaps in sound.

    # Check if the script is run with root privileges
    if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run with root privileges." >&2
    exit 1
    fi

    # Reset the latency timer for all PCI devices
    setpci -v -s '*:*' latency_timer=20
    setpci -v -s '0:0' latency_timer=0

    # Set latency timer for all sound cards
    setpci -v -d "*:*:04xx" latency_timer=80

    # Start the service for this script above
    sudo systemctl enable --now pci-latency.service

    # Before unplugging eGPU:
    # 1. Close all GPU-accelerated apps
    # 2. Switch to integrated graphics
    # 3. Wait 5 seconds
    # 4. Physically disconnect
    # use suspend-before-unplug workflow
    ```
## Step 13: Configure Snapper and Snapshots

```bash
- Instal Packages
  # rsync is required by the boot backup hook (called explicitly in hook Exec=)
  sudo pacman -S --needed snapper snap-pac rsync btrfs-assistant

- Diff Filter File
  # IMPORTANT: This filter only affects `snapper diff` / `snapper status` output.
  # It does NOT exclude paths from snapshots. Btrfs snapshots are atomic at the
  # subvolume level — to truly exclude a path (e.g. /home/.cache) from snapshots
  # it must be mounted as a separate Btrfs subvolume in fstab.
  sudo mkdir -p /etc/snapper/filters
  printf '/home/*/.cache\n/tmp\n/run\n/.snapshots\n/var/cache\n/var/tmp\n.nobackup\n' \
    | sudo tee /etc/snapper/filters/global-filter.txt > /dev/null

- Root Config — @snapshots Subvolume Dance 
  # snapper create-config creates a /.snapshots Btrfs subvolume inside @.
  # Since fstab mounts a dedicated @snapshots subvolume at /.snapshots, we must:
  #   1) unmount the existing mount (if any)
  #   2) run create-config (snapper creates its own /.snapshots subvolume)
  #   3) delete the subvolume snapper just created
  #   4) recreate /.snapshots as a plain directory and remount from fstab

  if mountpoint -q /.snapshots; then
      sudo umount /.snapshots
  fi
  [ -d /.snapshots ] && sudo rmdir /.snapshots 2>/dev/null || true

  sudo snapper -c root create-config /

  sudo btrfs subvolume delete /.snapshots
  sudo mkdir -p /.snapshots
  sudo mount -a

  sudo chmod 750 /.snapshots
  sudo chown root:wheel /.snapshots

- Home and Data Configs
  sudo snapper -c home create-config /home

  # Guard in case /data is not yet mounted
  if mountpoint -q /data; then
      sudo snapper -c data create-config /data
  fi

  # For home and data, snapper creates .snapshots as a subvolume inside their
  # respective subvolumes (@home, @data) — not nested inside @, so no fstab
  # dance is needed. Repeat the delete/remount dance ONLY if your fstab has
  # dedicated @home_snapshots / @data_snapshots subvolumes. Check with:
  #   grep snapshots /etc/fstab
  # No entries → the subvolumes snapper created are correct as-is.

  sudo chown root:wheel /home/.snapshots /data/.snapshots 2>/dev/null
  sudo chmod 750 /home/.snapshots /data/.snapshots 2>/dev/null

- Configure All Three Configs
  for CONF in root home data; do
      sudo snapper -c "$CONF" set-config \
          ALLOW_GROUPS="wheel" \
          SYNC_ACL="yes" \
          BACKGROUND_COMPARISON="yes" \
          FILTERS="/etc/snapper/filters/global-filter.txt" \
          TIMELINE_CREATE="yes" \
          TIMELINE_CLEANUP="yes" \
          TIMELINE_MIN_AGE="1800" \
          TIMELINE_LIMIT_HOURLY="0" \
          TIMELINE_LIMIT_DAILY="7" \
          TIMELINE_LIMIT_WEEKLY="4" \
          TIMELINE_LIMIT_MONTHLY="6" \
          TIMELINE_LIMIT_YEARLY="0" \
          NUMBER_CLEANUP="yes" \
          NUMBER_LIMIT="50" \
          NUMBER_LIMIT_IMPORTANT="10" \
          EMPTY_PRE_POST_CLEANUP="yes" \
          EMPTY_PRE_POST_MIN_AGE="1800"
  done
  # TIMELINE_LIMIT_HOURLY=0: captures non-pacman changes (config edits, user
  #   errors) during active use. Lower to 0 once the system is stable.
  # NUMBER_LIMIT=50: snap-pac generates a pre/post pair per pacman transaction.
  #   On rolling Arch, 20 fills in under a week of normal use.
  # EMPTY_PRE_POST_CLEANUP: removes snap-pac pairs where nothing actually changed,
  #   preventing silent snapshot bloat.
  # FILTERS: per-config assignment; also auto-loaded globally from the directory.
  #   Kept for self-documentation and deterministic behavior with multiple files.
  # EXCEPTION FOR HOME: Disable timeline creation for /home to prevent Btrfs 
  # metadata locking caused by constant browser cache and config churn.
  sudo snapper -c home set-config TIMELINE_CREATE="no"

- Secure Config Files
  sudo chmod 640 /etc/snapper/configs/*

- Configure SNAP-PAC
  # Without this file snap-pac snapshots every config it finds automatically.
  # Explicit is safer as your config count grows (e.g. if you add a cache or
  # VM subvolume later that you do NOT want tied to pacman transactions).
  sudo tee /etc/snap-pac.ini > /dev/null <<'EOF'
  [root]
  snapshot = True
  cleanup_algorithm = number

  [home]
  snapshot = True
  cleanup_algorithm = number

  [data]
  snapshot = True
  cleanup_algorithm = number
  EOF

- Boot Backup Pacman Hook
  # /boot (FAT32 ESP) is outside all Btrfs subvolumes — invisible to Snapper.
  # This hook rsyncs /boot into /etc/reproducible-boot, which lives inside @
  # (the root subvolume). Every root snapshot therefore captures the matching
  # boot state, making rollbacks coherent between userspace and kernel/initramfs.
  #
  # Hook execution order on a kernel-touching pacman transaction:
  #   90-mkinitcpio-install.hook  → generates NEW kernel + initramfs into /boot
  #   95-bootbackup.hook          → rsyncs the freshly built /boot  ← this hook
  #   zz-snap-pac-post.hook       → takes the post-transaction snapshot  
  #
  # At 90- this hook would fire before mkinitcpio, copying the OLD kernel into
  # /etc/reproducible-boot. The snapshot would contain a stale boot mirror —
  # on rollback: new modules in /usr/lib/modules, old kernel restored → mismatch
  # → boot failure. The 95- naming is not cosmetic; it is load-bearing.

  sudo mkdir -p /etc/pacman.d/hooks
  sudo mkdir -p /etc/reproducible-boot

  sudo tee /etc/pacman.d/hooks/95-bootbackup.hook > /dev/null <<'EOF'
  
  [Trigger]
  Type = Path
  Operation = Install
  Operation = Upgrade
  Operation = Remove
  Target = boot/*
  Target = usr/lib/modules/*/vmlinuz

  [Action]
  Description = Syncing /boot to /etc/reproducible-boot (Snapper-visible copy)...
  When = PostTransaction
  Exec = /usr/bin/rsync -a --delete /boot/ /etc/reproducible-boot/ || exit 1
  EOF

  sudo chmod 644 /etc/pacman.d/hooks/95-bootbackup.hook

- Enable Timers
  sudo systemctl enable --now snapper-timeline.timer   # periodic timeline snapshots
  sudo systemctl enable --now snapper-cleanup.timer    # periodic cleanup of old snapshots
  sudo systemctl enable --now snapper-boot.timer       # snapshot on every boot

- Optimize File Indexing (mlocate/plocate)
  # Prevent updatedb from crawling Btrfs snapshots, which causes CPU/IO spikes.
  # Edit /etc/updatedb.conf
  PRUNE_BIND_MOUNTS = "yes"
  PRUNENAMES = ".git .hg .svn .snapshots"
  PRUNEPATHS = "/tmp /var/spool /media /var/lib/os-prober /var/lib/flatpak /var/lib/libvirt/images /.snapshots /home/.snapshots /data/.snapshots"
  PRUNEFS = "NFS nfs nfs4 rpc_pipefs afs binfmt_misc devpts debugfs securityfs sysfs proc fuse.curlftpfs devfs autofs mfs shfs fuse.sshfs gpfs sfs lustre tmpfs devtmpfs zfs"

  # Update db
  sudo updatedb

  # Disable quotas for your subvolumes
  sudo btrfs quota disable /
  sudo btrfs quota disable /home
  sudo btrfs quota disable /data

  sudo snapper -c root delete 80-120
  sudo snapper -c root cleanup timeline
  sudo snapper -c home cleanup timeline
  sudo snapper -c data cleanup timeline

  # Automate Prune
  snapper -c root list | awk '$1 ~ /^[1-9][0-9]*$/ {print $1}' | head -n -15 | xargs -r sudo snapper -c root delete
  snapper -c home list | awk '$1 ~ /^[1-9][0-9]*$/ {print $1}' | head -n -15 | xargs -r sudo snapper -c home delete

- Verify Configuration
  echo "════ Snapshot coverage — what IS included in root snapshots ════"
  echo "  /etc, /usr, /opt, /root, /etc/reproducible-boot (boot mirror)"

  echo ""
  echo "════ Snapshot coverage — what is NOT included (separate subvolumes) ════"
  mount | grep btrfs | grep -E 'subvol=@(var|log|srv|swap|cache|tmp)' \
      | awk '{print "  EXCLUDED: " $3 " (" $0 ")"}'
  echo "  (This is expected — intentional architecture, not a gap)"

  echo "════ Configs ════"
  snapper list-configs

  echo ""
  echo "════ Subvolume check (all three must appear) ════"
  sudo btrfs subvolume list / | grep -E '\.snapshots'

  echo ""
  for CONF in root home data; do
      echo "════ $CONF ════"
      snapper -c "$CONF" get-config \
          | grep -E 'ALLOW|SYNC|FILTERS|TIMELINE|NUMBER|EMPTY|BACKGROUND'
      echo ""
  done

  echo "════ Mountpoint permissions ════"
  ls -ld /.snapshots /home/.snapshots /data/.snapshots 2>/dev/null

- Initial Baseline Snapshots
  for CONF in root home data; do
      sudo snapper -c "$CONF" create \
          --description "Baseline — post-snapper-install, pre-normal-use" \
        --userdata "important=yes"
  done

  echo ""
  echo "════ Snapshot lists ════"
  for CONF in root home data; do
      echo "── $CONF ──"
      snapper -c "$CONF" list
  done

- Apparmor Check
  if systemctl is-active --quiet apparmor; then
      echo "Checking AppArmor for Snapper denials..."
      journalctl -u apparmor --no-pager | grep -i "snapper" \
          && echo ">>> Denials found. Run: sudo aa-genprof snapper" \
          || echo "OK — no AppArmor denials for Snapper."
  fi

  # ════════════════════════════════════════════════════════════════════════════════
  # STEP 13 — APPENDIX: Rollback Procedure
  # Arch Linux · systemd-boot · Btrfs · LUKS2
  #
  # Two scenarios:
  #   A) System still boots — identify the target, surgically undo if possible
  #   B) System does not boot — full recovery from live USB
  #
  # NOTE: /var, /var/log, /var/lib are NOT snapshotted (separate subvolumes).
  # After any rollback, service state in /var will be newer than the restored root.
  # For a desktop this is a non-issue. Databases (PostgreSQL, MariaDB) may need
  # manual attention if their data directory lives inside /var.
  # ════════════════════════════════════════════════════════════════════════════════

  # ════════════════════════════════════════════════════════════════════════════════
  # SCENARIO A — SYSTEM STILL BOOTS
  # Use this to identify what to roll back to and surgically undo pacman changes.
  # For a full subvolume swap you must use Scenario B regardless — you cannot
  # replace @ while it is the running root.
  # ════════════════════════════════════════════════════════════════════════════════

  # ── A1. Identify the snapshot to roll back to ──────────────────────────────────
  snapper -c root list
  snapper -c home list
  snapper -c data list
  # Note the snapshot NUMBER you want. Entries marked important=yes are
  # pre/post pacman transactions and manual baselines.

  # ── A2. Inspect what changed between a snapshot and now ───────────────────────
  sudo snapper -c root status NUMBER..0   # list changed files
  sudo snapper -c root diff NUMBER..0 | less   # show actual diffs

  # ── A3. Undo a single pacman transaction (surgical, no reboot required) ────────
  # snap-pac creates a pre/post pair for every pacman transaction.
  # undochange restores only the files that changed between PRE and POST.
  # This is the right first tool — faster and safer than a full subvolume swap.
  sudo snapper -c root undochange PRE..POST

  # After undochange, sync /boot to match the restored root state.
  # undochange operates on the Btrfs subvolume only — it never touches the ESP.
  # If the rollback involved anything kernel or initramfs related, /boot is now
  # out of sync without this step.
  sudo rsync -a --delete /etc/reproducible-boot/ /boot/

  # Reboot to apply.

  # ── A4. Full subvolume rollback ────────────────────────────────────────────────
  # If undochange is not sufficient (e.g. broken kernel, wrecked /etc, bad
  # bootloader config), you need a full @ swap. This cannot be done from a
  # running system — the kernel holds a lock on the mounted @.
  # Note the snapshot NUMBER you want from A1, then reboot into a live USB
  # and follow Scenario B using that number.

  # ════════════════════════════════════════════════════════════════════════════════
  # SCENARIO B — FULL RECOVERY FROM LIVE USB
  # Boot from Arch live USB, then follow these steps exactly.
  # ════════════════════════════════════════════════════════════════════════════════

  # ── B1. Decrypt LUKS ──────────────────────────────────────────────────────────
  cryptsetup luksOpen /dev/nvme1n1p2 cryptroot
  # If using a keyfile:
  # cryptsetup luksOpen --key-file /path/to/keyfile /dev/nvme1n1p2 cryptroot

  # ── B2. Mount the Btrfs top-level (subvolid=5 — not any named subvolume) ──────
  # This gives visibility of all sibling subvolumes: @, @home, @snapshots, etc.
  # Mounting by subvolume name would land inside @ with no view of its siblings.
  mount -o subvolid=5 /dev/mapper/cryptroot /mnt
  ls /mnt
  # Expected: @ @home @data @snapshots @var @log @srv @swap

  # ── B3. Identify the snapshot to restore ──────────────────────────────────────
  ls /mnt/@snapshots/
  cat /mnt/@snapshots/N/info.xml   # replace N with your chosen snapshot number

  # ── B4. Rename the broken @ out of the way ────────────────────────────────────
  # Rename rather than delete — gives a revert-of-a-revert option if the chosen
  # snapshot also has problems. Delete only after confirming the restore works.
  mv /mnt/@ /mnt/@.broken

  # ── B5. Clone the snapshot into @ ─────────────────────────────────────────────
  btrfs subvolume snapshot /mnt/@snapshots/N/snapshot /mnt/@
  # Creates a read-write subvolume. The original snapshot stays intact.

  # ── B6. Sync /boot from the snapshot's reproducible-boot mirror ───────────────
  # The ESP (FAT32) is outside all Btrfs subvolumes — invisible to Snapper.
  # Without this step the restored @ contains coherent userspace but /boot still
  # has whatever kernel was there at failure time — kernel/module mismatch →
  # boot failure.
  # /etc/reproducible-boot inside @ holds the /boot state at snapshot time.
  # We mount the ESP directly into the restored @/boot — /mnt/boot does not
  # exist at the raw top-level (subvolid=5), only @/boot does.

  lsblk -f   # verify ESP partition before mounting
  mount /dev/nvme1n1p1 /mnt/@/boot   # adjust if your ESP is on a different partition

  # Restore /boot from the snapshot's mirror
  rsync -a --delete /mnt/@/etc/reproducible-boot/ /mnt/@/boot/

  # ── B7. Verify bootloader entries ─────────────────────────────────────────────
  ls /mnt/@/boot/loader/entries/
  # Entries should reference the UKIs or vmlinuz just restored.
  # In the vast majority of cases they will be intact — systemd-boot entries
  # are static files that were part of @ and were restored in B5.

  # ── B8. (Only if bootloader entries are missing or corrupted) Chroot ──────────
  mkdir -p /mnt/newroot
  mount -o subvol=@ /dev/mapper/cryptroot /mnt/newroot
  mount -o subvol=@home /dev/mapper/cryptroot /mnt/newroot/home
  mount -o subvol=@var  /dev/mapper/cryptroot /mnt/newroot/var  2>/dev/null || true
  mount --bind /proc /mnt/newroot/proc
  mount --bind /sys  /mnt/newroot/sys
  mount --bind /dev  /mnt/newroot/dev
  mount --bind /run  /mnt/newroot/run

  arch-chroot /mnt/newroot
  mkinitcpio -P                     # regenerate all initramfs presets
  bootctl install --esp-path=/boot  # reinstall systemd-boot if needed
  exit

  umount -R /mnt/newroot

  # ── B9. Unmount and reboot ─────────────────────────────────────────────────────
  umount /mnt/@/boot
  umount /mnt
  cryptsetup luksClose cryptroot
  reboot

  # ── B10. Post-boot cleanup (only after confirming the system is healthy) ───────
  # Mount the Btrfs top-level to reach @.broken.
  # NEVER run btrfs subvolume delete on /.snapshots — that is your entire
  # snapshot store. The target here is only the broken subvolume renamed in B4.
  sudo mount -o subvolid=5 /dev/mapper/cryptroot /mnt
  sudo btrfs subvolume delete /mnt/@.broken
  sudo umount /mnt

  # ════════════════════════════════════════════════════════════════════════════════
  # QUICK REFERENCE — the commands you will actually type in a crisis
  # ════════════════════════════════════════════════════════════════════════════════
  #
  #  List snapshots:
  #    snapper -c root list 
  #
  #  Inspect what changed:
  #    snapper -c root status N..0
  #
  #  Undo a pacman transaction (soft rollback):
  #    sudo snapper -c root undochange PRE..POST
  #    sudo rsync -a --delete /etc/reproducible-boot/ /boot/
  #    reboot
  #
  #  Full hard rollback (live USB):
  #    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot
  #    mount -o subvolid=5 /dev/mapper/cryptroot /mnt
  #    mv /mnt/@ /mnt/@.broken
  #    btrfs subvolume snapshot /mnt/@snapshots/N/snapshot /mnt/@
  #    lsblk -f && mount /dev/nvme1n1p1 /mnt/@/boot
  #    rsync -a --delete /mnt/@/etc/reproducible-boot/ /mnt/@/boot/
  #    umount /mnt/@/boot && umount /mnt
  #    cryptsetup luksClose cryptroot && reboot
  #
  #  Post-recovery cleanup (after confirmed working):
  #    sudo mount -o subvolid=5 /dev/mapper/cryptroot /mnt
  #    sudo btrfs subvolume delete /mnt/@.broken
  #    sudo umount /mnt
  ```
## Step 14: Configure Dotfiles

- Production Dotfiles & System State Management
  ```bash
  > **Goal:** Capture every customization—shell, terminal, editor, event-driven
  > wallpaper rotation, Rose Pine white-folder icons, GNOME extensions (Just
  > Perfection, Blur my Shell, Open Bar), audio tuning, system hardening, network
  > config, and custom scripts—into a single reproducible `chezmoi` repository.
  > A fresh machine can be restored to this exact state with one command.
  ```
- Pre-Flight: Confirm What Exists
  ```bash
  # Run this block. Fix any `❌ Missing` that matters before continuing.
  # ── Wallpaper (event-driven GNOME XML + inotify .path) ───────────────────────
  ls ~/Pictures/Wallpapers/Rotation                           || echo "❌ Missing"
  ls ~/.local/bin/generate-slideshow.sh                       || echo "❌ Missing"
  ls ~/.config/systemd/user/wallpaper-refresh.path            || echo "❌ Missing"
  ls ~/.config/systemd/user/wallpaper-refresh.service         || echo "❌ Missing"

  # ── Icons & shell ─────────────────────────────────────────────────────────────
  ls ~/.local/bin/setup-white-folders-v3.sh                   || echo "❌ Missing"
  ls ~/.zshrc                                                  || echo "❌ Missing"

  # ── Core tool configs ─────────────────────────────────────────────────────────
  ls ~/.config/wezterm/wezterm.lua                            || echo "❌ Missing"
  ls ~/.config/helix/config.toml                              || echo "❌ Missing"
  ls ~/.config/fastfetch/config.jsonc                         || echo "❌ Missing"

  # ── Audio ─────────────────────────────────────────────────────────────────────
  ls ~/.config/pipewire/pipewire.conf.d/99-latency.conf       || echo "❌ Missing (optional)"

  # ── Git and SSH config ────────────────────────────────────────────────────────
  ls ~/.gitconfig                                             || echo "❌ Missing (optional)"
  ls ~/.ssh/config                                            || echo "❌ Missing (optional)"

  # ── System scripts ────────────────────────────────────────────────────────────
  for script in update-system apparmor-gaming-fix save-kernel-config.sh \
              fix-tpm tpm-seal dns-help dns-status portal-login portal-restore; do
    ls "/usr/local/bin/$script" 2>/dev/null || echo "❌ Missing: $script"
  done

  # ── /etc overrides ────────────────────────────────────────────────────────────
  for f in \
    /etc/sysctl.d/99-hardening.conf \
    /etc/sysctl.d/99-zram-optimize.conf \
    /etc/fonts/conf.d/99-hide-variants.conf \
    /etc/modprobe.d/99-local-blacklist.conf \
    /etc/NetworkManager/conf.d/99-hardened-network.conf \
    /etc/security/limits.d/99-desktop-limits.conf \
    /etc/pacman.d/hooks/99-aide-update.hook \
    /etc/fwupd/fwupd.conf.d/99-secureboot.conf \
    /etc/apparmor/parser.conf \
    /etc/gdm/custom.conf \
    /etc/polkit-1/rules.d/49-run0-cache.rules \
    /etc/iwd/main.conf \
    /etc/mkinitcpio.d/linux.preset \
    /etc/plymouth/plymouthd.conf; do
    ls "$f" 2>/dev/null || echo "❌ Missing: $f"
  done
  ```
- Bootstrap chezmoi + AUR Helper
  ```bash
  sudo pacman -S --needed --noconfirm chezmoi base-devel git flatpak

  # Install paru only if absent
  if ! command -v paru &>/dev/null; then
    git clone --depth 1 https://aur.archlinux.org/paru.git /tmp/paru
    (cd /tmp/paru && makepkg -si --noconfirm)
    rm -rf /tmp/paru
  fi

  # Initialize chezmoi (safe on re-runs)
  [ -d "$HOME/.local/share/chezmoi" ] || chezmoi init
  ```
- Master Package Installation Script (Single Source of Truth)
  ```bash
  mkdir -p "$(chezmoi source-path)/dot_chezmoscripts"

  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_once_after_install-packages.sh" <<'EOF'
  #!/bin/bash
  set -euo pipefail

  # Cache sudo once — prevents mid-script password prompts
  sudo -v

  # ── Pacman packages ────────────────────────────────────────────────────────────
  PACMAN_PKGS=(
    zsh wezterm starship
    helix fastfetch fzf zoxide broot eza bat ripgrep fd
    snapper snap-pac btrfs-assistant rsync
    flatpak
    ttf-jetbrains-mono-nerd
    ttf-nerd-fonts-symbols-mono
    ttf-cascadia-code-nerd
  )

  # ── AUR packages ───────────────────────────────────────────────────────────────
  # GNOME extensions listed here so dconf settings have JS files to apply to.
  # Open Bar has no AUR package — see note above.
  # Verify names with `paru -Ss <n>` before running.
  AUR_PKGS=(
    rose-pine-cursor-git
    rose-pine-gtk-theme-git
    rose-pine-icon-theme-git
    gnome-shell-extension-just-perfection-desktop
    gnome-shell-extension-blur-my-shell
  )

  # ── Flatpak apps ───────────────────────────────────────────────────────────────
  FLATPAKS=(
    org.gimp.GIMP
    io.github.realmazharhussain.GdmSettings
    org.gnome.Lollypop
    org.mixxx.Mixxx
    com.logseq.Logseq
    org.gnome.Calculator
    org.gnome.Snapshot
    org.gnome.Characters
    org.gnome.baobab
    org.gnome.SimpleScan
    org.gnome.Papers
    org.gnome.font-viewer
    org.gnome.Loupe
    org.gnome.Logs
    ca.desrt.dconf-editor
    org.freedesktop.Bustle
    com.github.finefindus.eyedropper
    com.belmoussaoui.Obfuscate
    com.mattjakeman.ExtensionManager
    org.gnome.FileRoller
    org.libreoffice.LibreOffice
    io.github.rfrench3.scopebuddy-gui
    org.gnome.seahorse.Application
    ch.protonmail.protonmail-bridge
    net.nokyan.Resources
    org.gnome.Showtime
    )

  echo "→ Installing pacman packages..."
  sudo pacman -S --needed --noconfirm "${PACMAN_PKGS[@]}"

  echo "→ Installing AUR packages..."
  if command -v paru &>/dev/null; then
    paru -S --needed --noconfirm "${AUR_PKGS[@]}"
  else
    echo "WARNING: paru not found — skipping AUR packages. Install paru first."
  fi

  echo "→ Setting up Flatpak..."
  flatpak remote-add --if-not-exists --user flathub \
    https://dl.flathub.org/repo/flathub.flatpakrepo
  for app in "${FLATPAKS[@]}"; do
    # Failures are visible — not silently swallowed
    flatpak install -y --noninteractive --user flathub "$app" \
      || echo "⚠️  WARNING: Failed to install Flatpak app: $app"
  done

  # ── PATH guarantee ─────────────────────────────────────────────────────────────
  # .local/bin check is intentionally broad — catches any existing PATH entry
  # that references the directory, preventing duplicate entries on re-runs.
  if ! grep -q '.local/bin' "$HOME/.zshenv" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshenv"
  fi

  # ── Default shell ──────────────────────────────────────────────────────────────
  # getent reads /etc/passwd directly — reliable regardless of current session
  if [ "$(getent passwd "$USER" | cut -d: -f7)" != "/usr/bin/zsh" ]; then
    chsh -s /usr/bin/zsh "$USER"
  fi

  echo "✅ Package installation complete."
  echo "ℹ️  On Wayland: log out and back in before running dconf load."
  echo "ℹ️  Install Open Bar manually: https://extensions.gnome.org/extension/6580/open-bar/"
  EOF

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_once_after_install-packages.sh"
  ```
- Track User Dotfiles & Assets
  ```bash
  # ── Shell ─────────────────────────────────────────────────────────────────────
  chezmoi add ~/.zshrc
  chezmoi add ~/.zshenv   2>/dev/null || true
  chezmoi add ~/.zprofile 2>/dev/null || true

  # ── Git configuration ─────────────────────────────────────────────────────────
  # Track the config (aliases, user, signing preferences) — not keys or credentials.
  [ -f ~/.gitconfig ] && chezmoi add ~/.gitconfig

  # ── SSH configuration ─────────────────────────────────────────────────────────
  # Track only ~/.ssh/config (host aliases, identity file paths, options).
  # NEVER track private keys — those stay on the encrypted USB from Step 9.
  if [ -f ~/.ssh/config ]; then
    chezmoi add ~/.ssh/config
  fi

  # ── Terminal, editor, system banner ───────────────────────────────────────────
  chezmoi add ~/.config/wezterm
  chezmoi add ~/.config/helix
  chezmoi add ~/.config/fastfetch

  # ── GTK theme settings ────────────────────────────────────────────────────────
  chezmoi add ~/.config/gtk-3.0
  chezmoi add ~/.config/gtk-4.0

  # ── Audio latency tuning (conditional) ───────────────────────────────────────
  [ -f ~/.config/pipewire/pipewire.conf.d/99-latency.conf ] && \
    chezmoi add ~/.config/pipewire/pipewire.conf.d/99-latency.conf

  # ── Wallpaper rotation ────────────────────────────────────────────────────────
  # generate-slideshow.sh writes a GNOME XML playlist.
  # wallpaper-refresh.path watches the Rotation folder via inotify.
  # No swww, no timers, no polling — already running.
  chezmoi add ~/Pictures/Wallpapers/Rotation      # see .chezmoiignore in Step 6
                                                  # to exclude images if collection grows
  chezmoi add ~/.local/bin/generate-slideshow.sh
  chezmoi add ~/.config/systemd/user/wallpaper-refresh.path
  chezmoi add ~/.config/systemd/user/wallpaper-refresh.service

  # ── Rose Pine white-folder icon script ────────────────────────────────────────
  # Track the script only — NOT ~/.local/share/icons or ~/.local/share/themes.
  # AUR packages restore those. Hook B re-applies the white-folder layer.
  chmod +x ~/.local/bin/setup-white-folders-v3.sh
  chezmoi add ~/.local/bin/setup-white-folders-v3.sh

  # ── GNOME desktop state ───────────────────────────────────────────────────────
  # One dump captures all extension settings: Just Perfection, Blur my Shell,
  # Open Bar, and any other active extension — everything in one shot.
  # Extensions must be installed first (Step 2) for these settings to take effect.
  mkdir -p ~/.config/dconf
  dconf dump /org/gnome/desktop/interface/ > ~/.config/dconf/interface.dconf
  dconf dump /org/gnome/shell/extensions/  > ~/.config/dconf/extensions.dconf
  chezmoi add ~/.config/dconf/interface.dconf
  chezmoi add ~/.config/dconf/extensions.dconf

  # ── Flatpak overrides ─────────────────────────────────────────────────────────
  # Track the actual overrides directory — not a text export.
  # Flatpak reads override files directly from this directory at runtime.
  if [ -d ~/.local/share/flatpak/overrides ]; then
    chezmoi add ~/.local/share/flatpak/overrides
  fi

  # ── Steam (partial — library and controller config only) ─────────────────────
  # Full Steam dirs are gigabytes. Only config.vdf is meaningful to track.
  # Brave, Thunderbird, Mullvad Browser: use their built-in sync — profiles are
  # too large and cache-heavy for git.
  if [ -f ~/.steam/steam/config/config.vdf ]; then
    chezmoi add ~/.steam/steam/config/config.vdf
  fi

  # ── Reproducibility lists ─────────────────────────────────────────────────────
  pacman -Qqe  > ~/explicitly-installed-packages.txt
  pacman -Qqm  > ~/aur-packages.txt
  flatpak list --app --columns=application > ~/flatpak-packages.txt
  chezmoi add ~/explicitly-installed-packages.txt
  chezmoi add ~/aur-packages.txt
  chezmoi add ~/flatpak-packages.txt
  ```
- Track System-Level Files
  ```bash
  DEST="$(chezmoi source-path)/system-files"

  mkdir -p "$DEST/etc/sysctl.d"
  mkdir -p "$DEST/etc/fonts/conf.d"
  mkdir -p "$DEST/etc/modprobe.d"
  mkdir -p "$DEST/etc/NetworkManager/conf.d"
  mkdir -p "$DEST/etc/security/limits.d"
  mkdir -p "$DEST/etc/pacman.d/hooks"
  mkdir -p "$DEST/etc/fwupd/fwupd.conf.d"
  mkdir -p "$DEST/etc/apparmor"
  mkdir -p "$DEST/etc/gdm"
  mkdir -p "$DEST/etc/polkit-1/rules.d"
  mkdir -p "$DEST/etc/iwd"
  mkdir -p "$DEST/etc/mkinitcpio.d"
  mkdir -p "$DEST/etc/plymouth"
  mkdir -p "$DEST/etc/snapper/configs"
  mkdir -p "$DEST/usr/local/bin"

  # ── Kernel parameters ─────────────────────────────────────────────────────────
  cp /etc/sysctl.d/99-hardening.conf      "$DEST/etc/sysctl.d/"
  cp /etc/sysctl.d/99-zram-optimize.conf  "$DEST/etc/sysctl.d/"

  # ── Font suppression ──────────────────────────────────────────────────────────
  cp /etc/fonts/conf.d/99-hide-variants.conf "$DEST/etc/fonts/conf.d/"

  # ── Kernel module blacklist ───────────────────────────────────────────────────
  cp /etc/modprobe.d/99-local-blacklist.conf "$DEST/etc/modprobe.d/"

  # ── Network hardening ─────────────────────────────────────────────────────────
  cp /etc/NetworkManager/conf.d/99-hardened-network.conf "$DEST/etc/NetworkManager/conf.d/"
  cp /etc/iwd/main.conf "$DEST/etc/iwd/"

  # ── Desktop resource limits ───────────────────────────────────────────────────
  cp /etc/security/limits.d/99-desktop-limits.conf "$DEST/etc/security/limits.d/"

  # ── Pacman hooks (90-uki-sign.hook confirmed missing — not tracked) ───────────
  cp /etc/pacman.d/hooks/99-aide-update.hook "$DEST/etc/pacman.d/hooks/"

  # ── Firmware update / Secure Boot ─────────────────────────────────────────────
  cp /etc/fwupd/fwupd.conf.d/99-secureboot.conf "$DEST/etc/fwupd/fwupd.conf.d/"

  # ── AppArmor ──────────────────────────────────────────────────────────────────
  cp /etc/apparmor/parser.conf "$DEST/etc/apparmor/"

  # ── GDM ───────────────────────────────────────────────────────────────────────
  cp /etc/gdm/custom.conf "$DEST/etc/gdm/"

  # ── Polkit (root-only readable — requires sudo) ───────────────────────────────
  sudo cp /etc/polkit-1/rules.d/49-run0-cache.rules "$DEST/etc/polkit-1/rules.d/"

  # ── UKI build preset + Plymouth boot splash ───────────────────────────────────
  cp /etc/mkinitcpio.d/linux.preset "$DEST/etc/mkinitcpio.d/"
  cp /etc/plymouth/plymouthd.conf   "$DEST/etc/plymouth/"

  # ── Snapper snapshot configs (nullglob — safe on empty directory) ─────────────
  shopt -s nullglob
  files=(/etc/snapper/configs/*)
  if [ "${#files[@]}" -gt 0 ]; then
    cp "${files[@]}" "$DEST/etc/snapper/configs/"
  fi
  shopt -u nullglob

  # ── Custom system scripts (only confirmed-present) ────────────────────────────
  # pre-reboot-check.sh and archive-system-config.sh confirmed missing — not tracked.
  for script in \
    update-system \
    apparmor-gaming-fix \
    save-kernel-config.sh \
    fix-tpm \
    tpm-seal \
    dns-help \
    dns-status \
    portal-login \
    portal-restore; do
    cp "/usr/local/bin/$script" "$DEST/usr/local/bin/"
  done
  ```
- Post-Apply Hooks
  ```bash
  ### Hook A — System file deployment (10-)
  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_10-system-files.sh.tmpl" <<'TMPL'
  #!/bin/bash
  set -euo pipefail

  sudo -v

  echo "→ Deploying system-level configurations..."

  SRC="{{ .chezmoi.sourceDir }}/system-files"

  # ── safe_deploy: nullglob-safe directory copy ─────────────────────────────────
  # Handles two failure modes:
  #   1. Empty source directory — nullglob prevents `cp *` literal-star crash.
  #   2. Missing destination directory — `sudo mkdir -p` ensures it exists on
  #      fresh hardware where /etc/iwd/, /etc/snapper/configs/, etc. may not
  #      have been created yet by the relevant service.
  safe_deploy() {
    local src_dir="$1"
    local dest_dir="$2"
    shopt -s nullglob
    local files=("$src_dir"/*)
    if [ "${#files[@]}" -gt 0 ]; then
      sudo mkdir -p "$dest_dir"
      sudo cp "${files[@]}" "$dest_dir"
    fi
    shopt -u nullglob
  }

  # ── Dynamic glob triggers (future-proof — survive file renames and deletions) ──
  # Trigger sysctl:  {{ range (glob "system-files/etc/sysctl.d/*") }}{{ include . | sha256sum }}{{ end }}
  # Trigger fonts:   {{ range (glob "system-files/etc/fonts/conf.d/*") }}{{ include . | sha256sum }}{{ end }}
  # Trigger scripts: {{ range (glob "system-files/usr/local/bin/*") }}{{ include . | sha256sum }}{{ end }}
  # Trigger snapper: {{ range (glob "system-files/etc/snapper/configs/*") }}{{ include . | sha256sum }}{{ end }}

  # ── Kernel parameters ─────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/sysctl.d"              /etc/sysctl.d/
  sudo sysctl --system

  # ── Font suppression ──────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/fonts/conf.d"          /etc/fonts/conf.d/
  sudo fc-cache -fv

  # ── Module blacklist ──────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/modprobe.d"            /etc/modprobe.d/

  # ── Network hardening ─────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/NetworkManager/conf.d" /etc/NetworkManager/conf.d/
  safe_deploy "$SRC/etc/iwd"                   /etc/iwd/

  # ── Desktop limits ────────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/security/limits.d"     /etc/security/limits.d/

  # ── Pacman hooks ──────────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/pacman.d/hooks"        /etc/pacman.d/hooks/

  # ── fwupd Secure Boot ─────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/fwupd/fwupd.conf.d"   /etc/fwupd/fwupd.conf.d/

  # ── AppArmor ──────────────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/apparmor"              /etc/apparmor/

  # ── GDM ───────────────────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/gdm"                   /etc/gdm/

  # ── Polkit ────────────────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/polkit-1/rules.d"      /etc/polkit-1/rules.d/

  # ── UKI preset + Plymouth ─────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/mkinitcpio.d"          /etc/mkinitcpio.d/
  safe_deploy "$SRC/etc/plymouth"              /etc/plymouth/

  # ── Snapper configs ───────────────────────────────────────────────────────────
  safe_deploy "$SRC/etc/snapper/configs"       /etc/snapper/configs/
  shopt -s nullglob
  for conf in /etc/snapper/configs/*; do sudo chmod 640 "$conf"; done
  shopt -u nullglob

  # ── Custom system scripts ─────────────────────────────────────────────────────
  # `sudo install -m 755` is atomic — no partial writes.
  shopt -s nullglob
  for script in "$SRC/usr/local/bin/"*; do
    sudo install -m 755 "$script" "/usr/local/bin/$(basename "$script")"
  done
  shopt -u nullglob

  echo "✅ System files deployed."
  TMPL

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_10-system-files.sh.tmpl"
  
  ### Hook B — GTK + icon cache + Flatpak overrides (`20-`)
  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_20-gtk-icons.sh" <<'EOF'
  #!/bin/bash
  set -euo pipefail

  echo "→ Refreshing GTK, icon caches, and Flatpak overrides..."

  # Rebuild per-user icon theme caches
  for dir in ~/.local/share/icons/*/; do
    gtk-update-icon-cache -f -t "$dir" 2>/dev/null || true
  done

  # System-wide hicolor fallback
  sudo gtk-update-icon-cache -f -t /usr/share/icons/hicolor/ 2>/dev/null || true

  # Re-apply Rose Pine white-folder layer on top of base AUR theme
  if [ -x "$HOME/.local/bin/setup-white-folders-v3.sh" ]; then
    "$HOME/.local/bin/setup-white-folders-v3.sh"
  fi

  # Nudge GTK to reload without a session restart.
  # `tr -d "'"` strips gsettings single-quote wrapping.
  # `xargs` strips any trailing whitespace that can break theme names.
  if command -v gsettings &>/dev/null; then
    CURRENT=$(gsettings get org.gnome.desktop.interface gtk-theme | tr -d "'" | xargs)
    gsettings set org.gnome.desktop.interface gtk-theme "" 2>/dev/null || true
    gsettings set org.gnome.desktop.interface gtk-theme "$CURRENT" 2>/dev/null || true
  fi

  # Flatpak overrides are read directly from the tracked directory at runtime.
  # chezmoi restoring the directory is sufficient — no extra commands needed.
  if [ -d "$HOME/.local/share/flatpak/overrides" ]; then
    echo "  ✓ Flatpak overrides directory in place."
  fi

  echo "✅ GTK, icon caches, and Flatpak overrides refreshed."
  EOF

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_20-gtk-icons.sh"

  ### Hook C — User services reload (`30-`)
  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_30-user-services.sh" <<'EOF'
  #!/bin/bash
  set -euo pipefail

  # Guard: only run in a live user D-Bus session.
  # Exits silently in TTY-only, chroot, or headless contexts.
  if ! systemctl --user show-environment &>/dev/null; then
    echo "INFO: No user systemd session — skipping service reload."
    exit 0
  fi

  echo "→ Reloading user services..."

  systemctl --user daemon-reload

  # Wallpaper: inotify .path watcher — no timer, no polling
  systemctl --user enable --now wallpaper-refresh.path || true

  echo "✅ User services active."
  EOF

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_30-user-services.sh"
  ```
- Add `.chezmoiignore`
  ```bash
  cat > "$(chezmoi source-path)/.chezmoiignore" <<'EOF'
  # Generated caches and temporary data
  .cache/
  *.log
  *.tmp

  # Secrets — NEVER track in any repository
  *.key
  *.pem
  *.auth
  *.pub        # SSH public keys are low-risk but keep them off git too
  .ssh/id_*    # Block all SSH key variants explicitly
  luks-*
  tpm-*

  # Uncomment if wallpaper collection grows large.
  # Folder structure and scripts are still tracked; only images are excluded.
  # Pictures/Wallpapers/Rotation/*
  EOF
  ```
- Take a Snapper Snapshot Before Applying
  ```bash
  # Create a snapshot before applying any changes
  sudo snapper -c root create --description "pre-chezmoi-apply $(date +%Y-%m-%d)"

  # Apply all tracked files (hooks run in numbered order automatically)
  chezmoi apply --backup -v

  # Restore exact GNOME state.
  # Extensions must be installed (Step 2) for settings to take effect.
  # On Wayland: log out and back in FIRST — GNOME Wayland cannot restart
  # the shell inline. Extensions will not activate until after a full login.
  dconf load /org/gnome/desktop/interface/ < ~/.config/dconf/interface.dconf
  dconf load /org/gnome/shell/extensions/  < ~/.config/dconf/extensions.dconf

  # ── Health checks ─────────────────────────────────────────────────────────────
  chezmoi doctor || echo "chezmoi OK"
  chezmoi status                       # should report no differences

  fastfetch                            # verify system banner
  wezterm --version
  helix --health                          # Helix LSP status

  systemctl --user status wallpaper-refresh.path --no-pager
  systemctl list-timers --all          # verify lynis-audit, btrfs-balance, etc.
  systemctl status maintain.service --no-pager

  ls -l /etc/snapper/configs/          # all files should show 640
  ls    /etc/fonts/conf.d/99-hide-variants.conf
  ls    /etc/sysctl.d/99-hardening.conf
  ls    /etc/sysctl.d/99-zram-optimize.conf
  ls    /usr/local/bin/update-system   # confirm scripts deployed
  fc-list | head -10                   # spot-check font cache

  echo "✅ All checks passed."
  ```
- Export Reproducibility Lists
  ```bash
  # Run this now and repeat after any major package change.
  pacman -Qqe  > ~/explicitly-installed-packages.txt
  pacman -Qqm  > ~/aur-packages.txt
  flatpak list --app --columns=application > ~/flatpak-packages.txt

  chezmoi re-add ~/explicitly-installed-packages.txt
  chezmoi re-add ~/aur-packages.txt
  chezmoi re-add ~/flatpak-packages.txt
  ```
- Commit to Git
  ```bash
  chezmoi cd

  git init
  git add .
  git commit -m "Initial production dotfiles — Lenovo ThinkBook 2025 Arch setup"

  # Optional: push to a private remote
  # git remote add origin git@github.com:yourusername/dotfiles.git
  # git push -u origin main

  cd ~
  ```
- Backup Secure Boot + TPM Data to Encrypted USB
  ```bash
  # Replace `/dev/sdX1` with your actual USB partition (`lsblk` to confirm).
  lsblk
  sudo mount /dev/sdX1 /mnt/usb
  sudo cp -r /etc/sbctl /mnt/usb/sbctl-keys
  sudo cp /var/lib/tpm-pcr-initial.txt /mnt/usb/
  sudo umount /mnt/usb
  echo "⚠️  Keep this USB physically secure and offline. It contains Secure Boot keys."
  
  # Recovery Reference (Store in Bitwarden)

  > **On a completely fresh Arch install**, bootstrap in this order to avoid
  > `paru`-not-found failures inside chezmoi hook scripts:
  >
  > # 1. Install base tools
  > sudo pacman -S --needed git chezmoi base-devel 
  >
  > # 2. Pull the repo (does not apply yet)
  > chezmoi init https://github.com/yourusername/dotfiles.git  
  >
  > # 3. Apply — run_once package script installs paru, then everything else
  > chezmoi apply 
  >
  > # 4. Install Open Bar manually (no AUR package exists)
  > #    https://extensions.gnome.org/extension/6580/open-bar/
  >
  > # 5. Log out and back in (Wayland requires full session restart for extensions)
  >
  > # 6. Restore GNOME state
  > dconf load /org/gnome/desktop/interface/ < ~/.config/dconf/interface.dconf
  > dconf load /org/gnome/shell/extensions/  < ~/.config/dconf/extensions.dconf
  
  | Component | Restore Command / Note |
  |:----------|:-----------------------|
  | LUKS | `cryptsetup luksOpen /dev/nvme1n1p2 cryptroot` |
  | Mount | `mount -o subvol=@ /dev/mapper/cryptroot /mnt` |
  | Chroot | `arch-chroot /mnt` |
  | Dotfiles | See bootstrap order above |
  | GNOME UI | `dconf load /org/gnome/desktop/interface/ < ~/.config/dconf/interface.dconf` |
  | Extensions (Just Perfection, Blur my Shell, Open Bar) | `dconf load /org/gnome/shell/extensions/ < ~/.config/dconf/extensions.dconf` |
  | White-folder icons | `~/.local/bin/setup-white-folders-v3.sh` |
  | System scripts | `chezmoi apply` — Hook A redeploys all `/usr/local/bin/` |
  | Flatpak overrides | Hook B confirms; Flatpak reads directory at runtime |
  | Snapper permissions | `sudo chmod 640 /etc/snapper/configs/*` |
  | Font cache | `sudo fc-cache -fv` |
  | Open Bar | Install from GNOME Extensions site — no AUR package |
  | SSH keys | On encrypted USB from Step 9 — never in this repo |
  | Brave, Thunderbird, Mullvad Browser | Use their built-in sync — profiles too large for git |
  | Steam | `config.vdf` restored by chezmoi; game saves via Steam Cloud |
  | Rollback if something breaks | `sudo snapper -c root list` then `sudo snapper -c root undochange <N>..0` |

  # Troubleshooting

  | Problem | Fix |
  |---------|-----|
  | `chezmoi apply` fails on Hook A | `safe_deploy` prevents empty-dir crashes; check `journalctl -xe` |
  | Extension settings not applied | Log out/in first (Wayland), confirm extensions installed, then `dconf load` |
  | Open Bar not restoring | Install from GNOME Extensions site, then `dconf load /org/gnome/shell/extensions/` |
  | Wallpaper not changing | `systemctl --user status wallpaper-refresh.path` — confirm inotify watcher active |
  | White-folder icons reset | Hook B re-applies automatically on next `chezmoi apply` |
  | Fonts not suppressed | `sudo fc-cache -fv`; verify `/etc/fonts/conf.d/99-hide-variants.conf` |
  | System script missing after rebuild | Hook A uses `sudo install -m 755` — run `chezmoi apply` |
  | Flatpak install warning shown | Check the `⚠️ WARNING` line — failures are now visible, not swallowed |
  | Trigger hash crash on deleted file | Glob triggers handle this — `range glob` outputs nothing for missing files |
  | PATH duplicates in `.zshenv` | `grep -q` on exact string prevents duplicates; inspect with `cat ~/.zshenv` |
  | Need to roll back a bad apply | `sudo snapper -c root list` — find the pre-apply snapshot, then undo |
  | AppArmor denials | `journalctl -u apparmor \| grep -i chezmoi` |

  > **🔒 Security Warning**
  >
  > Never commit LUKS headers, TPM keys, SSH private keys, or Secure Boot
  > `.auth`/`.key` files to any Git repository — even a private one.
  > The `.chezmoiignore` explicitly blocks `*.key`, `*.pem`, `.ssh/id_*`, and
  > related patterns. Track only file *locations* and *configs*; keep secrets on
  > your encrypted USB from Step 9.
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

  # Check the PCRs you actually enrolled (7)
  tpm2_pcrread sha256:7 > /tmp/tpm-pcr-current.txt

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
  # (DEPRECATED) supergfxctl -s
  sbctl verify /lib/modules/*/kernel/drivers/gpu/drm/amd/amdgpu.ko || { echo "Signing amdgpu module"; sbctl sign -s /lib/modules/*/kernel/drivers/gpu/drm/amd/amdgpu.ko; }
  ```
- Test hibernation
  ```bash
  # Ensure the UKI cmdline has the resume parameters
  RES_UUID=$(cryptsetup luksUUID /dev/nvme1n1p2 2>/dev/null)
  RES_OFFSET=$(sudo btrfs inspect-internal map-swapfile -r /swap/swapfile 2>/dev/null)

  echo "Checking UKI Command Line..."
  # If using /etc/cmdline.d/ (Standard for modern mkinitcpio)
  echo "resume=UUID=$RES_UUID resume_offset=$RES_OFFSET" | sudo tee /etc/cmdline.d/99-resume.conf
  
  # Rebuild UKI to bake in the new parameters
  echo "Rebuilding UKI with resume parameters..."
  sudo mkinitcpio -P

  # Verify the baked-in parameters
  echo "Verifying parameters inside the EFI binary..."
  strings /boot/EFI/Linux/arch.efi | grep -E "resume|resume_offset" || echo "ERROR: Resume not baked into UKI! "

  # [Proceed with the existing safety checks and systemctl hibernate]
  echo -n "swap file status  → "
  swapon --show

  echo -n "swapfile location → "
  ls -l /swap/swapfile
  
  echo -n "physical extent count (must be == 1) → "
  filefrag -v /swap/swapfile | grep -oP 'extents found: \K\d+' || echo "?"

  echo -n "resume= parameter in UKI cmdline? → "
  bootctl list | grep -i resume || echo "not visible"

  echo ""
  echo "Quick test (VERY dangerous if values are wrong!)"
  echo "  1. Make sure you have working passphrase fallback"
  echo "  2. Make sure important work is saved"
  echo ""
  read -p "Really attempt hibernation now? (type YES to continue) " answer
  if [[ "$answer" = "YES" ]]; then
    sudo systemctl hibernate
  else
    echo "Hibernation test skipped (recommended for first run)."
    echo "When you are ready later, just run:  systemctl hibernate"
  fi

  # Test Hibernation
  systemctl hibernate
  # Wait 10 seconds
  # Power on
  # Verify applications restored

  echo ""
  echo "After resume (if it worked) run these checks:"
  echo "  journalctl -b -1 -u systemd-hibernate.service | grep -i "Error"
  echo "  dmesg | grep -i -E 'hibernate|resume|swap'"
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

  # Add the following lines to /etc/apparmor/parser.conf:
  write-cache
  Optimize=compress-fast

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
  echo "Use system normally (eGPU, browsers) for 1–2 hours."
  echo "Then run:"

  sudo ausearch -m avc -ts boot | audit2allow
  sudo aa-logprof
  ```
- Validate run0
  ```
  # Validate run0 (Polkit-based sudo replacement)
  # This tests:
  #   • Polkit rule grants wheel group access
  #   • Authentication is cached (~15 min)
  #   • Cache clears on reboot (expected)
  # after first real boot with GDM/polkit agent active
  echo "Testing run0 inside chroot..."

  # First use: should prompt for password
  run0 whoami
  # → Expected: Polkit prompt → outputs "root"

  # Second use: should use cached credentials (no prompt)
  run0 id
  # → Expected: **no prompt**, outputs UID/GID

  # Third reboot
  reboot

  # Forth use: should ask for password
  run0 whoami

  # "If you see polkit agent window + caching works → success."
  # "If run0 never asks for password → check /etc/polkit-1/rules.d/49-run0-cache.rules"

  # Note: Full cache behavior (including timeout) is only observable
  #       after first boot with a display manager (GDM).
  #       In chroot, caching is limited but rule application is verified.
 
  ```
- Forcepad Issues
  ```bash
  # Check if the touchpad is detected
  dmesg | grep -i "goodix"
  # If touchpad is with issue try this kernel patch https://github.com/ty2/goodix-gt7868q-linux-driver
  ```
- Kernel 7.0 & Security Context
  ```bash
  echo "--- Linux 7.0 & Mesa 26.0 Status ---"
  uname -r | grep -E "^7\." && echo "✓ Kernel 7.0+ installed" || echo "○ Kernel 6.x (7.0 available via 'pacman -Syu' from April 2026)"
  pacman -Q mesa | grep -E "26\." && echo "✓ Mesa 26.0+ installed (AMD RT +36-52% perf boost)" || echo "○ Mesa <26.0"
  pacman -Q pipewire | grep -E "1\.[6-9]|1\.[0-9]{2}" && echo "✓ PipeWire 1.6+ (LDAC support)" || echo "○ PipeWire <1.6"

  echo "--- Security CVE Mitigation Check ---"
  systemctl is-active apparmor && echo "✓ AppArmor active"
  systemctl list-timers | grep paru-update && echo "✓ Auto-updates enabled (mitigates ~8-9 CVEs/day in 2026)"

  # Verify Intel TSX is enabled (kernel 7.0+)
  grep -E 'hle|rtm' /proc/cpuinfo && echo "✓ Intel TSX enabled (automatic in 7.0+)" || echo "○ TSX not supported/enabled"
  ```
- Validation Checklist:
  ```bash
  # Create and run this one-shot script to validate critical components. This catches errors like UUID mismatches in fstab, unsigned files, or TPM issues.
  ```bash
  cat << 'EOF' | sudo tee /usr/local/bin/pre-reboot-check.sh
  #!/usr/bin/env bash
  set -euo pipefail
  
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
  
  ERRORS=0
  
  echo "=== PRE-REBOOT VALIDATION ==="
  echo ""
  
  # 1. Bootloader
  echo "=== 1. systemd-boot ==="
  if bootctl status >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} systemd-boot installed"
  else
    echo -e "${RED}✗${NC} systemd-boot missing"
    ((ERRORS++))
  fi
  
  if [ -f /boot/EFI/Linux/arch.efi ]; then
    echo -e "${GREEN}✓${NC} UKI exists"
  else
    echo -e "${RED}✗${NC} UKI missing"
    ((ERRORS++))
  fi
  echo ""
  
  # 2. Secure Boot
  echo "=== 2. Secure Boot ==="
  if sbctl verify 2>&1 | grep -q "Verifying"; then
    if sbctl verify 2>&1 | grep -q "✓"; then
      echo -e "${GREEN}✓${NC} All EFI files signed"
    else
      echo -e "${RED}✗${NC} Unsigned files detected:"
      sbctl verify
      ((ERRORS++))
    fi
  else
    echo -e "${RED}✗${NC} sbctl verify failed"
    ((ERRORS++))
  fi
  
  if sbctl status 2>&1 | grep -q "Secure Boot:.*Enabled"; then
    echo -e "${GREEN}✓${NC} Secure Boot enabled in BIOS"
  else
    echo -e "${YELLOW}⚠${NC} Secure Boot not enabled (enable after boot)"
  fi
  echo ""
  
  # 3. TPM
  echo "=== 3. TPM Auto-Unlock ==="
  if systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} TPM unlock test passed"
  else
    echo -e "${RED}✗${NC} TPM unlock test FAILED"
    echo "Run: sudo systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2"
    ((ERRORS++))
  fi
  echo ""
  
  # 4. fstab UUID Validation (CRITICAL)
  echo "=== 4. fstab UUID Validation ==="
  FSTAB_OK=true
  while read -r line; do
    UUID=$(echo "$line" | cut -d= -f2 | awk '{print $1}')
    if blkid | grep -q "$UUID"; then
      echo -e "${GREEN}✓${NC} UUID $UUID valid"
    else
      echo -e "${RED}✗${NC} UUID $UUID NOT FOUND in blkid"
      echo "This WILL cause boot failure. Fix /etc/fstab before proceeding."
      FSTAB_OK=false
      ((ERRORS++))
    fi
  done < <(grep -E '^UUID=' /etc/fstab 2>/dev/null || true)
  
  if $FSTAB_OK; then
    echo -e "${GREEN}✓${NC} All fstab UUIDs validated"
  fi
  echo ""
  
  # 5. Snapper
  echo "=== 5. Snapper Snapshots ==="
  if snapper list-configs >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Snapper configured"
    if snapper --config root list 2>/dev/null | grep -q "timeline"; then
      echo -e "${GREEN}✓${NC} Timeline snapshots active"
    else
      echo -e "${YELLOW}⚠${NC} No timeline snapshots (may be normal if just installed)"
    fi
  else
    echo -e "${RED}✗${NC} Snapper not configured"
    ((ERRORS++))
  fi
  echo ""
  
  # 6. Critical Services
  echo "=== 6. Critical Services ==="
  for service in gdm NetworkManager systemd-timesyncd; do
    if systemctl is-enabled $service >/dev/null 2>&1; then
      echo -e "${GREEN}✓${NC} $service enabled"
    else
      echo -e "${YELLOW}⚠${NC} $service not enabled"
    fi
  done
  echo ""
  
  # 7. Recovery Files
  echo "=== 7. Recovery Preparation ==="
  if [ -f /mnt/usb/luks-header-backup ]; then
    echo -e "${GREEN}✓${NC} LUKS header backup found"
  else
    echo -e "${YELLOW}⚠${NC} LUKS header backup not found on USB"
  fi
  
  if [ -f /etc/tpm2-ukey.pem ]; then
    echo -e "${GREEN}✓${NC} TPM public key exists"
  else
    echo -e "${YELLOW}⚠${NC} TPM public key missing"
  fi
  echo ""
  
  # Summary
  echo "======================================="
  if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ ALL CRITICAL CHECKS PASSED${NC}"
    echo ""
    echo "SAFE TO REBOOT"
    echo ""
    echo "Delete this script after successful boot:"
    echo "  sudo rm /usr/local/bin/pre-reboot-check.sh"
    exit 0
  else
    echo -e "${RED}✗ $ERRORS CRITICAL ERROR(S) FOUND${NC}"
    echo ""
    echo "DO NOT REBOOT UNTIL ERRORS ARE FIXED"
    echo ""
    echo "After fixing, re-run: sudo /usr/local/bin/pre-reboot-check.sh"
    exit 1
  fi
  EOF
  
  sudo chmod +x /usr/local/bin/pre-reboot-check.sh
  
  # Run validation
  echo "Running pre-reboot validation..."
  if sudo /usr/local/bin/pre-reboot-check.sh; then
    echo ""
    echo "Pre-reboot validation passed. Proceeding to final signing."
  else
    echo ""
    echo "VALIDATION FAILED. Fix errors above before proceeding."
    echo "Re-run validation: sudo /usr/local/bin/pre-reboot-check.sh"
    exit 1
  fi
  ```
- ntsync Verification
  ```bash
  echo "=== Verify ntsync support (Linux 7.0+) ==="
  KERNEL_VER=$(uname -r | cut -d. -f1-2)
  if [[ $(echo "$KERNEL_VER >= 7.0" | bc) -eq 1 ]]; then
    echo "✓ Kernel $KERNEL_VER supports ntsync"
    zgrep NTSYNC /proc/config.gz && echo "✓ ntsync enabled" || echo "✗ ntsync not compiled"
  else
    echo "○ Kernel $KERNEL_VER < 7.0 (ntsync unavailable, using fsync fallback)"
  fi
  ```
- Test Windows boot.
  ```bash
  echo "Reboot and select Windows from the boot menu (F12 or Enter). Verify Windows boots correctly."
  sbctl verify /boot/EFI/Microsoft/Boot/bootmgfw.efi || { echo "Signing Windows bootloader"; sbctl sign -s /boot/EFI/Microsoft/Boot/bootmgfw.efi; }
  ```
## Step 16: Create Recovery Documentation

- Document UEFI password, LUKS passphrase, keyfile location, MOK password, and recovery steps ina note titled: "ThinkBook 2025 - Arch Recovery".
  ```bash
  echo "Store UEFI password, LUKS passphrase, keyfile location, and MOK password"
  1. UEFI/BIOS Password: [Enter your password]
  2. LUKS Passphrase:    [Enter your boot passphrase]
  3. MOK/Secure Boot Passphrase: [Enter your password]
  --- SYSTEM IDENTIFIERS (For Recovery Mapping) ---
  echo "LUKS UUID:          $(cryptsetup luksUUID /dev/nvme1n1p2 2>/dev/null)"
  echo "Arch ESP PARTUUID:  $(blkid -s PARTUUID -o value /dev/nvme1n1p1)"
  echo "TPM PCRs Enrolled:  7 (Secure Boot)"
  ```
- TPM Seal breaks
  ```bash
  # Enter LUKS passphrase
  # Boot succeeds
  # Run fix-tpm
  # (Optional) gated reenrollment service
  # Save the command to repair TPM in the note.
  # sudo tpm-seal or fix-tpm
  # echo "This re-measures the current boot state and re-enrolls TPM automatically."
  # echo "No manual PCR reading. No key regeneration. Just one line."
  ```
- Prepare and verify USB
  ```bash
  echo "Available drives:"
  lsblk -d -o NAME,SIZE,TYPE,MODEL,MOUNTPOINT

  read -p "Enter the USB device to FORMAT (e.g. sdb): " USB_DISK
  [[ -b "/dev/$USB_DISK" ]] || { echo "Error: /dev/$USB_DISK not found"; exit 1; }

  echo "WARNING: This will ERASE /dev/$USB_DISK."
  read -p "Type YES to confirm: " danger
  [[ "$danger" != "YES" ]] && exit 1

  # Format as FAT32 for maximum compatibility with UEFI/BIOS environments
  sudo wipefs -a /dev/"$USB_DISK"
  sudo mkfs.fat -F 32 -n "RECOVERY" /dev/"$USB_DISK"1 || sudo mkfs.fat -F 32 -n "RECOVERY" /dev/"$USB_DISK"
  sudo mkdir -p /mnt/recovery
  sudo mount /dev/"$USB_DISK"* /mnt/recovery 2>/dev/null || sudo mount /dev/"$USB_DISK" /mnt/recovery
  ```
- Verify existing backups
  ```bash
  [ -f /mnt/usb/luks-keyfile ] || { echo "Error: /mnt/usb/luks-keyfile not found"; exit 1; }
  [ -f /mnt/usb/luks-header-backup ] || { echo "Error: /mnt/usb/luks-header-backup not found"; exit 1; }
  ```
- Backup LUKS header and Secure Boot keys
  ```bash
  echo "Backing up headers and keys..."
  DATE=$(date +%Y%m%d)
  [ -f /mnt/usb/luks-header-backup ] && { echo "Warning: /mnt/usb/luks-header-backup exists. Overwrite? (y/n): "; read confirm; [ "$confirm" = "y" ] || exit 1; }
  # LUKS Header Backup
  sudo cryptsetup luksHeaderBackup /dev/nvme1n1p2 --header-backup-file /mnt/recovery/luks-header-$DATE.bak

  # Keyfile Backup (Your automated unlock secondary key)
  sudo cp /etc/cryptsetup-keys.d/root.key /mnt/recovery/luks-recovery-keyfile
  sudo chmod 600 /mnt/recovery/luks-recovery-keyfile

  # Secure Boot (sbctl) Database
  # This allows you to re-sign kernels if you reinstall the OS
  sudo cp -r /usr/share/secureboot/keys /mnt/recovery/sbctl-keys-$DATE
  sudo chmod -R 600 /mnt/recovery/sbctl-keys-$DATE
  # If UEFI variables are reset or Secure Boot is disabled:
  # Boot Arch using passphrase or recovery USB
  # Re-enroll keys:
  sbctl enroll-keys -m -f
  sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
  sbctl sign -s /boot/EFI/Linux/*.efi
  # Reboot and re-enable Secure Boot in firmware


  # Create Integrity Checksums
  cd /mnt/recovery && sha256sum * > checksums.txt
  echo "✓ Binary backups complete."
  ```
- Create a recovery document for troubleshooting (Generate the RECOVERY-GUIDE.md):
  ```bash
  # This file is written to the USB so you can read it on another device during a crisis.
  [ -f /mnt/usb/luks-keyfile ] && [ -f /mnt/usb/luks-header-backup ] || { echo "Error: Required files missing"; exit 1; }
  cat << 'EOF' > /mnt/usb/recovery.md
  # Arch Linux Recovery Instructions

  a. **Scenario A: TPM Auto-Unlock Fails (Passphrase works) - Boot from Rescue USB **:
   - Insert the GRUB USB created in Step 9 or an Arch Linux ISO USB.
   - For GRUB USB: Select "Arch Linux Rescue" from the GRUB menu.
   - For Arch ISO: Boot into the Arch environment.
   - Type your LUKS Passphrase at the boot prompt.
  Once inside Arch, run:
   sudo systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2
   sudo systemd-cryptenroll /dev/nvme1n1p2 \
   --tpm2-device=auto \
   --tpm2-pcrs=7 \
   --tpm2-pcrs-bank=sha256 \
   --tpm2-public-key=/etc/tpm2-ukey.pem
  # This restores the original TPM policy (PCRs + SHA256 bank + authorized signing key).

  b. **Scenario B: System Won't Boot (Live ISO Recovery)**:
   Boot Arch Linux Live ISO.
   Unlock Drive:
    cryptsetup luksOpen /dev/nvme1n1p2 cryptroot --key-file /mnt/usb/luks-keyfile
   Mount:
     mount -o subvol=@ /dev/mapper/cryptroot /mnt
     mount -o subvol=@home /dev/mapper/cryptroot /mnt/home
     mount -o subvol=@data /dev/mapper/cryptroot /mnt/data
     mount /dev/nvme1n1p1 /mnt/boot
   Chroot:
     arch-chroot /mnt
   Fix:
     sbctl sign -s /boot/EFI/Linux/arch.efi
     mkinitcpio -P
     journalctl -u apparmor | grep -i DENIED
     sbctl status

  c. **Scenario C: LUKS Header Corrupted**:
   Boot Live ISO.
   Insert this USB.
   cryptsetup luksHeaderRestore /dev/nvme1n1p2 --header-backup-file /path/to/usb/luks-header-DATE.bak
   sha256sum -c /mnt/usb/luks-header-backup.sha256

  d. **Scenario D: Snapshot Rollback (BTRFS)**:
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
 
  e. **TPM Recovery**:
   - If TPM unlocking fails, use the LUKS passphrase or keyfile.
   - Wipe old TPM keyslot(s)
    mapfile -t TPM_SLOTS < <(cryptsetup luksDump /dev/nvme1n1p2 --dump-json-metadata \
    | jq -r '.tokens[] | select(.type == "systemd-tpm2") | .keyslots[]')

  for slot in "${TPM_SLOTS[@]}"; do
    echo "Wiping TPM keyslot $slot..."
    systemd-cryptenroll /dev/nvme1n1p2 --wipe-slot="$slot" || true
  done

  # Verify
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM OK"
  sbctl status | grep -q "Enabled" && echo "Secure Boot OK"
  EOF
  
  g. **Verify and unmount USB**
  [ -f /mnt/usb/recovery.md ] || { echo "Error: Failed to create /mnt/usb/recovery.md"; exit 1; }
  [ -d /mnt/usb/sbctl-keys ] || { echo "Error: /mnt/usb/sbctl-keys not found"; exit 1; }
  sha256sum /mnt/usb/recovery.md > /mnt/usb/recovery.md.sha256
  cat /mnt/usb/recovery.md
  sudo umount /mnt/usb
  echo "WARNING: Store /mnt/usb/recovery.md, /mnt/usb/luks-header-backup, /mnt/usb/sbctl-keys, and their checksums in Bitwarden or an encrypted cloud."
  echo "WARNING: Keep the recovery USB secure to prevent unauthorized access."
  ```
 - Check USB contents
  ```bash
  lsblk | grep $usb_dev
  sudo mount /dev/$usb_dev /mnt/usb
  ls /mnt/usb/recovery.md /mnt/usb/recovery.md.sha256 /mnt/usb/luks-keyfile /mnt/usb/luks-header-backup /mnt/usb/sbctl-keys
  sha256sum -c /mnt/usb/recovery.md.sha256
  sha256sum -c /mnt/usb/luks-header-backup.sha256
  sudo umount /mnt/usb
  ````
 - Final Verification
  ```bash
  echo "WARNING: Store UEFI password, LUKS passphrase, /mnt/usb/luks-keyfile location, MOK password, /mnt/usb/recovery.md, /mnt/usb/luks-header-backup, /mnt/usb/sbctl-keys, and their checksums in USB and Bitwarden or an encrypted cloud. Keep the recovery USB secure."
  read -p "Confirm all credentials and USB contents are stored in Bitwarden (y/n): " confirm
  [ "$confirm" = "y" ] || { echo "Error: Please review the documentation steps"; exit 1; }
  ```
## Step 17: Backup Strategy

- Local Snapshots:
  ```bash
  # Managed by Snapper for @, @home, @data, excluding /var, /var/lib, /log, /tmp, /run.
  ```
- Install `rustic` for backups:
  ```bash
  sudo pacman -S --noconfirm rustic
  ```
- Verify & sign binary for Secure Boot
  ```bash
  sbctl verify /usr/bin/rustic || sbctl sign -s /usr/bin/rustic
  ```
- Pacman hook (auto-sign on updates)
  ```bash
  if ! grep -q "Target = rustic" /etc/pacman.d/hooks/90-rustic-sign.hook 2>/dev/null; then
  sudo mkdir -p /etc/pacman.d/hooks
  sudo tee -a /etc/pacman.d/hooks/90-rustic-sign.hook >/dev/null <<'EOF'

  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = rustic

  [Action]
  Description = Sign rustic binary with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/rustic
  EOF
  fi
  ```
- Excludes File:
  ```bash
  sudo mkdir -p /etc/rustic

  # Create the password file (Random 32-char string)
  [ -f /etc/rustic/repo-password.txt ] || sudo openssl rand -base64 32 | sudo tee /etc/rustic/repo-password.txt >/dev/null
  sudo chmod 600 /etc/rustic/repo-password.txt

  # Create the excludes list
  sudo tee /etc/rustic/excludes.txt >/dev/null <<'EOF'
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
  sudo tee /usr/local/bin/rustic-backup.sh >/dev/null <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail

  # ----- CONFIGURATION -----
  REPO_PATH="/mnt/backup/backup-repo"  # Adjust this to your backup drive path
  PASS_FILE="/etc/rustic/repo-password.txt"
  EXCLUDES="/etc/rustic/excludes.txt"
  # -------------------------

  # Ensure backup drive is mounted
  if ! mountpoint -q /mnt/backup; then
    echo "Attempting to mount backup drive..."
    mount /mnt/backup || { echo "Error: Backup drive mount failed. Is the OCuLink dock on?"; exit 1; }
  fi

  # Set Rustic Environment Variables
  export RUSTIC_REPOSITORY="$REPO_PATH"
  export RUSTIC_PASSWORD_FILE="$PASS_FILE"
  export RUSTIC_CACHE_DIR="/var/cache/rustic"

  # Ensure cache dir exists for the systemd service
  mkdir -p "$RUSTIC_CACHE_DIR"

  echo "=== Starting Rustic Backup: $(date) ==="

  # Run Backup
  # --one-file-system prevents crossing into other mounts
  rustic backup \
    --exclude-file "$EXCLUDES" \
    --one-file-system \
    --tag "scheduled" \
    /etc /home /data /srv

  # Cleanup (Keep: 7 days, 4 weeks, 6 months)
  rustic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune

  # Quick Integrity Check
  rustic check --read-data-subset=1G

  echo "=== Backup Completed Successfully ==="
  EOF

  sudo chmod +x /usr/local/bin/rustic-backup.sh
  ```
- Systemd Service & Timer:
  ```bash
  # Update the actual backup script first
  # We use 'sed' to inject the graceful exit logic or simply rewrite the check block
  if ! grep -q "OCuLink Backup drive not found" /usr/local/bin/rustic-backup.sh; then
  sudo sed -i '/mountpoint -q \/mnt\/backup/!b;n;c\    echo "OCuLink Backup drive not found. Skipping."; logger -t rustic-backup "Backup skipped: /mnt/backup not mounted"; exit 0' /usr/local/bin/rustic-backup.sh
  fi
  
  # Service File
  sudo tee /etc/systemd/system/rustic-backup.service >/dev/null <<'EOF'
  [Unit]
  Description=Rustic Encrypted Backup
  # Only run if the dock is actually attached/mounted
  ConditionPathIsMountPoint=/mnt/backup
  After=network-online.target
  Wants=network-online.target

  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/rustic-backup.sh
  Nice=19
  IOSchedulingClass=best-effort

  # Reliability: Retry every 30m if it fails (e.g. temporary network drop)
  Restart=on-failure
  RestartSec=30min
  
  # Hardening
  ProtectSystem=strict
  ReadWritePaths=/mnt/backup /var/cache/rustic
  EOF

  # Timer File (Daily at 2:30 AM)
  sudo tee /etc/systemd/system/rustic-backup.timer >/dev/null <<'EOF'
  [Unit]
  Description=Daily Rustic Backup Timer

  [Timer]
  OnCalendar=*-*-* 02:30:00
  RandomizedDelaySec=15m
  Persistent=true

  [Install]
  WantedBy=timers.target
  EOF

  # Apply changes and enable
  sudo systemctl daemon-reload
  sudo systemctl enable --now rustic-backup.timer
  ```
- Weekly full repo check
  ```bash
  sudo tee /etc/systemd/system/rustic-check.service >/dev/null <<'EOF'
  [Unit]
  Description=Rustic Full Repository Integrity Check

  [Service]
  Type=oneshot
  Environment="RUSTIC_REPOSITORY=/mnt/backup/backup-repo"
  Environment="RUSTIC_PASSWORD_FILE=/etc/rustic/repo-password.txt"
  ExecStart=/usr/bin/rustic check
  # Ensure background check doesn't lag the desktop
  Nice=19
  IOSchedulingClass=best-effort
  EOF

  sudo tee /etc/systemd/system/rustic-check.timer >/dev/null <<'EOF'
  [Unit]
  Description=Weekly Rustic Repo Check

  [Timer]
  OnCalendar=Sun *-*-* 03:00:00
  Persistent=true

  [Install]
  WantedBy=timers.target
  EOF
  ```
- Final activation of all backup timers
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable --now rustic-backup.timer rustic-check.timer
  ```
- First-run initialization (interactive)
  ```bash
  echo "=== rustic REPOSITORY INITIALIZATION ==="
  # Set your desired path (e.g., an external HDD or an OCuLink-attached NVMe)
  read -p "Enter backup mount path (e.g. /mnt/backup/backup-repo): " MY_REPO

  # Initialize the repo using the password file we generated
  sudo rustic -r "$MY_REPO" --password-file /etc/rustic/repo-password.txt init

  echo "IMPORTANT: Copy /etc/rustic/repo-password.txt to your Bitwarden vault now."
  echo "Without this file or its contents, your backups are PERMANENTLY UNREADABLE."

  echo "CRITICAL: Copy this password to Bitwarden:"
  sudo cat /etc/rustic/repo-password.txt
- Secondary/offline key
  ```bash
  read -p "Create secondary offline key? (y/N) " choice
  if [[ "$$   choice" =~ ^[Yy]   $$ ]]; then
    SECONDARY="/root/rustic-offline-key.txt"
    sudo rustic -r "$MY_REPO" --password-file "$PASS_FILE" key add --new-password-file "$SECONDARY"
    echo "Store $SECONDARY VERY securely (recovery USB!)"
  fi
  ```
- Test + Notes
  ```bash
  echo "Running a quick test backup..."
  /usr/local/bin/rustic-backup.sh && echo "Test backup succeeded! "
  systemctl list-timers --all
  journalctl -u rustic-backup.timer -n 20

  # rustic provides **off-site / incremental** backups of /home, /data, /srv, /etc.
  # Check status any time:  rustic snapshots --repo <path>
  # Restore example:
  # rustic restore --target /tmp/restore latest --path /home/user/Documents
  # Weekly integrity: systemctl status rustic-check.timer

  echo "Verify password is in Bitwarden before continuing: "
  read -p "Confirmed? (yes/no): " confirm
  [[ "$confirm" != "yes" ]] && exit 1
  ```
## Step 18: Post-Installation Maintenance and Verification

- **a) Update System Regularly**:
  - Keep the system up-to-date:
    ```bash
    # Create File /usr/local/bin/update-system
    #!/bin/bash
    # =============================================
    # Arch Updates
    # =============================================

    set -u          # Treat unset variables as errors
    set -o pipefail # Catch pipeline errors

    # --- Colors ---
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'

    # --- Logging ---
    LOG_DIR="$HOME/Documents/System/Updates"
    mkdir -p "$LOG_DIR"
    LOGFILE="$LOG_DIR/update-log-$(date +%Y%m%d-%H%M).txt"
    exec > >(tee /dev/tty | sed 's/\x1b\[[0-9;]*m//g' >> "$LOGFILE") 2>&1

    echo -e "${CYAN}=== Arch Maintenance: $(date) ===${NC}"
    echo -e "${CYAN}Log: $LOGFILE${NC}\n"

    # --- Dependency Check ---
    if ! command -v paru &> /dev/null; then
        echo -e "${RED}Error: paru not installed.${NC}"
        exit 1
    fi

    # =============================================
    # 1. SYSTEM UPDATE
    # =============================================
    echo -e "${YELLOW}--- 1. Updating System & AUR ---${NC}"

     if ! paru -Syu; then
        echo -e "${RED}âš  System update failed or was interrupted.${NC}"
         read -p "Continue with remaining maintenance? (y/N) " -n 1 -r || true
         echo
         if [[ ! "${REPLY:-N}" =~ ^[Yy]$ ]]; then
             echo -e "${RED}Maintenance aborted.${NC}"
             exit 1
         fi
     else
        echo -e "${GREEN}âś” System and AUR updated.${NC}"
     fi

    echo ""
    echo "AppArmor Post-Update Check"
    sudo /usr/local/bin/apparmor-gaming-fix
    echo -e "${GREEN}✔  AppArmor gaming profile check complete.${NC}"

    # =============================================
    # 2. FLATPAK UPDATE
    # =============================================
    echo -e "\n${YELLOW}--- 2. Updating Flatpaks ---${NC}"

    if command -v flatpak &> /dev/null; then
        if flatpak update -y; then
            echo -e "${GREEN}âś” Flatpaks updated.${NC}"
        else
            echo -e "${RED}âš  Flatpak update failed.${NC}"
        fi
    
        if flatpak uninstall --unused -y; then
            echo -e "${GREEN}âś” Unused runtimes removed.${NC}"
        else
            echo -e "${RED}âš  Flatpak cleanup failed.${NC}"
        fi
    else
         echo -e "${YELLOW}âŠ Flatpak not installed. Skipping.${NC}"
    fi

    # =============================================
    # 3. ORPHAN CLEANUP
    # =============================================
    echo -e "\n${YELLOW}--- 3. Orphan Package Removal ---${NC}"

    orphans=$(pacman -Qdtq 2>/dev/null || true)

    if [[ -n "$orphans" ]]; then
        echo -e "${CYAN}Found orphaned packages:${NC}"
        if command -v column &> /dev/null; then
            echo "$orphans" | column
        else
            echo "$orphans"
        fi
    
        echo -e "${YELLOW}âš  Note: GPU drivers (mesa, xf86-video-*) may appear as orphans but are needed.${NC}"
    
        read -p "Remove these? (y/N) " -n 1 -r || true
        echo
        if [[ "${REPLY:-N}" =~ ^[Yy]$ ]]; then
            echo "$orphans" | xargs -r paru -Rns
            echo -e "${GREEN}âś” Orphans removed.${NC}"
        else
            echo -e "${YELLOW}âŠ Orphan removal skipped.${NC}"
        fi
    else
        echo -e "${GREEN}âś” No orphan packages.${NC}"
    fi

    # =============================================
    # 4. POST-UPDATE CLEANUP
    # =============================================
    echo -e "\n${YELLOW}--- 4. Post-Update Cleanup ---${NC}"

    # Clean old maintenance logs
    find "$LOG_DIR" -type f -name "update-log-*.txt" -mtime +30 -delete
    echo -e "${GREEN}âś” Old logs cleaned (>30 days).${NC}"

    # Clean systemd journal
    if sudo journalctl --vacuum-time=30d > /dev/null 2>&1; then
        echo -e "${GREEN}âś” Journal vacuumed to 30 days.${NC}"
    else
        echo -e "${RED}âš  Journal cleanup failed.${NC}"
    fi

    # Clean package cache (verbose output)
    if command -v paccache &> /dev/null; then
        echo -e "${CYAN}Cleaning package cache (keeping last 3 versions)...${NC}"
    
        # Verbose mode shows what's being removed
        sudo paccache -rv
        sudo paccache -ruvk0
    
        echo -e "${GREEN}âś” Package cache cleaned.${NC}"
    else
        echo -e "${YELLOW}âŠ Install pacman-contrib: sudo pacman -S pacman-contrib${NC}"
    fi

    echo -e "${CYAN}Rebuilding dynamic linker cache...${NC}"
    sudo ldconfig && echo -e "${GREEN}✔  ldconfig complete.${NC}"

    # =============================================
    # 5. DIAGNOSTICS
    # =============================================
    echo -e "\n${YELLOW}--- 5. System Diagnostics ---${NC}"

    # .pacnew check
    pacnew_list=$(find /etc \( -name "*.pacnew" -o -name "*.pacsave" \) 2>/dev/null || true)
    if [[ -n "$pacnew_list" ]]; then
        echo -e "${RED}âš  Config files require review:${NC}"
        echo "$pacnew_list"
        echo -e "${CYAN}Run: sudo pacdiff${NC}"
    else
        echo -e "${GREEN}âś” No .pacnew files.${NC}"
    fi

    # Kernel check
    current_kernel=$(uname -r)
    latest_kernel=$(basename -a /usr/lib/modules/* 2>/dev/null | sort -V | tail -1)

    if [[ -n "$latest_kernel" && "$current_kernel" != "$latest_kernel" ]]; then
        echo -e "${RED}âš  REBOOT REQUIRED: Running $current_kernel â†’ Installed $latest_kernel${NC}"
    else
        echo -e "${GREEN}âś” Kernel is current.${NC}"
    fi

    # Failed systemd services check
    failed_services=$(systemctl --failed --no-legend --no-pager 2>/dev/null)
    if [[ -n "$failed_services" ]]; then
        echo -e "${RED}âš  Failed systemd services detected:${NC}"
        echo "$failed_services"
        echo -e "${CYAN}Review with: systemctl --failed${NC}"
    else
        echo -e "${GREEN}âś” No failed services.${NC}"
    fi

    # Disk usage
    echo -e "\n${CYAN}Disk Usage:${NC}"
    df -h --output=size,used,pcent,target / 2>/dev/null | awk 'NR==2 {print "  Root: " $2 "/" $1 " (" $3 " used)"}'

    # Disk usage warning
    disk_use=$(df / --output=pcent | tail -1 | tr -dc '0-9')
    if (( disk_use > 85 )); then
        echo -e "${RED}  âš  Warning: Root filesystem is ${disk_use}% full!${NC}"
    fi

    # Cache size
    cache_size=$(command du -sh /var/cache/pacman/pkg 2>/dev/null | awk '{print $1}')
    echo -e "  Pacman Cache: ${cache_size:-unknown}"

    # Largest packages (FIXED - using tab delimiter)
    if command -v expac &> /dev/null; then
        echo -e "\n${CYAN}Top 5 Largest Packages:${NC}"
        expac -H M '%m\t%n' | sort -hr | head -5 | awk -F'\t' '{printf "  %-15s  %s\n", $1, $2}'
    fi

    # Font cache rebuild
    fc-cache -fv > /dev/null && echo -e "${GREEN}âś” Font cache rebuilt.${NC}"

    echo -e "\n${YELLOW}--- Security Audit (arch-audit) ---${NC}"

    # Arch Audit
    if command -v arch-audit &> /dev/null; then
       audit_output=$(arch-audit | grep High || true)

       if [[ -n "$audit_output" ]]; then
           echo -e "${RED}⚠ High severity vulnerabilities found:${NC}"
           echo "$audit_output"
       else
           echo -e "${GREEN}✔ No high severity vulnerabilities.${NC}"
       fi
    else
       echo -e "${YELLOW}⊘ arch-audit not installed.${NC}"
    fi

    # =============================================
    # 6. PACKAGE HYGIENE
    # =============================================
    echo -e "\n${YELLOW}--- 6. Package Hygiene Check ---${NC}"

    # Foreign packages count
    foreign_count=$(pacman -Qm 2>/dev/null | wc -l)
    if [[ $foreign_count -gt 0 ]]; then
        echo -e "${CYAN}Foreign/AUR packages installed: ${foreign_count}${NC}"
    
        # Check for missing AUR packages
        echo -e "${CYAN}Checking AUR package availability...${NC}"
        missing_count=0
    
        while read -r pkg _; do
            if ! pacman -Si "$pkg" &>/dev/null && ! paru -Si "$pkg" &>/dev/null; then
                echo -e "${RED}  âš  $pkg ${NC}(no longer in AUR)"
                ((missing_count++))
            fi
        done < <(pacman -Qm 2>/dev/null)
    
        if [[ $missing_count -eq 0 ]]; then
            echo -e "${GREEN}âś” All AUR packages still available.${NC}"
        else
            echo -e "${YELLOW}Found $missing_count missing AUR package(s).${NC}"
            echo -e "${CYAN}Remove with: sudo pacman -Rns <package_name>${NC}"
        fi
    else
        echo -e "${GREEN}âś” No foreign packages installed.${NC}"
    fi

    # =============================================
    # SUMMARY
    # =============================================
    echo -e "\n${CYAN}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${NC}"
    echo -e "${CYAN}    âś… Maintenance Complete                  ${NC}"
    echo -e "${CYAN}â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•${NC}"
    echo -e "${CYAN}Log saved: $LOGFILE${NC}"

    # Save and Valiate
    # Run the alias created in the Step 6 "update"
    # If you see in the output some .pacnew that requires attention make sure to run this sudo env DIFFPROG=diff pacdiff

    # You DO NOT need constant maintenance.
    # Only update baseline when:
    #  • You install new software introducing SUID
    #      ◦ Example: docker, wireshark, virtualization tools
    # When that happens:
    # sudo cp /var/lib/suid-audit/current.txt /var/lib/suid-audit/baseline.txt

    # We can remove the UKI sign to gain time in the build:
    sudo rm /etc/pacman.d/hooks/90-uki-sign.hook     
    ```
- **b) Monitor Logs**:
  - Check for errors in system logs:
    ```bash
    # Check for high-priority errors from the current boot
    journalctl -p 3 -xb
    journalctl -b -p err --since "1 hour ago"

    # Check for disk health (SSD)
    sudo smartctl -t short /dev/nvme0n1 && sudo smartctl -t short /dev/nvme1n1

    # Review current security in place on systemd https://roguesecurity.dev/blog/systemd-hardening
    ```
- **c) Check Snapshots**:
  - Verify Snapper snapshots:
    ```bash
    # List snapshots and delete old manual ones to save BTRFS metadata space
    snapper list
    snapper status 0..1

    # Clean up orphaned packages
    paru -Rcns $(pacman -Qdtq)
    ```
- **d) Firmware Updates**:
  ```bash
  fwupdmgr refresh --force
  fwupdmgr get-updates
  
  # If updates are available:
  fwupdmgr update
  
  # After fwupdmgr update
  echo "WARNING: Firmware updates (BIOS, eGPU dock) will change TPM PCR values."
  echo "TPM auto-unlock will fail on next boot. You MUST enter your LUKS passphrase."
  echo "Firmware updated—TPM PCRs changed. Re-enrolling TPM..."
  echo "After booting with passphrase, re-enroll TPM:"
  echo "  sudo touch /etc/allow-tpm-reenroll"
  echo "  sudo systemctl start tpm-reenroll.service"
  echo "Or manually: sudo tpm-seal"
  echo "WARNING: Firmware updates change PCRs. TPM auto-unlock fails once; enter passphrase."
  echo "If TPM fails (e.g., Secure Boot change):"
  echo "1. Enter LUKS Passphrase."
  echo "2. Run the automated fix script: sudo tpm-seal"
  tpm2_pcrread sha256:7 > /etc/tpm-pcr-post-firmware.txt  # Backup new PCRs
  reboot
  ```
- **e) Test eGPU**:
  - Verify eGPU detection and rendering:
    ```bash
    lspci | grep -i amd
    DRI_PRIME=1 glxinfo | grep renderer
    # (DEPRECATED) supergfxctl -g
    DRI_PRIME=1 glxgears -info | grep "GL_RENDERER"
    # Check if the ReDriver/Link is running at full speed (x4 4.0)
    sudo lspci -vvv -s $(lspci | grep AMD | awk '{print $1}') | grep LnkSta
    ```
- **f) Verify Secure Boot**:
  - Confirm Secure Boot is active:
    ```bash
    sbctl status
    sbctl verify
    mokutil --sb-state

    # Check the 'Exposure' score of systemd services (Aim for < 5.0 for critical ones)
    systemd-analyze security | head -n 20
    ```
- **g) TPM seal breaks Maintenance**:
  ```bash
  # If the TPM seal breaks (e.g., hook failure). Update the permanent policy file (captures new PCRs 7)
  # Run **only** when you know PCR 7 changed:
  #   • Firmware/BIOS update
  #   • Secure Boot DB change
  #   • UKI rebuilt with different cmdline
  
  sudo tpm-seal-fix

  sudo systemctl mask systemd-pcrextend.service
  
  # PCR 11 is service is masked and should be kept like that since we are only validating 7 but in case you want to bring it back
  # sudo systemctl unmask systemd-pcrextend.service
  # sudo systemctl enable --now systemd-pcrextend.service  
  ```
- **h) Security Audit**:
  ```bash
  lynis audit system > /root/lynis-report-$(date +%F).txt
  aide --check | grep -v "unchanged" > /root/aide-report-$(date +%F).txt

  # Systemd Security Score (from RogueSecurity recommendations)
  # Check the exposure score of critical services. Lower is better (0.0 is perfect).
  systemd-analyze security --no-pager | head -20 > /root/systemd-score-$(date +%F).txt
  # detailed check on a specific service if needed:
  # systemd-analyze security user@1000.service
  # https://roguesecurity.dev/blog/systemd-hardening

  # Auditd queries that can be executed any time
  # All sudo/run0 usage
  ausearch -k sudo_usage --format text

  # All commands executed as root
  ausearch -k root_exec

  # Every single command executed (great for post-mortem)
  ausearch -k all_execs -i

  # Privilege-escalation failures
  ausearch -k priv_fail

  # Changes to identity files
  ausearch -k identity -i  # Who changed /etc/passwd or /etc/shadow?
  ```
- **i) Adopt AppArmor.d for Enforce Policy and Automation (executed this one after a few months only)**:
  ```bash
  # Preparation: Install notification tools for real-time monitoring
  # Required for aa-notify desktop popups + dependencies
  sudo pacman -S --needed python-notify2 python-psutil
  echo "Installed aa-notify dependencies."

  # Optional but strongly recommended: XDG_RUNTIME_DIR tunable (fixes many denials)
  if [ ! -f /etc/apparmor.d/tunables/local/xdg.conf ]; then
    echo '@{XDG_RUNTIME_DIR}=/run/user/@{UID}' | sudo tee /etc/apparmor.d/tunables/local/xdg.conf >/dev/null
    echo "Added XDG_RUNTIME_DIR local tunable."
  fi

  # Enable policy caching (critical for boot speed with 1500+ profiles)
  sudo mkdir -p /etc/apparmor.d/cache
  sudo sed -i -E 's|^[[:space:]]*#?[[:space:]]*cache-loc.*|cache-loc = /etc/apparmor.d/cache|' /etc/apparmor/parser.conf
  grep '^cache-loc' /etc/apparmor/parser.conf || echo "Warning: cache-loc not set correctly"

  # Enable automatic profile rebuild timer
  if ! systemctl is-enabled --quiet apparmor.d-update.timer 2>/dev/null; then
    sudo systemctl enable --now apparmor.d-update.timer
    echo "Enabled apparmor.d-update.timer"
  else
    echo "apparmor.d-update.timer already enabled"
  fi
  systemctl status apparmor.d-update.timer --no-pager | head -5  # Quick confirmation

  # Reload profiles (builds cache if first time – can take 10–60s)
  echo "Building/reloading AppArmor cache and profiles... (may take a minute)"
  sudo apparmor_parser -r /etc/apparmor.d/ || echo "Warning: Reload showed issues – check journalctl -u apparmor"

  echo "--------------------------------------------------"
  echo "RECOMMENDATION: Monitor in real-time:"
  echo "  aa-notify -p -s 1 --display \$DISPLAY"
  echo "Add to GNOME/KDE startup or run in background terminal."
  echo "Use 'sudo aa-logprof' after normal usage to tune interactively."
  echo "--------------------------------------------------"

  # Switch to ENFORCE mode
  read -p "Ready to switch apparmor.d profiles to ENFORCE mode? (y/N): " confirm
  [[ $confirm =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

  if command -v just >/dev/null 2>&1 && just --list 2>/dev/null | grep -q 'enforce'; then
    echo "Using official 'just enforce' method..."
    sudo just enforce
  else
    echo "Falling back to manual aa-enforce..."
    sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || echo "Some profiles failed enforcement – check dmesg/audit.log"
  fi

  # Explicit reload after mode change
  sudo apparmor_parser -r /etc/apparmor.d/ || echo "Post-enforce reload had issues"

  # Verify and Warm Cache on Boot
  sudo mkdir -p /etc/systemd/system/apparmor.service.d
  sudo tee /etc/systemd/system/apparmor.service.d/cache-warm.conf >/dev/null <<'EOF'
  [Service]
  ExecStartPre=/usr/bin/apparmor_parser --cache-loc=/etc/apparmor.d/cache -r /etc/apparmor.d/*
  EOF
  sudo systemctl daemon-reload
  sudo systemctl restart apparmor

  # Final Status & Confinement Check
  echo "--- Enforcement Status Summary ---"
  sudo aa-status | grep -E "profiles are in enforce mode|complain mode|are loaded" || echo "aa-status issue?"

  echo ""
  echo "--- Quick Confinement Check for Key Installed Apps ---"
  echo "   (Make sure the apps are actually running/open before this check)"
  echo ""

  for app in brave torbrowser-launcher steam thunderbird nautilus gnome-shell; do
    if pgrep -f "$app" >/dev/null; then
        # Use -f for broader matching (e.g., torbrowser-launcher processes)
        if aa-status | grep -q "$(pgrep -f "$app" | head -n 1)"; then
            echo "✅ $app appears confined"
        else
            echo "⚠️ $app running but NOT showing as confined (check 'aa-status -x' or profile name)"
        fi
    else
        echo "( $app not currently running )"
    fi
  done

  # Special note for Mullvad Browser (manual install, not in standard path)
  echo ""
  echo "Mullvad Browser note:"
  echo "  Since it's manually extracted (e.g., ~/Downloads/mullvad-browser/.../Browser/firefox),"
  echo "  apparmor.d may not have a profile covering it by default."
  echo "  Run it once → check 'sudo aa-notify' or 'sudo journalctl -u apparmor -f' for denials."
  echo "  If confined under a firefox-like profile → good; else create local override or aa-genprof."

  echo "CRITICAL RECOVERY TIP:"
  echo "If boot/login fails due to enforcement:"
  echo "  - At systemd-boot: press 'e', add 'apparmor=0' to kernel line, Ctrl+X to boot"
  echo "  - Then revert with 'sudo aa-complain /etc/apparmor.d/*' and tune"
  echo ""
  echo "Reboot recommended to verify early cache load and full enforcement."
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

  # USE flags for modern Intel/AMD/Wayland setup:
  # xe intel-media amdgpu vulkan pipewire flatpak
  # Append to /etc/gentoo-prep/desired-use-flags.txt: xe intel-media amdgpu vulkan pipewire flatpak. Run emerge --info | grep -E 'xe|amdgpu' post-migration test chroot.

  # Packages
  # Use arch-packages.txt + mapping to build @world
  ```
- **k) Tunning Games**:
  ```bash
  # Mangohud and Gamescope Alert
  echo "ALERT: Do not use 'mangohud %command%' inside/beside Gamescope."
  echo "Instead, use the '--mangoapp' flag. Both use the same MangoHud.conf file."

  # eGPU Tip (OCuLink Specific)
  echo "TIP: Use MESA_VK_DEVICE_SELECT=amd (or the specific ID) to force Gamescope on eGPU."
  # Example: Shows FPS and CPU temperature in the top left
  # Launch Options: MANGOHUD_CONFIG="position=top-left,cpu_temp,fps" gamemoderun %command%

  # Toggle overlay: Default hotkey Shift+F1 (configurable)
  # ALERT: Do not use traditional MangoHud with Gamescope—it's unsupported. Use Gamescope's --mangoapp flag instead (e.g., gamescope --mangoapp -f -- %command%).
  # Example: Use Gamescope to run game at 1080p, FSR scale to 1440p, locked at 144 FPS
  # Replace 'amd' with your specific GPU ID if you have multiple AMD cards
  # --mangoapp (Overlay), --fsr-sharpness (Upscaling)
  LD_BIND_NOW=1 MESA_VK_DEVICE_SELECT=amd gamemoderun gamescope -w 2560 -h 1440 -W 2560 -H 1440 --fsr-sharpness 1 --mangoapp --adaptive-sync -- %command%
  # For FPS caps with VRR: Set to refresh_rate - 3 (e.g., 117 for 120Hz) to avoid VSync stutter.

  # Steam add in launch options:
  gamemoderun %command%

  # If you experience flickering, stutter, or other issues with VRR, or if your hardware does not support it try testing those options below in order:
  echo "# If issues with VRR, try fixed refresh rate ('-r 144' instead of '--adaptive-sync'):"
  echo "# LD_BIND_NOW=1 gamemoderun gamescope -w 2560 -h 1440 -W 3840 -H 2160 -r 144 -- %command%"
  echo "  ACO: default RADV compiler on modern Mesa (no forcing needed)"

  # Tune games individually using the application "Scopebuddy" (GUI for Gamescope settings)

  # GameMode pacman hook
  sudo tee /etc/pacman.d/hooks/91-gaming-sign.hook <<'EOF'
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = steam
  Target = mangohud
  Target = gamemode
  Target = lib32-gamemode
  Target = gamescope

  [Action]
  Description = Sign gaming binaries for Secure Boot
  When = PostTransaction
  Exec = /bin/sh -c '/usr/bin/sbctl sign -s /usr/bin/steam /usr/bin/mangohud /usr/bin/mangoapp /usr/bin/gamemoderun /usr/bin/gamescope 2>/dev/null || true'
  Depends = sbctl
  EOF

  sudo sbctl sign -s /usr/bin/steam /usr/bin/mangohud /usr/bin/mangoapp /usr/bin/gamemoderun /usr/bin/gamescope 2>/dev/null || true
  
  # Environment variables (add to ~/.zshrc for system-wide effect):
  cat >> ~/.zshrc <<'EOF'
  export LD_BIND_NOW=1
  # Gaming Env Vars (comment out if issues)
  # export RADV_FORCE_VRS=1  # VRS perf boost (toggle per-game if glitches)
  # NOTE (Feb 2026): Mesa 26.0+ may enable Variable Rate Shading automatically for compatible games.
  # Only force VRS if you confirm performance gain without visual artifacts. Test per-game.
  # export MANGOHUD=1        # Always-on HUD (Setting this globally is NOT recommended due to conflicts)
  # export MANGOHUD_CONFIG="cpu_stats,cpu_temp,gpu_stats,gpu_temp,vram,ram,fps_limit=117,frame_timing"
  EOF

  # Reload shell
  source ~/.zshrc

  # Open Steam Client and make sure to "Enable" Steam Overlay

  ### HDR Configuration (Per-Game, AMD eGPU)

  **Important**: HDR in GNOME + Gamescope has a known limitation. Gamescope HDR will appear "washed out" when used with GNOME due to protocol incompatibility (GNOME uses xx-color-management-v4, Gamescope expects frog-color-management-v1). See: https://gitlab.gnome.org/GNOME/mutter/-/issues/4083

  This section documents per-game HDR as a starting point. Full gamescope-session is NOT recommended until the protocol conflict is resolved.

  ### Enable HDR in GNOME Display Settings
  
  # Launch GNOME Settings
  # Settings → Displays → Select your HDR monitor → Enable HDR toggle
  # (Requires mutter >= 48.0, which Arch provides)
  
  ### Configure Steam for HDR (Global Settings)
  1. Launch Steam
  2. **Settings → Display**:
   - Enable **HDR**
   - Enable **Experimental HDR Support**

  ### Enable HDR for Individual Games
  For each HDR-compatible game:
  1. Right-click game → **Properties**
  2. **Compatibility** tab:
   - Set: **Force the use of a specific Steam Play compatibility tool**
   - Select: **Proton 8.0** or **Proton Experimental** (both support HDR)
  3. **General** tab → **Launch Options**:
  ENABLE_HDR_WSI=1 DXVK_HDR=1 gamescope -f --hdr-enabled --hdr-itm-enable -W 3840 -H 2160 -w 3840 -h 2160 --adaptive-sync --mangoapp -- %command%
     - Adjust `-W/-H` (output resolution) and `-w/-h` (game internal resolution) as needed
     - Use `-r 240` to cap refresh rate if needed
  4. Launch the game and enable HDR in in-game settings

  ### Verify HDR is Working
  # In a game with HDR enabled, check MangoHud overlay (configured with --mangoapp above)
  # Should show HDR status if configured correctly
  # Check Gamescope is actually running:
  ps aux | grep gamescope


  ### Known Limitations
  - **Washed out appearance**: When you Alt+Tab back to GNOME, colors will look washed out due to the protocol mismatch. The game itself should render correctly while in focus.
  - **AMD RADV only**: Your AMD eGPU uses RADV (Mesa's Vulkan driver), which natively supports HDR. NVIDIA has critical HDR issues with Gamescope.
  - **Wait for upstream fix**: Monitor the GNOME issue (#4083) for resolution. When fixed, this will work properly without workarounds.

  ### Future: gamescope-session (Not Recommended Yet)
  Full gamescope-session (boot into Gamescope from GDM) would solve the washed-out issue, but:
  - The AUR package (gamescope-session-steam-git) hasn't been updated since 2024
  - Adds complexity (separate session, switching between GNOME and Gamescope)
  - Wait until GNOME + Gamescope protocol compatibility is resolved

  For now, per-game HDR with the washed-out caveat is the most practical approach.

  # Disable Steam telemetry for privacy (create or edit the file)
  mkdir -p ~/.steam/
  echo "STEAM_DISABLE_TELEMETRY=1" >> ~/.steam/steam.cfg

  # Verify
  sbctl verify /usr/bin/steam /usr/bin/mangohud /usr/bin/mangoapp /usr/bin/gamemoderun /usr/bin/gamescope
  gamemoded -t && echo "GameMode is working! "
  ```
- **l) Audio and Software Enhancements**:
  ```bash
  # Enhancing Laptop Speaker Sound - https://wiki.cachyos.org/configuration/general_system_tweaks/#audio-and-software-enhancements
  sudo pacman -S pavucontrol
  sudo pacman -S easyeffects
  sudo pacman -S lsp-plugins-lv2
  sudo pacman -S zam-plugins
  sudo pacman -S calf
  sudo pacman -S mda.lv2

  # Launch EasyEffects only when using laptop speakers
  # DO NOT enable effects globally or permanently for all outputs
  # Recommended:
  #   - Enable effects only on the "Built-in Audio" sink
  #   - Disable EasyEffects entirely when gaming or using external DAC/headphones
  #   - Avoid heavy presets during video calls or screen sharing
  easyeffects &
  # To prevent latency issues, do NOT enable EasyEffects autostart by default

  # Media Verification Checklist
  # Use vainfo + intel_gpu_top + radeontop
  vainfo
  intel_gpu_top
  radeontop

  # Geck browser audio settings
  about:config:
  media.ffmpeg.vaapi.enabled = true
  media.rdd-ffmpeg.enabled = true
  Verify in about:support
  Look for:
  Hardware decoding: yes
  VAAPI enabled

  # Chromium/Brave:
  chrome://gpu
  Video Acceleration section must show:
  Decode: Hardware accelerated

  # Note: PipeWire 1.6 (released Feb 19, 2026) includes native LDAC decoder for high-quality Bluetooth audio.
  # LDAC will auto-negotiate for compatible headphones. Configure codecs in:
  # /etc/wireplumber/wireplumber.conf.d/51-bluez-config.conf if needed.
  # See: https://wiki.archlinux.org/title/PipeWire#Bluetooth
  ```
- **m) ACPI Troubleshooting**:
  ```bash
  # Check for ACPI functionality: Test all Fn keys and laptop-specific hardware features. If everything works, no action is needed.
  # Identify Potential Module (if needed): If a feature fails, attempt to identify a vendor-specific ACPI module. For a Lenovo, it's often thinkpad_acpi.
  # From: https://wiki.archlinux.org/title/ACPI_modules
  # A complete list for your running kernel can be obtained with the following command:
  sudo ls -l /usr/lib/modules/$(uname -r)/kernel/drivers/acpi
  # You have to try yourself which module works for your machine using modprobe yourmodule, then check if the module is supported on your hardware by using dmesg. It may help to add a grep text search to narrow your results:
  dmesg | grep -i acpi
  # Test Module Loading (Examples):
  sudo modprobe thinkpad_acpi
  sudo modprobe intel_pmc_core
  # Test the broken feature again.
  # Make Permanent (if successful): If the feature starts working, add the module to the list of modules loaded at boot in your mkinitcpio configuration:
  # Edit the mkinitcpio hook file (e.g., /etc/mkinitcpio.conf)
  # Add 'thinkpad_acpi' and/or 'intel_pmc_core' to the MODULES array if they are not enabled by default:
  # Example MODULES=(... sd-vconsole plymouth block sd-encrypt filesystems resume thinkpad_acpi intel_pmc_core)
  # Re-generate the UKI
  sudo mkinitcpio -P
  ```
- **n) Binary verification**:
  ```bash
  # This is a manual verification. Do not create a hook to run this because it degrades performance.
  sudo pacman -Qkk | grep -i 'mismatch\|warning' # Only prints explicit errors
  # Run this once a month. It checks every file on the system against the pacman DB.
  # Any 'mismatch' could indicate disk corruption or unauthorized modification.
  sudo pacman -Qkk | grep -v '0 alterations'
  # Explote adding this as event refreshing daily an widget in the step 19
  ```
- **o) Disable storage of Coredumps after system stability (3-6 months)**:
  ```bash
  sudo mkdir -p /etc/systemd/coredump.conf.d
  cat <<EOF | sudo tee /etc/systemd/coredump.conf.d/custom.conf
  [Coredump]
  Storage=none
  ProcessSizeMax=0
  EOF
  
  # Wipe coredump artifacts from stabilization phase
  sudo rm -rf /var/lib/systemd/coredump/*
  sudo journalctl --vacuum-time=1s
  sudo systemctl daemon-reload
  
  echo "Coredumps disabled. Production security posture active."
  ```
- **p) Two ESPs is valid — but**:
  ```bash
  # fwupd updates often assume the first ESP
  # Lenovo firmware tools can be sloppy
  # You already plan to remove Windows
  # Recommendation
  # After Windows retirement:
  # Migrate to a single ESP
  # Copy Arch EFI files
  # Delete the second ESP
  # This improves firmware update reliability and simplifies Secure Boot signing.
  ```
- **q) Enable Immutable Audit Rules**
  ```bash
  **Only do this after:**
  - All installation steps completed
  - eGPU tested and working  
  - System stable for 1+ week
  - No more audit rule changes needed
  
  # Verify current rules working:
  sudo auditctl -l | wc -l

  # Enable immutable mode:
  sudo nano /etc/audit/rules.d/99-security.rules

  # Uncomment this line:
  -e 2

  # Reload rules (final time):
  sudo augenrules --load

  # Verify immutable:
  sudo auditctl -s
  # Should show: enabled 2

  # Test lock is active:
  sudo auditctl -w /tmp/test -k test
  # Should fail with "immutable" error
  
  **WARNING:** After `-e 2`, any audit changes require full reboot!
  ```
- **r) Configure USBGuard**:
  ```bash
  # Prerequisites:
  # - Steps 1-19 completed
  # - System used daily for 2+ months
  # - ALL USB devices connected at least once:
  #  - Keyboards, mice (all variants you use)
  #  - eGPU dock (via OCuLink)
  #  - USB drives (all of them)
  #  - Phone (USB charging/data/tethering)
  #  - USB-C hubs/docks
  #  - Bluetooth adapters
  #  - Webcam, audio interfaces
  #  - Any other peripherals
  # - No USB connection issues
  # - Sleep/resume cycles stable

  # usbguard is already installed in Step 10

  ### Connect ALL Your Devices

  **CRITICAL: Before generating policy, connect EVERYTHING:**
  ### Before Running USBGuard Setup:
  # Connect EVERY device:
  □ Primary keyboard (test it!)
  □ Primary mouse (test it!)
  □ Backup keyboard
  □ Backup mouse
  □ Phone (USB charging + data mode)
  □ All USB drives you own
  □ USB-C hub/dock
  □ eGPU dock (if it has USB ports)
  □ USB devices through eGPU dock
  □ Bluetooth adapter (if external)
  □ Webcam (if external)
  □ Audio interface
  □ Gaming controllers
  □ Any other USB peripherals

  # Verify internal devices visible:
  lsusb | grep -i "fingerprint\|camera\|bluetooth"
  # Should show built-in fingerprint reader, webcam, etc.

  # If you have eGPU dock with USB:
  # - Power on eGPU
  # - Run GPU benchmark/game
  # - Verify dock USB hub appears: lsusb | grep -i hub

  # # Count devices that USBGuard will manage:
  usbguard list-devices | wc -l
  # Should be 10-25+ rules

  # Verify sleep/resume works:
  # - Suspend laptop
  # - Resume
  # - Check all USB devices still work

  # Only THEN generate policy

  ### Generate Policy
  # Generate policy with ALL devices connected:
  sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf > /dev/null

  # Verify policy was created:
  cat /etc/usbguard/rules.conf | wc -l
  # Should show 10-20+ rules (one per device)

  # Backup the policy:
  sudo cp -r /etc/usbguard /etc/usbguard.backup
  
  ### Configure Daemon (with [Daemon] header)
  sudo mkdir -p /etc/usbguard
  sudo tee /etc/usbguard/usbguard-daemon.conf > /dev/null <<'EOF'
  [Daemon]
  # Keep devices that were present at boot (prevents Bluetooth issues)
  PresentDevicePolicy=keep

  # Apply policy to newly inserted devices
  InsertedDevicePolicy=apply-policy

  # START SAFE: Allow unknown devices for first 2-4 weeks
  # Change to "block" only after monitoring period
  ImplicitPolicyTarget=allow

  # Allow wheel group users to manage USBGuard via GUI
  IPCAllowedGroups=wheel

  # Device manager backend
  DeviceManagerBackend=uevent
  EOF

  ### Create Polkit Rule
  sudo tee /etc/polkit-1/rules.d/70-usbguard.rules > /dev/null <<'EOF'
  polkit.addRule(function(action, subject) {
    if (/^org\.usbguard\./.test(action.id) &&
        subject.active === true &&
        subject.local === true &&
        subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
  });
  EOF

  ### Enable Services
  # Enable and start USBGuard:
  sudo systemctl enable --now usbguard.service usbguard-dbus.service

  # Verify services running:
  systemctl status usbguard.service
  systemctl status usbguard-dbus.service

  ### Enable GNOME USB Protection
  # Enable lockscreen USB protection:
  gsettings set org.gnome.desktop.privacy usb-protection true
  gsettings set org.gnome.desktop.privacy usb-protection-level 'lockscreen'

  ### Monitoring Period (2-4 Weeks)
  # Monitor USBGuard logs:
  sudo journalctl -u usbguard -f

  # List all devices:
  usbguard list-devices

  # Check for blocked devices:
  usbguard list-devices --blocked

  # Test: Plug in a new USB device
  # Should see notification allowing you to authorize it

  ### Final Hardening (After Monitoring)
  **Only after 2-4 weeks of ImplicitPolicyTarget=allow:**
  # Verify no unexpected devices:
  usbguard list-devices --blocked
  # Should be empty

  # Switch to block mode:
  sudo nano /etc/usbguard/usbguard-daemon.conf

  # Change:
  ImplicitPolicyTarget=block

  # Restart service:
  sudo systemctl restart usbguard

  # Test with unknown device:
  # Plug in a USB drive you've never used
  # Should be blocked with notification

  ### Emergency Recovery

  **If you get locked out (keyboard/mouse blocked):**
  # Method 1: Boot to console (Ctrl+Alt+F2)
  # Login, then:
  sudo systemctl stop usbguard
  sudo systemctl disable usbguard

  # Method 2: Kernel parameter at boot
  # Add to kernel cmdline:
  usbguard.daemon.disable=1

  # Method 3: Live USB
  # Boot Arch live USB
  # Mount and chroot into system
  # Edit /etc/usbguard/rules.conf
  # Add your keyboard/mouse device IDs

  ### Verification
  # Check USBGuard status:
  sudo usbguard list-devices | head -20

  # View generated policy:
  sudo cat /etc/usbguard/rules.conf | head -10

  # Verify services running:
  systemctl status usbguard.service --no-pager
  systemctl status usbguard-dbus.service --no-pager

  # (OPTIONAL) If you want audit monitoring of USBGuard config:
  # First add to /etc/audit/rules.d/99-security.rules:
  # -w /etc/usbguard/rules.conf -p wa -k usbguard
  # -w /etc/usbguard/usbguard-daemon.conf -p wa -k usbguard
  # Then: sudo augenrules --load
  # Then verify: sudo auditctl -l | grep usbguard

  # Helpful instructions
  cat <<EOS
  # USBGuard is now active with a safe daily-driver configuration.

  # Next steps for GSConnect:
  # Unlock your session
  # Pair your phone in GSConnect → it will pop up a USBGuard notification
  # Click "Allow" (or run: usbguard allow-device <id> if it doesn't appear)
  # The rule is automatically made permanent

  # After first suspend/resume:
  #  - If Bluetooth/GSConnect stops working, run:
  #       usbguard list-devices | grep -i bluetooth
  #       usbguard allow-device <id>
  #  - Then make it permanent with:
  #       usbguard allow-device <id> --permanent

  # To see current blocked devices at any time:
  # usbguard list-devices --blocked
  # Reload rules without restarting: sudo usbguard reload-rules

  EOS
  ```
- **s) Final Reboot & Lock**:
  ```bash
  # Sign only unsigned EFI binaries
  sbctl sign -s $(sbctl verify | grep "not signed" | awk '{print $1}')

  sbctl verify
  echo "System locked and ready. Final reboot recommended."
  reboot
  ```
## Step 19: User Customizations ** To be refined post production! WIP - For now ignore this part.

- Wallpaper Rotation — GNOME (Arch Linux)
  ```bash
  # Uses GNOME's native XML slideshow: no extensions, no daemons, smooth cross-fades.

  ---
  
  # Create the slideshow XML
  nano ~/.local/bin/generate-slideshow.sh

  #!/usr/bin/env bash
  # =============================================================================
  # generate-slideshow.sh — GNOME Native Wallpaper Rotation
  # Place at : ~/.local/bin/generate-slideshow.sh
  # Auto-run : systemd path unit watches the folder via inotify
  # =============================================================================
  set -euo pipefail

  WALLPAPER_DIR="$HOME/Pictures/Wallpapers/Rotation"
  XML_PATH="$HOME/.local/share/backgrounds/wallpaper-slideshow.xml"
  HASH_FILE="$HOME/.cache/wallpaper-slideshow.hash"
  DURATION=300.0
  TRANSITION=5.0
  RANDOMIZE_ORDER=false

  if [[ ! -d "$WALLPAPER_DIR" ]]; then
    echo "❌  Directory not found: ${WALLPAPER_DIR}" >&2
    exit 1
  fi

  if [[ "$RANDOMIZE_ORDER" == true ]]; then
    SORT_CMD="shuf -z"
  else
    SORT_CMD="sort -z"
  fi

  mapfile -d '' IMAGES < <(
    find "$WALLPAPER_DIR" -maxdepth 1 -type f \
      \( -iname "*.jpg" -o -iname "*.jpeg" \
         -o -iname "*.png" -o -iname "*.webp" \) \
      -print0 | $SORT_CMD
  )

  COUNT=${#IMAGES[@]}
  if [[ $COUNT -lt 2 ]]; then
    echo "❌  Need at least 2 images in ${WALLPAPER_DIR}, found ${COUNT}." >&2
    exit 1
  fi

  mkdir -p "$(dirname "$HASH_FILE")"
  NEW_HASH=$(printf '%s\0' "${IMAGES[@]}" | sha256sum)

  if [[ -f "$HASH_FILE" ]] && grep -qF "$NEW_HASH" "$HASH_FILE"; then
    echo "✔  No changes detected — skipping regeneration."
    exit 0
  fi

  echo "$NEW_HASH" > "$HASH_FILE"
  echo "✔  Found ${COUNT} images — regenerating slideshow."

  mkdir -p "$(dirname "$XML_PATH")"
  mkdir -p "$HOME/.local/share/gnome-background-properties"

  {
    cat <<'XMLHEAD'
  <?xml version="1.0" encoding="UTF-8"?>
  <background>
    <starttime>
      <year>2024</year><month>01</month><day>01</day>
      <hour>00</hour><minute>00</minute><second>00</second>
    </starttime>
  XMLHEAD

    for i in "${!IMAGES[@]}"; do
      NEXT=$(( (i + 1) % COUNT ))
      printf '  <static><duration>%s</duration><file>%s</file></static>\n' \
        "$DURATION" "${IMAGES[i]}"
      printf '  <transition><duration>%s</duration><from>%s</from><to>%s</to></transition>\n' \
        "$TRANSITION" "${IMAGES[i]}" "${IMAGES[NEXT]}"
    done

    echo '</background>'
  } > "$XML_PATH"

  echo "✔  XML written → ${XML_PATH}"

  FILE_URI="file://${XML_PATH}"
  gsettings set org.gnome.desktop.background picture-uri      "$FILE_URI"
  gsettings set org.gnome.desktop.background picture-uri-dark "$FILE_URI"
  gsettings set org.gnome.desktop.background picture-options  'zoom'

  APPLIED=$(gsettings get org.gnome.desktop.background picture-uri)
  if [[ "$APPLIED" == *"wallpaper-slideshow.xml"* ]]; then
    echo "✔  Applied: ${APPLIED}"
  else
    echo "⚠  Unexpected gsettings value: ${APPLIED}" >&2
  fi

  cat > "$HOME/.local/share/gnome-background-properties/rotation-slideshow.xml" <<PROPS
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE wallpapers SYSTEM "gnome-wp-list.dtd">
  <wallpapers>
    <wallpaper>
      <name>My Rotating Wallpapers</name>
      <filename>${XML_PATH}</filename>
      <options>zoom</options>
      <shade_type>solid</shade_type>
      <pcolor>#111111</pcolor>
      <scolor>#111111</scolor>
    </wallpaper>
  </wallpapers>
  PROPS

  echo "✔  Registered in GNOME Settings UI."
  echo "   Drop new images into ${WALLPAPER_DIR} — systemd handles the rest."
  ```  
- Deploy the wallpaper rotation:  
  ```bash
  sudo chown zureta:zureta ~/.local/bin/generate-slideshow.sh
  chmod +x ~/.local/bin/generate-slideshow.sh
  ~/.local/bin/generate-slideshow.sh

  ~/.config/systemd/user/wallpaper-refresh.service:
    [Unit]
    Description=Regenerate GNOME wallpaper slideshow
    [Service]
    ExecStart=%h/.local/bin/generate-slideshow.sh

  ~/.config/systemd/user/wallpaper-refresh.path:
    [Unit]
    Description=Watch for changes in wallpaper rotation directory
    [Path]
    PathChanged=%h/Pictures/Wallpapers/Rotation
    PathModified=%h/Pictures/Wallpapers/Rotation
    [Install]
    WantedBy=default.target

  # Enable:
    systemctl --user enable --now wallpaper-refresh.path

  # Verify:
    gsettings get org.gnome.desktop.background picture-uri
    #'file:///home/zureta/.local/share/backgrounds/wallpaper-slideshow.xml' 
  ```
- Install a custom theme for GNOME:
  ```bash
  nano ~/.local/bin/setup-white-folders-v3.sh
  #!/usr/bin/env bash
  # =============================================================================
  # setup-white-folders-v3.sh — Sparse Child Theme Implementation
  # Only contains overrides. Falls back to parent for sidebar/apps/status icons.
  # =============================================================================
  set -euo pipefail

  SOURCE="/usr/share/icons/rose-pine-icons"
  DEST="$HOME/.local/share/icons/rose-pine-white"

  # ── Cleanup ──────────────────────────────────────────────────────────────────
  echo "🧹 Cleaning old version..."
  rm -rf "$DEST"
  mkdir -p "$DEST"

  # ── Create the index.theme ───────────────────────────────────────────────────
  # This is the most critical part. We copy the original and inject the fallback.
  echo "📝 Generating child theme index..."
  cp "$SOURCE/index.theme" "$DEST/index.theme"

  # Change the name so it shows up distinctly in GNOME Tweaks
  sed -i "s/^Name=.*/Name=Rose Pine (White Folders)/" "$DEST/index.theme"

  # Inject the Inheritance. GNOME looks left-to-right.
  # We put rose-pine-icons first so it fills in all the gaps (Trash, Apps, etc.)
  if grep -q "^Inherits=" "$DEST/index.theme"; then
      sed -i 's/^Inherits=/Inherits=rose-pine-icons,/' "$DEST/index.theme"
  else
      # If no Inherits line exists, we add it to the [Icon Theme] section
      sed -i '/\[Icon Theme\]/a Inherits=rose-pine-icons,hicolor' "$DEST/index.theme"
  fi

  # ── Perform the Surgical Swap ────────────────────────────────────────────────
  echo "⚪ Creating white folder overrides..."

  # We crawl the SOURCE theme for any "white" icons
  # We create a matching directory structure in DEST and symlink them
  find "$SOURCE" -type f \( -name "*white*.svg" \) | while read -r WHITE_ICON; do
      # Get the relative path (e.g., 64x64/places/folder-white.svg)
      REL_PATH="${WHITE_ICON#$SOURCE/}"
      REL_DIR=$(dirname "$REL_PATH")
      FILENAME=$(basename "$REL_PATH")
    
      # Determine the target name (e.g., folder.svg)
      STANDARD_NAME="${FILENAME//-white/}"
    
      # Create the local directory and symlink the white icon to the standard name
      mkdir -p "$DEST/$REL_DIR"
      ln -sf "$WHITE_ICON" "$DEST/$REL_DIR/$STANDARD_NAME"
  done

  # ── Update Icon Cache ────────────────────────────────────────────────────────
  echo "🔄 Updating icon cache..."
  if command -v gtk-update-icon-cache &>/dev/null; then
      gtk-update-icon-cache -f -t "$DEST"
  fi

  echo ""
  echo "✅ Success!"
  echo "1. Open GNOME Tweaks -> Appearance"
  echo "2. Select 'Rose Pine (White Folders)' in the Icons dropdown."
  echo "3. Restart Nautilus: 'nautilus -q' or log out/in."
  ```
- Deploy the theme:
  ```bash
  # One-time setup
  chmod +x ~/.local/bin/setup-white-folders-v3.sh
  ~/.local/bin/setup-white-folders-v3.sh

  # Apply
  gsettings set org.gnome.desktop.interface icon-theme 'rose-pine-white'

  # Verify
  gsettings get org.gnome.desktop.interface icon-theme
  # → 'rose-pine-white'

  # Revert anytime
  gsettings set org.gnome.desktop.interface icon-theme 'rose-pine-icons'
  ```
- Config Helix
  ```bash
  # ~/.config/helix/config.toml
  theme = "bogster_light"

  [editor]
  line-number = "relative"
  cursorline = true
  color-modes = true
  scrolloff = 8
  bufferline = "multiple"
  true-color = true
  popup-border = "all"
  end-of-line-diagnostics = "hint"
  trim-trailing-whitespace = true
  insert-final-newline = true

  [editor.cursor-shape]
  insert = "bar"
  normal = "block"
  select = "underline"

  [editor.lsp]
  display-inlay-hints = true
  display-signature-help-docs = true

  [editor.statusline]
  left = ["mode", "spinner", "file-name", "file-modification-indicator"]
  center = ["version-control"]
  right = ["diagnostics", "position", "file-encoding", "file-type"]
  separator = "│"
  mode.normal = "NORMAL"
  mode.insert = "INSERT"
  mode.select = "SELECT"

  [editor.indent-guides]
  render = true
  character = "╎"
  skip-levels = 1

  [editor.inline-diagnostics]
  cursor-line = "warning"

  [editor.search]
  smart-case = true
  wrap-around = true

  [editor.soft-wrap]
  enable = true
  ```
- Fastfetch config
  ```bash
  # Edit ~/.config/fastfetch/config.jsonc
  // ~/.config/fastfetch/config.jsonc
  // ─── Srcery Fastfetch ─────────────────────────────────────────────────────
  // Kitty image protocol · Categories · Security status · Srcery palette
  //
  // SETUP:
  //   1. Set logo.source to your actual image path
  //   2. Adjust logo.height to match line count (count your modules)
  //   3. Install: fastfetch mokutil btrfs-progs snapper apparmor ufw dnscrypt-proxy
  //   4. Place at: ~/.config/fastfetch/config.jsonc
  //
  // SECURITY MODULES: each runs a live shell command on every fetch.
  // If a tool is not installed, that line will show an error — comment it out.
  // ─────────────────────────────────────────────────────────────────────────────
  {
      "$schema": "https://github.com/fastfetch-cli/fastfetch/raw/dev/doc/json_schema.json",
      "logo": {
          "type": "kitty-direct",
          "source": "/home/zureta/Pictures/Fastfetch/fastfetch_white.png",
          "width": 48,
          "height": 34
      },
      "display": {
          "separator": "  ",
          "key": {
              "width": 18
          },
          "color": {
              "keys": "90",
              "title": "33"
          }
      },
      "modules": [
          "title",
          {
              "type": "separator",
              "string": "─",
              "color": "90"
          },
          {
              "type": "custom",
              "format": "\u001b[33m Hardware \u001b[90m────────────────────\u001b[0m"
          },
          {
              "type": "host",
              "key": "  Model",
              "keyColor": "90"
          },
          {
              "type": "cpu",
              "key": "  CPU",
              "keyColor": "90"
          },
          {
              "type": "gpu",
              "key": "  GPU",
              "keyColor": "90"
          },
          {
              "type": "memory",
              "key": "󱊄  RAM",
              "keyColor": "90"
          },
          {
              "type": "disk",
              "key": "  Disk",
              "keyColor": "90"
          },
          {
              "type": "display",
              "key": "  Resolution",
              "keyColor": "90"
          },
          {
              "type": "custom",
              "format": "\u001b[33m Software \u001b[90m────────────────────\u001b[0m"
          },
          {
              "type": "os",
              "key": "  OS",
              "keyColor": "90"
          },
          {
              "type": "kernel",
              "key": "  Kernel",
              "keyColor": "90"
          },
          {
              "type": "de",      
              "key": "  DE",
              "keyColor": "90"
          },
          {
              "type": "wm",
              "key": "  WM",
              "keyColor": "90"
          },
          {
              "type": "shell",
              "key": "  Shell",
              "keyColor": "90"
          },
          {
              "type": "terminal",
              "key": "  Terminal",
              "keyColor": "90"
          },
          {
              "type": "packages",
              "key": "  Packages",
              "keyColor": "90"
          },
          {
              "type": "gtk",
              "key": "  Theme",
              "keyColor": "90"
          },
          {
              "type": "custom",
              "format": "\u001b[33m Uptime / Age \u001b[90m────────────────\u001b[0m"
          },
          {
              "type": "os-age",
              "key": "  OS Age",
              "keyColor": "90"
          },
          {
              "type": "uptime",
              "key": "  Uptime",
              "keyColor": "90"
          },
          {
              "type": "custom",
              "format": "\u001b[33m Security \u001b[90m────────────────────\u001b[0m"
          },
          {
              "type": "command",
              "key": "󰒃  Lynis Score",
              "keyColor": "90",
              "text": "report='/var/log/lynis/lynis-report.dat'; [ -f \"$report\" ] && awk -F= '/hardening_index/{print $2}' \"$report\" || echo '\u001b[31mNot found\u001b[0m'"
          },
          {
              "type": "command",
              "key": "󰒃  LVFS HSI",
              "keyColor": "90",
              "text": "fwupdmgr security --force 2>/dev/null | grep -i 'Host Security ID' | sed 's/.*HSI://' | xargs | awk '{print \"HSI:\"$1}'"
          },
          {
              "type": "command",
              "key": "  Secure Boot",
              "keyColor": "90",
              "text": "bootctl status 2>/dev/null | grep -q 'Secure Boot: enabled' && printf '\\u001b[32m✓ Enabled\\u001b[0m' || printf '\\u001b[31m✗ Disabled\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  TPM2",
              "keyColor": "90",
              "text": "[ -d /sys/class/tpm/tpm0 ] && printf '\\u001b[32m✓ Present\\u001b[0m' || printf '\\u001b[31m✗ Not found\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  LUKS",
              "keyColor": "90",
              "text": "lsblk -rpo NAME,TYPE 2>/dev/null | awk '$2==\"crypt\"{f=1} END{if(f) printf \"\\u001b[32m✓ Active\\u001b[0m\"; else printf \"\\u001b[31m✗ None\\u001b[0m\"}'"
          },
          {
              "type": "command",
              "key": "  BTRFS",
              "keyColor": "90",
              "text": "btrfs device stats / 2>/dev/null | awk -F= 'NF==2 && $2+0>0{e++} END{if(e>0) printf \"\\u001b[31m⚠ %d errors\\u001b[0m\",e; else printf \"\\u001b[32m✓ Clean\\u001b[0m\"}'"
          },
          {
              "type": "command",
              "key": "  AIDE",
              "keyColor": "90",
              "text": "systemctl is-active aidecheck.timer 2>/dev/null | grep -q '^active' && printf '\\u001b[32m✓ Scheduled\\u001b[0m' || printf '\\u001b[93m⚠ Not active\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  AppArmor.d",
              "keyColor": "90",
              "text": "aa-status 2>/dev/null | grep -q 'apparmor module is loaded' && printf '\\u001b[32m✓ Apparmor.d Loaded and Enforced\\u001b[0m' || printf '\\u001b[31m✗ Inactive\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  Snapper",
              "keyColor": "90",
              "text": "count=$(snapper -c root list 2>/dev/null | tail -n +3 | wc -l); printf '\\u001b[32m✓ %d snapshots\\u001b[0m' \"$count\""
          },
          {
              "type": "command",
              "key": "  VPN",
              "keyColor": "90",
              "text": "ip link show 2>/dev/null | grep -qE 'proton|tun[0-9]+' && printf '\\u001b[32m✓ Connected\\u001b[0m' || printf '\\u001b[31m✗ Down\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  UFW",
              "keyColor": "90",
              "text": "systemctl is-active --quiet ufw && printf '\\u001b[32m✓ Active\\u001b[0m' || printf '\\u001b[31m✗ Inactive\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "  DNS",
              "keyColor": "90",
              "text": "systemctl is-active dnscrypt-proxy 2>/dev/null | grep -q '^active' && printf '\\u001b[32m✓ dnscrypt-proxy\\u001b[0m' || printf '\\u001b[31m✗ Down\\u001b[0m'"
          },
          {
              "type": "command",
              "key": "󰏗  Reproducible",
              "keyColor": "90",
              "text": "cache=\"$HOME/.cache/repro_score\"; [ -s \"$cache\" ] && cat \"$cache\" || echo '\u001b[90mRun update script...\u001b[0m'"
          },
          {
              "type": "colors",
              "paddingLeft": 2,
              "symbol": "block"
          }
      ]
  }
  ```
- Use eww 
  ```bash
  - **TPM2 + Secure Boot** — `sbctl status`
  - **AIDE integrity** — reads cached result from systemd timer
  - **DNS / dnscrypt-proxy** — your existing `dns-status` script, not generic `systemd-resolved`
  - **Journalctl errors** — priority 3 and above since boot
  - **Backup monitor** — rustic last run + exit code
  - **Snapper snapshot status** — age of last `@` and `@home` snapshots
  - **AppArmor enforcement** — enforce vs complain count, flag any complain slippage
  - **Namespace audit** — `lsns` anomaly detection
  - **ProtonVPN / `proton0` interface status** — you have a named interface. A simple `ip link show proton0` tells you immediately if the tunnel is up or silently dropped. Critical given your UFW rules assume the VPN is active.
  - **UFW firewall status** — `ufw status` should show "active" with rule count. A kernel update or misconfigured service can disable it silently.
  - **Failed systemd units** — `systemctl --failed` is one of the most operationally useful checks. One line, instant signal that something broke since last boot.
  - **Pending security updates** — `checkupdates` (from `pacman-contrib`) filtered for packages with known CVEs or security advisories. Pairs well with your `update-system` script.
  - **Recent auth failures** — `journalctl _SYSTEMD_UNIT=sshd.service` or `faillock --user $USER` for local auth. Relevant on a machine that might have SSH exposed occasionally or for detecting local brute-force attempts.
  - **auditd / AVC denial count** — separate from AppArmor, `ausearch -m AVC -ts today | wc -l` gives you a daily denial counter. A spike is meaningful.
  - **eGPU presence** — `lspci | grep -i amd` confirms the OCuLink device is recognized. Worth knowing at a glance before launching anything GPU-dependent.

  # `notify-send` for **critical threshold alerts** from your systemd timer scripts. The dashboard is pull (you open it with `Super+S`), but some events — AIDE detecting a change, AppArmor dropping to complain, VPN going down — need to be push. Your timer scripts should call `notify-send -u critical` when a check crosses a bad threshold, so GNOME's native notification system surfaces it immediately without you having to open the dashboard.

  | Widget | Source command | Refresh |
  |---|---|---|
  | TPM2 + Secure Boot | `sbctl status` | 10 min |
  | LUKS / BTRFS health | `cryptsetup status`, `btrfs device stats` | 10 min |
  | AIDE integrity | cached file from timer | 1 hr (timer) |
  | AppArmor enforcement | `aa-status --summary` | 5 min |
  | auditd AVC denials | `ausearch -m AVC -ts today` | 5 min |
  | Snapper snapshots | `snapper list` → last entry age | 5 min |
  | Backup monitor | rustic log / exit code | 5 min |
  | ProtonVPN (`proton0`) | `ip link show proton0` | 30 sec |
  | UFW firewall | `ufw status` | 2 min |
  | DNS (dnscrypt-proxy) | your `dns-status` script | 30 sec |
  | Failed systemd units | `systemctl --failed` | 1 min |
  | Journalctl errors | `journalctl -p 3 -b -n 20` | 1 min |
  | Auth failures | `faillock --user $USER` | 5 min |
  | Pending updates | `checkupdates` | 1 hr |
  | eGPU presence | `lspci \| grep -i amd` | 10 min |
  | Namespace audit | `lsns -t user` | 5 min |
  | Reproducible | *see below | 30 min |

  # *If you want a more nuanced view of your system's integrity, these factors are arguably more meaningful:
  # Local Verification Coverage: Instead of just showing the global score, a metric showing "Verified Locally: 85/1912 BAD packages" would tell you how much of the "untrusted" software on your system you have personally audited.
  # Chain of Trust Status: Monitoring how many of your packages are signed by "Master Keys" versus individual developer keys.
  # The "Delta" Factor: A metric showing the difference between the Global Score and your Personal Reproducibility Score. If the global score is 87% but your local verification of "BAD" packages brings your personal confidence to 92%, that's a significant security win.  

  # That's 17 checks, all local, all scriptable in a few lines each, all feeding into one dashboard panel with `notify-send` push alerts for the critical ones.
  ```  
