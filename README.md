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
     ✅ **Follow Step 4 exactly as written**
   
   - If Windows is on `/dev/nvme1n1` and empty drive is `/dev/nvme0n1`:
     ⚠️ **SWAP all device names in Step 4**:
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
    # "warning:  /mnt/etc/fstab installed as /mnt/etc/fstab.pacnew" --> It can be safely ignored, this new file can be removed later since we already created the fstab. This is a generic fstab created by the pacstrap and we created it earlier.
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
  # Load fzf if available
  if command -v fzf >/dev/null 2>&1; then
    source <(fzf --zsh)
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
  alias grep='rg --color=auto'
  alias find='fd --color=auto --hidden --no-ignore'
  alias ls='eza --icons --git --color=auto --group-directories-first --header'
  alias cat='bat -p --paging=never'
  alias du='dua'                    
  alias ps='procs --color=always'
  alias dig='dog'
  alias btop='btm'
  alias iftop='bandwhich --immediate --tree'

  # Ignore trivial & sensitive commands
  setopt HIST_IGNORE_SPACE
  setopt HIST_REDUCE_BLANKS
  export HISTSIZE=5000
  export SAVEHIST=5000
  export HISTFILE=~/.zsh_history

  # Don't record obvious secrets
  export HISTIGNORE="*password*:*token*:*secret*:*--key*"
  
  # Optional: make sudo preserve these aliases when you really want it
  # (rarely needed, but harmless)
  alias sudo='sudo '  # trailing space → sudo also expands aliases
  fi
  
  # zoxide: use 'z' and 'zi' (no autojump alias needed)
  (( ${+commands[zoxide]} )) && eval "$(zoxide init zsh)"
    
  # Safe update alias
  alias update='paru -Syu'
  echo "Run 'update' weekly. Use 'paru -Syu' for full control."
  # NOTE: The following are now system-wide tools, not aliases:
  # - fix-tpm       → /usr/local/bin/fix-tpm (script)
  # - yay           → /usr/local/bin/yay (symlink to paru)
  # - sysctl/systeroid → separate tools (no alias, use each for its purpose)
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
  root=UUID=$ROOT_UUID rootflags=subvol=@ resume_offset=$RESUME_OFFSET rw quiet splash intel_iommu=on amd_iommu=on iommu=pt pci=pcie_bus_perf randomize_kstack_offset=on hash_pointers=always mitigations=auto page_alloc.shuffle=1 vsyscall=none debugfs=off vdso32=0 proc_mem.force_override=never kfence.sample_interval=100 rd.systemd.show_status=auto rd.udev.log_priority=3 lsm=landlock,lockdown,yama,integrity,apparmor,bpf
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

  echo "Sealing LUKS to TPM PCRs 7+11..."

  systemd-cryptenroll "$LUKS_DEV" \
    --wipe-slot=tpm2 \
    --tpm2-device=auto \
    --tpm2-pcrs=7+11 \
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

  if sudo systemd-cryptenroll --tpm2-device=auto --test "\$LUKS_DEV" >/dev/null 2>&1; then
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
  PCRs: 7,11
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
  
  # Raw PCR + Public-Key Enrollment - Create the tpm-reenroll systemd service file that will be a wrapper of TPM Seal Script
  cat > /etc/systemd/system/tpm-reenroll.service << 'EOF'
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
  ExecStart=/usr/local/bin/tpm-seal
  
  [Install]
  WantedBy=multi-user.target
  EOF

  # Create fix-tpm script
  cat << 'EOF' | sudo tee /usr/local/bin/fix-tpm > /dev/null
  #!/usr/bin/env bash
  # Re-enroll TPM2 LUKS unlock after PCR changes (e.g., firmware updates)
  # Creates temporary flag file, triggers service, then shows logs

  set -euo pipefail

  echo "Re-enrolling TPM2 LUKS unlock..."

  # Create allow-file (tpm-reenroll.service checks for this)
  sudo touch /etc/allow-tpm-reenroll

  # Start the service
  if sudo systemctl start tpm-reenroll.service; then
    echo "✓ Re-enrollment triggered"
  else
    echo "✗ Re-enrollment failed"
    sudo rm -f /etc/allow-tpm-reenroll
    exit 1
  fi

  # Clean up flag file
  sudo rm -f /etc/allow-tpm-reenroll

  # Show recent logs
  echo ""
  echo "=== Recent TPM Re-enrollment Logs ==="
  sudo journalctl -u tpm-reenroll.service -n 50 --no-pager

  # Final status
  if sudo systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 >/dev/null 2>&1; then
    echo ""
    echo "✓ TPM unlock test PASSED"
  else
    echo ""
    echo "✗ TPM unlock test FAILED - manual intervention needed"
    exit 1
  fi
  EOF

  sudo chmod +x /usr/local/bin/fix-tpm
  echo "Created /usr/local/bin/fix-tpm script"

  # Test fix-tpm
  fix-tpm --help 2>/dev/null || echo "fix-tpm ready (run without args to re-enroll)"
  
  # Reload daemon and enable the service
  sudo systemctl daemon-reload
  sudo systemctl enable tpm-reenroll.service
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
  ls -R /boot/EFI
  
  # Set Boot Order – main Arch → LTS → Fallback → Windows (robust & future-proof)
  echo "Setting final UEFI boot order..."
  sudo efibootmgr --bootorder \
  $(sudo efibootmgr | grep -E 'Arch Linux( |$)' | grep -v 'LTS' | grep -v 'Fallback' | head -n 1 | awk '{print $1}' | cut -c5-),\
  $(sudo efibootmgr | grep 'LTS Kernel' | awk '{print $1}' | cut -c5-),\
  $(sudo efibootmgr | grep 'Fallback' | awk '{print $1}' | cut -c5-),\
  $(sudo efibootmgr | grep -i 'windows boot manager' | awk '{print $1}' | cut -c5-) \
  2>/dev/null || echo "Boot order set (some entries may be missing – this is fine)"
  
  # Verify the TPM Seal one last time using the physical device
  if sudo systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2; then
    echo "✓ TPM unlock test PASSED: System is ready for password-less boot."
  else
    echo "✗ TPM unlock test FAILED: Running repair..."
  sudo fix-tpm
  fi

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
  sudo mount /dev/sdX1 /mnt/usb  # Replace with your USB
  sudo tpm2_pcrread sha256:7,11 > /mnt/usb/tpm-pcr-post-secureboot.txt
  sudo diff /mnt/usb/tpm-pcr-backup.txt /mnt/usb/tpm-pcr-post-secureboot.txt || echo "PCR 7 changed (expected)"
  echo "WARNING: Store /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden."
  echo "WARNING: Compare PCR values to ensure TPM policy consistency."
  ```
- Create a GRUB USB for recovery:
  ```bash
  lsblk  # Identify USB device (e.g., /dev/sdX1)
  read -p "Enter USB partition (e.g. /dev/sdb1): " USB_PART
  sudo mkfs.fat -F32 -n RESCUE_USB /dev/sdX1 # Make sure to enter the USB ID in use replacing the placeholder "/dev/sdX1"

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
  sudo cp -r /lib/firmware/amdgpu /mnt/usb/firmware/

  # Generate minimal rescue initramfs (no plymouth, resume)
  sudo cp /etc/mkinitcpio.conf /mnt/usb/mkinitcpio-rescue.conf
  sudo sed -i 's/HOOKS=(.*/HOOKS=(base systemd autodetect modconf block sd-encrypt btrfs filesystems keyboard)/' /mnt/usb/mkinitcpio-rescue.conf
  sudo mkinitcpio -c /mnt/usb/mkinitcpio-rescue.conf -g /mnt/usb/initramfs-rescue.img
  sudo cp /mnt/usb/initramfs-rescue.img /mnt/usb/initramfs-linux.img

  # Copy LUKS keyfile
  sudo cp /crypto_keyfile /mnt/usb/luks-keyfile 2>/dev/null || \
  echo "Warning: No keyfile found. Using passphrase only."
  sudo chmod 600 /mnt/usb/luks-keyfile 2>/dev/null || true

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
  sudo sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  sudo shred -u /crypto_keyfile # This may fail and you will need to enter the chroot, mount everything, then wipe
  umount /mnt/usb
  
  echo "WARNING: Store the GRUB USB securely; it contains the LUKS keyfile."
  ```
- Ensure the LUKS keyfile was deleted
  ```bash
  if [ -f /crypto_keyfile ]; then
    echo "WARNING: /crypto_keyfile still exists. Securely wiping it now."
    sudo shred -vfz -n 3 /crypto_keyfile
    sudo rm -f /crypto_keyfile
  fi
  ls -la /crypto_keyfile || echo "✓ Keyfile wiped"
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
  sudo systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM unlock test PASSED"
  sudo sbctl status
  ```
- Check Windows
  ```bash
  # Reboot to Windows and verify it boots
  # Then reboot to Linux to continue
  ```
## Milestone 5: After Step 9 (systemd-boot and UKI Setup) - Can pause at this point

## Step 10: Install and Configure DE and Applications

  set -euo pipefail

- Install the **GNOME desktop environment**:
  ```bash
  # Core Desktop Environment (Shell, Compositor, Login Manager)
  sudo pacman -S --needed mutter gnome-shell gdm gnome-control-center gnome-session gnome-settings-daemon \

  # Install Essential Tools
  nautilus gnome-keyring gnome-backgrounds xdg-user-dirs-gtk xdg-desktop-portal-gnome xdg-desktop-portal-gtk localsearch libadwaita xdg-utils glycin-gtk4 gnome-power-manager webp-pixbuf-loader \

  # GNOME Adwaita, Orchis and Papirus
  adw-gtk-theme gnome-themes-extra adwaita-fonts adwaita-icon-theme orchis-theme papirus-icon-theme
  ```
- Create ~/Music, Pictures, Documents, Downloads, Desktop, Videos, Public, Git, Games etc. (for Lollypop, etc) (NO SUDO)
  ```bash
  xdg-user-dirs-update 
  ```
- Install **Paru and configure it**:
  ```bash   
  # Clone & build in a clean temp dir
  TMP_PARU=$(mktemp -d --tmpdir=paru.XXXXXX)
  git clone --depth 1 https://aur.archlinux.org/paru.git "$TMP_PARU"
  (
    cd "$TMP_PARU" || exit 1
    set -e  # Fail fast on any error

  # Make pacman non-interactive for deps (passes to internal pacman -S calls)
  export PACMAN_OPTS=("--noconfirm")
  
  # Build the package (creates the .pkg.tar.zst file)
  makepkg -s --clean
  
  # NAMCAP AUDIT (Insert Check Here)
  echo "--- Running namcap audit on the built paru package ---"
  # Audits the built package. The || true allows the script to continue on warnings.
  namcap PKGBUILD || true
  namcap paru-*.pkg.tar.zst || true
  
  # Install the audited package
  sudo pacman -U paru-*.pkg.tar.zst
  )
  rm -rf "$TMP_PARU"

  # Configure to show PKGBUILD diffs (edit the Paru config file):
  mkdir -p ~/.config/paru
  cat << 'EOF' > ~/.config/paru/paru.conf
  [options]
  PgpFetch
  BottomUp
  RemoveMake
  CleanAfter = true
  SudoLoop
  EditMenu = true
  CombinedUpgrade = false

  [bin]
  DiffMenu = true
  UseAsk = true
  Chroot = true
  EOF
    
  # Verify if paru shows the PKGBUILD diffs
  paru -Pg | grep -E 'diffmenu|combinedupgrade|editmenu' || true # Should show: combinedupgrade: Off diffmenu: Edit editmenu: Edit

  # Set build directory
  echo "BUILDDIR = $HOME/.cache/paru-build" | sudo tee -a /etc/makepkg.conf
  mkdir -p ~/.cache/paru-build

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
  gnome-system-monitor gnome-disk-utility logwatch tlp upower zram-generator libappindicator \
  \
  # Hardware
  bluez bluez-utils cups fprintd \
  \
  # Networking & Privacy
  dnscrypt-proxy opensnitch wireguard-tools proton-vpn-gtk-app \
  \
  # CLI Tools
  atuin bat bandwhich bottom broot delta dog dua eza fd fzf gcc gdb gitui glow gping \
  helix httpie hyfetch linux-docs procs python-gobject rage ripgrep rustup starship systeroid tealdeer \
  xdg-ninja yazi zoxide zsh-autosuggestions \
  \
  # Multimedia (system)
  ffmpeg gstreamer gst-libav gst-plugins-bad gst-plugins-good gst-plugins-ugly \
  libva-utils libva-vdpau-driver vulkan-tools clinfo wine 7zip exfatprogs \
  \
  # Browsers, Email-Client and Virtual Machine (Make sure to set in the Tor application to perform automatic updates)
  torbrowser-launcher thunderbird protonmail-bridge virt-manager libvirt qemu-desktop \
  \
  # Games
  steam mangohud gamemode lib32-gamemode gamescope umu-launcher goverlay lib32-alsa-plugins lib32-giflib lib32-gst-plugins-base-libs lib32-gtk3 libjpeg-turbo lib32-libjpeg-turbo \
  lib32-libva lib32-mpg123 lib32-ocl-icd lib32-openal lib32-libpulse lib32-libxcomposite lib32-libxinerama libxslt mpg123 openal protontricks winetricks \
  \
  # Fonts (Emoji/symbol coverage + CJK support)
  noto-fonts noto-fonts-cjk noto-fonts-emoji noto-fonts-extra ttf-jetbrains-mono-nerd inter-font otf-hermit ttf-mona-sans	ttf-monaspace-variable \
  ttf-roboto ttf-roboto-mono-nerd cantarell-fonts ttf-ubuntu-mono-nerd ttf-ubuntu-nerd ttf-ibmplex-mono-nerd ttf-atkinson-hyperlegible otf-ipaexfont ttf-libertinus ttf-liberation \
  ttf-firacode-nerd ttf-cascadia-code-nerd ttf-hack-nerd ttf-iosevka-nerd ttf-sourcecodepro-nerd ttf-anonymouspro-nerd ttf-dejavu-nerd ttf-nerd-fonts-symbols-mono ttf-croscore ttf-victor-mono-nerd \
  \
  # GNOME Extras
  gnome-bluetooth-3.0 gnome-tweaks gnome-shell-extensions gnome-firmware gnome-browser-connector gnome-shell-extension-appindicator \
  gvfs gvfs-afc gvfs-smb gvfs-mtp gvfs-gphoto2 gvfs-wsdd libgsf
  ```
- Permanently allow the bandwhich binary its required privileges (Assign capabilities):
  ```bash
  sudo setcap cap_sys_ptrace,cap_dac_read_search,cap_net_raw,cap_net_admin+ep $(command -v bandwhich)
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
  sudo systemctl enable gdm.service bluetooth ufw systemd-timesyncd libvirtd.service tlp fprintd fstrim.timer sshguard logwatch.timer xdg-desktop-portal-gnome systemd-oomd upower.service cups.service
  sudo systemctl --failed  # Check for failed services
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
    aylurs-gtk-shell-git \
    libastal-meta  \
    gst-thumbnailers \
    gst-plugins-rs-git \
    brave-bin \
    kanagawa-icon-theme-git \
    kanagawa-gtk-theme-git \
    rose-pine-cursor \
    rose-pine-gtk-theme-full \
    stylepak-git \
    run0-sudo-shim-git \
    wluma 
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

  # Append fwupd trigger to existing 90-uki-sign.hook (ensure kernel targets)
  if ! grep -q "Target = linux" /etc/pacman.d/hooks/90-uki-sign.hook; then
    sed -i '/\[Trigger\]/a Target = linux\nTarget = linux-lts' /etc/pacman.d/hooks/90-uki-sign.hook || \
    echo -e "\nTarget = linux\nTarget = linux-lts" | sudo tee -a /etc/pacman.d/hooks/90-uki-sign.hook
  fi
  if ! grep -q "Target = fwupd" /etc/pacman.d/hooks/90-uki-sign.hook; then
    cat << 'EOF' | sudo tee -a /etc/pacman.d/hooks/90-uki-sign.hook
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
  fi

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
- Enable Brave hardware video encoding (for WebRTC/screen sharing):
  ```bash
  # Copy Brave .desktop to local override
  mkdir -p ~/.local/share/applications
  cp /usr/share/applications/brave-browser.desktop ~/.local/share/applications/
  
  # Add hardware encode flag to all Exec lines
  sed -i 's|Exec=/usr/bin/brave-browser|Exec=/usr/bin/brave-browser --enable-features=AcceleratedVideoEncoder|g' \
    ~/.local/share/applications/brave-browser.desktop

  echo "Brave hardware video encoding enabled"
  
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
- Install Bazaar, Flatseal and the Flatpak applications via GUI
  ```bash
  # Install Bazaar (Flatpak-focused app store) and Flatseal
  flatpak remote-add --if-not-exists --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo
  flatpak install --user -y flathub io.github.kolunmi.Bazaar com.github.tchx84.Flatseal

  # Launch once to initialize
  flatpak run io.github.kolunmi.Bazaar

  # Open Bazaar (search in GNOME overview or via flatpak run io.github.kolunmi.Bazaar)
  echo "Open Bazaar (via GNOME overview or 'flatpak run io.github.kolunmi.Bazaar') and install: GIMP (org.gimp.GIMP), GDM Settings (io.github.realmazharhussain.GdmSettings), Lollypop (org.gnome.Lollypop), Mixx (org.mixxx.Mixxx), Logseq (com.logseq.Logseq), Calculator (org.gnome.Calculator), Camera (org.gnome.Snapshot), Characters (org.gnome.Characters), Disk Usage Analyzer (org.gnome.baobab), Document Scanner (org.gnome.SimpleScan), Document Viewer (org.gnome.Papers), Fonts (org.gnome.font-viewer), Image Viewer (org.gnome.Loupe), Logs (org.gnome.Logs), Dconf Editor (ca.desrt.dconf-editor), Bustle (org.freedesktop.Bustle), Eyedropper (com.github.finefindus.eyedropper), Obfuscate (com.belmoussaoui.Obfuscate), Extension Manager (com.mattjakeman.ExtensionManager), File Roller (org.gnome.FileRoller), LibreOffice (org.libreoffice.LibreOffice), Scopebuddy GUI (io.github.rfrench3.scopebuddy-gui), Resources (net.nokyan.Resources) and Video Player (org.gnome.Showtime). Use Flatseal (com.github.tchx84.Flatseal) to fine-tune per-app permissions (e.g., add --filesystem=home:rw for Lollypop if needed)."
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
  flatpak run io.github.kolunmi.Bazaar  # Should launch without "display" errors
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
- Install Extensions from extensions.gnome.org using Extension Manager application flatpak
  ```bash
  # GNOME Extension Compatibility Note (GNOME 50 - March 2026):
  # Some extensions may break with GNOME 50 release. Check compatibility at:
  # https://extensions.gnome.org/local/
  # Affected extensions typically include: AppIndicator, Dash to Dock, custom themes.
  # Wait for extension updates if GNOME Shell crashes after 'pacman -Syu' to GNOME 50.
  
  echo "Install GSConnect from https://extensions.gnome.org/extension/1319/gsconnect/ using Extension Manager"
  echo "Install Copyous from https://extensions.gnome.org/extension/8834/copyous/ using Extension Manager"
  echo "Install Just Perfection from https://extensions.gnome.org/extension/3843/just-perfection/ using Extension Manager"
  echo "Install Blur my Shell from https://extensions.gnome.org/extension/3193/blur-my-shell/ using Extension Manager"
  echo "Install User Themes from https://extensions.gnome.org/extension/19/user-themes/ using Extension Manager"
  echo "Install Astra Monitor from https://extensions.gnome.org/extension/6682/astra-monitor/ using Extension Manager"
  echo "Install Space Bar from https://extensions.gnome.org/extension/5090/space-bar/ using Extension Manager"
  echo "Install Caffeine from https://extensions.gnome.org/extension/517/caffeine/ using Extension Manager"
  echo "Install Floating Mini Panel from https://extensions.gnome.org/extension/8274/floating-mini-panel/ using Extension Manager"
  echo "Install Bastion from https://extensions.gnome.org/extension/8898/bastion/ using Extension Manager"
  echo "Install AppIndicator and KStatusNotifier from https://extensions.gnome.org/extension/615/appindicator-support/ using Extension Manager"
  echo "After installing via Extension Manager, enable it and restart GNOME Shell (Alt+F2 → r → Enter)"
  ```
- Enroll fingerprint if device has a reader
  ```bash
  if fprintd-enroll -f list | grep -q "no devices"; then
    echo "No fingerprint reader detected"
  else
    echo "Fingerprint reader found! Run 'fprintd-enroll' to set it up (optional)"
  fi
  # If fingerprint doesn't work try to install the thinkfinger from AUR.
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
       PART 1: HIDE NOTO WEIGHT VARIANTS
       noto-fonts-extra ships Condensed, Thin, ExtraLight, Black, Heavy
       across every script — dozens of entries per script family.
       Regular and Bold remain fully visible and available.
       ════════════════════════════════════════════════════════════════ -->

  <selectfont>
    <rejectfont>
      <glob>/usr/share/fonts/noto/Noto*Condensed*</glob>
      <glob>/usr/share/fonts/noto/Noto*Cond*</glob>
      <glob>/usr/share/fonts/noto/Noto*Thin*</glob>
      <glob>/usr/share/fonts/noto/Noto*ExtraLight*</glob>
      <glob>/usr/share/fonts/noto/Noto*ExtraThin*</glob>
      <glob>/usr/share/fonts/noto/Noto*Black*</glob>
      <glob>/usr/share/fonts/noto/Noto*Heavy*</glob>
      <!-- Specialist subsets rarely needed in UI pickers -->
      <glob>/usr/share/fonts/noto/NotoSansMath*</glob>
      <glob>/usr/share/fonts/noto/NotoSansSymbols2*</glob>
    </rejectfont>
  </selectfont>


  <!-- ════════════════════════════════════════════════════════════════
       PART 2: HIDE NERD FONT PROPORTIONAL AND PROPO VARIANTS
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
      
      <!-- Fira Code (ttf-firacode-nerd) -->
      <pattern><patelt name="family"><string>FiraCode Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>FiraCode Nerd Font</string></patelt></pattern>

      <!-- RobotoMono (ttf-roboto-mono-nerd) -->
      <pattern><patelt name="family"><string>RobotoMono Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>RobotoMono Nerd Font</string></patelt></pattern>
            
      <!-- Cascadia Code → renamed CaskaydiaCove (ttf-cascadia-code-nerd) -->
      <pattern><patelt name="family"><string>CaskaydiaCove Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>CaskaydiaCove Nerd Font</string></patelt></pattern>
      
      <!-- Hack (ttf-hack-nerd) -->
      <pattern><patelt name="family"><string>Hack Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>Hack Nerd Font</string></patelt></pattern>
      
      <!-- Iosevka (ttf-iosevka-nerd) -->
      <pattern><patelt name="family"><string>Iosevka Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>Iosevka Nerd Font</string></patelt></pattern>
      
      <!-- Source Code Pro → renamed SauceCodePro (ttf-sourcecodepro-nerd) -->
      <pattern><patelt name="family"><string>SauceCodePro Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>SauceCodePro Nerd Font</string></patelt></pattern>
      
      <!-- Anonymous Pro → renamed AnonymicePro (ttf-anonymouspro-nerd) -->
      <pattern><patelt name="family"><string>AnonymicePro Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>AnonymicePro Nerd Font</string></patelt></pattern>
      
      <!-- DejaVu → renamed DejaVuSansM (ttf-dejavu-nerd) -->
      <pattern><patelt name="family"><string>DejaVuSansM Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>DejaVuSansM Nerd Font</string></patelt></pattern>
      
      <!-- Victor Mono (ttf-victor-mono-nerd) -->
      <pattern><patelt name="family"><string>VictorMono Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>VictorMono Nerd Font</string></patelt></pattern>
      
      <!-- Ubuntu Mono (ttf-ubuntu-mono-nerd) -->
      <pattern><patelt name="family"><string>UbuntuMono Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>UbuntuMono Nerd Font</string></patelt></pattern>
      
      <!-- Ubuntu (ttf-ubuntu-nerd) -->
      <pattern><patelt name="family"><string>Ubuntu Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>Ubuntu Nerd Font</string></patelt></pattern>
      
      <!-- IBM Plex Mono → renamed BlexMono (ttf-ibmplex-mono-nerd) -->
      <pattern><patelt name="family"><string>BlexMono Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>BlexMono Nerd Font</string></patelt></pattern>
      
      <!-- Hermit → renamed Hurmit (otf-hermit, if nerd-patched) -->
      <pattern><patelt name="family"><string>Hurmit Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>Hurmit Nerd Font</string></patelt></pattern>
      
      <!-- Symbols Only (ttf-nerd-fonts-symbols-mono) -->
      <pattern><patelt name="family"><string>Symbols Nerd Font Propo</string></patelt></pattern>
      <pattern><patelt name="family"><string>Symbols Nerd Font</string></patelt></pattern>
      
    </rejectfont>
  </selectfont>


  <!-- ════════════════════════════════════════════════════════════════
       PART 3: ALIAS REDIRECTS — complete set for all 14 Nerd fonts
       When any app requests a font by its hidden base proportional name,
       redirect to the Mono variant. Ensures WezTerm, Helix, Starship,
       and dotfiles copied from other machines resolve correctly.
       ════════════════════════════════════════════════════════════════ -->

  <alias>
    <family>JetBrainsMono Nerd Font</family>
    <prefer><family>JetBrainsMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>FiraCode Nerd Font</family>
    <prefer><family>FiraCode Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>RobotoMono Nerd Font</family>
    <prefer><family>RobotoMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>CaskaydiaCove Nerd Font</family>
    <prefer><family>CaskaydiaCove Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Hack Nerd Font</family>
    <prefer><family>Hack Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Iosevka Nerd Font</family>
    <prefer><family>Iosevka Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>SauceCodePro Nerd Font</family>
    <prefer><family>SauceCodePro Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>AnonymicePro Nerd Font</family>
    <prefer><family>AnonymicePro Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>DejaVuSansM Nerd Font</family>
    <prefer><family>DejaVuSansM Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>VictorMono Nerd Font</family>
    <prefer><family>VictorMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>UbuntuMono Nerd Font</family>
    <prefer><family>UbuntuMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Ubuntu Nerd Font</family>
    <prefer><family>Ubuntu Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>BlexMono Nerd Font</family>
    <prefer><family>BlexMono Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Hurmit Nerd Font</family>
    <prefer><family>Hurmit Nerd Font Mono</family></prefer>
  </alias>
  <alias>
    <family>Symbols Nerd Font</family>
    <prefer><family>Symbols Nerd Font Mono</family></prefer>
  </alias>

  </fontconfig>
  EOF
  
  # Rebuild cache
  fc-cache -fv

  # Validate, all three should return zero output if the config is working:
  fc-list : family | grep "Nerd Font" | grep -v "Mono" | grep -v "Propo"
  fc-list | grep -i "propo"
  fc-list | grep -i "condensed"

  # These should still show your 14 Mono entries:
  fc-list | grep -i "nerd font mono"
  ```
- Edit the Wezterm Visuals:
  ```bash
  # Configure WezTerm
  mkdir -p ~/.config/wezterm
  if [[ ! -f ~/.config/wezterm/wezterm.lua ]]; then
    cat <<'EOF' > ~/.config/wezterm/wezterm.lua
  local wezterm = require 'wezterm'
  local config = wezterm.config_builder()

  # Fonts & Rendering
  config.font = wezterm.font_with_fallback({
    { family = "JetBrains Mono", weight = "Regular" },
    { family = "Symbols Nerd Font Mono", scale = 1.0 },
    "Noto Color Emoji",   -- very useful fallback nowadays
  })

  config.font_size           = 12.5           -- ← most popular range on 14–16" 3K/4K laptops
  config.line_height         = 1.03           -- ← subtle improvement in readability
  config.harfbuzz_features   = { 'liga', 'calt', 'ss01', 'ss02', 'ss03', 'ss04', 'ss05' }

  # Appearance
  config.color_scheme             = 'rose-pine'
  config.window_background_opacity = 0.90       -- ← bit stronger blur, modern preference
  config.text_background_opacity   = 1.0        -- ← keep! very important with transparency

  config.window_padding = {
    left   = '12px',
    right  = '12px',
    top    = '8px',
    bottom = '8px',
  }

  config.window_decorations     = "RESIZE"      -- ← clean look, GNOME-friendly
  config.hide_tab_bar_if_only_one_tab = true

  # Performance / Backend
  config.front_end    = "WebGpu"       -- ← still the best choice on Linux Intel+AMD in 2026
  config.enable_wayland = true         -- ← can usually be removed (auto-detected), but explicit is fine

  # Quality of Life
  config.audible_bell = 'Disabled'
  config.visual_bell  = {
    fade_in_duration_ms  = 100,
    fade_out_duration_ms = 100,
    target               = 'BackgroundColor',
  }

  # Dim inactive panes — very helpful when using many splits
  config.inactive_pane_hsb = {
    saturation = 0.85,
    brightness = 0.75,
  }

  return config
  EOF
  else
    echo "WezTerm config already exists – skipping"
  fi
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
  echo 'options i915 enable_fbc=1' >> /etc/modprobe.d/i915.conf
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
  sudo ufw allow out on lo
  # Allow VPN
  sudo ufw allow in on wg0
  sudo ufw allow out on wg0
  # Replace '51413' with the actual port number from your torrent client.
  sudo ufw allow 51413/tcp
  sudo ufw allow 51413/udp
  # GSConnect / KDE Connect (Required for phone pairing)
  sudo ufw allow 1714:1764/udp
  sudo ufw allow 1714:1764/tcp
  # Enables the firewall and applies the rules
  sudo ufw enable
  ```
- Configure Wayland environment variables:
  ```bash
  sudo tee /etc/environment > /dev/null <<'EOF'
  # WAYLAND (FORCE HIGH-PERFORMANCE)
  MOZ_ENABLE_WAYLAND=1
  # GDK_BACKEND=wayland <-- Commented out to prevent Electron app crashes; use per-app if needed.
  CLUTTER_BACKEND=wayland
  QT_QPA_PLATFORM=wayland
  SDL_VIDEODRIVER=wayland
  ELECTRON_OZONE_PLATFORM_HINT=auto
  XDG_SESSION_TYPE=wayland
  # For Proton: PROTON_USE_WINED3D=1 env if DX12 issues.

  # PATH HARDENING (SYSTEM-WIDE ONLY)
  # # Avoid global PATH overrides to prevent breaking admin tools.
  # User paths ($HOME/.local/bin) added in ~/.zshrc
  EOF
  #The envars below should NOT BE INCLUDED and rely on switcheroo-control to automatic drive the use of the AMD eGPU or the Intel iGPU. DO NOT ADD INITIALLY:
  # LIBVA_DRIVER_NAME=radeonsi
  # LIBVA_DRIVER_NAME=iHD

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
- [OUTDATED] Configure MAC randomization (Those are introduced earlier in the Step 6 inside chroot):
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
  cat << 'EOF' > /etc/audit/rules.d/99-security.rules
  ## Delete all existing rules first (good practice in the last file)
  -D
  ## Buffer & failure mode
  -b 8192
  -f 1
  --failure silent

  ## Make rules immutable (-e 2)
  # Uncomment after tuning
  # -e 2

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

  ## Kernel & boot
  -w /boot/              -p wa -k boot
  -w /usr/lib/modules/   -p wa -k modules   # kernel module changes

  ## Security frameworks
  -w /etc/apparmor/      -p wa -k apparmor
  -w /etc/apparmor.d/    -p wa -k apparmor
  -w /etc/usbguard/rules.conf -p wa -k usbguard

  ## Privilege escalation & interesting failures
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_usage
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/run0 -k sudo_usage
  -a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k pkexec_usage

  ## Time changes (very useful for forensics)
  -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
  -w /etc/localtime -p wa -k time_change
  EOF

  # Commands that should be executed once
  # Load the new rules
  sudo augenrules --load          # or: sudo auditctl -R /etc/audit/rules.d/*

  # Verify immutable flag shows "immutable"
  sudo auditctl -s | grep enabled.*2

  # Check for syntax errors
  sudo auditctl -l | grep -i error && echo "ERROR" || echo "Rules OK"

  # Remove old logs
  cat << 'EOF' | sudo tee /etc/logrotate.d/audit
  /var/log/audit/audit.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        /usr/bin/systemctl kill -s HUP auditd.service >/dev/null 2>&1 || true
    endscript
  }
  EOF

  # Validate the logs remotions
  sudo augenrules --check

  # Make it survive reboot
  sudo systemctl enable --now auditd
  ```  
- Configure `dnscrypt-proxy` for secure DNS:
  ```bash
  # Prevent systemd-resolved conflict (Critical for dnscrypt socket)
  # systemd-resolved listens on 53stub, which can block dnscrypt.
  sudo systemctl disable --now systemd-resolved
  sudo systemctl mask systemd-resolved
  sudo rm -f /etc/resolv.conf
  # Create a new resolv.conf pointing to localhost (dnscrypt)
  echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
  # Lock it so NetworkManager doesn't overwrite it
  sudo chattr +i /etc/resolv.conf

  # Instruct NetworkManager to stop managing DNS for all connections
  sudo mkdir -p /etc/NetworkManager/conf.d/
  echo -e "[main]\ndns=none\nsystemd-resolved=false" | sudo tee /etc/NetworkManager/conf.d/90-custom-dns.conf

  # Restart NetworkManager to apply the global configuration change immediately
  sudo systemctl restart NetworkManager

  # Create Optimized Config
  cat << 'EOF' | sudo tee /etc/dnscrypt-proxy/dnscrypt-proxy.toml > /dev/null
  # Server List: Privacy + Blocking focused
  server_names = ['quad9-dnscrypt-ip4-filter-pri', 'adguard-dns', 'mullvad-adblock', 'cloudflare']

  # Listen Addresses
  listen_addresses = ['127.0.0.1:53', '[::1]:53']

  # Protocol Support
  max_clients = 2500    # Increased for heavy multitasking
  ipv4_servers = true
  ipv6_servers = true
  dnscrypt_servers = true
  doh_servers = true

  # Security
  require_dnssec = true
  require_nolog = true
  require_nofilter = false

  # Performance & Load Balancing
  force_tcp = false
  timeout = 2000        # Lower timeout for faster failover
  lb_strategy = 'p2'    # 'p2' balances randomly between the top 2 fastest servers

  # Laptop/Roaming Tweaks
  netprobe_timeout = 5  # Detect network changes faster (default is 60s)
  keepalive = 30        # Keep connections open slightly longer

  # Caching (Critical for desktop responsiveness)
  cache = true
  cache_size = 4096     # Store more records in RAM
  cache_min_ttl = 2400  # Force minimum TTL to reduce lookups
  cache_max_ttl = 86400
  cache_neg_min_ttl = 60
  EOF

  # Enable Socket Activation (Resource Efficient)
  # Do not enable the service directly; enable the socket.
  sudo systemctl enable dnscrypt-proxy.socket
  sudo systemctl start dnscrypt-proxy.socket

  # Test DNS resolution:
  echo "Waiting for DNS to initialize..."
  sleep 2
  dog archlinux.org || echo "DNS Test Failed - Check journalctl -u dnscrypt-proxy"

  # Create hook to automate dnscrypt on and off based on VPN on and off
  sudo tee /etc/NetworkManager/dispatcher.d/90-dnscrypt-vpn > /dev/null << 'EOF'
  #!/bin/bash
  set -euo pipefail

  IFACE="$1"
  STATUS="$2"

  CONNECTION=$(nmcli -t -f GENERAL.CONNECTION device show "$IFACE" 2>/dev/null || true)

  if [[ "$CONNECTION" == *VPN* || "$IFACE" == "tun0" || "$IFACE" == "wg0" ]]; then
  case "$STATUS" in
    up)
      systemctl stop dnscrypt-proxy.socket
      logger "VPN up ($IFACE): dnscrypt-proxy socket stopped"
      ;;
    down)
      systemctl start dnscrypt-proxy.socket
      logger "VPN down ($IFACE): dnscrypt-proxy socket started"
      ;;
  esac
  fi
  EOF
  # NetworkManager dispatcher scripts run as root.
  # No sudo is required inside this script.

  # Set permissions
  chmod +x /etc/NetworkManager/dispatcher.d/90-dnscrypt-vpn
  systemctl enable dnscrypt-proxy.socket

  # Verify DNS
  # Using resolvectl status will not retrieve anything because we masked systemd-resolved 
  ss -lnptu | grep :53
  dog archlinux.org
  dog +trace archlinux.org
  grep nameserver /etc/resolv.conf
  ```
- Check if there is a VPN or DNS leak:
  ```bash
  # Verify (check IP and no leaks)
  # Proton VPN ON
  curl ifconfig.me  # Should show Proton IP

  # Proton VPN OFF
  curl ifconfig.me  # Should show DNSCrypt IP
  ```
- Configure USBGuard:
  ```bash
  # Generate initial policy for currently connected devices (keyboard, mouse, etc.)
  sudo sh -c usbguard generate-policy > /etc/usbguard/rules.conf

  # Recommended daemon settings (make resume and Bluetooth happier)
  sudo mkdir -p /etc/usbguard
  cat <<EOF | sudo tee /etc/usbguard/usbguard-daemon.conf
  # Allow currently present devices after resume (prevents most Bluetooth/GSConnect breakage)
  PresentDevicePolicy=keep

  # New devices get the full policy check (not just auto-blocked without notification)
  InsertedDevicePolicy=apply-policy

  # Slightly more forgiving default for new devices (still blocks, but you get a notification)
  ImplicitPolicyTarget=allow
  # Start with ImplicitPolicyTarget=allow for first month. Switch to block only after device list is stable.
  # Use system for 2-4 weeks
  usbguard generate-policy > /etc/usbguard/rules.conf  # Export stable device list
  # Change to ImplicitPolicyTarget=block
  systemctl restart usbguard
  
  # Allow users in wheel group to talk to the daemon directly (complements Polkit)
  IPCAllowedGroups=wheel
  EOF

  # Correct & complete Polkit rule (fixed typo + all current actions as of usbguard 1.1+)
  cat <<'EOF' | sudo tee /etc/polkit-1/rules.d/70-usbguard.rules
  polkit.addRule(function(action, subject) {
    if (/^org\.usbguard\./.test(action.id) &&
        subject.active === true &&
        subject.local === true &&
        subject.isInGroup("wheel")) {
        return polkit.Result.YES;
    }
  });
  EOF

  # Enable both the main daemon and the DBus service (required for GNOME/GSConnect dialogs)
  sudo systemctl enable --now usbguard.service usbguard-dbus.service

  # GNOME privacy settings – block only on lock screen
  gsettings set org.gnome.desktop.privacy usb-protection true || true
  gsettings set org.gnome.desktop.privacy usb-protection-level 'lockscreen'

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

  EOS
  ```
- Harden Bluetooth Connections:
  ```bash
  cat >> /etc/bluetooth/main.conf <<EOF
  [Policy]
  AutoEnable=false  # Don't auto-enable on boot
  ReconnectAttempts=0
  ReconnectIntervals=1,2,4,8,16

  [General]
  Discoverable=false
  DiscoverableTimeout=0
  EOF
  ```
- Harden CUPS (Printer Attack Surface):
  ```bash
  # Add to /etc/cups/cupsd.conf
  <Location />
  Order allow,deny
  Allow localhost
  </Location>
  ```
- Configure Lynis audit and log management:
  ```bash
  # Create a dedicated, secure log directory
  sudo mkdir -p /var/log/lynis
  sudo chown root:root /var/log/lynis
  sudo chmod 700 /var/log/lynis

  # Timer Unit (Unchanged, correct as-is)
  cat << 'EOF' | sudo tee /etc/systemd/system/lynis-audit.timer
  [Unit]
  Description=Run Lynis audit weekly

  [Timer]
  OnCalendar=weekly
  Persistent=true

  [Install]
  WantedBy=timers.target
  EOF

   # Service Unit (Final Corrected Version)
  cat << 'EOF' | sudo tee /etc/systemd/system/lynis-audit.service
  [Unit]
  Description=Run Lynis audit
  After=network-online.target
  ConditionVirtualization=!container

  [Service]
  Type=oneshot
  User=root
  # Run the audit with the official --cronjob flag and skip for consistency
  # REMOVED: ExecStart=/usr/bin/lynis audit system --cronjob --skip-test SSH-7408,BOOT-5122,BOOT-5139
  ExecStart=/usr/bin/lynis audit system --quick --warnings --deeppen --auditor "Automated Audit" --logfile /var/log/lynis/lynis.log --report-file /var/log/lynis/lynis-report.dat --skip-test SSH-7408,BOOT-5122,BOOT-5139
  StandardOutput=journal
  StandardError=journal
  ProtectSystem=full
  ProtectHome=true
  PrivateTmp=true
  # Save the human-readable report summary (MUST run first)
  ExecStartPost=/usr/bin/lynis show warnings >> /var/log/lynis/lynis-report-$(date +%F).txt
  ExecStartPost=/usr/bin/lynis show suggestions >> /var/log/lynis/lynis-report-$(date +%F).txt
  # Archive the raw data and log files (MUST run last)
  ExecStartPost=/usr/bin/mv /var/log/lynis-report.dat /var/log/lynis/lynis-data-$(date +%F).dat
  ExecStartPost=/usr/bin/mv /var/log/lynis.log /var/log/lynis/lynis-log-$(date +%F).log
  TimeoutStartSec=15min
  EOF

  # Configure Log Rotation
  # This keeps 12 months (52 weeks) worth of reports and compresses them.
  cat << 'EOF' | sudo tee /etc/logrotate.d/lynis
  /var/log/lynis/* {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
  }
  EOF

  # Reload, Enable, and Start the Timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now lynis-audit.timer
  sudo systemctl enable lynis-audit.service

  # Run Initial Audit Manually (Aligned with service for consistency)
  echo "Running initial Lynis audit now..."
  sudo /usr/bin/lynis audit system --cronjob --skip-test SSH-7408,BOOT-5122,BOOT-5139
  # Capture report summary and archive files immediately after
  sudo /usr/bin/lynis show warnings >> /var/log/lynis/lynis-report-$(date +%F).txt
  sudo /usr/bin/lynis show suggestions >> /var/log/lynis/lynis-report-$(date +%F).txt
  sudo /usr/bin/mv /var/log/lynis-report.dat /var/log/lynis/lynis-data-$(date +%F).dat
  sudo /usr/bin/mv /var/log/lynis.log /var/log/lynis/lynis-log-$(date +%F).log
  echo "Report summary saved to /var/log/lynis/lynis-report-$(date +%F).txt"
  ```
- Configure AIDE:
  ```bash
  # Backup default config
  cp /etc/aide.conf /etc/aide.conf.bak

  # Customize aide.conf for hardened setup (focus on critical paths, strong hashes)
  cat << 'EOF' >> /etc/aide.conf

  # Global settings for better reports and compression
  verbose=20
  gzip_dbout=yes
  report_ignore_changed_attrs=b  # Ignore block changes (BTRFS-friendly)
  report_force_attrs=u+g         # Always show user/group in reports

  # Custom group: Strong security checks (attributes + strong hashes)
  SecGroup = p+i+n+u+g+s+m+c+acl+xattrs+sha512+sha256

  # Monitor critical paths
  /boot SecGroup
  /etc SecGroup
  /usr/bin SecGroup
  /usr/sbin SecGroup
  /usr/lib SecGroup
  /var/lib SecGroup  # For pacman db, but exclude /var/lib/aide (self-db)

  # Excludes for volatile subdirs
  !/var/lib/flatpak
  !/var/lib/systemd/coredump  # If using systemd-coredump
  !/var/lib/docker  # If Docker installed later
  !/var/lib/pacman/sync  # Pacman DB sync files change often

  /etc/apparmor.d SecGroup  # AppArmor profiles
  /etc/systemd SecGroup     # Systemd configs (e.g., hardening)
  !/var/log                 # Exclude logs (volatile)
  /!/tmp                    # Exclude temp files
  !/proc                    # Exclude procfs
  !/dev                     # Exclude devices (but warn on dead symlinks)
  !/home                    # Exclude user home (add if needed)
  /!/var/spool              # Exclude spools

  # Warn on dead symlinks for security
  warn_dead_symlinks=yes
  EOF
  
  # Validate config
  aide -D || { echo "Config error - check /etc/aide.conf"; exit 1; }
  echo "AIDE config customized and validated."

  # Initialize with verbose output
  aide --init --verbose=20

  # Move new DB to production
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz  # Note: .gz if gzip_dbout=yes

  # Run initial check to verify
  aide --check || { echo "Initial check failed - investigate changes"; }
  
  # Enable timer for daily checks
  systemctl enable --now aide-check.timer

  # Pacman hook to auto-update DB after upgrades (convenience: no manual mv/review unless daily check alerts)
  cat << 'EOF' > /etc/pacman.d/hooks/99-aide-update.hook
  [Trigger]
  Operation = Upgrade
  Type = Package
  Target = *
  [Action]
  Description = Auto-update AIDE database after upgrades
  When = PostTransaction
  Exec = /usr/bin/bash -c '/usr/bin/aide --update | tee /var/log/aide/aide-update-report-$(date +%F).txt; mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'
  EOF

  # Override: write clean JSON report + trigger desktop notification + update AGS widget
  sudo mkdir -p /etc/systemd/system/aide-check.service.d

  cat << 'EOF' | sudo tee /etc/systemd/system/aide-check.service.d/99-widget-notify.conf
  [Service]
  # Run the actual check and capture structured output
  ExecStartPost=/usr/bin/bash -c '\
  set -euo pipefail; \
  REPORT_FILE="/var/log/aide/last-check-$(date +%%Y%m%d-%H%M%S).txt"; \
  JSON_FILE="/run/aide-status.json"; \
  \
  if aide --check > "$REPORT_FILE" 2>&1; then \
    STATUS="clean"; \
    SUMMARY="AIDE: System integrity verified — no changes detected"; \
    notify-desktop --urgency=low --icon=security-high "AIDE Check" "$SUMMARY"; \
  else \
    STATUS="alert"; \
    SUMMARY="AIDE: Potential unauthorized changes detected! "; \
    notify-desktop --urgency=critical --icon=security-high --expire-time=0 "AIDE Alert" "$SUMMARY"; \
    # Also make a loud sound so you really notice it \
    canberra-gtk-play -i dialog-warning & \
  fi; \
  \
  # Write tiny JSON for AGS/Astal widget (readable by any user in the graphical session) \
  echo "{\"status\":\"$STATUS\",\"timestamp\":\"$(date -Iseconds)\",\"report\":\"$REPORT_FILE\"}" | \
    tee "$JSON_FILE"; \
  chmod 644 "$JSON_FILE"'
  EOF

  sudo systemctl daemon-reload
  ```
- Create systemd global hardening:
  ```bash
  sudo mkdir -p /etc/systemd/{system.conf.d,user.conf.d}

  # system.conf.d
  sudo tee /etc/systemd/system.conf.d/10-hardening.conf > /dev/null <<'EOF'
  [Manager]
  # Timing (bumped to 90s for slower services like NetworkManager on WiFi)
  DefaultTimeoutStartSec=90s
  DefaultTimeoutStopSec=90s
  DefaultLimitNOFILE=65536
  EOF
  
  # Service defaults
  sudo tee /etc/systemd/system.conf.d/99-security-defaults.conf > /dev/null <<'EOF'
  [Service]
  ProtectSystem=full
  NoNewPrivileges=yes
  RestrictSUIDSGID=yes
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectKernelLogs=yes
  ProtectClock=yes
  ProtectControlGroups=yes
  ProtectHostname=yes
  LockPersonality=yes
  RestrictRealtime=yes
  PrivateDevices=yes
  PrivateUsers=yes
  RemoveIPC=yes
  MemoryDenyWriteExecute=yes
  RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
  SystemCallArchitectures=native
  UMask=0077
  # REMOVED: PrivateTmp=yes ["Ghost" issues. Applications might fail to launch, audio might glitch, or inter-app features (like drag-and-drop or clipboard sharing between sandboxed apps) might fail silently.]
  # REMOVED: ProtectHome=read-only (Breaks Backups)
  # REMOVED: This was previously removed MemoryDenyWriteExecute=yes (Breaks JIT/Browsers) but it seems that we should be fine now so we are keeping it.

  # Filesystem protections (strict but compatible)
  # REMOVED: ProtectSystem=strict           # Read-only /usr, /boot, /efi — standard now [This makes /usr and /boot read-only for all services. While good for security, this often conflicts with updaters (like fwupd), driver managers (like dkms for your specific eGPU setup), or log rotation tools that aren't perfectly configured.]
  EOF

  echo "Systemd global hardening applied — verify scores post-boot with 'systemd-analyze security'."

  sudo systemctl daemon-reload
  systemd-analyze security --threshold=7.0
  ```
- Configure sysctl hardening:
  ```bash
  sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
  # === NETWORK HARDENING ===
  net.ipv4.conf.default.rp_filter=1
  net.ipv4.conf.all.rp_filter=1
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
  net.ipv6.conf.all.log_martians=1
  net.ipv6.conf.default.log_martians=1
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
  kernel.warn_limit = 10                # Reboot on excessive warnings
  kernel.oops_limit = 10                # Reboot on excessive oopses

  # === COMPATIBILITY HARDENING ===
  kernel.unprivileged_bpf_disabled=0   # MUST BE 0 for Games/Tracing
  kernel.modules_disabled=0            # MUST BE 0 for eGPU/WiFi (Default is fine, but ensures we don't accidentally disable it)

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
  vm.min_free_kbytes=1048576
  vm.page_lock_unfairness=1
  vm.zone_reclaim_mode=0
  kernel.sched_nr_migrate=128
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
  sudo systeroid --load=/etc/sysctl.d/99-hardening.conf -e --quiet

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
  sudo tee /etc/tmpfiles.d/10-gaming-tweaks.conf > /dev/null <<'EOF'
  # Transparent Huge Pages → madvise + no defrag (eliminates THP stalls in games)
  w /sys/kernel/mm/transparent_hugepage/enabled           - - - - madvise
  w /sys/kernel/mm/transparent_hugepage/shmem_enabled      - - - - advise
  w /sys/kernel/mm/transparent_hugepage/khugepaged/defrag  - - - - 0

  # Full MGLRU (multi-gen LRU) – gives 5–12 % better 1% lows on Zen 4/Meteor Lake
  w /sys/kernel/mm/lru_gen/enabled                         - - - - 7
  EOF

  # Apply immediately apply
  sudo systemd-tmpfiles --create
  ```
- Audit SUID binaries:
  ```bash
  #!/usr/bin/env bash
  set -euo pipefail

  # Colors for output
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m' # No Color

  AUDIT_FILE="/data/suid_audit.txt"
  LOG_FILE="/data/suid_audit.log"
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

  mkdir -p "$(dirname "$AUDIT_FILE")"
  mkdir -p "$(dirname "$LOG_FILE")"

  log() {
    echo -e "${TIMESTAMP} - $1" | tee -a "$LOG_FILE"
  }

  log "${GREEN}Starting SUID/SGID audit${NC}"

  # Full audit of all SUID and SGID files (including SGID which is often forgotten)
  log "Generating full list of SUID/SGID files..."
  {
    echo "=== SUID/SGID Audit Report - $TIMESTAMP ==="
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo
    echo "SUID files (u+s):"
    find / -xdev -type f -perm -u+s 2>/dev/null | sort
    echo
    echo "SGID files (g+s):"
    find / -xdev -type f -perm -g+s 2>/dev/null | sort
    echo
    echo "Total SUID files: $(find / -xdev -type f -perm -u+s 2>/dev/null | wc -l)"
    echo "Total SGID files: $(find / -xdev -type f -perm -g+s 2>/dev/null | wc -l)"
  } > "$AUDIT_FILE"

  log "${GREEN}Audit saved to $AUDIT_FILE${NC}"

  # Known good vs suspicious SUID binaries (customize per distro!)
  declare -A KNOWN_GOOD_SUID=(
    ["/bin/su"]="yes"
    ["/bin/mount"]="yes"
    ["/bin/umount"]="yes"
    ["/bin/ping"]="yes"      # we'll replace this
    ["/usr/bin/sudo"]="yes"
    ["/usr/bin/passwd"]="yes"
    ["/usr/bin/chsh"]="yes"
    ["/usr/bin/chfn"]="yes"
    ["/usr/bin/newgrp"]="yes"
    ["/usr/bin/gpasswd"]="yes"
    ["/usr/lib/polkit-1/polkit-agent-helper-1"]="yes"
    ["/usr/lib/x86_64-linux-gnu/libexec/polkit-agent-helper-1"]="yes"
  )

  log "${YELLOW}Checking for unexpected SUID binaries...${NC}"
  while IFS= read -r file; do
    if [[ -z "$file" ]]; then continue; fi
    
    if [[ -z "${KNOWN_GOOD_SUID[$file]:-}" ]]; then
        log "${RED}WARNING: Unexpected SUID binary found: $file${NC}"
        echo "UNEXPECTED SUID: $file" >> "$AUDIT_FILE.unexpected"
    fi
  done < <(find / -xdev -type f -perm -u+s 2>/dev/null)

  # Safer ping replacement with capabilities (only if setcap exists)
  if command -v setcap >/dev/null 2>&1; then
    PING_BIN=$(command -v ping || echo "")
    if [[ -n "$PING_BIN" && -f "$PING_BIN" ]]; then
        if [[ $(stat -c "%A" "$PING_BIN" 2>/dev/null || echo "") == *s* ]]; then
            log "Replacing SUID bit on ping with Linux capabilities..."
            if chmod u-s "$PING_BIN" && setcap cap_net_raw+ep "$PING_BIN"; then
                log "${GREEN}Successfully applied cap_net_raw+ep to $PING_BIN${NC}"
            else
                log "${RED}Failed to set capabilities on ping${NC}"
            fi
        else
            log "ping already has capabilities or no SUID bit"
        fi
    fi
  else
    log "${YELLOW}setcap not available - cannot replace ping SUID with capabilities${NC}"
  fi

  log "${GREEN}SUID audit completed. Check $AUDIT_FILE and $LOG_FILE${NC}"
  ```
- Configure zram:
  ```bash
  cat << 'EOF' | sudo tee /etc/systemd/zram-generator.conf
  [zram0]
  zram-size = min(ram / 2, 8192)
  compression-algorithm = zstd
  swap-priority = 100
  EOF
  sudo systemctl daemon-reload

  # Remove old conflicting services first (very common source of silent failure)
  sudo systemctl disable --now zramswap.service 2>/dev/null || true
  sudo systemctl disable --now zram-config.service 2>/dev/null || true
  sudo systemctl mask zramswap.service 2>/dev/null || true

  # TLP sometimes ships its own zram module on older distros
  sudo systemctl disable --now tlp-zram.service 2>/dev/null || true

  # Broader cleanup
  for unit in $(systemctl list-unit-files --plain | grep -i zram | awk '{print $1}'); do
    sudo systemctl disable --now "$unit" 2>/dev/null || true
    sudo systemctl mask "$unit" 2>/dev/null || true
  done

  # Now enable the modern generator-based one
  systemctl enable --now systemd-zram-setup@zram0.service 
  ```
- Configure systemd-oomd for desktop responsiveness
  ```bash
  # This prevents the system from freezing by killing memory-hogging background apps before the swap fills up completely.
  sudo mkdir -p /etc/systemd/oomd.conf.d
  cat << 'EOF' | sudo tee /etc/systemd/oomd.conf.d/10-desktop.conf
  [OOM]
  # Start acting when 80% of swap is used (preserves system responsiveness)
  SwapUsedLimit=80%
  # Start acting when 90% of RAM is used
  DefaultMemoryPressureLimit=90%
  EOF
  sudo systemctl restart systemd-oomd
  ```
- Memory/scheduler tweaks:
  ```bash
  sudo tee /etc/tmpfiles.d/consistent-response-time-for-gaming.conf > /dev/null <<'EOF'
  # Memory/Jitter Reduction (Arch Wiki Gaming)
  w /proc/sys/vm/compaction_proactiveness - - - - 0
  w /proc/sys/vm/min_free_kbytes - - - - 204800
  w /proc/sys/vm/swappiness - - - - 10
  w /sys/kernel/mm/lru_gen/enabled - - - - 7
  w /proc/sys/vm/zone_reclaim_mode - - - - 0
  w /sys/kernel/mm/transparent_hugepage/enabled - - - - madvise
  w /sys/kernel/mm/transparent_hugepage/shmem_enabled - - - - advise
  w /sys/kernel/mm/transparent_hugepage/khugepaged/defrag - - - - 0
  w /proc/sys/vm/page_lock_unfairness - - - - 1
  w /proc/sys/kernel/sched_child_runs_first - - - - 0
  w /proc/sys/kernel/sched_autogroup_enabled - - - - 1
  w /proc/sys/kernel/sched_migration_cost_ns - - - - 500000
  w /proc/sys/kernel/sched_nr_migrate - - - - 32
  EOF
  sudo systemd-tmpfiles --create
  ```
- Configure udisk for Firmware Updates:
  ```bash
  # Install and enable
  pacman -S udisks2
  systemctl enable --now udisks2.service

  # Secure Boot: Allow capsule updates
  echo '[uefi_capsule]\nDisableShimForSecureBoot=true' >> /etc/fwupd/fwupd.conf

  # Sign fwupd EFI binary
  sbctl sign -s /usr/lib/fwupd/efi/fwupdx64.efi

  # Verify setup (NO update checks)
  fwupdmgr get-devices 2>/dev/null | grep -i "UEFI" && echo "fwupd: UEFI device detected"
  echo "fwupd configured. Updates will be checked in Step 18 (after first boot)."
  ```
- Configure opensnitch:
  ```bash
  # Enable and start the daemon
  sudo systemctl enable --now opensnitchd.service

  # Launch the GUI to configure/unpause (unpause to enable blocking!)
  opensnitch-ui

  # Verify
  systemctl status opensnitchd.service
  journalctl -u opensnitchd.service -f # Tail logs for connection attempts

  # Will annoy you the first 30–60 min until you allow Firefox, Steam, Signal, etc. But that is the point. Just keep the GUI open the first day.
  ```
- Binary Hardening: Replace Setuid with Capabilities
  ```bash
  # Find all setuid binaries on your system to create a baseline for review:
  find / -type f -perm /4000 2>/dev/null > /root/setuid-binaries.list
  cat /root/setuid-binaries.list

  # Review the list, focusing on common targets like /usr/bin/ping and /usr/bin/mount.
  # For most modern systems, the most common candidate for this hardening is ping, which requires elevated privileges only to create a raw socket.
  # Remove the setuid bit from the ping binary:
  sudo chmod u-s /usr/bin/ping
  # Verify the 's' is gone:
  ls -l /usr/bin/ping

  # Apply the minimal required capability (CAP_NET_RAW):
  # Set the capability: 'p' means Permitted set
  sudo setcap cap_net_raw+p /usr/bin/ping
  # Verify the capability is set:
  getcap /usr/bin/ping
  # Test: The ping command should still function for unprivileged users. Repeat this process for any other minimal-privilege setuid binaries you identify.
  ```
- Enable Apparmor in COMPLAIN mode
  ```bash
  # This activates the *complete* AppArmor.d policy (1000+ profiles)
  # DO NOT use aa-complain on /etc/apparmor.d/* — that's legacy.
  
  # Enable the upstream-sync timer (weekly profile updates)
  sudo systemctl enable --now apparmor.d-update.timer
  
  # Load Full System Policy in COMPLAIN mode
  sudo just fsp-complain   # from the apparmor.d build dir (installed to /usr/share/apparmor.d)

  # Warm cache for boot-time performance (critical for UKI + Secure Boot)
  sudo apparmor_parser -r /usr/share/apparmor.d/*

  # Restart to apply everything
  sudo systemctl restart apparmor

  # Regenerate UKI
  mkinitcpio -P && sbctl sign -s /boot/EFI/Linux/arch*.efi

  echo "AppArmor is now in COMPLAIN mode."
  echo "Use system normally for 1–2 days, then check denials:"
  echo "  journalctl -u apparmor | grep DENIED" # (THIS IS IMPORTANT STEP, MAKE SURE TO PERFORM IT)
  echo "  sudo aa-logprof"
  echo "NEXT STEPS (after eGPU setup + normal use):"
  echo "  1. Use system normally for 1–2 days"
  echo "  2. Check denials:"
  echo "       journalctl -u apparmor | grep -i DENIED"
  echo "       ausearch -m avc -ts recent | tail -20"
  echo "  3. Tune interactively:"
  echo "       sudo aa-logprof"
  echo "       sudo aa-genprof <binary>  # e.g., Astal, supergfxctl"
  echo "  4. After tuning → ENFORCE:"
  echo "       sudo just fsp-enforce"
  echo " Note: Full AppArmor.d policy will be enforced in Step 18j via 'just enforce
  echo "       sudo systemctl restart apparmor"
  ```
- Check for TME support (If your CPU support it and is active in the BIOS this is a check)
  ```bash
  dmesg | grep -i "Memory Encryption"
  # If you see "TME: enabled", your RAM is encrypted against physical extraction.
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

- Install Snapper and snap-pac
  ```bash
  pacman -S --noconfirm snapper snap-pac btrfs-assistant
  ```
- Create global filter
  ```bash
  mkdir -p /etc/snapper/filters
  echo -e "/home/.cache\n/tmp\n/run\n/.snapshots\n.nobackup" | sudo tee /etc/snapper/filters/global-filter.txt
  ```
- Create Snapper configurations for root, home and data:
  ```bash
  if mountpoint -q /.snapshots; then
    sudo umount /.snapshots
    sudo rmdir /.snapshots
  fi
  sudo snapper -c root create-config /
  sudo snapper -c home create-config /home
  sudo snapper -c data create-config /data
  sudo btrfs subvolume delete /.snapshots
  sudo mkdir /.snapshots
  sudo mount -a  # Remounts from /etc/fstab
  sudo chmod 750 /.snapshots
  sudo chown :wheel /.snapshots
  sudo chown :wheel /home/.snapshots /data/.snapshots
  sudo chmod 750 /home/.snapshots /data/.snapshots
  ```
- Configure Snapper for automatic snapshots:
  ```bash
  for CONF in root home data; do
    sudo snapper -c $CONF set-config \
        ALLOW_GROUPS="wheel" \
        SYNC_ACL="yes" \
        TIMELINE_CREATE="yes" \
        TIMELINE_CLEANUP="yes" \
        TIMELINE_MIN_AGE="1800" \
        TIMELINE_LIMIT_HOURLY="0" \
        TIMELINE_LIMIT_DAILY="7" \
        TIMELINE_LIMIT_WEEKLY="4" \
        TIMELINE_LIMIT_MONTHLY="6" \
        TIMELINE_LIMIT_YEARLY="0" \
        NUMBER_CLEANUP="yes" \
        NUMBER_LIMIT="20" \
        NUMBER_LIMIT_IMPORTANT="10"
  done
  ```
- Config permissions:
  ```bash
  sudo chmod 640 /etc/snapper/configs/*
  ```
  - Create the backup directory on the Btrfs root
  ```bash
  sudo mkdir -p /etc/reproducible-boot
  ```
  - Create a Pacman hook to sync the ESP to the root before/after transactions
  ```bash
  sudo tee /etc/pacman.d/hooks/95-bootbackup.hook <<'EOF'
  [Trigger]
  Type = Path
  Operation = Install
  Operation = Upgrade
  Operation = Remove
  Target = boot/*

  [Action]
  Description = Backing up /boot to /etc/reproducible-boot (for Snapper)...
  When = PostTransaction
  Exec = /usr/bin/rsync -a --delete /boot/ /etc/reproducible-boot/
  EOF

  sudo chmod 644 /etc/pacman.d/hooks/95-bootbackup.hook
  ```
  - Enable Snapper timeline and cleanup:
  ```bash
  sudo systemctl enable --now snapper-timeline.timer
  sudo systemctl enable --now snapper-cleanup.timer
  ```
  - Verify configuration:
  ```bash 
  snapper list-configs
  snapper -c root get-config
  snapper -c home get-config
  snapper -c data get-config
  ```
  - Test snapshot creation:
  ```bash
  snapper -c root create --description "Initial test snapshot"
  snapper -c home create --description "Initial test snapshot"
  snapper -c data create --description "Initial test snapshot"
  snapper -c root list  # Check all configs similarly
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
  sudo pacman -S --noconfirm chezmoi
  ```
- Initialize your repo (replace with your actual repo)
  ```bash
  # Note: init --apply will attempt to apply the repo immediately.
  # If you HAVE a repo:
  # chezmoi init --apply [https://github.com/yourusername/dotfiles.git](https://github.com/yourusername/dotfiles.git)
  # If starting from zero:
  if [ ! -d "$HOME/.local/share/chezmoi" ]; then
      chezmoi init
  fi
  ```
- Backup existing configurations
  ```bash
  cp -r ~/.zshrc ~/.config/gnome ~/.config/wezterm ~/.config/gtk-4.0 ~/.config/gtk-3.0 ~/.local/share/backgrounds # ~/.config/gnome-backup 
  ```
- Create a folder in chezmoi to hold system templates
  ```bash
  mkdir -p "$(chezmoi source-path)/system-files/etc/sysctl.d/"
  mkdir -p "$(chezmoi source-path)/system-files/etc/snapper/configs"
  mkdir -p "$(chezmoi source-path)/dot_chezmoscripts"
  cp /etc/sysctl.d/99-hardening.conf "$(chezmoi source-path)/system-files/etc/sysctl.d/"
  cp /etc/snapper/configs/* "$(chezmoi source-path)/system-files/etc/snapper/configs/"
  ```
- Create a script in chezmoi source
  ```bash
  # Create a file named dot_chezmoscripts/run_onchange_after_apply-system-settings.sh.tmpl
  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_apply-system-settings.sh.tmpl" <<'EOF'
  #!/bin/bash
  # This script runs automatically when files in system-files/ change.
  # It uses sudo to safely deploy them.

  # Exit on error, undefined vars, or pipe failures
  set -euo pipefail

  # hardening-hash: {{ include "system-files/etc/sysctl.d/99-hardening.conf" | sha256sum }}
  # snapper-hash: {{ include "system-files/etc/snapper/configs/root" | sha256sum }}

  echo "Root permissions required to sync system configurations..."

  # a. Sync Hardening Parameters
  sudo cp {{ .chezmoi.sourceDir }}/system-files/etc/sysctl.d/99-hardening.conf /etc/sysctl.d/
  sudo sysctl --load=/etc/sysctl.d/99-hardening.conf

  # b. Sync Snapper Configs (and fix permissions)
  sudo cp {{ .chezmoi.sourceDir }}/system-files/etc/snapper/configs/* /etc/snapper/configs/
  sudo chmod 640 /etc/snapper/configs/*

  # c. Update UKI entries (if managed via chezmoi)
  # sudo rsync -a {{ .chezmoi.sourceDir }}/system-files/boot/loader/ /boot/loader/

  EOF

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_onchange_after_apply-system-settings.sh.tmpl"
  ```
- Use a chezmoi script to ensure production packages are always present
  ```bash
  # Create dot_chezmoscripts/run_once_after_install-packages.sh
  cat > "$(chezmoi source-path)/dot_chezmoscripts/run_once_after_install-packages.sh" <<'EOF'
  #!/bin/bash
  # Generate a list of currently missing packages and install them
  # This makes your dotfiles repo a "one-click" installer for your whole system.

  PACKAGES=(
    "snapper" "snap-pac" "btrfs-assistant" "rsync" "chezmoi" 
    "gnome-terminal" # Add your critical apps here
  )

  for pkg in "${PACKAGES[@]}"; do
    if ! pacman -Qi "$pkg" &> /dev/null; then
        sudo pacman -S --noconfirm "$pkg"
    fi
  done
  EOF

  chmod +x "$(chezmoi source-path)/dot_chezmoscripts/run_once_after_install-packages.sh"
  ```
- Export GNOME settings and Add user files to chezmoi
  ```bash
  dconf dump /org/gnome/ > ~/.config/gnome-settings.dconf
  dconf dump /org/gnome/shell/extensions/ > ~/.config/gnome-shell-extensions.dconf
  flatpak override --user --export > ~/.config/flatpak-overrides
  pacman -Qqe > ~/explicitly-installed-packages.txt
  pacman -Qqem > ~/aur-packages.txt
  chezmoi add ~/.zshrc ~/.config/gnome-settings.dconf
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
- Export package lists for reproducibility
  ```bash
  pacman -Qqe > ~/explicitly-installed-packages.txt
  pacman -Qqm > ~/aur-packages.txt
  flatpak list --app > ~/flatpak-packages.txt
  ```
- Backup Secure Boot and TPM data to USB (replace /dev/sdX1 with your USB partition, confirm via lsblk)
  ```bash
  lsblk
  sudo mount /dev/sdX1 /mnt/usb
  sudo cp -r /etc/sbctl /mnt/usb/sbctl-keys
  sudo cp /var/lib/tpm-pcr-initial.txt /mnt/usb/
  sudo umount /mnt/usb
  echo "WARNING: Store /mnt/usb/sbctl-keys, /mnt/usb/tpm-pcr-initial.txt, and /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden or an encrypted cloud."
  ```
- Apply configurations and set permissions
  ```bash
  chezmoi apply -v
  sudo chmod 640 /etc/snapper/configs/*
  ```
- Run doctor as user
  ```bash
  chezmoi doctor || echo "chezmoi OK"
  ```
- Verify dotfile application:
  ```bash
  chezmoi status
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
  ls -l /etc/snapper/configs/ # Verify 640 permissions
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
- Warning
  ```bash
  Crucial Security Warning: NEVER upload your LUKS headers or Secure Boot .auth/.key files to a public GitHub repo, even if "private."

   The Production approach: Use chezmoi to track the location of these backups on your USB drive, but keep the actual data on the encrypted USB you created in Step 9.
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

  # Check the PCRs you actually enrolled (7,11)
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
  echo "Use system normally (eGPU, browsers, AGS) for 1–2 hours."
  echo "Then run:"

  sudo ausearch -m avc -ts boot | audit2allow
  sudo aa-logprof

  # For Astal/AGS:
  sudo aa-genprof ags
  # → In another terminal: ags -c ~/.config/ags/config.js
  # → Exercise UI, then Ctrl+C and finish aa-genprof

  echo "Repeat for: AGS, supergfxctl, boltctl, qemu-system-x86_64"

  echo "After tuning: reboot and verify no denials in journalctl -u apparmor"
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
  sysctl kernel.unprivileged_userns_clone 2>/dev/null | grep "= 0" && echo "✓ User namespaces restricted"
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
  echo "TPM PCRs Enrolled:  7,11 (Integrity + Secure Boot)"
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
   --tpm2-pcrs=7+11 \
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
    paru -Syu --noconfirm || echo "paru failed"
    flatpak update -y || echo "flatpak failed"
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
  tpm2_pcrread sha256:7,11 > /etc/tpm-pcr-post-firmware.txt  # Backup new PCRs
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
  # Explote adding this as event refreshing daily an widget in the Astal/AGS step 19
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
- **q) Final Reboot & Lock**:
  ```bash
  # Sign only unsigned EFI binaries
  sbctl sign -s $(sbctl verify | grep "not signed" | awk '{print $1}')

  sbctl verify
  echo "System locked and ready. Final reboot recommended."
  reboot
  ```
## Step 19: User Customizations ** To be refined post production! WIP - For now ignore this part.

- Create script report for Astal/AGS
  ```bash
  # Create a system verification script
  cat << 'EOF' | sudo tee /usr/local/bin/verify-arch-setup.sh
  #!/usr/bin/env bash
  set -e

  echo "=== 1. Secure Boot & TPM ==="
  sbctl status | grep "Enabled" && echo "✓ Secure Boot Enabled" || echo "✗ Secure Boot DISABLED"
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 >/dev/null 2>&1 && echo "✓ TPM Unlock Valid" || echo "✗ TPM Unlock Failed"

  echo "=== 2. Graphics & eGPU ==="
  if lspci | grep -i "VGA.*AMD"; then
    echo "✓ AMD eGPU Detected"
    DRI_PRIME=1 glxinfo | grep "OpenGL renderer" | grep "AMD" && echo "✓ AMD Rendering Active" || echo "✗ AMD Rendering Failed"
  else
    echo "⚠ No AMD eGPU detected (Check OCuLink)"
  fi

  echo "=== 3. Security Hardening ==="
  sysctl kernel.yama.ptrace_scope | grep "1" && echo "✓ Ptrace Scope Restricted" || echo "✗ Ptrace Scope Open"
  if systemctl is-active --quiet apparmor; then
    echo "✓ AppArmor Active"
    aa-status | grep -q "profiles are in enforce mode" && echo "✓ AppArmor Enforced" || echo "⚠ AppArmor in Complain Mode"
  else
    echo "✗ AppArmor Inactive"
  fi

  echo "=== 4. Snapshots ==="
  snapper --config root list | grep -q "timeline" && echo "✓ Snapper Timeline Active" || echo "✗ Snapper Timeline Missing"

  echo "=== Verification Complete ==="
  EOF
  sudo chmod +x /usr/local/bin/verify-arch-setup.sh
  ```
- Install a custom theme for GNOME:
  ```bash
  # Review this video https://www.youtube.com/watch?v=3KhHVkL8yKM
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
            label: systemd.unit("rustic-backup.service")
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
            onClicked: () => Utils.execAsync("systemctl start rustic-backup.service"),
        }),
    ],
  });
  ```
- Namspace Audit Widget
  ```bash
  // ~/.config/ags/widgets/namespace-monitor.ts
  import { Widget, Utils } from 'astal/gtk3';

  // Command to check for processes sharing the *global* Mount or PID namespace
  // and exclude known safe system processes (PID 1, kernel threads, kthreadd etc.)
  // -n: namespace ID; -t: type; -o: output fields
  const NS_AUDIT_CMD = [
    'lsns',
    '--noheading',
    '--output', 'PID,USER,COMMAND,NSFS',
    '|', 
    'awk', 
    `{
        // $4 (NSFS) is the inode of the namespace. 
        // 4026531836 is the inode of the *global* mount namespace on most systems.
        // 4026531835 is the inode of the *global* PID namespace on most systems.
        // This script is simplified for demonstration. In a real environment, 
        // you'd typically look for specific processes/users or compare NSFS.
        
        // A simple, effective check: count entries and alert on unusual spikes.
        // For this visual indicator, we will count the number of custom PID namespaces (PID != 4026531835)
        
        if ($2 != "root" && $1 > 1) { // Exclude root/kernel PIDs for simplicity
            print $0;
        }
    }`
  ];

  export default () => Widget.Box({
    className: "namespace-monitor",
    spacing: 6,
    children: [
        Widget.Icon({ 
            icon: "preferences-system-security-symbolic" // Security icon 
        }),
        Widget.Label({
            // This label will run a simplified audit and count isolated processes
            // The actual check runs 'lsns' and pipes it to 'wc -l' to count lines.
            // A higher count of namespaces is generally good (more isolation), but 
            // the label should be about *status* rather than just count.
            label: Utils.poll(10000, NS_AUDIT_CMD.join(' '), (out) => {
                const lines = out.split('\n').filter(line => line.trim() !== '');
                const ns_count = lines.length;
                
                if (ns_count > 100) {
                    return `Isolation: ${ns_count} OK`;
                } else if (ns_count > 50) {
                    // A dynamic threshold based on your setup.
                    return `Isolation: ${ns_count} (Normal)`;
                }
                return `Isolation: ${ns_count} (Low Count)`;
            }),
        }),
        Widget.Button({
            label: "Details",
            onClicked: () => Utils.execAsync(['foot', '-e', 'bash', '-c', 'lsns -t pid,mnt | less']),
        }),
    ],
  });
  ```
- AIDE Astal/AGS Widget
  ```bash
  // ~/.config/ags/widgets/aide-monitor.ts
  const aideStatusFile = "/run/aide-status.json";

  const AideWidget = () =>
  Widget.Box({
    class_name: "aide-monitor",
    tooltip_text: "AIDE integrity status",
    children: [
      Widget.Icon({
        icon: "security-high-symbolic",
        size: 18,
      }),
      Widget.Label({
        label: Utils.watch(
          { status: "unknown", timestamp: "" },
          aideStatusFile,
          () => {
            try {
              const data = JSON.parse(Utils.readFile(aideStatusFile) || "{}");
              return data.status === "clean"
                ? "Clean"
                : data.status === "alert"
                ? "ALERT"
                : "Unknown";
            } catch {
              return "No data";
            }
          }
        ),
        class_name: Utils.watch("clean", aideStatusFile, () => {
          try {
            const data = JSON.parse(Utils.readFile(aideStatusFile) || "{}");
            return data.status === "clean"
              ? "aide-clean"
              : data.status === "alert"
              ? "aide-alert"
              : "";
          } catch {
            return "";
          }
        }),
      }),
    ],
  });

  // Then just import and add AideWidget() to your bar/panel
  # CSS Style
  .aide-clean {
  color: @success_color;
  }
  .aide-alert {
    color: @error_color;
    font-weight: bold;
    animation: blink 1s infinite alternate; 
  }
  # Click the widget to open the latest report
  AideWidget().on("button-press-event", () => {
  Utils.execAsync(`xdg-open ${Utils.readFile("/run/aide-status.json")?.match(/"report":"([^"]+)"/)?.[1] || "/var/log/aide"}`)
    .catch(() => App.toggleWindow("whatever-your-sidebar-is"));
  });
  ```
- Logwatch
  ```bash
  // ~/.config/astal/widgets/logwatch.ts
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
