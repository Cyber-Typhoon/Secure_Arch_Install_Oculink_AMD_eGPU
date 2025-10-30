# Secure Arch Installation for an Intel Lenovo ThinkBook using an AMD eGPU via OCuLink

## Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)

- This guide provides a **comprehensive action plan** for installing and configuring **Arch Linux** on a **Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H** with **Intel iGPU (Arc 140T)**, no dGPU, using **GNOME Wayland**, **BTRFS**, **LUKS2**, **TPM2**, **AppArmor**, **systemd-boot with Unified Kernel Image (UKI)**, **Secure Boot**, **run0**, **Firejail** and an **OCuP4V2 OCuLink GPU Dock ReDriver with an AMD eGPU**.
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
    # Remove auto-generated swap and tmpfs lines to avoid duplicates
    sed -i '/swapfile\|\/tmp\|\/var\/tmp/d' /mnt/etc/fstab
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
- Enable parallel downloads
  ```bash
  sed -i 's/^#ParallelDownloads/ParallelDownloads/' /etc/pacman.conf
  ```
- Install the base system and necessary packages:
  ```bash
  pacstrap /mnt \
  # Core
  base base-devel linux linux-firmware mkinitcpio archlinux-keyring \
  \
  # Boot / Encryption
  intel-ucode sbctl cryptsetup btrfs-progs efibootmgr dosfstools systemd-boot\
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
  useradd -m -G wheel,video,input,storage,audio,power,lp -s /usr/bin/zsh "$username"
  chsh -s /usr/bin/zsh "$username"
  passwd  # root
  passwd "$username"
  ```
- Enable sudo
  ```bash
  sed -i '/^# %wheel ALL=(ALL:ALL) ALL/s/^# //' /etc/sudoers
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
    if [[ " $* " == *" yay "* ]] || [[ " $* " == *" yay-bin "* ]]; then
      echo -e "\nERROR: Do not install 'yay'. This system uses 'paru' only.\n"
      return 1
    fi
    command pacman "$@"
  }
  
  # Modern CLI tool alias:
  if [[ $- == *i* ]]; then
    alias sysctl='systeroid'
    alias grep='rg'
    alias find='fd'
    alias ls='eza  --icons --git'
    alias cat='bat --paging=never'
    alias du='dua'
    alias man='tldr'
    alias ps='procs'
    alias dig='dog'
    alias curl='http --continue'  # curl-like behavior
    alias btop='btm'
    alias iftop='bandwhich'

  # Interactive: Prefer run0 (secure, no SUID, polkit)
  if [[ -t 1 ]]; then
    alias sudo='run0'
  fi

  # zoxide: use 'z' and 'zi' (no autojump alias needed)
  if command -v zoxide >/dev/null 2>&1; then
    eval "$(zoxide init zsh)"
  fi
  fi

  # Safe update alias
  alias update='paru -Syu --noconfirm'
  echo "Run 'update' weekly. Use 'paru -Syu' for full control."
  EOF

  # Set ownership
  chown $username:$username /home/$username/.zshrc
  chmod 644 /home/$username/.zshrc
  ```
- Validate run0
  ```
  $ run0 whoami
  # → polkit prompt (first time)
  root

  $ run0 id
  # → **no prompt** (cached)

  $ reboot
  # → cache cleared on next login
  ```
## Milestone 3: After Step 6 (System Configuration) - Can pause at this point

## Step 7: Set Up TPM and LUKS2

- Install TPM tools:
  ```bash
  pacman -S --noconfirm tpm2-tools tpm2-tss systemd-ukify tpm2-tss-engine
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
  tpm2_pcrread sha256:4 | grep -v "0x00\{64\}"
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
  mkdir -p /mnt/usb
  lsblk  # Identify USB device
  mkfs.fat -F32 /dev/sdX1  # Replace sdX1 with USB partition
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
  # Enter chroot
  arch-chroot /mnt

  # Create and enroll sbctl keys
  sbctl create-keys
  sbctl enroll-keys --tpm-eventlog

  # Regenerate UKI (required before signing)
  mkinitcpio -P

  # Sign all EFI binaries
  sbctl sign -s /usr/lib/systemd/boot/efi/systemd-bootx64.efi
  sbctl sign -s /boot/EFI/Linux/arch.efi
  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
  sbctl sign -s /boot/EFI/BOOT/BOOTX64.EFI
  ```
- Check Plymouth and GDM compatibility with Secure Boot:
  ```bash
  # Plymouth
  if [[ -f /usr/lib/plymouth/plymouthd ]]; then
    sbctl verify /usr/lib/plymouth/plymouthd || sbctl sign -s /usr/lib/plymouth/plymouthd
  fi

  # GDM (or other display manager)
  if [[ -f /usr/lib/gdm/gdm ]]; then
    sbctl verify /usr/lib/gdm/gdm || sbctl sign -s /usr/lib/gdm/gdm
  fi
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
  Target = linux-lts
  Target = fwupd
  Target = plymouth
  
  [Action]
  Description = Signing EFI binaries with sbctl after updates
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
  # You should see the sbctl key listed. If not, re-run sbctl enroll-keys --tpm-eventlog.
  ```
- Reboot to enroll keys and enable Secure Boot in UEFI:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```
  ## In UEFI (BIOS - F1), enable **Secure Boot** and enroll the sbctl key when prompted. You may need to reboot twice: once to enroll, once to activate.
- Update TPM PCR policy after enabling Secure Boot:
  ```bash
  # Boot back into Arch ISO
  arch-chroot /mnt
  # Wipe old TPM policy and reenroll with Secure Boot PCRs
  systemd-cryptenroll --wipe-slot=tpm2 /dev/nvme1n1p2
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 --tpm2-pcrs-bank=sha256 /dev/nvme1n1p2
  # Final TPM unlock test
  systemd-cryptenroll --tpm2-device=auto --test /dev/nvme1n1p2 && echo "TPM unlock test PASSED"
  # Should return 0 and print "Unlocking with TPM2... success".
  # Confirm Secure Boot is active
  sbctl status
  # Expected:
  ✓ Secure Boot: Enabled
  ✓ Setup Mode: Disabled
  ✓ Signed: all files
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
  mount /dev/sdX1 /mnt/usb  # Replace with your USB
  tpm2_pcrread sha256:0,4,7 > /mnt/usb/tpm-pcr-post-secureboot.txt
  diff /mnt/usb/tpm-pcr-backup.txt /mnt/usb/tpm-pcr-post-secureboot.txt || echo "PCR 7 changed (expected)"
  echo "WARNING: Store /mnt/usb/tpm-pcr-post-secureboot.txt in Bitwarden."
  echo "WARNING: Compare PCR values to ensure TPM policy consistency."
  ```
- Final reboot into encrypted system:
  ```bash
  exit
  umount -R /mnt
  reboot
  ```
## Step 9: Configure systemd-boot with UKI

- Mount ESP (EFI System Partition)
  ```bash
  mount /dev/nvme1n1p1 /boot
  ```
- Install `systemd-boot`:
  ```bash
  # Creates /boot/loader/, installs systemd-bootx64.efi.
  bootctl --esp-path=/boot install
  ```
- Configure Unified Kernel Image (UKI):
  ```bash
  cat << 'EOF' > /etc/mkinitcpio.d/linux.preset
  # UKI output path
  default_uki="/boot/EFI/Linux/arch.efi"
  # Use main mkinitcpio config
  all_config="/etc/mkinitcpio.conf"
  # Kernel command line (expand variables at runtime)  
  default_options="rd.luks.uuid=$LUKS_UUID \
    root=UUID=$ROOT_UUID \
    resume_offset=$SWAP_OFFSET \
    rw quiet splash \
    intel_iommu=on amd_iommu=on iommu=pt \
    pci=pcie_bus_perf,realloc \
    mitigations=auto,nosmt \
    slab_nomerge slub_debug=FZ \
    init_on_alloc=1 init_on_free=1 \
    rd.emergency=poweroff \
    tpm2-measure=yes \
    amdgpu.dc=1 amdgpu.dpm=1"
  EOF
  # Update mkinitcpio.conf HOOKS (critical order)
  sed -i 's/HOOKS=(.*/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt btrfs resume filesystems keyboard)/' /etc/mkinitcpio.conf
  # Generate UKI
  mkinitcpio -P
  ```
- Verify configuration:
  ```bash
  # Check HOOKS order
  grep HOOKS /etc/mkinitcpio.conf

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
  ```
- Create a fallback UKI:
  ```bash
  # Minimal config (same hooks, different output)
  cp /etc/mkinitcpio.conf /etc/mkinitcpio-fallback.conf
  sed -i 's/HOOKS=(.*/HOOKS=(base systemd autodetect modconf block plymouth sd-encrypt btrfs resume filesystems keyboard)/' /etc/mkinitcpio-fallback.conf
  echo 'UKI_OUTPUT_PATH="/boot/EFI/Linux/arch-fallback.efi"' >> /etc/mkinitcpio-fallback.conf
  # Generate fallback UKI
  mkinitcpio -P -c /etc/mkinitcpio-fallback.conf
  # Sign it
  sbctl sign -s /boot/EFI/Linux/arch-fallback.efi
  # Fallback entry
  cat << 'EOF' > /boot/loader/entries/arch-fallback.conf
  title Arch Linux (Fallback)
  efi /EFI/Linux/arch-fallback.efi
  EOF
  
  # Verify resume_offset is numeric (not $SWAP_OFFSET)
  grep resume_offset /etc/fstab
  grep resume_offset /boot/loader/entries/arch.conf
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
    linux /vmlinuz-linux cryptdevice=UUID=$LUKS_UUID:cryptroot root=UUID=$ROOT_UUID resume_offset=$SWAP_OFFSET rw
    initrd /initramfs-linux.img
  }
  EOF

  # Sign GRUB bootloader
  sbctl sign -s /mnt/usb/EFI/BOOT/BOOTX64.EFI
  shred -u /crypto_keyfile
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
  Target = linux-lts

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
  # Ensure SUDO_USER is defined. This step uses $SUDO_USER extensively (e.g., in Paru configuration, Firejail profiles for Astal/AGS, and aliases).
  SUDO_USER=${SUDO_USER:-$(logname || getent passwd 1000 | cut -d: -f1)}
  id "$SUDO_USER" >/dev/null 2>&1 || { echo "Error: User $SUDO_USER does not exist"; exit 1; }
  # Install Gnome
  pacman -Sy --needed gnome
  ```
- Install **Paru and configure it**:
  ```bash   
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
- Install the AUR applications:
  ```bash
  # AUR applications:
  sudo -u $SUDO_USER paru -S --needed \
    apparmor.d-git \
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
  
  # Append Astal/AGS to existing 91-sbctl-sign.hook
  if ! grep -q "Target = astal-git" /etc/pacman.d/hooks/91-sbctl-sign.hook; then
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
  fi
  
  # Test the hook after installation:
  sbctl verify /usr/bin/astal  #Should show "signed"
  ```
- Install Pacman applications:
  ```bash
  # System packages (CLI + system-level)
  pacman -S --needed \
  # Security & Hardening
  aide apparmor auditd chkrootkit lynis rkhunter sshguard ufw usbguard firejail\
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
  helix httpie hyfetch jaq procs python-pygobject rage ripgrep rustup starship tealdeer \
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
  bandwhich pacman-contrib pacman-notifier \
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
- Enable AppArmor integration for Firejail
  ```bash
  # Check if Apparmor service is active:
  systemctl is-active apparmor || { echo "Error: AppArmor service not active"; exit 1; }
  # Activate the integration if Apparmor is active
  sed -i 's/# apparmor/apparmor/' /etc/firejail/firejail.config
  ```
- Verify AppArmor is enabled
  ```bash
  grep apparmor /etc/firejail/firejail.config | grep -v '^#' || echo "Warning: Firejail AppArmor not enabled"
  ```
- Sign Firejail binary for Secure Boot
  ```bash
  sbctl verify /usr/bin/firejail || { echo "Signing Firejail binary"; sbctl sign -s /usr/bin/firejail; }
  ```
- Append Firejail to existing 91-sbctl-sign.hook
  ```bash
  if ! grep -q "Target = firejail" /etc/pacman.d/hooks/91-sbctl-sign.hook; then
  cat << 'EOF' >> /etc/pacman.d/hooks/91-sbctl-sign.hook
  [Trigger]
  Operation = Install
  Operation = Upgrade
  Type = Package
  Target = firejail

  [Action]
  Description = Signing Firejail binary with sbctl
  When = PostTransaction
  Exec = /usr/bin/sbctl sign -s /usr/bin/firejail
  EOF
  ```
- Create .local Overrides for High-Risk Apps
  ```bash
  # DO NOT edit default profiles. Use .local to *add* GPU/Wayland access.
  # --- Browsers ---
  for app in brave-browser mullvad-browser tor-browser; do
  sudo tee /etc/firejail/$app.local > /dev/null << 'EOF'
  # Local override: Add eGPU + Wayland + Audio
  protocol wayland
  whitelist /dev/dri
  whitelist /dev/snd
  whitelist ${HOME}/.config/pulse
  whitelist ${HOME}/.config/pipewire
  EOF
  done

  # --- OBS Studio ---
  sudo tee /etc/firejail/obs-studio.local > /dev/null << 'EOF'
  # Local override: eGPU + Wayland + Audio + Capture
  protocol wayland
  whitelist /dev/dri
  whitelist /dev/snd
  whitelist /dev/video*
  whitelist ${HOME}/.config/obs-studio
  whitelist ${HOME}/Videos
  include /etc/firejail/disable-common.inc
  EOF
  ```
- Add Aliases to ~/.zshrc
  ```bash
  cat >> /home/$SUDO_USER/.zshrc << 'EOF'
  # HIGH-RISK: Always sandboxed with AppArmor:
  alias brave="firejail --apparmor --private-tmp brave-browser"
  alias mullvad="firejail --apparmor --private-tmp mullvad-browser"
  alias tor="firejail --apparmor --private-tmp tor-browser"
  alias obs="firejail --apparmor --private-tmp obs-studio"
  EOF
  ```
- Explicitly set permissions for custom Firejail profiles
  ```bash
  chmod 644 /etc/firejail/*.profile
  chown root:root /etc/firejail/*.profile
  ls -l /etc/firejail/*.profile | grep -q "rw-r--r--.*root:root" || echo "Warning: Firejail profile permissions incorrect"
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
  Search/install: GIMP (org.gimp.GIMP), Inkscape (org.inkscape.Inkscape), Krita (org.kde.krita), Blender (org.blender.Blender), GDM Settings (io.github.realmazharhussain.GdmSettings), Lollypop (org.gnome.Lollypop)
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

  cat > ~/.zshrc <<'EOF'
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
  cat > ~/.profile <<'EOF'
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
- Enable FSP in COMPLAIN mode
  ```bash
  # This activates the *complete* AppArmor.d policy (1000+ profiles)
  # DO NOT use aa-complain on /etc/apparmor.d/* — that's legacy.
  
  # Enable service
  sudo systemctl enable --now apparmor
  
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

  # Log denials to a file for review
  journalctl -u apparmor | grep -i DENIED > /var/log/apparmor-denials.log

  # Example: Allow Brave to access /dev/dri/ if denied
  echo "  /dev/dri/* rw," >> /etc/apparmor.d/firejail-brave-browser
  aa-enforce /etc/apparmor.d/firejail-brave-browser
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
  fwupdmgr update - echo "fwupd upgrade moved to Step 18 for BIOS/firmware updates."
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
  # Ensure SUDO_USER is defined
  SUDO_USER=${SUDO_USER:-$(logname || getent passwd 1000 | cut -d: -f1)}
  id "$SUDO_USER" >/dev/null 2>&1 || { echo "Error: User $SUDO_USER does not exist"; exit 1; }
  # Install chezmoi
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
- Backup existing configurations
  ```bash
  cp -r ~/.zshrc ~/.config/gnome ~/.config/alacritty ~/.config/gtk-4.0 ~/.config/gtk-3.0 ~/.local/share/backgrounds ~/.config/gnome-backup
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
  ```
- Add system-wide configurations
  ```bash
  sudo chezmoi add /etc/pacman.conf /etc/paru.conf /etc/pacman.d/hooks
  sudo chezmoi add /etc/audit/rules.d/audit.rules /etc/security/limits.conf /etc/sysctl.d/99-hardening.conf
  sudo chezmoi add /etc/NetworkManager/conf.d/00-macrandomize.conf /etc/dnscrypt-proxy/dnscrypt-proxy.toml /etc/usbguard/rules.conf
  sudo chezmoi add /etc/snapper/configs /etc/snapper/filters/global-filter.txt
  sudo chezmoi add /etc/modprobe.d/i915.conf /etc/modprobe.d/amdgpu.conf /etc/supergfxd.conf
  sudo chezmoi add /etc/udev/rules.d/99-oculink.rules /etc/modules-load.d/pciehp.conf /etc/modules-load.d/vfio.conf
  sudo chezmoi add /etc/mkinitcpio.conf /etc/mkinitcpio.d/linux.preset
  sudo chezmoi add /boot/loader/entries/arch.conf /boot/loader/entries/arch-fallback.conf /boot/loader/entries/windows.conf
  sudo chezmoi add /etc/fstab /etc/environment /etc/gdm/custom.conf /etc/systemd/zram-generator.conf /etc/systemd/logind.conf /etc/host.conf
  sudo chezmoi add /etc/systemd/system/lynis-audit.timer /etc/systemd/system/lynis-audit.service
  sudo chezmoi add /etc/systemd/system/btrfs-balance.timer /etc/systemd/system/btrfs-balance.service
  sudo chezmoi add /etc/systemd/system/arch-news.timer /etc/systemd/system/arch-news.service
  sudo chezmoi add /etc/systemd/system/paccache.timer /etc/systemd/system/paccache.service
  sudo chezmoi add /etc/systemd/system/maintain.timer /etc/systemd/system/maintain.service
  sudo chezmoi add /etc/systemd/system/astal-widgets.service
  sudo chezmoi add /etc/pacman.d/hooks/91-sbctl-sign.hook
  sudo chezmoi add /usr/local/bin/maintain.sh /usr/local/bin/toggle-theme.sh /usr/local/bin/check-arch-news.sh
  sudo chezmoi add /etc/mkinitcpio.d/linux.preset
  sudo chezmoi add /etc/mkinitcpio-arch-fallback.efi.conf
  sudo chezmoi add /etc/pacman.d/hooks/90-mkinitcpio-uki.hook
  sudo chezmoi add /boot/loader/entries/
  ```
- Add Firejail configuration files
  ```bash
  for profile in firejail.config brave-browser.profile mullvad-browser.profile tor-browser.profile obs-studio.profile; do
    [ -f /etc/firejail/$profile ] || { echo "Error: /etc/firejail/$profile not found"; exit 1; }
    sudo chezmoi add /etc/firejail/$profile
  done
  sudo chezmoi add /etc/firejail/firejail.config
  sudo chezmoi add /etc/firejail/brave-browser.profile
  sudo chezmoi add /etc/firejail/mullvad-browser.profile
  sudo chezmoi add /etc/firejail/tor-browser.profile
  sudo chezmoi add /etc/firejail/obs-studio.profile
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
  sudo cp /mnt/usb/tpm-pcr-initial.txt /mnt/usb/tpm-pcr-post-secureboot.txt /mnt/usb/
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
  sudo chezmoi chown root:root /etc/firejail/*
  sudo chezmoi chmod 644 /etc/firejail/*
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
  ls /etc/firejail/{brave-browser,mullvad-browser,tor-browser,obs-studio}.profile || echo "Error: Firejail profiles not restored by chezmoi"
  # Test to ensure Firejail profiles are functional post-restore
  echo "Testing Firejail profiles after chezmoi restore"
  for profile in brave-browser mullvad-browser tor-browser obs-studio; do
    [ -f /etc/firejail/$profile.profile ] && firejail --noprofile --profile=/etc/firejail/$profile.profile --dry-run || echo "Error: Firejail profile $profile.profile not functional"
    firejail --apparmor $app --version || echo "Warning: Restored $app profile test failed"
  done
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
  sbctl verify /boot/loader/loader.efi || { echo "Signing bootloader"; sbctl sign -s /boot/loader/loader.efi; }
  echo "Rebooting to test systemd-boot. Press F1 to access the boot menu and confirm Arch and Windows entries."
  reboot
  ```
- Verify TPM unlocking:
  ```bash
  # Boot and confirm the LUKS partition unlocks automatically via TPM.
  echo "After reboot, checking TPM unlock logs"
  journalctl -b | grep -i "systemd-cryptsetup.*tpm2" || echo "Warning: TPM unlock not confirmed"
  tpm2_pcrread sha256:0,1,7 > /tmp/tpm-pcr-current.txt
  diff /tmp/tpm-pcr-current.txt /root/tpm-pcr-post-secureboot.txt || echo "Warning: TPM PCR values differ"
  ```  
- Check Secure Boot status:
  ```bash
  sbctl verify /boot/EFI/Linux/arch.efi
  sbctl status
  mokutil --sb-state
  ```
- Verify eGPU detection:
  ```bash
  lspci | grep -i amd
  dmesg | grep -i amdgpu
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
  btrfs inspect-internal map-swapfile /mnt/swap/swapfile
  filefrag -v /mnt/swap/swapfile | grep "extents found: 1" || echo "Warning: Swapfile is fragmented" # Ensure no fragmentation
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
    mount | grep -E "subvol=/@$config" || echo "Warning: Subvolume @$config not mounted"
    snapper --config "$config" create --description "Test snapshot"
    snapper --config "$config" list
  done
  ```
- Test Timers
  ```bash
  systemctl list-timers --all | grep -E "paru-update|snapper-timeline|fstrim|lynis-audit"
  journalctl -u paru-update.timer
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
  paru -S --builddir ~/.cache/paru_build --noconfirm hello-world-bin
  sbctl verify ~/.cache/paru_build/*/hello-world-bin || { echo "Signing AUR binary"; sbctl sign -s ~/.cache/paru_build/*/hello-world-bin; }
  ```
- Test Firejail sandboxing
  ```bash
  echo "Verifying Firejail sandboxing"
  firejail --apparmor brave-browser --version || echo "Warning: Brave browser sandbox test failed"
  firejail --apparmor mullvad-browser --version || echo "Warning: Mullvad browser sandbox test failed"
  firejail --apparmor tor-browser --version || echo "Warning: Tor browser sandbox test failed"
  firejail --apparmor obs-studio --version || echo "Warning: OBS Studio sandbox test failed"
  firejail --list || echo "No Firejail sandboxes running"
  journalctl -u apparmor | grep -i "firejail\|brave\|mullvad\|tor-browser\|obs" || echo "No AppArmor denials for Firejail"
  firejail --list || echo "No Firejail sandboxes running (expected if tests passed)"
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
  echo "Store UEFI password, LUKS passphrase, /mnt/usb/luks-keyfile location, and MOK password in Bitwarden."
  read -p "Confirm that UEFI password, LUKS passphrase, /mnt/usb/luks-keyfile location, and MOK password are stored in Bitwarden (y/n): " confirm
  [ "$confirm" = "y" ] || { echo "Error: Please store credentials in Bitwarden before proceeding."; exit 1; }
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
   - Enter the LUKS passphrase or use the keyfile: /mnt/usb/luks-keyfile

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
   - Re-enroll TPM:
     systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/nvme1n1p2

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

  g. **Firejail Troubleshooting**:
   - Check AppArmor logs for denials:
   journalctl -u apparmor | grep -i firejail
   - Debug Firejail profile:
   firejail --debug <application> (e.g., `firejail --debug brave-browser`)
   - Rebuild profile:
   Edit `/etc/firejail/<application>.profile` (e.g., add `whitelist /dev/dri/` for eGPU)
   - Re-sign Firejail binary:
   sbctl sign -s /usr/bin/firejail
  EOF
  ```
  - Verify and unmount USB
  ```bash
  [ -f /mnt/usb/recovery.md ] || { echo "Error: Failed to create /mnt/usb/recovery.md"; exit 1; }
  [ -d /mnt/usb/sbctl-keys ] || { echo "Error: /mnt/usb/sbctl-keys not found"; exit 1; }
  sha256sum /mnt/usb/recovery.md > /mnt/usb/recovery.md.sha256
  cat /mnt/usb/recovery.md
  firejail --noprofile --profile=/etc/firejail/<application>.profile --dry-run || echo "Error: Invalid profile syntax for <application>"
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
  ```
  - Verify Bitwarden storage (manual)
  ```bash
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
  if ! grep -q "Target = restic" /etc/pacman.d/hooks/91-sbctl-sign.hook 2>/dev/null; then
    sudo tee -a /etc/pacman.d/hooks/91-sbctl-sign.hook >/dev/null <<'EOF'

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
  sudo sed -i "s|^REPO=.*|REPO=\"$REPO\"|" /usr/local/bin/restic-backup.s
  
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
- **f) Verify Firejail profiles**:
  ```bash
  echo "Checking Firejail profiles..."
  for app in brave-browser mullvad-browser tor-browser obs-studio; do
    [ -f "/etc/firejail/$app.profile" ] && echo "✓ $app.profile" || echo "✗ $app.profile missing"
  done

  for browser in brave-browser mullvad-browser tor-browser; do
    firejail --apparmor "$browser" --version >/dev/null 2>&1 && echo "✓ $browser sandbox OK" || echo "✗ $browser sandbox failed"
  done

  journalctl -u apparmor | grep -i "firejail\|brave\|mullvad\|tor" || echo "No AppArmor denials"
  firejail --version
  ```
- **g) Firmware Updates**:
  ```bash
  fwupdmgr refresh --force
  fwupdmgr get-updates
  fwupdmgr update
  ```
- **h) Security Audit**:
  ```bash
  lynis audit system > /root/lynis-report-$(date +%F).txt
  rkhunter --check --sk > /root/rkhunter-report-$(date +%F).log
  aide --check | grep -v "unchanged" > /root/aide-report-$(date +%F).txt
  ```
- **i) Adopt AppArmor.d for Full-System Policy and Automation**:
  ```bash
  # Enable early policy caching (required for boot-time FSP)
  sudo mkdir -p /etc/apparmor.d/cache
  sudo sed -i '/^#.*cache-loc/s/^#//' /etc/apparmor/parser.conf
  sudo sed -i 's|.*cache-loc.*|cache-loc = /etc/apparmor.d/cache|' /etc/apparmor/parser.conf

  # Enable the upstream-sync timer (weekly profile updates)
  sudo systemctl enable --now apparmor.d-update.timer

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

  # Verify Firejail integration (unchanged from Step 10)
  firejail --apparmor --list
  journalctl -u apparmor | grep -i firejail || echo "No Firejail denials"

  # Reboot to apply cache & early load
  echo "Rebooting in 10 seconds to apply AppArmor.d cache..."
  sleep 10
  reboot
  ```
- **j) Create sandboxed (FireJail) desktop launchers (menu only)**:
  ```bash
  for app in brave-browser mullvad-browser tor-browser obs-studio alacritty; do
  desktop-file-install --dir="$HOME/.local/share/applications" \
    --set-key=Name --set-value="$app (Sandboxed)" \
    --set-key=Exec --set-value="firejail --apparmor $app %U" \
    --set-key=Icon --set-value="$app" \
    --set-key=NoDisplay --set-value="false" \
    /usr/share/applications/$app.desktop
  done

  # Update menu
  update-desktop-database ~/.local/share/applications
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
  SUDO_USER=${SUDO_USER:-$(logname || getent passwd 1000 | cut -d: -f1)}
  id "$SUDO_USER" >/dev/null 2>&1 || { echo "Error: User $SUDO_USER does not exist"; exit 1; }
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
      Widget.Button({
        label: "Open",
        onClicked: () => Utils.execAsync("firejail --apparmor gnome-logs"),
      }),
    ],
  });
  ```
