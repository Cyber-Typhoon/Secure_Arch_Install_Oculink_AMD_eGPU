# Secure_Arch_AMD_Install_Oculink_eGPU
Installation Steps for a new Lenovo Thinkbook TGX (Oculink) Security Enhanhed Arch Gnome Wayland AMD only

# Arch Linux Setup Action Plan for Lenovo ThinkBook 14+ 2025 (AMD eGPU Focus)
This action plan outlines the steps to install and configure Arch Linux on a Lenovo ThinkBook 14+ 2025 Intel Core Ultra 7 255H without dGPU, **using GNOME Wayland, BTRFS, LUKS2, TPM2, AppArmor, systemd-boot with UKI, Secure Boot, and an OCuP4V2 OCuLink GPU Dock ReDriver with an AMD GPU**. This laptop has two M.2, we will have Windows in a slot to help updating BIOS and Firmware at least in the beginning.

Observation: Not adopting linux-hardened kernel because of complexity in the setup.

**Attention:** Before executing commands, especially those involving** dd, mkfs, cryptsetup, parted, and efibootmgr, re-read them multiple times to ensure you understand their effect** and that the target device/partition is correct. Ensure LUKS and TPM unlocking work perfectly before touching Secure Boot, and ensure Secure Boot works before diving into the eGPU.

