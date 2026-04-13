using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Orchestrates input-device lockout detection and emergency recovery.
    ///
    /// Workflow:
    ///  1. <see cref="DetectAndShowRecoveryIfNeeded"/> is called early in Program.cs (before the
    ///     main monitoring loop).  It uses <see cref="InputDeviceMonitor"/> to detect whether any
    ///     keyboard or mouse is currently blocked by policy.
    ///  2. If blocked devices are found it logs a critical event and shows
    ///     <see cref="EmergencyRecoveryForm"/> — a large, mouse-clickable UI that works even when
    ///     the keyboard is unavailable.
    ///  3. The form exposes four recovery tiers (Restore Backup / Remove DenyUnspecified /
    ///     Safe Mode Guide / Nuclear Wipe) and delegates the actual registry changes back to this
    ///     class so that dry-run mode and logging remain centralised.
    /// </summary>
    public class EmergencyRecoveryManager
    {
        private const string PolicyRestrictionsKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        private const string AllowDeviceIDsSubKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs";

        private readonly SecurityEventLogger _logger;
        private readonly AllowedDevicesBackupManager _backupManager;
        private readonly InputDeviceMonitor _monitor;
        private readonly bool _dryRun;

        public EmergencyRecoveryManager(
            SecurityEventLogger logger,
            AllowedDevicesBackupManager? backupManager = null,
            bool dryRun = false)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _backupManager = backupManager ?? new AllowedDevicesBackupManager();
            _monitor = new InputDeviceMonitor();
            _dryRun = dryRun;
        }

        // ---- Public entry point ----

        /// <summary>
        /// Checks for input-device lockout and, if detected, shows the emergency recovery UI.
        /// Should be called during application startup before the main monitoring loop.
        /// </summary>
        public void DetectAndShowRecoveryIfNeeded()
        {
            try
            {
                var blocked = _monitor.DetectBlockedInputDevices();
                if (blocked.Count == 0) return;

                // Log the lockout
                var deviceList = string.Join(", ", blocked.ConvertAll(d => d.Description));
                _logger.LogCritical(0, "LockoutDetected",
                    $"Input device lockout detected — emergency recovery initiated. " +
                    $"Blocked devices: {deviceList}");

                Debug.WriteLine($"[EmergencyRecoveryManager] Lockout detected. Blocked: {deviceList}");

                // Show recovery UI on the UI thread
                var mainForm = Application.OpenForms.Count > 0 ? Application.OpenForms[0] : null;
                if (mainForm != null && mainForm.IsHandleCreated)
                    mainForm.Invoke((Action)(() => ShowRecoveryUI(blocked)));
                else
                    ShowRecoveryUI(blocked);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[EmergencyRecoveryManager] DetectAndShowRecoveryIfNeeded failed: {ex.Message}");
            }
        }

        /// <summary>Shows the emergency recovery form.</summary>
        public void ShowRecoveryUI(List<InputDeviceMonitor.BlockedInputDevice>? blockedDevices = null)
        {
            using var form = new EmergencyRecoveryForm(this, blockedDevices ?? new List<InputDeviceMonitor.BlockedInputDevice>());
            form.ShowDialog();
        }

        // ---- Recovery actions (called by EmergencyRecoveryForm) ----

        /// <summary>
        /// Tier 1: Restore AllowDeviceIDs from the last-known-good backup.
        /// Returns a human-readable result message.
        /// </summary>
        public string RestoreFromBackup()
        {
            _logger.LogInfo(0, "RecoveryTier1", "User initiated Tier 1 recovery: restore from backup.");
            string result = _backupManager.RestoreBackup(_dryRun);
            _logger.LogInfo(0, "RecoveryTier1Result", result);
            return result;
        }

        /// <summary>
        /// Tier 2: Remove DenyUnspecified=1 only, keeping AllowDeviceIDs intact.
        /// Returns a human-readable result message.
        /// </summary>
        public string RemoveDenyUnspecified()
        {
            _logger.LogInfo(0, "RecoveryTier2", "User initiated Tier 2 recovery: remove DenyUnspecified.");

            if (_dryRun)
            {
                string dryMsg = "[DRY RUN] Would delete HKLM\\" + PolicyRestrictionsKey + "\\DenyUnspecified.";
                _logger.LogInfo(0, "RecoveryTier2Result", dryMsg);
                return dryMsg;
            }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PolicyRestrictionsKey, writable: true);
                if (key == null)
                    return "Policy restrictions key not found — DenyUnspecified may already be removed.";

                key.DeleteValue("DenyUnspecified", throwOnMissingValue: false);
                string msg = "DenyUnspecified removed. New devices will install automatically. " +
                             "Please reconnect your keyboard/mouse.";
                _logger.LogInfo(0, "RecoveryTier2Result", msg);
                return msg;
            }
            catch (Exception ex)
            {
                string err = $"Failed to remove DenyUnspecified: {ex.Message}";
                _logger.LogWarning(0, "RecoveryTier2Error", err);
                return err;
            }
        }

        /// <summary>
        /// Tier 4: Remove both DenyUnspecified and AllowDeviceIDs (nuclear option).
        /// Returns a human-readable result message.
        /// </summary>
        public string NuclearWipe()
        {
            _logger.LogCritical(0, "RecoveryTier4", "User initiated Tier 4 nuclear recovery: wipe all device policies.");

            if (_dryRun)
            {
                string dryMsg = "[DRY RUN] Would wipe DenyUnspecified and delete AllowDeviceIDs subkey.";
                _logger.LogInfo(0, "RecoveryTier4Result", dryMsg);
                return dryMsg;
            }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PolicyRestrictionsKey, writable: true);
                if (key == null)
                    return "Policy restrictions key not found — policies may already be removed.";

                key.DeleteValue("DenyUnspecified", throwOnMissingValue: false);

                // Delete the AllowDeviceIDs subkey entirely
                try { key.DeleteSubKeyTree("AllowDeviceIDs", throwOnMissingSubKey: false); }
                catch (Exception) { /* best-effort */ }

                string msg = "All device installation policies wiped. Please reconnect your keyboard/mouse " +
                             "and reboot to restore full functionality.";
                _logger.LogCritical(0, "RecoveryTier4Result", msg);
                return msg;
            }
            catch (Exception ex)
            {
                string err = $"Nuclear wipe failed: {ex.Message}";
                _logger.LogWarning(0, "RecoveryTier4Error", err);
                return err;
            }
        }

        /// <summary>
        /// Returns true if a backup file exists and appears loadable.
        /// </summary>
        public bool BackupAvailable() => _backupManager.BackupExists();

        /// <summary>
        /// Exposes the backup manager so the form can display backup metadata.
        /// </summary>
        public AllowedDevicesBackupManager BackupManager => _backupManager;
    }
}
