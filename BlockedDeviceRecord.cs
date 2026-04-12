using System;
using System.Collections.Generic;

namespace USBGuardian
{
    /// <summary>
    /// Records a single device-blocking event.
    /// Stores every identifier needed to recognise the device and every value
    /// needed to reverse the block operations that USB Guardian applied.
    ///
    /// Safety design principle: nothing is unblocked unless the original
    /// (pre-block) values were explicitly captured at block time.
    /// Default-hardcoded rollback values are intentionally avoided.
    /// </summary>
    public class BlockedDeviceRecord
    {
        /// <summary>Unique ID for this record (GUID, no hyphens).</summary>
        public string RecordId { get; set; } = Guid.NewGuid().ToString("N");

        // --- Device identity ---

        public string Vid { get; set; } = string.Empty;
        public string Pid { get; set; } = string.Empty;
        public string InstanceId { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;

        // --- Block event metadata ---

        /// <summary>UTC time at which the device was blocked.</summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>Human-readable reason for the block (threat layer, rule, or user action).</summary>
        public string BlockReason { get; set; } = string.Empty;

        // --- Rollback data ---

        /// <summary>
        /// Ordered list of actions that were taken to block this device, together
        /// with the original values required to reverse each action.
        /// </summary>
        public List<BlockActionRecord> Actions { get; set; } = new();
    }

    /// <summary>
    /// Describes one atomic block action and the state needed to reverse it.
    /// Supported ActionType values:
    ///   "ConfigFlags"   – a registry ConfigFlags DWORD was modified
    ///   "ServiceStart"  – a service Start DWORD was set to 4 (disabled)
    ///   "WmiDisable"    – the device was disabled via WMI Win32_PnPEntity.Disable()
    /// </summary>
    public class BlockActionRecord
    {
        /// <summary>Action type token; one of "ConfigFlags", "ServiceStart", "WmiDisable".</summary>
        public string ActionType { get; set; } = string.Empty;

        /// <summary>
        /// Registry key path relative to HKLM that was modified (for ConfigFlags and
        /// ServiceStart actions). Example:
        ///   SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\ABCDEF01
        /// </summary>
        public string RegistryPath { get; set; } = string.Empty;

        /// <summary>
        /// The full ConfigFlags DWORD value that was present in the registry
        /// BEFORE USB Guardian set the disabled bit (0x100) or reinstall bit (0x40).
        /// Null if not recorded (unblock will clear only the Guardian bits in that case).
        /// </summary>
        public int? PreviousConfigFlags { get; set; }

        /// <summary>
        /// The service Start DWORD value BEFORE USB Guardian set it to 4 (disabled).
        /// Null means the value was not recorded; unblocking will skip this action.
        /// </summary>
        public int? PreviousServiceStart { get; set; }

        /// <summary>
        /// Name of the service that was modified, e.g. "usbstor" or "kbdhid".
        /// Used for ServiceStart rollback.
        /// </summary>
        public string ServiceName { get; set; } = string.Empty;
    }
}
