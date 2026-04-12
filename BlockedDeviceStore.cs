using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;

namespace USBGuardian
{
    /// <summary>
    /// Persists and retrieves <see cref="BlockedDeviceRecord"/> objects as JSON.
    ///
    /// Safety design:
    /// - All file writes are atomic (write to *.tmp then replace) to avoid
    ///   corruption on crash.
    /// - A corrupt or missing file starts with an empty list (no data loss
    ///   for other records).
    /// - Thread-safe via an internal lock.
    ///
    /// Default file location: &lt;Application.StartupPath&gt;\blocked_devices.json
    /// </summary>
    public class BlockedDeviceStore
    {
        private readonly string _filePath;
        private readonly object _lock = new();
        private List<BlockedDeviceRecord> _cache;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public BlockedDeviceStore(string? filePath = null)
        {
            _filePath = filePath ?? Path.Combine(Application.StartupPath, "blocked_devices.json");
            _cache = LoadFromDisk();
        }

        // ---- Public API ----

        /// <summary>
        /// Add a new record or replace the existing one for the same
        /// (Vid, Pid, InstanceId) tuple. Persists immediately.
        /// </summary>
        public void AddOrUpdate(BlockedDeviceRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));

            lock (_lock)
            {
                _cache.RemoveAll(r =>
                    string.Equals(r.Vid, record.Vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.Pid, record.Pid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.InstanceId, record.InstanceId, StringComparison.OrdinalIgnoreCase));

                _cache.Add(record);
                SaveToDisk();
            }
        }

        /// <summary>
        /// Remove the record for a device after it has been successfully unblocked.
        /// No-op if no matching record exists.
        /// </summary>
        public void Remove(string vid, string pid, string instanceId)
        {
            lock (_lock)
            {
                _cache.RemoveAll(r =>
                    string.Equals(r.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.Pid, pid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.InstanceId, instanceId, StringComparison.OrdinalIgnoreCase));
                SaveToDisk();
            }
        }

        /// <summary>Return a snapshot of all blocked-device records.</summary>
        public List<BlockedDeviceRecord> GetAll()
        {
            lock (_lock)
                return new List<BlockedDeviceRecord>(_cache);
        }

        // ---- Persistence helpers ----

        private List<BlockedDeviceRecord> LoadFromDisk()
        {
            try
            {
                if (!File.Exists(_filePath))
                    return new List<BlockedDeviceRecord>();

                string json = File.ReadAllText(_filePath);
                return JsonSerializer.Deserialize<List<BlockedDeviceRecord>>(json, JsonOptions)
                       ?? new List<BlockedDeviceRecord>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BlockedDeviceStore] Failed to load '{_filePath}': {ex.Message}. Starting with empty store.");
                return new List<BlockedDeviceRecord>();
            }
        }

        private void SaveToDisk()
        {
            try
            {
                string json = JsonSerializer.Serialize(_cache, JsonOptions);
                // Atomic write: temp file → replace, so a crash mid-write cannot corrupt the store.
                string tempPath = _filePath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, _filePath, overwrite: true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BlockedDeviceStore] Failed to save '{_filePath}': {ex.Message}");
            }
        }

        // ---- Self-test ----

        /// <summary>
        /// Verifies that JSON round-trip persistence works correctly.
        /// Uses a temporary file; safe to call at any time.
        /// Returns true if all checks pass.
        /// </summary>
        public static bool RunSelfTest(string? testPath = null)
        {
            string path = testPath ?? Path.Combine(Path.GetTempPath(), "usb_guardian_store_selftest.json");

            try
            {
                if (File.Exists(path)) File.Delete(path);

                // 1. Write a record
                var store = new BlockedDeviceStore(path);
                var rec = new BlockedDeviceRecord
                {
                    Vid = "1234",
                    Pid = "5678",
                    InstanceId = "TESTINSTANCE",
                    Description = "Test Device",
                    BlockReason = "Self-test",
                    Actions = new List<BlockActionRecord>
                    {
                        new BlockActionRecord
                        {
                            ActionType = "ConfigFlags",
                            RegistryPath = @"SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\TESTINSTANCE",
                            PreviousConfigFlags = 0
                        },
                        new BlockActionRecord
                        {
                            ActionType = "ServiceStart",
                            ServiceName = "usbstor",
                            PreviousServiceStart = 3
                        }
                    }
                };
                store.AddOrUpdate(rec);

                // 2. Reload and verify
                var store2 = new BlockedDeviceStore(path);
                var records = store2.GetAll();
                if (records.Count != 1)
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: expected 1 record after AddOrUpdate");
                    return false;
                }

                var loaded = records[0];
                if (loaded.Vid != "1234" || loaded.Pid != "5678" || loaded.InstanceId != "TESTINSTANCE")
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: loaded record fields do not match");
                    return false;
                }

                if (loaded.Actions.Count != 2)
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: expected 2 actions");
                    return false;
                }

                if (loaded.Actions[0].PreviousConfigFlags != 0 || loaded.Actions[1].PreviousServiceStart != 3)
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: action fields did not round-trip correctly");
                    return false;
                }

                // 3. Update and verify
                rec.Description = "Updated Description";
                store2.AddOrUpdate(rec);
                var store3 = new BlockedDeviceStore(path);
                if (store3.GetAll().Count != 1 || store3.GetAll()[0].Description != "Updated Description")
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: update did not work correctly");
                    return false;
                }

                // 4. Remove and verify
                store3.Remove("1234", "5678", "TESTINSTANCE");
                var store4 = new BlockedDeviceStore(path);
                if (store4.GetAll().Count != 0)
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: remove did not delete the record");
                    return false;
                }

                Debug.WriteLine("[BlockedDeviceStore.SelfTest] ALL TESTS PASSED");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BlockedDeviceStore.SelfTest] EXCEPTION: {ex.Message}");
                return false;
            }
            finally
            {
                try { if (File.Exists(path)) File.Delete(path); } catch { }
            }
        }
    }
}
