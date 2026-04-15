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
    /// Default file location: <Application.StartupPath>\blocked_devices.json
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
        /// Add a new record or update the existing one for the same physical device.
        ///
        /// Matching strategy:
        ///  1. When the incoming record has a non-empty <see cref="BlockedDeviceRecord.SerialNumber"/>,
        ///     the store looks for an existing entry with the same (Vid, Pid, SerialNumber). This
        ///     correctly deduplicates the same physical device plugged into different USB ports
        ///     (which would otherwise produce different InstanceIds).
        ///  2. When no SerialNumber is available, falls back to matching on (Vid, Pid, InstanceId)
        ///     to preserve the original behaviour.
        ///
        /// When updating an existing record, the new InstanceId is merged into the
        /// <see cref="BlockedDeviceRecord.InstanceIds"/> list so every port the device
        /// has been seen on is tracked without creating separate records.
        ///
        /// Persists immediately.
        /// </summary>
        public void AddOrUpdate(BlockedDeviceRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));

            lock (_lock)
            {
                // Normalize: ensure the current InstanceId is in the InstanceIds list.
                if (!string.IsNullOrEmpty(record.InstanceId) &&
                    !record.InstanceIds.Contains(record.InstanceId, StringComparer.OrdinalIgnoreCase))
                    record.InstanceIds.Add(record.InstanceId);

                bool hasSerial = !string.IsNullOrEmpty(record.SerialNumber);

                // Find an existing record to update (serial-number match takes priority).
                BlockedDeviceRecord? existing = hasSerial
                    ? _cache.FirstOrDefault(r =>
                          string.Equals(r.Vid, record.Vid, StringComparison.OrdinalIgnoreCase) &&
                          string.Equals(r.Pid, record.Pid, StringComparison.OrdinalIgnoreCase) &&
                          !string.IsNullOrEmpty(r.SerialNumber) &&
                          string.Equals(r.SerialNumber, record.SerialNumber, StringComparison.OrdinalIgnoreCase))
                    : _cache.FirstOrDefault(r =>
                          string.Equals(r.Vid, record.Vid, StringComparison.OrdinalIgnoreCase) &&
                          string.Equals(r.Pid, record.Pid, StringComparison.OrdinalIgnoreCase) &&
                          string.Equals(r.InstanceId, record.InstanceId, StringComparison.OrdinalIgnoreCase));

                if (existing != null)
                {
                    // Merge new InstanceId(s) into the existing record so every port is tracked.
                    foreach (string id in record.InstanceIds)
                    {
                        if (!string.IsNullOrEmpty(id) &&
                            !existing.InstanceIds.Contains(id, StringComparer.OrdinalIgnoreCase))
                            existing.InstanceIds.Add(id);
                    }

                    // Update the "current" InstanceId and other mutable fields.
                    existing.InstanceId   = record.InstanceId;
                    existing.PnpDeviceId  = record.PnpDeviceId;
                    existing.Description  = record.Description;
                    existing.Timestamp    = record.Timestamp;
                    existing.BlockReason  = record.BlockReason;
                    existing.Actions      = record.Actions;
                }
                else
                {
                    _cache.Add(record);
                }

                SaveToDisk();
            }
        }

        /// <summary>
        /// Remove a record by its unique <see cref="BlockedDeviceRecord.RecordId"/> after
        /// the device has been successfully unblocked.  No-op if no matching record exists.
        /// </summary>
        public void Remove(BlockedDeviceRecord? record)
        {
            if (record == null) return;
            lock (_lock)
            {
                _cache.RemoveAll(r => string.Equals(r.RecordId, record.RecordId, StringComparison.OrdinalIgnoreCase));
                SaveToDisk();
            }
        }

        /// <summary>
        /// Remove the record for a device after it has been successfully unblocked.
        ///
        /// Matching strategy mirrors <see cref="AddOrUpdate"/>:
        ///  1. When <paramref name="serialNumber"/> is non-empty, match on (Vid, Pid, SerialNumber).
        ///  2. Otherwise, fall back to matching on (Vid, Pid, InstanceId).
        ///
        /// No-op if no matching record exists.
        /// </summary>
        public void Remove(string vid, string pid, string instanceId, string? serialNumber = null)
        {
            lock (_lock)
            {
                bool hasSerial = !string.IsNullOrEmpty(serialNumber);
                if (hasSerial)
                {
                    _cache.RemoveAll(r =>
                        string.Equals(r.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(r.Pid, pid, StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrEmpty(r.SerialNumber) &&
                        string.Equals(r.SerialNumber, serialNumber, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    _cache.RemoveAll(r =>
                        string.Equals(r.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(r.Pid, pid, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(r.InstanceId, instanceId, StringComparison.OrdinalIgnoreCase));
                }
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

                // 4a. Deduplication by SerialNumber: same VID/PID/Serial on a different InstanceId
                //     must NOT create a second record; instead it merges InstanceIds.
                var store3b = new BlockedDeviceStore(path);
                store3b.Remove(store3b.GetAll()[0]); // clear for dedup test

                var recWithSerial = new BlockedDeviceRecord
                {
                    Vid = "AAAA",
                    Pid = "BBBB",
                    InstanceId = "INSTANCE_PORT_A",
                    SerialNumber = "SERIALXYZ",
                    Description = "Dedup Device",
                    BlockReason = "Self-test dedup",
                    Actions = new List<BlockActionRecord>()
                };
                var storeS = new BlockedDeviceStore(path);
                storeS.AddOrUpdate(recWithSerial);

                var recSameSerialNewPort = new BlockedDeviceRecord
                {
                    Vid = "AAAA",
                    Pid = "BBBB",
                    InstanceId = "INSTANCE_PORT_B",
                    SerialNumber = "SERIALXYZ",
                    Description = "Dedup Device (Port B)",
                    BlockReason = "Self-test dedup port B",
                    Actions = new List<BlockActionRecord>()
                };
                storeS.AddOrUpdate(recSameSerialNewPort);
                var storeS2 = new BlockedDeviceStore(path);
                var dedupAll = storeS2.GetAll();
                if (dedupAll.Count != 1)
                {
                    Debug.WriteLine($"[BlockedDeviceStore.SelfTest] FAIL: expected 1 record after serial dedup, got {dedupAll.Count}");
                    return false;
                }
                if (!dedupAll[0].InstanceIds.Contains("INSTANCE_PORT_B", StringComparer.OrdinalIgnoreCase))
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: port-B InstanceId was not merged into existing record");
                    return false;
                }
                storeS2.Remove(storeS2.GetAll()[0]); // clean up

                // 4b. No-serial fallback: different InstanceIds without SerialNumber = separate records.
                var storeF = new BlockedDeviceStore(path);
                var recNoSerial1 = new BlockedDeviceRecord { Vid = "1111", Pid = "2222", InstanceId = "INST1", BlockReason = "t" };
                var recNoSerial2 = new BlockedDeviceRecord { Vid = "1111", Pid = "2222", InstanceId = "INST2", BlockReason = "t" };
                storeF.AddOrUpdate(recNoSerial1);
                storeF.AddOrUpdate(recNoSerial2);
                var storeF2 = new BlockedDeviceStore(path);
                if (storeF2.GetAll().Count != 2)
                {
                    Debug.WriteLine($"[BlockedDeviceStore.SelfTest] FAIL: expected 2 records for different InstanceIds without serial, got {storeF2.GetAll().Count}");
                    return false;
                }
                foreach (var r in storeF2.GetAll()) storeF2.Remove(r); // clean up

                // 4c. Remove-by-record and verify
                var storeR = new BlockedDeviceStore(path);
                storeR.AddOrUpdate(rec);
                var toRemove = storeR.GetAll()[0];
                storeR.Remove(toRemove);
                var store4 = new BlockedDeviceStore(path);
                if (store4.GetAll().Count != 0)
                {
                    Debug.WriteLine("[BlockedDeviceStore.SelfTest] FAIL: Remove(record) did not delete the record");
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
