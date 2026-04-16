using System;
using System.Collections.Generic;
using System.Linq;

namespace USBGuardian
{
    public class RubberDuckyPatternResult
    {
        public bool IsThreat { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public List<string> Matches { get; set; } = new();
    }

    public class RubberDuckyPatternDetector
    {
        private static readonly string[] HighRiskPatterns =
        {
            "powershell", "cmd.exe", "-enc", "encodedcommand", "invoke-expression", "iex", "start-process"
        };

        public RubberDuckyPatternResult AnalyzeCommands(IEnumerable<string> commands)
        {
            var result = new RubberDuckyPatternResult();
            var commandList = commands?.ToList() ?? new List<string>();
            foreach (var command in commandList)
            {
                foreach (var pattern in HighRiskPatterns)
                {
                    if (command.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Matches.Add(pattern);
                    }
                }
            }

            result.IsThreat = result.Matches.Count > 0;
            result.ThreatLevel = result.IsThreat ? ThreatLevel.Critical : ThreatLevel.None;
            return result;
        }
    }
}
