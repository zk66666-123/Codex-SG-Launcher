using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;

// Only launches the Store desktop application through the local guard.
internal static class DesktopLauncher {
    // Search explicitly in absolute PATH entries, never in the current directory.
    static string FindExe(string name) {
        foreach (string part in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';')) {
            string dir = Environment.ExpandEnvironmentVariables(part.Trim().Trim('"'));
            if (dir.Length < 3 || !Path.IsPathRooted(dir) || Path.GetPathRoot(dir).Length <= 1) continue;
            string candidate = Path.Combine(dir, name);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
    [STAThread] static int Main() {
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string script = Path.Combine(root, "tools", "env.py");
            if (!File.Exists(script)) throw new FileNotFoundException("Keep this launcher next to tools/env.py.");
            string python = Environment.GetEnvironmentVariable("CLAUDE7898_PYTHON");
            bool pyLauncher = false;
            if (!String.IsNullOrEmpty(python)) {
                if (!Path.IsPathRooted(python) || !File.Exists(python)) throw new FileNotFoundException("Check CLAUDE7898_PYTHON (absolute python.exe path required).");
            } else {
                python = FindExe("py.exe");
                pyLauncher = python != null;
                if (python == null) python = FindExe("python.exe");
            }
            if (python == null) throw new FileNotFoundException("Install Python 3.9+ or set CLAUDE7898_PYTHON.");
            var info = new ProcessStartInfo(python, (pyLauncher ? "-3 " : "") + "-I -B -X utf8 \"" + script + "\" desktop");
            info.WorkingDirectory = root;
            info.UseShellExecute = false; info.CreateNoWindow = true;
            info.RedirectStandardOutput = true; info.RedirectStandardError = true;
            info.StandardOutputEncoding = Encoding.UTF8; info.StandardErrorEncoding = Encoding.UTF8;
            using (var p = Process.Start(info)) {
                var stdout = p.StandardOutput.ReadToEndAsync();
                var stderr = p.StandardError.ReadToEndAsync();
                p.WaitForExit();
                string log = stdout.Result + stderr.Result;
                string dir = Path.Combine(root, "runtime");
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "desktop-launcher.log"), DateTimeOffset.Now.ToString("o") + Environment.NewLine + log, Encoding.UTF8);
                if (p.ExitCode != 0) throw new InvalidOperationException(String.IsNullOrWhiteSpace(log) ? "Python launcher failed." : log);
            }
            return 0;
        } catch (Exception e) {
            MessageBox.Show(e.Message, "Claude Desktop launcher", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1;
        }
    }
}
