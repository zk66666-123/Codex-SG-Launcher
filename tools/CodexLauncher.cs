// codex-sg.exe（控制台，在当前目录跑 CLI）/ codex-app-sg.exe（无窗口，启动桌面版，出错弹窗）
// 只是 tools\codex_env.py 的壳：参数原样转发，退出码透传。
// 编译：csc /target:exe    /out:codex-sg.exe     tools\CodexLauncher.cs
//       csc /target:winexe /define:APP /out:codex-app-sg.exe /r:System.Windows.Forms.dll tools\CodexLauncher.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
#if APP
using System.Threading.Tasks;
using System.Windows.Forms;
#endif

internal static class CodexLauncher
{
    private static string FindPython()
    {
        string fixedPath = @"C:\Python314\python.exe";
        if (File.Exists(fixedPath)) return fixedPath;
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            try
            {
                string p = Path.Combine(dir.Trim().Trim('"'), "python.exe");
                if (dir.Length > 0 && File.Exists(p) && p.IndexOf("WindowsApps", StringComparison.OrdinalIgnoreCase) < 0) return p;
            }
            catch (ArgumentException) { }
        }
        throw new FileNotFoundException("没有找到 Python（C:\\Python314\\python.exe 或 PATH 中的 python.exe）。");
    }

    // 原样取出 exe 名之后的命令行，避免二次转义改变参数。
    private static string RawArgs()
    {
        string cmd = Environment.CommandLine.TrimStart();
        int end = cmd.StartsWith("\"") ? cmd.IndexOf('"', 1) + 1 : cmd.IndexOf(' ');
        return end <= 0 || end >= cmd.Length ? "" : cmd.Substring(end).TrimStart();
    }

    [STAThread]
    private static int Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(root, "tools", "codex_env.py");
#if APP
        try
        {
            if (!File.Exists(script))
                throw new FileNotFoundException("启动器必须和 tools\\codex_env.py 放在同一个 Codex-SG-Launcher 目录里。");
            var info = new ProcessStartInfo(FindPython(), "-X utf8 \"" + script + "\" app " + RawArgs());
            info.WorkingDirectory = root;
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.StandardOutputEncoding = Encoding.UTF8;
            info.StandardErrorEncoding = Encoding.UTF8;
            using (Process p = Process.Start(info))
            {
                Task<string> o = p.StandardOutput.ReadToEndAsync();
                Task<string> e = p.StandardError.ReadToEndAsync();
                p.WaitForExit();
                string report = o.Result + e.Result;
                Directory.CreateDirectory(Path.Combine(root, "runtime"));
                File.WriteAllText(Path.Combine(root, "runtime", "app-launcher.log"),
                    DateTimeOffset.Now.ToString("o") + Environment.NewLine + report, Encoding.UTF8);
                if (p.ExitCode != 0) throw new InvalidOperationException(report);
            }
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Codex 新加坡出口：桌面版启动失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
#else
        try
        {
            if (!File.Exists(script))
                throw new FileNotFoundException("启动器必须和 tools\\codex_env.py 放在同一个 Codex-SG-Launcher 目录里。");
            // 不改工作目录：codex 在你所在的项目目录里运行；继承当前控制台。
            var info = new ProcessStartInfo(FindPython(), "-X utf8 \"" + script + "\" run " + RawArgs());
            info.UseShellExecute = false;
            using (Process p = Process.Start(info))
            {
                Console.CancelKeyPress += (s, e) => e.Cancel = true; // Ctrl+C 交给 codex
                p.WaitForExit();
                return p.ExitCode;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[ERROR] " + ex.Message);
            return 1;
        }
#endif
    }
}
