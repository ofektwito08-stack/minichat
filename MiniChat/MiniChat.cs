// Mini Chat - a small Windows chat app for you and your friends.
// Rooms are private: you join with a code, and messages are encrypted with that code
// before they go through ntfy.sh (a free public message relay - no account needed).
// Build with build.bat (uses the C# compiler that comes with Windows).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace MiniChat
{
    static class Program
    {
        const string CodeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars, no I/O/0/1 mix-ups

        [STAThread]
        static int Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            if (args.Length > 0 && args[0] == "--selftest") return SelfTest.Run();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ChatForm());
            return 0;
        }

        public static string RandomCode(int length)
        {
            var bytes = new byte[length];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(bytes);
            return new string(bytes.Select(b => CodeChars[b % CodeChars.Length]).ToArray());
        }

        /// <summary>"k7qm-2xpa 9d" -> "K7QM2XPA9D"</summary>
        public static string NormalizeCode(string code)
        {
            return new string((code ?? "").ToUpperInvariant().Where(char.IsLetterOrDigit).ToArray());
        }

        /// <summary>"K7QM2XPA9DRT" -> "K7QM-2XPA-9DRT"</summary>
        public static string PrettyCode(string code)
        {
            var parts = new List<string>();
            for (int i = 0; i < code.Length; i += 4) parts.Add(code.Substring(i, Math.Min(4, code.Length - i)));
            return string.Join("-", parts);
        }
    }

    class ChatMessage
    {
        public string Id, Name, Kind, Text;
        public DateTime Time;
    }

    /// <summary>A room: its relay topic and encryption key both come from the room code.</summary>
    class Room
    {
        public readonly string Code, Topic;
        readonly byte[] key;

        public Room(string code)
        {
            Code = code;
            Topic = "minichat-v1-" + Hex(Sha("topic:" + code)).Substring(0, 24);
            key = Sha("key:" + code);
        }

        static byte[] Sha(string s)
        {
            using (var h = SHA256.Create()) return h.ComputeHash(Encoding.UTF8.GetBytes(s));
        }

        static string Hex(byte[] b)
        {
            return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
        }

        public string Encrypt(string plain)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                using (var enc = aes.CreateEncryptor())
                {
                    var p = Encoding.UTF8.GetBytes(plain);
                    var c = enc.TransformFinalBlock(p, 0, p.Length);
                    var all = new byte[16 + c.Length];
                    Buffer.BlockCopy(aes.IV, 0, all, 0, 16);
                    Buffer.BlockCopy(c, 0, all, 16, c.Length);
                    return Convert.ToBase64String(all);
                }
            }
        }

        /// <summary>Returns null if the text wasn't encrypted with this room's code.</summary>
        public string Decrypt(string b64)
        {
            try
            {
                var all = Convert.FromBase64String(b64);
                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    var iv = new byte[16];
                    Buffer.BlockCopy(all, 0, iv, 0, 16);
                    aes.IV = iv;
                    using (var dec = aes.CreateDecryptor())
                        return Encoding.UTF8.GetString(dec.TransformFinalBlock(all, 16, all.Length - 16));
                }
            }
            catch { return null; }
        }
    }

    /// <summary>Talks to ntfy.sh: POST to send, a long-lived streaming GET to receive.</summary>
    static class Relay
    {
        const string Base = "https://ntfy.sh/";
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
        static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static void Send(Room room, string myId, string name, string kind, string text)
        {
            var payload = Json.Serialize(new Dictionary<string, object> { { "id", myId }, { "n", name }, { "k", kind }, { "t", text } });
            var body = Encoding.UTF8.GetBytes(room.Encrypt(payload));
            var req = (HttpWebRequest)WebRequest.Create(Base + room.Topic);
            req.Method = "POST";
            req.ContentType = "text/plain";
            req.ContentLength = body.Length;
            req.Timeout = 15000;
            using (var s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            using (req.GetResponse()) { }
        }

        /// <summary>Streams messages until cancelled, reconnecting after errors.
        /// Starts with the last 12 hours (the relay's history), then resumes from the last message seen.</summary>
        public static void Listen(Room room, CancellationToken ct, Action<ChatMessage> onMessage, Action<bool> onConnected)
        {
            string since = "12h";
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(Base + room.Topic + "/json?since=" + since);
                    req.Timeout = 30000;
                    req.ReadWriteTimeout = 90000; // the relay sends a keepalive about every 45s
                    using (ct.Register(req.Abort))
                    using (var resp = req.GetResponse())
                    using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        onConnected(true);
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            var d = Json.Deserialize<Dictionary<string, object>>(line);
                            object ev;
                            if (!d.TryGetValue("event", out ev) || (ev as string) != "message") continue;
                            since = (string)d["id"];
                            var m = Parse(room, d["message"] as string, Convert.ToInt64(d["time"]));
                            if (m != null) onMessage(m);
                        }
                    }
                }
                catch (Exception)
                {
                    if (ct.IsCancellationRequested) break;
                }
                onConnected(false);
                ct.WaitHandle.WaitOne(3000);
            }
        }

        static ChatMessage Parse(Room room, string cipher, long unixTime)
        {
            var plain = cipher == null ? null : room.Decrypt(cipher);
            if (plain == null) return null;
            try
            {
                var d = Json.Deserialize<Dictionary<string, object>>(plain);
                return new ChatMessage
                {
                    Id = Str(d, "id"), Name = Str(d, "n"), Kind = Str(d, "k"), Text = Str(d, "t"),
                    Time = Epoch.AddSeconds(unixTime).ToLocalTime()
                };
            }
            catch { return null; }
        }

        static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? v.ToString() : "";
        }
    }

    public class SavedRoom
    {
        public string Code { get; set; }
        public string Label { get; set; }
        public override string ToString() { return Label; }
    }

    /// <summary>Your name, id and rooms, kept in %APPDATA%\MiniChat\settings.json.</summary>
    public class Settings
    {
        public string Name { get; set; }
        public string MyId { get; set; }
        public string LastRoom { get; set; }
        public List<SavedRoom> Rooms { get; set; }

        static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MiniChat");
        static readonly string FilePath = Path.Combine(Dir, "settings.json");

        public static Settings Load()
        {
            Settings s = null;
            try { if (File.Exists(FilePath)) s = new JavaScriptSerializer().Deserialize<Settings>(File.ReadAllText(FilePath, Encoding.UTF8)); }
            catch { }
            s = s ?? new Settings();
            if (s.Rooms == null) s.Rooms = new List<SavedRoom>();
            if (string.IsNullOrEmpty(s.MyId)) s.MyId = Program.RandomCode(16);
            return s;
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(FilePath, new JavaScriptSerializer().Serialize(this), Encoding.UTF8);
            }
            catch { }
        }
    }

    class ChatForm : Form
    {
        static readonly Color Bg = Color.FromArgb(43, 45, 49);
        static readonly Color Side = Color.FromArgb(30, 31, 34);
        static readonly Color InputBg = Color.FromArgb(56, 58, 64);
        static readonly Color Fg = Color.FromArgb(230, 232, 235);
        static readonly Color Muted = Color.FromArgb(150, 155, 163);
        static readonly Color Accent = Color.FromArgb(88, 101, 242);
        static readonly Color[] NameColors =
        {
            Color.FromArgb(242, 140, 140), Color.FromArgb(240, 178, 102), Color.FromArgb(230, 214, 110),
            Color.FromArgb(126, 214, 141), Color.FromArgb(104, 200, 220), Color.FromArgb(140, 160, 250),
            Color.FromArgb(200, 140, 240), Color.FromArgb(240, 140, 200)
        };
        const int MaxMessageLength = 1000; // keeps each relay message under its 4 KB limit

        readonly Settings settings = Settings.Load();
        readonly Font boldFont, smallFont, italicFont;
        Room room;
        CancellationTokenSource cts;
        DateTime liveSince;

        ListBox roomList;
        RichTextBox chat;
        TextBox input;
        Button sendBtn, copyBtn;
        Label roomTitle, statusLabel;
        LinkLabel meLabel;
        NotifyIcon tray;

        public ChatForm()
        {
            Text = "Mini Chat";
            Size = new Size(840, 580);
            MinimumSize = new Size(600, 400);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Bg;
            ForeColor = Fg;
            Font = new Font("Segoe UI", 10f);
            boldFont = new Font(Font, FontStyle.Bold);
            smallFont = new Font(Font.FontFamily, 8f);
            italicFont = new Font(Font, FontStyle.Italic);
            Icon = MakeIcon();
            tray = new NotifyIcon { Icon = Icon, Text = "Mini Chat", Visible = true };
            tray.BalloonTipClicked += (s, e) => BringToFront2();
            tray.DoubleClick += (s, e) => BringToFront2();

            BuildUi();
            Shown += (s, e) => Start();
            FormClosing += (s, e) =>
            {
                if (cts != null) cts.Cancel();
                tray.Visible = false;
                tray.Dispose();
            };
        }

        // ---------- layout ----------

        void BuildUi()
        {
            // Right side: header, chat, input box
            var right = new Panel { Dock = DockStyle.Fill, BackColor = Bg };

            chat = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                BackColor = Bg, ForeColor = Fg, DetectUrls = true, ScrollBars = RichTextBoxScrollBars.Vertical
            };
            chat.LinkClicked += (s, e) => { try { Process.Start(e.LinkText); } catch { } };
            var chatWrap = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 8, 8, 8) };
            chatWrap.Controls.Add(chat);

            var header = new Panel { Dock = DockStyle.Top, Height = 48, Padding = new Padding(16, 10, 10, 10), BackColor = Bg };
            roomTitle = new Label { Dock = DockStyle.Fill, Font = new Font(Font.FontFamily, 12f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft };
            statusLabel = new Label { Dock = DockStyle.Right, Width = 120, ForeColor = Muted, TextAlign = ContentAlignment.MiddleRight };
            copyBtn = MakeButton("Copy code");
            copyBtn.Dock = DockStyle.Right;
            copyBtn.Width = 100;
            copyBtn.Click += (s, e) => CopyCode();
            header.Controls.Add(roomTitle);
            header.Controls.Add(statusLabel);
            header.Controls.Add(copyBtn);
            var line = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = Side };

            var inputBar = new Panel { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(16, 10, 16, 12) };
            input = new TextBox { Dock = DockStyle.Fill, BackColor = InputBg, ForeColor = Fg, BorderStyle = BorderStyle.FixedSingle, MaxLength = MaxMessageLength };
            input.KeyDown += (s, e) =>
            {
                if (e.KeyCode != Keys.Enter) return;
                e.SuppressKeyPress = true; // no beep
                SendCurrent();
            };
            sendBtn = MakeButton("Send");
            sendBtn.Dock = DockStyle.Right;
            sendBtn.Width = 80;
            sendBtn.Click += (s, e) => SendCurrent();
            inputBar.Controls.Add(input);
            inputBar.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
            inputBar.Controls.Add(sendBtn);

            right.Controls.Add(chatWrap);
            right.Controls.Add(line);
            right.Controls.Add(header);
            right.Controls.Add(inputBar);

            // Left side: rooms
            var left = new Panel { Dock = DockStyle.Left, Width = 210, BackColor = Side, Padding = new Padding(10) };
            var title = new Label { Text = "ROOMS", Dock = DockStyle.Top, Height = 28, ForeColor = Muted, Font = smallFont };
            roomList = new ListBox
            {
                Dock = DockStyle.Fill, BackColor = Side, ForeColor = Fg, BorderStyle = BorderStyle.None,
                ItemHeight = 30, DrawMode = DrawMode.OwnerDrawFixed, IntegralHeight = false
            };
            roomList.DrawItem += DrawRoomItem;
            roomList.SelectedIndexChanged += (s, e) =>
            {
                var r = roomList.SelectedItem as SavedRoom;
                if (r != null && (room == null || room.Code != r.Code)) OpenRoom(r);
            };

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.TopDown, Height = 150, WrapContents = false };
            var newBtn = MakeButton("+  New room");
            var joinBtn = MakeButton("Join with code");
            var leaveBtn = MakeButton("Leave room");
            leaveBtn.BackColor = InputBg;
            foreach (var b in new[] { newBtn, joinBtn, leaveBtn })
            {
                b.Width = 188;
                b.Margin = new Padding(0, 0, 0, 6);
                buttons.Controls.Add(b);
            }
            newBtn.Click += (s, e) => NewRoom();
            joinBtn.Click += (s, e) => JoinRoom();
            leaveBtn.Click += (s, e) => LeaveRoom();

            meLabel = new LinkLabel
            {
                Dock = DockStyle.Bottom, Height = 24, ForeColor = Muted, LinkColor = Fg, ActiveLinkColor = Fg,
                LinkBehavior = LinkBehavior.HoverUnderline, TextAlign = ContentAlignment.MiddleLeft
            };
            meLabel.LinkClicked += (s, e) => ChangeName();

            left.Controls.Add(roomList);
            left.Controls.Add(title);
            left.Controls.Add(buttons);
            left.Controls.Add(meLabel);

            Controls.Add(right);
            Controls.Add(left);
        }

        void DrawRoomItem(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0) return;
            bool sel = (e.State & DrawItemState.Selected) != 0;
            using (var bg = new SolidBrush(sel ? InputBg : Side)) e.Graphics.FillRectangle(bg, e.Bounds);
            var r = (SavedRoom)roomList.Items[e.Index];
            TextRenderer.DrawText(e.Graphics, "# " + r.Label, Font, new Rectangle(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 6, e.Bounds.Height),
                sel ? Color.White : Muted, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        Button MakeButton(string text)
        {
            var b = new Button { Text = text, FlatStyle = FlatStyle.Flat, BackColor = Accent, ForeColor = Color.White, Height = 32, Cursor = Cursors.Hand };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        static Icon MakeIcon()
        {
            var bmp = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                using (var b = new SolidBrush(Accent))
                {
                    g.FillEllipse(b, 1, 2, 30, 23);
                    g.FillPolygon(b, new[] { new Point(7, 19), new Point(4, 30), new Point(15, 23) });
                }
                for (int i = 0; i < 3; i++) g.FillEllipse(Brushes.White, 8 + i * 6, 11, 5, 5);
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        // ---------- rooms ----------

        void Start()
        {
            if (string.IsNullOrWhiteSpace(settings.Name)) ChangeName();
            if (string.IsNullOrWhiteSpace(settings.Name)) settings.Name = "Guest" + Program.RandomCode(3);
            settings.Save();
            UpdateMeLabel();
            RefreshRooms();
            var last = settings.Rooms.FirstOrDefault(r => r.Code == settings.LastRoom) ?? settings.Rooms.FirstOrDefault();
            if (last != null) roomList.SelectedItem = last;
            else ShowWelcome();
        }

        void ShowWelcome()
        {
            room = null;
            chat.Clear();
            roomTitle.Text = "Welcome to Mini Chat";
            statusLabel.Text = "";
            copyBtn.Visible = false;
            input.Enabled = sendBtn.Enabled = false;
            AppendSystem("Make a room with \"+ New room\" and send the code to your friends,\nor click \"Join with code\" if a friend sent you one.\n\n" +
                         "Only share room codes with people you know. Anyone who has the code can read the room.");
        }

        void RefreshRooms()
        {
            roomList.Items.Clear();
            foreach (var r in settings.Rooms) roomList.Items.Add(r);
        }

        void OpenRoom(SavedRoom saved)
        {
            if (cts != null) cts.Cancel();
            room = new Room(saved.Code);
            settings.LastRoom = saved.Code;
            settings.Save();

            chat.Clear();
            roomTitle.Text = "# " + saved.Label;
            copyBtn.Visible = true;
            input.Enabled = sendBtn.Enabled = true;
            statusLabel.Text = "Connecting…";
            AppendSystem("Room code " + Program.PrettyCode(saved.Code) + " - only share it with people you know. " +
                         "Messages are encrypted with this code. The last 12 hours of chat are shown.");

            var r = room;
            cts = new CancellationTokenSource();
            var token = cts.Token;
            liveSince = DateTime.Now.AddSeconds(-5);
            Task.Run(() => Relay.Listen(r, token,
                m => OnUi(() => OnMessage(r, m)),
                ok => OnUi(() => { if (r == room) statusLabel.Text = ok ? "● Connected" : "Reconnecting…"; })));
            input.Focus();
        }

        void NewRoom()
        {
            var label = Prompt("New room", "Room name (only you see this name):", "Friends");
            if (label == null) return;
            var saved = new SavedRoom { Code = Program.RandomCode(12), Label = CleanLabel(label) };
            AddAndOpen(saved);
            Clipboard.SetText(Program.PrettyCode(saved.Code));
            MessageBox.Show(this, "Your room code is:\n\n" + Program.PrettyCode(saved.Code) +
                "\n\nIt's copied - paste it to your friends so they can join with \"Join with code\".", "Room created");
        }

        void JoinRoom()
        {
            var raw = Prompt("Join a room", "Room code from your friend:", "");
            if (raw == null) return;
            var code = Program.NormalizeCode(raw);
            if (code.Length < 8)
            {
                MessageBox.Show(this, "That doesn't look like a room code. Codes look like K7QM-2XPA-9DRT.", "Join a room");
                return;
            }
            var existing = settings.Rooms.FirstOrDefault(r => r.Code == code);
            if (existing != null) { roomList.SelectedItem = existing; return; }
            var label = Prompt("Join a room", "Name this room (only you see this name):", "Friends");
            if (label == null) return;
            AddAndOpen(new SavedRoom { Code = code, Label = CleanLabel(label) });
        }

        void AddAndOpen(SavedRoom saved)
        {
            settings.Rooms.Add(saved);
            settings.Save();
            RefreshRooms();
            roomList.SelectedItem = saved; // opens it
            var r = room;
            var name = settings.Name;
            Task.Run(() => { try { Relay.Send(r, settings.MyId, name, "join", ""); } catch { } });
        }

        void LeaveRoom()
        {
            var saved = roomList.SelectedItem as SavedRoom;
            if (saved == null) return;
            if (MessageBox.Show(this, "Remove \"" + saved.Label + "\" from your list?\nYou can rejoin later with its code.",
                    "Leave room", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
            if (cts != null) cts.Cancel();
            room = null;
            settings.Rooms.Remove(saved);
            settings.Save();
            RefreshRooms();
            if (settings.Rooms.Count > 0) roomList.SelectedIndex = 0;
            else ShowWelcome();
        }

        void CopyCode()
        {
            if (room == null) return;
            Clipboard.SetText(Program.PrettyCode(room.Code));
            statusLabel.Text = "Code copied!";
        }

        void ChangeName()
        {
            var name = Prompt("Your name", "What should your friends see as your name?", settings.Name ?? "");
            if (string.IsNullOrWhiteSpace(name)) return;
            settings.Name = name.Trim().Length > 24 ? name.Trim().Substring(0, 24) : name.Trim();
            settings.Save();
            UpdateMeLabel();
        }

        void UpdateMeLabel()
        {
            meLabel.Text = "You: " + settings.Name + "  (change)";
        }

        static string CleanLabel(string s)
        {
            s = (s ?? "").Trim();
            if (s.Length == 0) s = "Room";
            return s.Length > 30 ? s.Substring(0, 30) : s;
        }

        // ---------- messages ----------

        void SendCurrent()
        {
            var text = input.Text.Trim();
            if (text.Length == 0 || room == null) return;
            input.Clear();
            var r = room;
            var name = settings.Name;
            Task.Run(() =>
            {
                try { Relay.Send(r, settings.MyId, name, "msg", text); }
                catch
                {
                    OnUi(() =>
                    {
                        if (r != room) return;
                        AppendSystem("Message not sent - check your internet and try again.");
                        if (input.Text.Length == 0) input.Text = text;
                    });
                }
            });
        }

        void OnMessage(Room r, ChatMessage m)
        {
            if (r != room) return; // from a room we already switched away from
            if (m.Kind == "join")
            {
                AppendSystem(m.Name + " joined the room");
                return;
            }
            if (m.Kind != "msg") return;
            bool mine = m.Id == settings.MyId;
            AppendMessage(mine ? m.Name + " (you)" : m.Name, ColorFor(m.Id), m.Time.ToString("HH:mm"), m.Text);
            if (!mine && m.Time >= liveSince && ActiveForm != this) Notify(m);
        }

        void AppendMessage(string name, Color nameColor, string time, string text)
        {
            chat.SelectionStart = chat.TextLength;
            chat.SelectionFont = boldFont;
            chat.SelectionColor = nameColor;
            chat.AppendText(name);
            chat.SelectionFont = smallFont;
            chat.SelectionColor = Muted;
            chat.AppendText("   " + time + "\n");
            chat.SelectionFont = Font;
            chat.SelectionColor = Fg;
            chat.AppendText(text + "\n\n");
            chat.ScrollToCaret();
        }

        void AppendSystem(string text)
        {
            chat.SelectionStart = chat.TextLength;
            chat.SelectionFont = italicFont;
            chat.SelectionColor = Muted;
            chat.AppendText(text + "\n\n");
            chat.ScrollToCaret();
        }

        static Color ColorFor(string id)
        {
            int h = 0;
            foreach (var ch in id ?? "") h = (h * 31 + ch) & 0x7fffffff;
            return NameColors[h % NameColors.Length];
        }

        void Notify(ChatMessage m)
        {
            var label = settings.Rooms.Where(r => r.Code == room.Code).Select(r => r.Label).FirstOrDefault() ?? "Mini Chat";
            var text = m.Text.Length > 120 ? m.Text.Substring(0, 120) + "…" : m.Text;
            tray.ShowBalloonTip(4000, m.Name + " in #" + label, text, ToolTipIcon.None);
            var info = new FLASHWINFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)), hwnd = Handle,
                dwFlags = 3 | 12, // flash caption + taskbar until the window is focused
                uCount = uint.MaxValue
            };
            FlashWindowEx(ref info);
        }

        void BringToFront2()
        {
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
        }

        void OnUi(Action a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(a); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { }
        }

        string Prompt(string title, string message, string value)
        {
            using (var f = new Form
            {
                Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, MinimizeBox = false, MaximizeBox = false,
                StartPosition = FormStartPosition.CenterParent, ClientSize = new Size(360, 130), Font = Font,
                BackColor = Bg, ForeColor = Fg, ShowInTaskbar = false
            })
            {
                var lbl = new Label { Text = message, Left = 14, Top = 14, Width = 330, Height = 22 };
                var box = new TextBox { Text = value, Left = 14, Top = 40, Width = 330, BackColor = InputBg, ForeColor = Fg, BorderStyle = BorderStyle.FixedSingle };
                var ok = MakeButton("OK");
                ok.SetBounds(178, 82, 80, 32);
                ok.DialogResult = DialogResult.OK;
                var cancel = MakeButton("Cancel");
                cancel.SetBounds(264, 82, 80, 32);
                cancel.BackColor = InputBg;
                cancel.DialogResult = DialogResult.Cancel;
                f.Controls.AddRange(new Control[] { lbl, box, ok, cancel });
                f.AcceptButton = ok;
                f.CancelButton = cancel;
                return f.ShowDialog(this) == DialogResult.OK ? box.Text : null;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        [DllImport("user32.dll")]
        static extern bool FlashWindowEx(ref FLASHWINFO pwfi);
    }

    /// <summary>MiniChat.exe --selftest : checks encryption and a real send/receive through the relay.
    /// Exit code 0 = everything works.</summary>
    static class SelfTest
    {
        public static int Run()
        {
            try
            {
                var room = new Room(Program.RandomCode(12));
                var wrong = new Room("WRONGCODE123");
                const string hello = "hello שלום"; // "hello shalom" with Hebrew letters
                if (room.Decrypt(room.Encrypt(hello)) != hello) return 2;
                if (wrong.Decrypt(room.Encrypt(hello)) == hello) return 3;

                var connected = new ManualResetEvent(false);
                var got = new ManualResetEvent(false);
                string text = null, kind = null;
                var cts = new CancellationTokenSource();
                Task.Run(() => Relay.Listen(room, cts.Token,
                    m => { if (m.Kind == "msg") { text = m.Text; kind = m.Kind; got.Set(); } },
                    ok => { if (ok) connected.Set(); }));
                if (!connected.WaitOne(20000)) return 4;
                Relay.Send(room, "selftest", "Tester", "msg", hello);
                bool received = got.WaitOne(20000);
                cts.Cancel();
                return received && text == hello ? 0 : 5;
            }
            catch { return 6; }
        }
    }
}
