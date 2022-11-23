using Microsoft.Win32;
using SiretT;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SNTProxifier {
    /// <summary>
    /// Representa la estructura necesaria para el trabajo de lectura asincrona de los clientes
    /// </summary>
    internal class StateObject {
        /// <summary>
        /// Client  socket.
        /// </summary>
        public Socket workSocket = null;
        /// <summary>
        /// Size of receive buffer.
        /// </summary>
        public const int BufferSize = 1024;
        /// <summary>
        /// Receive buffer.
        /// </summary>
        public byte[] buffer = new byte[BufferSize];
        /// <summary>
        ///  Received data string.
        /// </summary>
        public StringBuilder sb = new StringBuilder();

        public IPEndPoint endPoint = null;
    }

    public struct INTERNET_PROXY_INFO {
        public int dwAccessType;
        public IntPtr proxy;
        public IntPtr proxyBypass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEMTIME {
        public short wYear;
        public short wMonth;
        public short wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    #region COM Interfaces

    [ComImport, Guid("00000112-0000-0000-C000-000000000046"),
    InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleObject {
        void SetClientSite(IOleClientSite pClientSite);
        void GetClientSite(IOleClientSite ppClientSite);
        void SetHostNames(object szContainerApp, object szContainerObj);
        void Close(uint dwSaveOption);
        void SetMoniker(uint dwWhichMoniker, object pmk);
        void GetMoniker(uint dwAssign, uint dwWhichMoniker, object ppmk);
        void InitFromData(IDataObject pDataObject, bool
            fCreation, uint dwReserved);
        void GetClipboardData(uint dwReserved, IDataObject ppDataObject);
        void DoVerb(uint iVerb, uint lpmsg, object pActiveSite,
            uint lindex, uint hwndParent, uint lprcPosRect);
        void EnumVerbs(object ppEnumOleVerb);
        void Update();
        void IsUpToDate();
        void GetUserClassID(uint pClsid);
        void GetUserType(uint dwFormOfType, uint pszUserType);
        void SetExtent(uint dwDrawAspect, uint psizel);
        void GetExtent(uint dwDrawAspect, uint psizel);
        void Advise(object pAdvSink, uint pdwConnection);
        void Unadvise(uint dwConnection);
        void EnumAdvise(object ppenumAdvise);
        void GetMiscStatus(uint dwAspect, uint pdwStatus);
        void SetColorScheme(object pLogpal);
    }

    [ComImport, Guid("00000118-0000-0000-C000-000000000046"),
    InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleClientSite {
        void SaveObject();
        void GetMoniker(uint dwAssign, uint dwWhichMoniker, object ppmk);
        void GetContainer(object ppContainer);
        void ShowObject();
        void OnShowWindow(bool fShow);
        void RequestNewObjectLayout();
    }

    [ComImport, GuidAttribute("6d5140c1-7436-11ce-8034-00aa006009fa"),
    InterfaceTypeAttribute(ComInterfaceType.InterfaceIsIUnknown),
    ComVisible(false)]
    public interface IServiceProvider {
        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int QueryService(ref Guid guidService, ref Guid riid, out IntPtr ppvObject);
    }

    [ComImport, GuidAttribute("79EAC9D0-BAF9-11CE-8C82-00AA004BA90B"),
    InterfaceTypeAttribute(ComInterfaceType.InterfaceIsIUnknown),
    ComVisible(false)]
    public interface IAuthenticate {
        [return: MarshalAs(UnmanagedType.I4)]
        [PreserveSig]
        int Authenticate(ref IntPtr phwnd, ref IntPtr pszUsername, ref IntPtr pszPassword);
    }

    public class Proxy {
        public Proxy() { }

        public string Hostname { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        public override string ToString() {
            return $"{Hostname}:{Port}";
        }
    }

    #endregion

    /// <summary>
    /// Lógica de interacción para MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetSystemTime(ref SYSTEMTIME st);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetLocalTime(ref SYSTEMTIME st);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetSystemTime(ref SYSTEMTIME st);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetLocalTime(ref SYSTEMTIME st);

        [DllImport("wininet.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, StringBuilder pchCookieData, ref uint pcchCookieData, int dwFlags, IntPtr lpReserved);
        const int INTERNET_COOKIE_HTTPONLY = 0x00002000;

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
        private Guid IID_IAuthenticate = new Guid("79eac9d0-baf9-11ce-8c82-00aa004ba90b");
        private const int INET_E_DEFAULT_ACTION = unchecked((int)0x800C0011);
        private const int S_OK = unchecked((int)0x00000000);
        private const int INTERNET_OPTION_PROXY = 38;
        private const int INTERNET_OPEN_TYPE_DIRECT = 1;
        private const int INTERNET_OPEN_TYPE_PROXY = 3;
        private const int SNTPDataLength = 48;
        private DateTime EpochTime = DateTime.Parse("Thu, 1 Jan 1970 00:00:00Z");
        private string agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.124 YaBrowser/22.9.5.712 Yowser/2.5 Safari/537.36";
        private string timeanddate_url = "https://www.timeanddate.com/scripts/ts.php?";
        private string timeanddate_referer = "https://www.timeanddate.com/worldclock/cuba/havana";
        private string _currentUsername;
        protected string _currentPassword;
        private IWebProxy proxy;
        private Uri defaultUri = new Uri("http://www.google.com");
        private IniFile ini;
        private string iniPath;
        private bool isBusy;
        private AssemblyName assembly;

        protected string SecretKey { get; private set; }

        public MainWindow() {
            InitializeComponent();
            SecretKey = "C7A04BDB-6518-4619-AEA9-52E1F2616036";
            iniPath = System.IO.Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]) + "\\config.ini";
            ini = new IniFile(iniPath);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var secureString = ini.GetValue("Proxy\\SecureString", (object)"").ToString();
            ntp1Server.Text = ini.GetValue("Servers\\Server1", (object)ntp1Server.Text).ToString();
            ntp2Server.Text = ini.GetValue("Servers\\Server2", (object)ntp2Server.Text).ToString();
            ntp3Server.Text = ini.GetValue("Servers\\Server3", (object)ntp3Server.Text).ToString();
            ntp4Server.Text = ini.GetValue("Servers\\Server4", (object)ntp4Server.Text).ToString();
            var uri = SiretT.Crypto.Decrypt(Encoding.UTF8.GetString(Convert.FromBase64String(secureString)), $"{{{SecretKey}}}", System.Security.Cryptography.CipherMode.ECB);
            var credentialParts = uri.Split("@:".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            proxy_host.Text = credentialParts[0];
            proxy_port.Text = credentialParts[1];
            if (credentialParts.Length > 2) {
                proxy_username.Text = Uri.UnescapeDataString(credentialParts[2]);
                proxy_password.Password = Uri.UnescapeDataString(credentialParts[3]);
            }
            assembly = Assembly.GetExecutingAssembly().GetName();
            this.Title = assembly.Name + " - " + assembly.Version;
            autorun.IsChecked = (bool)ini.GetValue("Main\\Autorun", false);
            enable.IsChecked = (bool)ini.GetValue("Main\\Enabled", false);
        }

        protected override void OnSourceInitialized(EventArgs e) {
            base.OnSourceInitialized(e);
            var left = ini.GetValue("Main\\Left", (int)Left);
            var top = ini.GetValue("Main\\Top", (int)Top);
            Left = left is int ? (int)left : Left;
            Top = top is int ? (int)top : Top;
        }

        protected override void OnClosed(EventArgs e) {
            base.OnClosed(e);
            ini.AddOrUpdate("Main\\Left", this.Left);
            ini.AddOrUpdate("Main\\Top", this.Top);
            ini.AddOrUpdate("Main\\Autorun", this.autorun.IsChecked);
            ini.AddOrUpdate("Main\\Enabled", this.enable.IsChecked);
            ini.AddOrUpdate("Servers\\Server1", ntp1Server.Text);
            ini.AddOrUpdate("Servers\\Server2", ntp2Server.Text);
            ini.AddOrUpdate("Servers\\Server3", ntp3Server.Text);
            ini.AddOrUpdate("Servers\\Server4", ntp4Server.Text);
            ini.Save();
        }

        private bool NTPUpdate(string ntpServer, out DateTime dateTime) {
            dateTime = new DateTime();
            var ntpData = new byte[SNTPDataLength];
            ntpData[0] = 0x1B;
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.ReceiveTimeout = 5000;
            var host = ntpServer;
            try {
                socket.Connect(host, 123);
                socket.Send(ntpData);
                socket.Receive(ntpData);
                socket.Close();

                var li = ntpData[0] >> 6;
                var vn = ntpData[0] >> 3 & 7;
                var mode = ntpData[0] & 7;
                var stratum = ntpData[1];
                var poll = ntpData[2];
                var precision = ntpData[3];
                //var rootDelay = ntpData[4],5,6,7];
                //var rootDispersion = ntpData[8,9,10,11];
                //var referenceIdentifier = ntpData[12];

                var intPart = ((ulong)ntpData[40] << 24) | ((ulong)ntpData[41] << 16) | ((ulong)ntpData[42] << 8) | ntpData[43];
                var fractPart = ((ulong)ntpData[44] << 24) | ((ulong)ntpData[45] << 16) | ((ulong)ntpData[46] << 8) | ntpData[47];

                var milliseconds = intPart * 1000 + fractPart * 1000 / 0x100000000L;
                var networkDateTime = new DateTime(1900, 1, 1).AddMilliseconds((long)milliseconds);
                var finalTime = TimeZoneInfo.ConvertTimeFromUtc(networkDateTime, TimeZoneInfo.Local);
                dateTime = finalTime;
                return true;
            } catch (Exception ex) {
                //MessageBox.Show(ex.Message, "NTP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return false;
        }

        private bool HTTP_NTP(out DateTime dateTime) {
            dateTime = new DateTime();
            try {
                //proxy = WebRequest.GetSystemWebProxy();
                //proxy = new WebProxy();
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(timeanddate_url);
                request.Method = "GET";
                request.Proxy = proxy;
                request.Accept = "*/*";
                request.Referer = timeanddate_referer;
                request.UserAgent = agent;

                var response = (HttpWebResponse)request.GetResponse();
                var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
                var milliString = responseString.Split(' ')[0];
                var seconds = long.Parse(milliString.Split('.')[0]);
                var milliseconds = long.Parse(milliString.Split('.')[1]);

                var now = EpochTime.AddSeconds(seconds).AddMilliseconds(0 * milliseconds);
                //return now;
                dateTime = now;
                return true;
            } catch (Exception ex) {
                //MessageBox.Show(ex.Message, "HTTP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return false;
            //return DateTime.Now;
        }

        private void SetProxyServer(string proxy) {
            //Create structure
            INTERNET_PROXY_INFO proxyInfo = new INTERNET_PROXY_INFO();

            if (proxy == null) {
                proxyInfo.dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
            } else {
                proxyInfo.dwAccessType = INTERNET_OPEN_TYPE_PROXY;
                proxyInfo.proxy = Marshal.StringToHGlobalAnsi(proxy);
                proxyInfo.proxyBypass = Marshal.StringToHGlobalAnsi("local");
            }

            // Allocate memory
            IntPtr proxyInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(proxyInfo));

            // Convert structure to IntPtr
            Marshal.StructureToPtr(proxyInfo, proxyInfoPtr, true);
            bool returnValue = InternetSetOption(IntPtr.Zero, INTERNET_OPTION_PROXY,
                proxyInfoPtr, Marshal.SizeOf(proxyInfo));
        }

        #region IOleClientSite Members

        public void SaveObject() {
        }

        public void GetMoniker(uint dwAssign, uint dwWhichMoniker, object ppmk) {
        }

        public void GetContainer(object ppContainer) {
        }

        public void ShowObject() {
        }

        public void OnShowWindow(bool fShow) {
        }

        public void RequestNewObjectLayout() {
        }

        #endregion

        #region IServiceProvider Members

        [return: MarshalAs(UnmanagedType.I4)]
        public int QueryService(ref Guid guidService, ref Guid riid, out IntPtr ppvObject) {
            int nRet = guidService.CompareTo(IID_IAuthenticate);
            if (nRet == 0) {
                nRet = riid.CompareTo(IID_IAuthenticate);
                if (nRet == 0) {
                    ppvObject = Marshal.GetComInterfaceForObject(this, typeof(IAuthenticate));
                    return S_OK;
                }
            }

            ppvObject = new IntPtr();
            return INET_E_DEFAULT_ACTION;
        }

        #endregion

        #region IAuthenticate Members

        [return: MarshalAs(UnmanagedType.I4)]
        public int Authenticate(ref IntPtr phwnd, ref IntPtr pszUsername, ref IntPtr pszPassword) {
            IntPtr sUser = Marshal.StringToCoTaskMemAuto(_currentUsername);
            IntPtr sPassword = Marshal.StringToCoTaskMemAuto(_currentPassword);

            pszUsername = sUser;
            pszPassword = sPassword;
            return S_OK;
        }

        #endregion

        private void Button_Click(object sender, RoutedEventArgs e) {
            DateTime dateTime;
            if (isBusy) return;
            var server1 = ntp1Server.Text;
            var server2 = ntp2Server.Text;
            var server3 = ntp3Server.Text;
            var server4 = ntp4Server.Text;
            var isServer1 = ntp1Server.IsEnabled;
            var isServer2 = ntp2Server.IsEnabled;
            var isServer3 = ntp3Server.IsEnabled;
            var isServer4 = ntp4Server.IsEnabled;
            var wServer = server1;
            var proto = "NTP";
            (sender as Button).IsEnabled = false;
            new Thread(new ThreadStart(() => {
                isBusy = true;
                if (isServer1 && NTPUpdate(server1, out dateTime)) {
                    wServer = server1;
                } else if (isServer2 && NTPUpdate(server2, out dateTime)) {
                    wServer = server2;
                } else if (isServer3 && NTPUpdate(server3, out dateTime)) {
                    wServer = server3;
                } else if (isServer4 && NTPUpdate(server4, out dateTime)) {
                    wServer = server4;
                } else if (HTTP_NTP(out dateTime)) {
                    proto = "HTTP";
                    wServer = timeanddate_referer;
                } else {
                    dateTime = DateTime.Now;
                }
                this.Dispatcher.Invoke(new Action(() => {
                    ntp_time.Text = wServer;
                    http_time.Text = dateTime.ToString();
                    proto_info.Text = $"{proto}:";
                    if (enable.IsChecked == true) {
                        SYSTEMTIME st = new SYSTEMTIME();
                        //GetLocalTime(ref st);
                        st.wYear = (short)dateTime.Year;
                        st.wMonth = (short)dateTime.Month;
                        st.wDay = (short)dateTime.Day;
                        st.wHour = (short)dateTime.Hour;
                        st.wMinute = (short)dateTime.Minute;
                        st.wSecond = (short)dateTime.Second;
                        st.wMilliseconds = (short)dateTime.Millisecond;
                        //SetSystemTime(ref st);
                        SetLocalTime(ref st);
                    }
                    (sender as Button).IsEnabled = true;
                }));
                isBusy = false;
            })).Start();
        }

        private void sysProxyRBtn_Checked(object sender, RoutedEventArgs e) {
            _currentUsername = null;
            _currentPassword = null;
            if ((sender as RadioButton).Name == "noProxyRBtn") {
                proxy = new WebProxy();
                SetProxyServer(null);
            } else if ((sender as RadioButton).Name == "sysProxyRBtn") {
                proxy = WebRequest.GetSystemWebProxy();
                var urip = proxy.GetProxy(defaultUri);
                if (urip == defaultUri)
                    SetProxyServer(null);
                else SetProxyServer(urip.Authority);
            } else if ((sender as RadioButton).Name == "custProxyRBtn") {
                proxy = new WebProxy($"{proxy_host.Text}:{proxy_port}");
                _currentUsername = "";
                _currentPassword = "";
                SetProxyServer($"{proxy_host.Text}:{proxy_port}");
                proxy.Credentials = new NetworkCredential(proxy_username.Text, proxy_password.Password);
                _currentUsername = proxy_username.Text;
                _currentPassword = proxy_password.Password;
            }
        }

        private void proxyItem_Checked(object sender, RoutedEventArgs e) {
            var host = proxy_host.Text.Trim();
            var port = proxy_port.Text.Trim();
            proxy = new WebProxy($"{host}:{port}");
            _currentUsername = proxy_username.Text.Trim();
            _currentPassword = proxy_password.Password;
            SetProxyServer($"{host}:{port}");
            proxy.Credentials = new NetworkCredential(_currentUsername, _currentPassword);
            var proxySecureString = "";
            var proxy_server = "";
            if (string.IsNullOrEmpty(_currentUsername.Trim()))
                proxy_server = $"{host}:{port}";
            else
                proxy_server = $"{host}:{port}@{Uri.EscapeDataString(_currentUsername)}:{Uri.EscapeDataString(_currentPassword)}";

            proxySecureString = Convert.ToBase64String(Encoding.UTF8.GetBytes(Crypto.Encrypt(proxy_server, $"{{{SecretKey}}}", System.Security.Cryptography.CipherMode.ECB)));
            ini.AddOrUpdate("Proxy\\SecureString", proxySecureString);
            ini.Save();
        }

        private void enable_Checked(object sender, RoutedEventArgs e) {
            ini.AddOrUpdate("Main\\Enabled", this.enable.IsChecked);
            ini.Save();
        }

        private void autorun_Checked(object sender, RoutedEventArgs e) {
            RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            if (autorun.IsChecked == true)
                rk.SetValue(assembly.Name, '"' + Environment.GetCommandLineArgs()[0] + '"', RegistryValueKind.String);
            else
                rk.DeleteValue(assembly.Name);
            rk.Close();
            ini.AddOrUpdate("Main\\Autorun", this.autorun.IsChecked);
            ini.Save();
        }
    }
}
