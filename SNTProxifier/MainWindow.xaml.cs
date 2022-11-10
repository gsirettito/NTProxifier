using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
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
        private string _currentPassword;
        private IWebProxy proxy;
        private Uri defaultUri = new Uri("http://www.google.com");

        public MainWindow() {
            InitializeComponent();

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        private DateTime NTPUpdate() {
            var ntpData = new byte[SNTPDataLength];
            ntpData[0] = 0x1B;
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.ReceiveTimeout = 5000;
            var host = ntpServer.Text;
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
                return finalTime;
            } catch (Exception ex) {
                MessageBox.Show(ex.Message, "NTP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return DateTime.Now;
        }

        private DateTime HTTP_NTP() {
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
                return now;
            } catch (Exception ex) {
                MessageBox.Show(ex.Message, "HTTP Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return DateTime.Now;
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
            ntp_time.Text = NTPUpdate().ToString();
            http_time.Text = HTTP_NTP().ToString();
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
            proxy = new WebProxy($"{proxy_host.Text}:{proxy_port.Text}");
            _currentUsername = "";
            _currentPassword = "";
            SetProxyServer($"{proxy_host.Text}:{proxy_port.Text}");
            proxy.Credentials = new NetworkCredential(proxy_username.Text, proxy_password.Password);
            _currentUsername = proxy_username.Text;
            _currentPassword = proxy_password.Password;
        }
    }
}
