using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace WpfApplication3
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        readonly string PasswordHash = "P@@Sw0rd";
        readonly string SaltKey = "S@LT&KEY";
        readonly string VIKey = "@1B2c3D4e5F6g7H8";
        string u = null;
        string p = null;
        System.Windows.Threading.DispatcherTimer dispatcherTimer = new System.Windows.Threading.DispatcherTimer();
        public MainWindow()
        {
            InitializeComponent();
            showNoti();
            using (StreamReader r = new StreamReader("config.json"))
            {
                string json = r.ReadToEnd();
                List<Item> items = JsonConvert.DeserializeObject<List<Item>>(json);
                u = items[0].username;
                p = Decrypt(items[0].password);
                Console.WriteLine("User:  " + u);
                Console.WriteLine("Pass:  " + p);
                if (items[0].status == 1)
                {
                    checkBox.IsChecked = true;
                    Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate (object o)
                    {
                        Hide();
                        return null;
                    }, null);

                }
            }
            dispatcherTimer.Tick += new EventHandler(dispatcherTimer_Tick);
            dispatcherTimer.Interval = new TimeSpan(0, 0, 2);
            dispatcherTimer.Start();
            //Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate (object o)
            //{
            //    Hide();
            //    return null;
            //}, null);
        }
        public string Encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
        }
        public string Decrypt(string encryptedText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }
        public class Item
        {
            public string username;
            public string password;
            public int status;
        }
        public bool IsNetworkAvailable()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
                return false;

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                // discard because of standard reasons
                if ((ni.OperationalStatus != OperationalStatus.Up) ||
                    (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) ||
                    (ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel))
                    continue;

                // this allow to filter modems, serial, etc.
                // I use 10000000 as a minimum speed for most cases

                // discard virtual cards (virtual box, virtual pc, etc.)
                if ((ni.Description.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (ni.Name.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0))
                    continue;

                // discard "Microsoft Loopback Adapter", it will not show as NetworkInterfaceType.Loopback but as Ethernet Card.
                if (ni.Description.Equals("Microsoft Loopback Adapter", StringComparison.OrdinalIgnoreCase))
                    continue;

                return true;
            }
            return false;
        }
    //    public bool checkLogin()
    //{
    //        HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://tinyurl.com/dbysxp");
    //        request.AllowAutoRedirect = false;
    //        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
    //        string redirUrl = response.Headers["Location"];
    //        response.Close();
    //        bool res = false;
    //        if (redirUrl==null) {
    //            res = false;
    //            //not Login
    //        }
    //        else {
    //            res = true;
    //        }
    //        return res;
           
    //    }

        public void Login(string username,string password) {
            dispatcherTimer.Stop();
            for (int i=1;i<19;i++) {
                string url = "";
                if (i < 10)
                {
                    url = "https://nac0" + i + ".kku.ac.th/login?username="+username+ "&password=" + password + "";
                }
                else {
                    url = "https://nac" + i + ".kku.ac.th/login?username=" + username + "&password=" + password + "";
                }
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.AllowAutoRedirect = false;
                request.Timeout=2000;

                try {
                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                    if (PingCheck("google.com")) {
                        break;
                    }
                    response.Close();
                } catch {
                }
           
          
            }
            dispatcherTimer.Start();
        }




    private void dispatcherTimer_Tick(object sender, EventArgs e)
        {
            if (IsNetworkAvailable())
            {
                if (!PingCheck("google.com")) {
                    Login(u,p);
                }
            }
            //if (!checkLogin()) {
            //    Login(u,p);
            //}
           
        }
        private void showNoti() {
            System.Windows.Forms.NotifyIcon notifyIcon = new System.Windows.Forms.NotifyIcon();
            notifyIcon.Icon = new System.Drawing.Icon("a.ico");
            notifyIcon.Visible = true;
            notifyIcon.MouseClick += new System.Windows.Forms.MouseEventHandler(notifyIcon_Click);
            //notifyIcon.ShowBalloonTip(500, "I'm Here", "Click me to Open", System.Windows.Forms.ToolTipIcon.Info);
            System.Windows.Forms.ContextMenu notifyIconContextMenu = new System.Windows.Forms.ContextMenu();
            notifyIconContextMenu.MenuItems.Add("Open", new EventHandler(Open));
            notifyIconContextMenu.MenuItems.Add("Exit", new EventHandler(Exit));
            notifyIcon.ContextMenu = notifyIconContextMenu;
        }
        private void button_Click(object sender, RoutedEventArgs e)
        {
            u = username.Text;
            p = passsword.Password;
           
            Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate (object o)
            {
                Hide();
                return null;
            }, null);             
            string json = File.ReadAllText("config.json");
            dynamic jsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject(json);
            if (checkBox.IsChecked == true)
            {
                jsonObj[0]["status"] = 1;
            }
            else {
                jsonObj[0]["status"] = 0;
            }
            
            jsonObj[0]["username"] =u;
            jsonObj[0]["password"] = Encrypt(p);
            string output = Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText("config.json", output);
        }
        private void Open(object sender,EventArgs e) {
            username.Text = u;
            passsword.Password = p;
            Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate (object o)
            {
                Show();
                dispatcherTimer.Stop();
                return null;
            }, null);
        }
        private void Exit(object sender, EventArgs e)
        {
            Application.Current.Shutdown();
            dispatcherTimer.Stop();
           
        }
        public bool PingCheck(string nameOrAddress)
        {
            bool pingable = false;
            Ping pinger = new Ping();
            byte[] packet = new byte[1];
            try
            {
                PingReply reply = pinger.Send(nameOrAddress,2000,packet);
                pingable = reply.Status == IPStatus.Success;
                Console.WriteLine("Try  "+nameOrAddress);
            }
            catch (PingException)
            {
                Console.WriteLine("Catch  " + nameOrAddress);
            }
            return pingable;
        }
        private void notifyIcon_Click(object sender,System.Windows.Forms.MouseEventArgs e) {
        }
        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate (object o)
                    {
                        Hide();
                        return null;
                    }, null);
            e.Cancel = true;
        }

    }
}
