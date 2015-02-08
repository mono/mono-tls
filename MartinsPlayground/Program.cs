using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Reflection;
using System.Net.Sockets;
using System.Net.Security;

using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace MartinsPlayground
{
    class MainClass
    {
        const string Address = "https://Hamiller-Tube.local:4433/";
        const string Address2 = "https://www.xamarin.com/";
        public static void Main(string[] args)
        {
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            // CreateStores();
            // TestSSL(Address2);
            Run();
        }

        static void TestException()
        {
            try {
                throw new InvalidOperationException("Out of coffee.");
            } catch (Exception ex) {
                throw new IOException("Problem in the kitchen.", ex);
            }
        }

        static void CreateStores ()
        {
            #if MARTINS_PLAYGROUND
            MX.X509StoreManager.LocalMachine.CreateStores();
            MX.X509StoreManager.CurrentUser.CreateStores();
            #endif
        }

        static X509Certificate2 GetServerCertificate ()
        {
            return new X509Certificate2(ReadResource("CA.server-cert.cert"), "monkey");
        }

        static byte[] ReadResource (string name)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("MartinsPlayground." + name))
            {
                var data = new byte[stream.Length];
                var ret = stream.Read(data, 0, data.Length);
                if (ret != data.Length)
                    throw new IOException();
                return data;
            }
        }

        static void TestSSL (string address)
        {
            var request = (HttpWebRequest)WebRequest.Create(address);
            var response = (HttpWebResponse)request.GetResponse();
            Console.WriteLine("RESPONSE: {0} {1}", response.StatusCode, response.StatusDescription);
        }

        static void Run ()
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            // socket.Connect("www.xamarin.com", 443);
            socket.Connect(IPAddress.Loopback, 4433);
            // socket.Connect(IPAddress.Parse("172.16.221.1"), 4433);

            var stream = new NetworkStream(socket, true);
            Console.WriteLine(stream);

            var tls = new SslStream(stream, false, (sender, certificate, chain, sslPolicyErrors) => true);
            tls.AuthenticateAsClient (string.Empty, null, SslProtocols.Tls12, false);
            Console.WriteLine(tls);

            var reader = new StreamReader(tls);
            var hello = reader.ReadLine();
            Console.WriteLine(hello);

            while (true)
            {
                var line = reader.ReadLine();
                Console.WriteLine(line);
            }

            var contents = reader.ReadToEnd();
            Console.WriteLine(contents);
            Console.WriteLine("DONE!");
        }

    }
}
