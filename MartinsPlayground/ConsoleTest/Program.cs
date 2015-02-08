//
// Program.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Mono.Security.Providers;

namespace ConsoleTest
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			// TestSSL ("https://www.xamarin.com/");
			var dotnetprovider = new DotNetTlsProvider ();
			MonoTlsProviderFactory.InstallProvider (dotnetprovider);
			var endpoint = new IPEndPoint (IPAddress.Loopback, 4433);
			Run ("localhost", endpoint);
		}

		static void TestSSL (string address)
		{
			var request = (HttpWebRequest)WebRequest.Create(address);
			var response = (HttpWebResponse)request.GetResponse();
			Console.WriteLine("RESPONSE: {0} {1}", response.StatusCode, response.StatusDescription);
		}

		static bool CertificateValidationCallback (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			Console.WriteLine ("CERT VALIDATION ({0}): {1}", sslPolicyErrors, certificate.Subject);
			return true;
		}

		static X509Certificate CertificateSelectionCallback (
			object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate,
			string[] acceptableIssuers)
		{
			Console.WriteLine ("CERT SELECTION: {0}", targetHost);
			return null;
		}

		static void Run (string targetHost, IPEndPoint endpoint)
		{
			var socket = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			socket.Connect (endpoint);

			var stream = new NetworkStream (socket, true);
			Console.WriteLine (stream);

			var provider = MonoTlsProviderFactory.GetProvider ();
			var tls = provider.CreateSslStream (stream, false, CertificateValidationCallback, CertificateSelectionCallback);

			tls.AuthenticateAsClient (targetHost, null, SslProtocols.Tls, false);
			Console.WriteLine (tls);

			var reader = new StreamReader (tls.AuthenticatedStream);
			var hello = reader.ReadLine ();
			Console.WriteLine (hello);

			while (true) {
				var line = reader.ReadLine ();
				Console.WriteLine (line);
			}

			var contents = reader.ReadToEnd ();
			Console.WriteLine (contents);
			Console.WriteLine ("DONE!");
		}
	}
}
