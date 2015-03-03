using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class DotNetClient : DotNetConnection, IClient
	{
		new public IClientParameters Parameters {
			get { return (IClientParameters)base.Parameters; }
		}

		public DotNetClient (ClientFactory factory, IPEndPoint endpoint, IClientParameters parameters)
			: base (factory, endpoint, parameters)
		{
		}

		protected override Stream Start (Socket socket)
		{
			Debug ("Connected.");

			var clientCerts = new X509Certificate2Collection ();
			if (Parameters.ClientCertificate != null) {
				var clientCert = (ClientCertificate)Parameters.ClientCertificate;
				clientCerts.Add (clientCert.Certificate);
			}

			var targetHost = "Hamiller-Tube.local";

			var stream = new NetworkStream (socket);
			var server = new SslStream (stream, false, RemoteValidationCallback, null);
			server.AuthenticateAsClient (targetHost, clientCerts, SslProtocols.Tls12, false);

			Debug ("Successfully authenticated.");

			return server;
		}
	}
}

