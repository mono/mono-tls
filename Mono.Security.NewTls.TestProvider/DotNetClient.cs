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
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestProvider
{
	public class DotNetClient : DotNetConnection, IClient
	{
		new public IClientParameters Parameters {
			get { return (IClientParameters)base.Parameters; }
		}

		public DotNetClient (IPEndPoint endpoint, IClientParameters parameters)
			: base (endpoint, parameters)
		{
		}

		protected override async Task<Stream> Start (TestContext ctx, Socket socket, CancellationToken cancellationToken)
		{
			ctx.LogDebug (1, "Connected.");

			var clientCerts = new X509Certificate2Collection ();
			if (Parameters.ClientCertificate != null) {
				var clientCert = new X509Certificate2 (Parameters.ClientCertificate.Data, Parameters.ClientCertificate.Password);
				clientCerts.Add (clientCert);
			}

			var targetHost = "Hamiller-Tube.local";

			var stream = new NetworkStream (socket);
			var server = new SslStream (stream, false, RemoteValidationCallback, null);
			await server.AuthenticateAsClientAsync (targetHost, clientCerts, SslProtocols.Tls12, false);

			ctx.LogDebug (1, "Successfully authenticated.");

			return server;
		}
	}
}

