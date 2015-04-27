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
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	public class DotNetServer : DotNetConnection, IServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		new public IServerParameters Parameters {
			get { return (IServerParameters)base.Parameters; }
		}

		public DotNetServer (IPEndPoint endpoint, IServerParameters parameters)
			: base (endpoint, parameters.ConnectionParameters)
		{
		}

		protected override async Task<Stream> Start (TestContext ctx, Socket socket, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("Accepted connection from {0}.", socket.RemoteEndPoint);

			if (Parameters.AskForClientCertificate || Parameters.RequireClientCertificate)
				throw new NotSupportedException ();

			var serverCert = CertificateProvider.GetCertificate (Certificate);

			var stream = new NetworkStream (socket);
			var server = new SslStream (stream, false);
			await server.AuthenticateAsServerAsync (serverCert, false, SslProtocols.Tls12, false);

			ctx.LogMessage ("Successfully authenticated.");

			return server;
		}
	}
}

