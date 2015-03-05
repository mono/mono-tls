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

namespace Mono.Security.NewTls.TestProvider
{
	public class DotNetServer : DotNetConnection, IServerTestHost, IServer
	{
		public ServerCertificate Certificate {
			get;
			private set;
		}

		IServerCertificate IServer.Certificate {
			get { return Certificate; }
		}

		new public IServerParameters Parameters {
			get { return (IServerParameters)base.Parameters; }
		}

		public DotNetServer (IPEndPoint endpoint, IServerParameters parameters)
			: base (endpoint, parameters)
		{
			Certificate = new ServerCertificate (parameters.ServerCertificate);
		}

		protected override Stream Start (Socket socket)
		{
			Debug ("Accepted connection from {0}.", socket.RemoteEndPoint);

			if (Parameters.AskForClientCertificate || Parameters.RequireClientCertificate)
				throw new NotSupportedException ();

			var stream = new NetworkStream (socket);
			var server = new SslStream (stream, false);
			server.AuthenticateAsServer (Certificate.Certificate, false, SslProtocols.Tls12, false);

			Debug ("Successfully authenticated.");

			return server;
		}
	}
}

