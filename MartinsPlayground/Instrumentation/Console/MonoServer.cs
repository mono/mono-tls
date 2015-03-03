extern alias NewSystemSource;

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Diagnostics;
using System.Collections.Generic;

using SslProtocols = System.Security.Authentication.SslProtocols;
using EncryptionPolicy = NewSystemSource::System.Net.Security.EncryptionPolicy;

using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Mono.Security.Providers.NewTls;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class MonoServer : MonoConnection, IServer
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

		public MonoServer (ServerFactory factory, IPEndPoint endpoint, ServerCertificate pfx, IServerParameters parameters)
			: base (factory, endpoint, parameters)
		{
			Certificate = pfx;
		}

		protected override TlsSettings GetSettings ()
		{
			var settings = new TlsSettings ();
			if (Parameters.RequireClientCertificate)
				settings.RequireClientCertificate = true;
			else if (Parameters.AskForClientCertificate)
				settings.AskForClientCertificate = true;
			settings.RequestedCiphers = Parameters.ServerCiphers;
			return settings;
		}

		protected override MonoNewTlsStream Start (Socket socket, TlsSettings settings)
		{
			var monoParams = Parameters as IMonoServerParameters;
			if (monoParams != null)
				settings.Instrumentation = monoParams.ServerInstrumentation;

			settings.ClientCertValidationCallback = ClientCertValidationCallback;

			var stream = new NetworkStream (socket);
			return MonoNewTlsStreamFactory.CreateServer (
				stream, false, null, null, EncryptionPolicy.RequireEncryption, settings,
				Certificate.Certificate, false, SslProtocols.Tls12, false);
		}

		bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}
	}
}
