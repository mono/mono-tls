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
using Mono.Security.Interface;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	public class MonoServer : MonoConnection, IMonoServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		ServerParameters IServer.Parameters {
			get { return Parameters; }
		}

		new public MonoServerParameters Parameters {
			get { return (MonoServerParameters)base.Parameters; }
		}

		public MonoServer (IPEndPoint endpoint, MonoServerParameters parameters)
			: base (endpoint, parameters)
		{
		}

		protected override TlsSettings GetSettings ()
		{
			var settings = new TlsSettings ();
			if ((Parameters.Flags & ServerFlags.RequireClientCertificate) != 0)
				settings.RequireClientCertificate = settings.AskForClientCertificate = true;
			else if ((Parameters.Flags & ServerFlags.AskForClientCertificate) != 0)
				settings.AskForClientCertificate = true;
			settings.RequestedCiphers = Parameters.ServerCiphers;
			return settings;
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Socket socket, TlsSettings settings, CancellationToken cancellationToken)
		{
			#if FIXME
			var monoParams = Parameters as IMonoServerParameters;
			if (monoParams != null)
				settings.Instrumentation = monoParams.ServerInstrumentation;
			#endif

			settings.ClientCertValidationCallback = ClientCertValidationCallback;

			var serverCert = CertificateProvider.GetCertificate (Certificate);

			var stream = new NetworkStream (socket);

			var provider = DependencyInjector.Get<NewTlsProvider> ();
			var monoSslStream = provider.CreateSslStream (stream, false, null, settings);

			var newTlsStream = NewTlsProvider.GetNewTlsStream (monoSslStream);

			try {
				await monoSslStream.AuthenticateAsServerAsync (serverCert, false, SslProtocols.Tls12, false);
			} catch (Exception ex) {
				var lastError = newTlsStream.LastError;
				if (lastError != null)
					throw new AggregateException (ex, lastError);
				throw;
			}

			return monoSslStream;
		}

		bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}
	}
}
