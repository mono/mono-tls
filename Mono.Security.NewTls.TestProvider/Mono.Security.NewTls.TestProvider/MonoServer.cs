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
using MSI = Mono.Security.Interface;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoServer : MonoConnection, IMonoServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		ServerParameters IServer.Parameters {
			get { return Parameters; }
		}

		new public ServerParameters Parameters {
			get { return (ServerParameters)base.Parameters; }
		}

		public MonoServerParameters MonoParameters {
			get { return base.Parameters as MonoServerParameters; }
		}

		public MonoServer (MonoConnectionProviderImpl provider, ServerParameters parameters)
			: base (provider, parameters)
		{
		}

		protected override bool IsServer {
			get { return true; }
		}

		protected override TlsSettings GetSettings (UserSettings userSettings)
		{
			var settings = new TlsSettings (userSettings);
			if ((Parameters.Flags & ServerFlags.RequireClientCertificate) != 0)
				settings.UserSettings.RequireClientCertificate = settings.UserSettings.AskForClientCertificate = true;
			else if ((Parameters.Flags & ServerFlags.AskForClientCertificate) != 0)
				settings.UserSettings.AskForClientCertificate = true;

			if (MonoParameters != null)
				settings.UserSettings.RequestedCiphers = MonoParameters.ServerCiphers;

			return settings;
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Socket socket, MSI.MonoTlsSettings settings, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("Accepted connection from {0}.", socket.RemoteEndPoint);

			var stream = new NetworkStream (socket);
			var server = await ConnectionProvider.CreateServerStreamAsync (stream, Parameters, settings, cancellationToken);

			ctx.LogMessage ("Successfully authenticated server.");

			return server;
		}
	}
}
