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

		public MonoConnectionParameters MonoParameters {
			get { return base.Parameters as MonoConnectionParameters; }
		}

		public MonoServer (MonoConnectionProvider provider, ConnectionParameters parameters)
			: base (provider, parameters)
		{
		}

		protected override bool IsServer {
			get { return true; }
		}

		protected override void GetSettings (UserSettings settings)
		{
			if (Parameters.RequireClientCertificate)
				settings.RequireClientCertificate = settings.AskForClientCertificate = true;
			else if (Parameters.AskForClientCertificate)
				settings.AskForClientCertificate = true;

			if (MonoParameters != null) {
				settings.RequestedCiphers = MonoParameters.ServerCiphers;
				settings.NamedCurve = MonoParameters.ServerNamedCurve;
			}
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Stream stream, MSI.MonoTlsSettings settings, CancellationToken cancellationToken)
		{
			var server = await ConnectionProvider.CreateServerStreamAsync (stream, Parameters, settings, cancellationToken);

			ctx.LogMessage ("Successfully authenticated server.");

			return server;
		}
	}
}
