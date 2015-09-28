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
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;

using NewSslPolicyErrors = NewSystemSource::System.Net.Security.SslPolicyErrors;
using SslProtocols = System.Security.Authentication.SslProtocols;
using EncryptionPolicy = NewSystemSource::System.Net.Security.EncryptionPolicy;

using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Mono.Security.Providers.NewTls;
using MSI = Mono.Security.Interface;

using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoClient : MonoConnection, IMonoClient
	{
		public MonoConnectionParameters MonoParameters {
			get { return base.Parameters as MonoConnectionParameters; }
		}

		public MonoClient (MonoConnectionProvider provider, ConnectionParameters parameters)
			: base (provider, parameters)
		{
		}

		protected override bool IsServer {
			get { return false; }
		}

		protected override void GetSettings (UserSettings settings)
		{
			if (MonoParameters != null) {
				settings.RequestedCiphers = MonoParameters.ClientCiphers;
				settings.NamedCurve = MonoParameters.ClientNamedCurve;
			}
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Stream stream, MSI.MonoTlsSettings settings, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("Connected.");

			var targetHost = Parameters.TargetHost ?? EndPoint.HostName ?? EndPoint.Address;
			ctx.LogDebug (1, "Using '{0}' as target host.", targetHost);

			var client = await ConnectionProvider.CreateClientStreamAsync (stream, targetHost, Parameters, settings, cancellationToken);

			ctx.LogMessage ("Successfully authenticated client.");

			return client;
		}
	}
}
