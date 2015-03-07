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
using Mono.Security.Interface;

using Xamarin.AsyncTests;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace Mono.Security.NewTls.TestProvider
{
	public class MonoClient : MonoConnection, IClient
	{
		new public IClientParameters Parameters {
			get { return (IClientParameters)base.Parameters; }
		}

		public MonoClient (IPEndPoint endpoint, IClientParameters parameters)
			: base (endpoint, parameters)
		{
		}

		protected override TlsSettings GetSettings ()
		{
			var settings = new TlsSettings ();
			#if FIXME
			var monoParams = Parameters as IMonoClientParameters;
			if (monoParams != null) {
				settings.ClientCertificateParameters = monoParams.ClientCertificateParameters;
				settings.Instrumentation = monoParams.ClientInstrumentation;
			}
			#endif
			settings.RequestedCiphers = Parameters.ClientCiphers;
			return settings;
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Socket socket, TlsSettings settings, CancellationToken cancellationToken)
		{
			Debug ("Connected.");

			var clientCerts = new X509Certificate2Collection ();
			if (Parameters.ClientCertificate != null) {
				var clientCert = new X509Certificate2 (Parameters.ClientCertificate.Data, Parameters.ClientCertificate.Password);
				clientCerts.Add (clientCert);
			}

			var targetHost = "Hamiller-Tube.local";

			var stream = new NetworkStream (socket);

			var provider = DependencyInjector.Get<NewTlsProvider> ();
			var monoSslStream = provider.CreateSslStream (
				stream, false, MonoRemoteValidationCallback, null, settings);

			await monoSslStream.AuthenticateAsClientAsync (targetHost, clientCerts, SslProtocols.Tls12, false);

			return monoSslStream;
		}

		bool MonoRemoteValidationCallback (string targetHost, X509Certificate certificate, X509Chain chain, MonoSslPolicyErrors errors)
		{
			return base.RemoteValidationCallback (this, certificate, chain, (SslPolicyErrors)errors);
		}

		bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}
	}
}
