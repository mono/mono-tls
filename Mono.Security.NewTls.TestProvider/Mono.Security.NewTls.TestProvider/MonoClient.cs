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
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

using SSCX = System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace Mono.Security.NewTls.TestProvider
{
	public class MonoClient : MonoConnection, IMonoClient
	{
		ClientParameters IClient.Parameters {
			get { return Parameters; }
		}

		new public MonoClientParameters Parameters {
			get { return (MonoClientParameters)base.Parameters; }
		}

		public MonoClient (IPEndPoint endpoint, MonoClientParameters parameters)
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

		static ICertificateValidator GetValidationCallback (ClientParameters parameters)
		{
			var validator = parameters.ClientCertificateValidator;
			if (validator == null)
				return null;

			var validationCallback = ((CertificateValidator)validator).ValidationCallback;

			var settings = new MonoTlsSettings {
				ServerCertificateValidationCallback = (s, c, ch, e) => validationCallback (s, c, ch, (SslPolicyErrors)e)
			};
			return CertificateValidationHelper.CreateDefaultValidator (settings);
		}

		protected override async Task<MonoSslStream> Start (TestContext ctx, Socket socket, TlsSettings settings, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("Connected.");

			var clientCerts = new X509Certificate2Collection ();
			if (Parameters.ClientCertificate != null) {
				var clientCert = CertificateProvider.GetCertificate (Parameters.ClientCertificate);
				clientCerts.Add (clientCert);
			}

			var targetHost = "Hamiller-Tube.local";

			var stream = new NetworkStream (socket);

			var certificateValidator = GetValidationCallback (Parameters);

			var provider = DependencyInjector.Get<NewTlsProvider> ();
			var monoSslStream = provider.CreateSslStream (stream, false, certificateValidator, settings);

			var newTlsStream = NewTlsProvider.GetNewTlsStream (monoSslStream);

			try {
				await monoSslStream.AuthenticateAsClientAsync (targetHost, clientCerts, SslProtocols.Tls12, false);
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
