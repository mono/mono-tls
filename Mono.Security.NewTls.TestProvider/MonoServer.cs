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
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestProvider
{
	public class MonoServer : MonoConnection, IServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		new public IServerParameters Parameters {
			get { return (IServerParameters)base.Parameters; }
		}

		public MonoServer (IPEndPoint endpoint, IServerParameters parameters)
			: base (endpoint, parameters)
		{
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
			#if FIXME
			var monoParams = Parameters as IMonoServerParameters;
			if (monoParams != null)
				settings.Instrumentation = monoParams.ServerInstrumentation;
			#endif

			settings.ClientCertValidationCallback = ClientCertValidationCallback;

			var serverCert = new SSCX.X509Certificate2 (Certificate.Data, Certificate.Password);

			var stream = new NetworkStream (socket);
			return MonoNewTlsStreamFactory.CreateServer (
				stream, false, null, null, EncryptionPolicy.RequireEncryption, settings,
				serverCert, false, SslProtocols.Tls12, false);
		}

		bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}
	}
}
