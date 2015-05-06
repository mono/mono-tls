using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	public class OpenSslServer : OpenSslConnection, IMonoServer
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

		public OpenSslServer (ServerParameters parameters)
			: base (parameters)
		{
		}

		protected override bool IsServer {
			get { return true; }
		}

		protected override void Initialize ()
		{
			var endpoint = GetEndPoint ();
			if (!IPAddress.IsLoopback (endpoint.Address) && endpoint.Address != IPAddress.Any)
				throw new InvalidOperationException ();

			// openssl.SetCertificate (Certificate.Data, Certificate.Password);
			openssl.SetCertificate (CertificateProvider.GetCertificate (Certificate).GetRawCertData ());
			openssl.Bind (endpoint);
		}

		protected override void CreateConnection ()
		{
			if (MonoParameters != null) {
				if (MonoParameters.ServerCiphers != null)
					openssl.SetCipherList (MonoParameters.ServerCiphers);
			}

			openssl.Accept ();
		}
	}
}

