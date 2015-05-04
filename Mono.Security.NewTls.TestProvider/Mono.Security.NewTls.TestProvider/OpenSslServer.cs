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

		new public MonoServerParameters Parameters {
			get { return (MonoServerParameters)base.Parameters; }
		}

		IPEndPoint endpoint;

		public OpenSslServer (IPEndPoint endpoint, MonoServerParameters parameters)
			: base (endpoint, parameters)
		{
			this.endpoint = endpoint;
		}

		protected override void Initialize ()
		{
			if (!IPAddress.IsLoopback (endpoint.Address) && endpoint.Address != IPAddress.Any)
				throw new InvalidOperationException ();

			// openssl.SetCertificate (Certificate.Data, Certificate.Password);
			openssl.SetCertificate (CertificateProvider.GetCertificate (Certificate).GetRawCertData ());
			openssl.Bind (endpoint);
		}

		protected override void CreateConnection ()
		{
			if (Parameters.ServerCiphers != null)
				openssl.SetCipherList (Parameters.ServerCiphers);
			openssl.Accept ();
		}
	}
}

