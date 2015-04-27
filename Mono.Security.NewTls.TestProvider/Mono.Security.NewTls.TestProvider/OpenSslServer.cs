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

namespace Mono.Security.NewTls.TestProvider
{
	public class OpenSslServer : OpenSslConnection, IServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		IServerParameters IServer.Parameters {
			get { return Parameters; }
		}

		new public IMonoServerParameters Parameters {
			get { return (IMonoServerParameters)base.Parameters; }
		}

		public OpenSslServer (IPEndPoint endpoint, IMonoServerParameters parameters)
			: base (endpoint, parameters.ConnectionParameters)
		{
		}

		protected override void Initialize ()
		{
			if (!IPAddress.IsLoopback (EndPoint.Address) && EndPoint.Address != IPAddress.Any)
				throw new InvalidOperationException ();

			// openssl.SetCertificate (Certificate.Data, Certificate.Password);
			openssl.SetCertificate (CertificateProvider.GetCertificate (Certificate).GetRawCertData ());
			openssl.Bind (EndPoint);
		}

		protected override void CreateConnection ()
		{
			if (Parameters.ServerCiphers != null)
				openssl.SetCipherList (Parameters.ServerCiphers);
			openssl.Accept ();
		}
	}
}

