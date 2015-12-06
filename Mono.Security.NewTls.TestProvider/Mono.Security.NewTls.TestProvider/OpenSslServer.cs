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
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	public class OpenSslServer : OpenSslConnection, IMonoServer
	{
		public IServerCertificate Certificate {
			get { return Parameters.ServerCertificate; }
		}

		public MonoConnectionParameters MonoParameters {
			get { return base.Parameters as MonoConnectionParameters; }
		}

		public OpenSslServer (OpenSslConnectionProvider provider, ConnectionParameters parameters)
			: base (provider, parameters)
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

			var provider = DependencyInjector.Get<ICertificateProvider> ();

			string password;
			var data = provider.GetRawCertificateData (Certificate, out password);
			openssl.SetCertificate (data, password);
			openssl.Bind (endpoint);
		}

		protected override void CreateConnection (TestContext ctx)
		{
			if (MonoParameters != null)
				SelectCiphers (ctx, MonoParameters.ServerCiphers);

			openssl.Accept ();
		}
	}
}

