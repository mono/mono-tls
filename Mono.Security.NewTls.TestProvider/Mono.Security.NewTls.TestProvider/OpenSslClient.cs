using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls.TestFramework;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	public class OpenSslClient : OpenSslConnection, IMonoClient
	{
		public MonoConnectionParameters MonoParameters {
			get { return base.Parameters as MonoConnectionParameters; }
		}

		public OpenSslClient (OpenSslConnectionProvider provider, ConnectionParameters parameters)
			: base (provider, parameters)
		{
		}

		protected override bool IsServer {
			get { return false; }
		}

		protected override void Initialize ()
		{
			;
		}

		protected override void CreateConnection (TestContext ctx)
		{
			var endpoint = GetEndPoint ();
			if (Parameters.ClientCertificate != null) {
				var provider = DependencyInjector.Get<ICertificateProvider> ();
				string password;
				var data = provider.GetRawCertificateData (Parameters.ClientCertificate, out password);
				openssl.SetCertificate (data, password);
			}

			if (MonoParameters != null)
				SelectCiphers (ctx, MonoParameters.ClientCiphers);

			openssl.Connect (endpoint);
		}

		protected override void Stop ()
		{
			base.Stop ();
		}
	}
}

