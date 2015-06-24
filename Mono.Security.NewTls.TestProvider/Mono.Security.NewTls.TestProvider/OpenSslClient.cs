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
		ClientParameters IClient.Parameters {
			get { return Parameters; }
		}

		new public ClientParameters Parameters {
			get { return (ClientParameters)base.Parameters; }
		}

		public MonoClientParameters MonoParameters {
			get { return base.Parameters as MonoClientParameters; }
		}

		public OpenSslClient (OpenSslConnectionProvider provider, ClientParameters parameters)
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

		protected override void CreateConnection ()
		{
			var endpoint = GetEndPoint ();
			if (Parameters.ClientCertificate != null)
				openssl.SetCertificate (CertificateProvider.GetCertificate (Parameters.ClientCertificate).GetRawCertData ());

			if (MonoParameters != null) {
				if (MonoParameters.ClientCiphers != null)
					openssl.SetCipherList (MonoParameters.ClientCiphers);
			}

			openssl.Connect (endpoint);
		}

		protected override void Stop ()
		{
			base.Stop ();
		}
	}
}

