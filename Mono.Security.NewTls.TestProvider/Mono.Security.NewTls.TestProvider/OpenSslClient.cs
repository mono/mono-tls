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
using Xamarin.WebTests.Server;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	public class OpenSslClient : OpenSslConnection, IMonoClient
	{
		ClientParameters IClient.Parameters {
			get { return Parameters; }
		}

		new public MonoClientParameters Parameters {
			get { return (MonoClientParameters)base.Parameters; }
		}

		IPEndPoint endpoint;

		public OpenSslClient (IPEndPoint endpoint, MonoClientParameters parameters)
			: base (endpoint, parameters)
		{
			this.endpoint = endpoint;
		}

		protected override void Initialize ()
		{
			;
		}

		protected override void CreateConnection ()
		{
			if (Parameters.ClientCertificate != null)
				openssl.SetCertificate (CertificateProvider.GetCertificate (Parameters.ClientCertificate).GetRawCertData ());
			if (Parameters.ClientCiphers != null)
				openssl.SetCipherList (Parameters.ClientCiphers);
			openssl.Connect (endpoint);
		}

		protected override void Stop ()
		{
			base.Stop ();
		}
	}
}

