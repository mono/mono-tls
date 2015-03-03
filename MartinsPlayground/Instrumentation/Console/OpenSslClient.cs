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

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class OpenSslClient : OpenSslConnection, IClient
	{
		new public IClientParameters Parameters {
			get { return (IClientParameters)base.Parameters; }
		}

		public OpenSslClient (ClientFactory factory, IPEndPoint endpoint, IClientParameters parameters)
			: base (factory, endpoint, parameters)
		{
		}

		protected override void Initialize ()
		{
			;
		}

		protected override void CreateConnection ()
		{
			if (Parameters.ClientCertificate != null)
				openssl.SetCertificate (Parameters.ClientCertificate.Data, Parameters.ClientCertificate.Password);
			if (Parameters.ClientCiphers != null)
				openssl.SetCipherList (Parameters.ClientCiphers);
			openssl.Connect (EndPoint);
		}

		protected override void Stop ()
		{
			base.Stop ();
		}
	}
}

