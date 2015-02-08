using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class OpenSslServer : OpenSslConnection, IServer
	{
		public ServerCertificate Certificate {
			get;
			private set;
		}

		new public IServerParameters Parameters {
			get { return (IServerParameters)base.Parameters; }
		}

		public OpenSslServer (ServerFactory factory, IPEndPoint endpoint, ServerCertificate certificate, IServerParameters parameters)
			: base (factory, endpoint, parameters)
		{
			Certificate = certificate;
		}

		protected override void Initialize ()
		{
			if (!IPAddress.IsLoopback (EndPoint.Address) && EndPoint.Address != IPAddress.Any)
				throw new InvalidOperationException ();

			openssl.SetCertificate (Certificate.Data, Certificate.Password);
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

