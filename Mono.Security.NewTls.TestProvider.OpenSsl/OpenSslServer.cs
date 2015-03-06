﻿using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.NewTls.TestProvider
{
	public class OpenSslServer : OpenSslConnection, IServer
	{
		public ServerCertificate Certificate {
			get;
			private set;
		}

		IServerCertificate IServer.Certificate {
			get { return Certificate; }
		}

		new public IServerParameters Parameters {
			get { return (IServerParameters)base.Parameters; }
		}

		public OpenSslServer (IPEndPoint endpoint, IServerParameters parameters)
			: base (endpoint, parameters)
		{
			Certificate = new ServerCertificate (parameters.ServerCertificate);
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

