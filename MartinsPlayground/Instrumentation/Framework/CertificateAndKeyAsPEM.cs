using System;

namespace Mono.Security.Instrumentation.Framework
{
	public class CertificateAndKeyAsPEM : PrivateFile
	{
		public CertificateAndKeyAsPEM (string filename, string password)
			: base (filename, password)
		{
		}
	}
}

