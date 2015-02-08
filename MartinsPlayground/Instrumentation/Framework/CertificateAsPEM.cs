using System;

namespace Mono.Security.Instrumentation.Framework
{
	public class CertificateAsPEM : PrivateFile
	{
		public CertificateAsPEM (byte[] data)
			: base (data, null)
		{
		}
	}
}

