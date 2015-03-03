using System;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	public class CertificateAsPEM : PrivateFile, ICertificateAsPEM
	{
		public CertificateAsPEM (byte[] data)
			: base (data, null)
		{
		}
	}
}

