using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public class ClientParameters : ConnectionParameters, IClientParameters
	{
		public CipherSuiteCollection ClientCiphers {
			get; set;
		}

		public ICertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

