using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public class ClientParameters : ConnectionParameters, IClientParameters
	{
		public CipherSuiteCollection ClientCiphers {
			get; set;
		}

		public CertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

