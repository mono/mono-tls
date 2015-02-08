using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IClientParameters : IConnectionParameters
	{
		CipherSuiteCollection ClientCiphers {
			get; set;
		}

		CertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

