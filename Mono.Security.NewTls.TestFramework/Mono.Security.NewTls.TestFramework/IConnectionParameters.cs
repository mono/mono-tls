using System;

namespace Mono.Security.NewTls.TestFramework
{
	public interface IConnectionParameters
	{
		bool VerifyPeerCertificate {
			get; set;
		}

		bool EnableDebugging {
			get; set;
		}

		ICertificateAsPEM TrustedCA {
			get; set;
		}
	}
}

