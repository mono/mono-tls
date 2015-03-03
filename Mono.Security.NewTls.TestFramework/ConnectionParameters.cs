namespace Mono.Security.NewTls.TestFramework
{
	public class ConnectionParameters : IConnectionParameters
	{
		bool verifyPeerCertificate = true;

		public bool VerifyPeerCertificate {
			get { return verifyPeerCertificate; }
			set { verifyPeerCertificate = value; }
		}

		public bool EnableDebugging {
			get; set;
		}

		public ICertificateAsPEM TrustedCA {
			get; set;
		}
	}
}

