using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestFramework
{
	public class ConnectionParameters : IConnectionParameters, ITestParameter
	{
		bool verifyPeerCertificate = true;

		public string Identifier {
			get;
			private set;
		}

		string ITestParameter.Value {
			get { return Identifier; }
		}

		public ConnectionParameters (string identifier)
		{
			Identifier = identifier;
		}

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

