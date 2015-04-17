using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;

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

		protected ConnectionParameters (ConnectionParameters other)
		{
			Identifier = other.Identifier;
			verifyPeerCertificate = other.verifyPeerCertificate;
			EnableDebugging = other.EnableDebugging;
			TrustedCA = other.TrustedCA;
		}

		public bool VerifyPeerCertificate {
			get { return verifyPeerCertificate; }
			set { verifyPeerCertificate = value; }
		}

		public bool EnableDebugging {
			get; set;
		}

		public ICertificate TrustedCA {
			get; set;
		}

	}
}

