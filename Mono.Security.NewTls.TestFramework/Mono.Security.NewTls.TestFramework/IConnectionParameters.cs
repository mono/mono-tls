using System;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Portable;

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

		ICertificate TrustedCA {
			get; set;
		}
	}
}

