using System.Collections.Generic;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public interface IClientParameters : ICommonConnectionParameters
	{
		ICollection<CipherSuiteCode> ClientCiphers {
			get; set;
		}

		CipherSuiteCode? ExpectedCipher {
			get; set;
		}

		IClientCertificate ClientCertificate {
			get; set;
		}
	}
}

