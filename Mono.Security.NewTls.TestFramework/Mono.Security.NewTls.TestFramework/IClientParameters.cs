using System.Collections.Generic;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public interface IClientParameters : ICommonConnectionParameters
	{
		IClientCertificate ClientCertificate {
			get; set;
		}
	}
}

