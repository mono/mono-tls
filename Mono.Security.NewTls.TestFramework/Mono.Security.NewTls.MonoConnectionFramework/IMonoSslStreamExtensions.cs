using System;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.AsyncTests;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoSslStreamExtensions : IExtensionObject<IMonoSslStream>
	{
		Exception LastError {
			get;
		}

		bool SupportsConnectionInfo {
			get;
		}

		MonoTlsConnectionInfo GetConnectionInfo ();

		Task Shutdown ();

		bool SupportsRenegotiation {
			get;
		}

		Task RequestRenegotiation ();
	}
}

