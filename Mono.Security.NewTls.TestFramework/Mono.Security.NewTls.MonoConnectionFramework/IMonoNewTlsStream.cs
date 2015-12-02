using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoNewTlsStream
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

