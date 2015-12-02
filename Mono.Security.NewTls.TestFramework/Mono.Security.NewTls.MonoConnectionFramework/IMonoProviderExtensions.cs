using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoProviderExtensions
	{
		bool IsNewTls {
			get;
		}

		bool SupportsInstrumentation {
			get;
		}

		IMonoNewTlsStream GetStreamExtension (IMonoSslStream stream);
	}
}

