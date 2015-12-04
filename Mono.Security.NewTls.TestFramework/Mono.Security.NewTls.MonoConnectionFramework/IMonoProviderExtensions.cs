using System;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.AsyncTests;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoProviderExtensions : IExtensionObject<MonoTlsProvider>
	{
		bool IsNewTls {
			get;
		}

		bool SupportsMonoExtensions {
			get;
		}

		bool SupportsInstrumentation {
			get;
		}

		IMonoNewTlsStream GetStreamExtension (IMonoSslStream stream);
	}
}

