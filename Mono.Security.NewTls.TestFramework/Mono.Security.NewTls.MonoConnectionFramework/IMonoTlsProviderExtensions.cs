using System;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.AsyncTests;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoTlsProviderExtensions : IExtensionObject<MonoTlsProvider>
	{
		bool IsNewTls {
			get;
		}

		bool SupportsInstrumentation {
			get;
		}
	}
}

