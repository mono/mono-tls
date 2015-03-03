using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public interface IMonoServerParameters : IServerParameters
	{
		InstrumentCollection ServerInstrumentation {
			get;
		}
	}
}

