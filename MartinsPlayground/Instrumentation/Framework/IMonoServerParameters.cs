using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;

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

