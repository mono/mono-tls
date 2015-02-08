using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Instrumentation;

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

