using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Instrumentation;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public class MonoServerParameters : ServerParameters, IMonoServerParameters
	{
		public InstrumentCollection ServerInstrumentation {
			get; set;
		}
	}
}

