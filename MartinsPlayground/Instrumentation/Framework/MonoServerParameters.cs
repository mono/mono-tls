using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;

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

