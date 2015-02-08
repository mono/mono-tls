using System;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.Instrumentation.Framework
{
	public interface ILineBasedStream
	{
		Task<string> ReadLineAsync ();

		Task WriteLineAsync (string line);
	}
}

