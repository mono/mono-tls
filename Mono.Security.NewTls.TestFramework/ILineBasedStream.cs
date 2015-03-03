using System;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public interface ILineBasedStream
	{
		Task<string> ReadLineAsync ();

		Task WriteLineAsync (string line);
	}
}

