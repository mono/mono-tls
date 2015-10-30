using System;

namespace Mono.Security.NewTls
{
	public interface ILogger
	{
		void LogMessage (string format, params object[] args);
	}
}

