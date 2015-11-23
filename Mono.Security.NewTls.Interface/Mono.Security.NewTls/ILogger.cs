using System;

namespace Mono.Security.NewTls
{
	public interface ILogger
	{
		void LogDebug (int level, string format, params object[] args);

		void LogMessage (string format, params object[] args);

		void LogError (string message, Exception error);
	}
}

