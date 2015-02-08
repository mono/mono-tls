using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ConnectionHandler
	{
		public IConnection Connection {
			get;
			private set;
		}

		public ConnectionHandler (IConnection connection)
		{
			Connection = connection;
		}

		public abstract Task Run ();
	}
}

