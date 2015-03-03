using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class CommonConnectionHandler : ConnectionHandler
	{
		new public ICommonConnection Connection {
			get { return (ICommonConnection)base.Connection; }
		}

		public CommonConnectionHandler (ICommonConnection connection)
			: base (connection)
		{
		}

		public override Task Run ()
		{
			var wrapper = new StreamWrapper (Connection.Stream);
			return MainLoop (wrapper);
		}

		protected abstract Task MainLoop (ILineBasedStream stream);
	}
}

