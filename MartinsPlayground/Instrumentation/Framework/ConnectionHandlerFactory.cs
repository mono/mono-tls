using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ConnectionHandlerFactory
	{
		public abstract ConnectionHandler Create (IConnection connection);

		public static readonly ConnectionHandlerFactory OkAndDone = new SimpleFactory (c => new OkAndDoneHandler (c));

		public static readonly ConnectionHandlerFactory Echo = new SimpleFactory (c => new EchoHandler (c));

		public static readonly ConnectionHandlerFactory WaitForOkAndDone = new SimpleFactory (c => new WaitForOkAndDoneHandler (c));

		public static readonly ConnectionHandlerFactory HandshakeAndDone = new SimpleFactory (c => new HandshakeAndDoneHandler (c));

		delegate ConnectionHandler FactoryDelegate (IConnection connection);

		class SimpleFactory : ConnectionHandlerFactory
		{
			FactoryDelegate func;

			public SimpleFactory (FactoryDelegate func)
			{
				this.func = func;
			}

			public override ConnectionHandler Create (IConnection connection)
			{
				return func (connection);
			}
		}

		class OkAndDoneHandler : CommonConnectionHandler
		{
			public OkAndDoneHandler (IConnection connection)
				: base ((ICommonConnection)connection)
			{
			}

			protected override async Task MainLoop (ILineBasedStream stream)
			{
				await stream.WriteLineAsync ("OK");
				await Connection.Shutdown (Connection.Factory.SupportsCleanShutdown, true);
				Connection.Dispose ();
			}
		}

		class EchoHandler : CommonConnectionHandler
		{
			public EchoHandler (IConnection connection)
				: base ((ICommonConnection)connection)
			{
			}

			protected override async Task MainLoop (ILineBasedStream stream)
			{
				string line;
				while ((line = await stream.ReadLineAsync ()) != null)
					await stream.WriteLineAsync (line);
			}
		}

		class WaitForOkAndDoneHandler : ClientAndServerHandler
		{
			public WaitForOkAndDoneHandler (IConnection connection)
				: base ((ClientAndServer)connection)
			{
			}

			protected override async Task MainLoop (ILineBasedStream serverStream, ILineBasedStream clientStream)
			{
				await serverStream.WriteLineAsync ("OK");
				var line = await clientStream.ReadLineAsync ();
				if (!line.Equals ("OK"))
					throw new ConnectionException ("Got unexpected output '{0}'", line);
				await Connection.Shutdown (Connection.Factory.SupportsCleanShutdown, true);
				Connection.Dispose ();
			}
		}

		class HandshakeAndDoneHandler : ClientAndServerHandler
		{
			public HandshakeAndDoneHandler (IConnection connection)
				: base ((ClientAndServer)connection)
			{
			}

			protected override async Task MainLoop (ILineBasedStream serverStream, ILineBasedStream clientStream)
			{
				await serverStream.WriteLineAsync ("SERVER OK");
				var line = await clientStream.ReadLineAsync ();
				if (!line.Equals ("SERVER OK"))
					throw new ConnectionException ("Got unexpected output from server: '{0}'", line);
				await clientStream.WriteLineAsync ("CLIENT OK");
				line = await serverStream.ReadLineAsync ();
				if (!line.Equals ("CLIENT OK"))
					throw new ConnectionException ("Got unexpected output from client: '{0}'", line);
				await Connection.Shutdown (Connection.Factory.SupportsCleanShutdown, true);
				Connection.Dispose ();
			}
		}

	}
}

