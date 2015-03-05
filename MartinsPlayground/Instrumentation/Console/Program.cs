using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using TLS = Mono.Security.NewTls;
using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Mono.Security.NewTls.TestFramework;
using NUnit.Core;
using NUnit.ConsoleRunner;
using NDesk.Options;
using C = System.Console;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;
	using Resources;
	using Tests;

	public class MainClass
	{
		public TestConfiguration Configuration {
			get;
			private set;
		}

		static void Main (string[] args)
		{
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

			var main = new MainClass ();
			main.Run (args);
		}

		MainClass ()
		{
			Configuration = TestConfiguration.DangerousGetInstance ();

			var provider = new NewTlsProvider ();
			MSI.MonoTlsProviderFactory.InstallProvider (provider);
		}

		protected virtual void Run (string[] args)
		{
			if (args.Length == 0) {
				Work ();
				return;
			}

			var mode = args [0];
			var newArgs = new ArraySegment<string> (args, 1, args.Length - 1);

			switch (mode) {
			#if FIXME
			case "client":
				Client (newArgs.ToArray ());
				break;
			case "server":
				Server (args);
				break;
			case "connection":
				Connection (newArgs.ToArray ());
				break;
			#endif
			case "test":
				RunTests (newArgs.ToArray ());
				break;
			case "work":
				Work ();
				break;
			case "generate":
				CryptoTest.Generate (new NativeCryptoTest ());
				break;
			case "generate-cbc":
				GenerateCbc (args [1]);
				break;
			case "generate-gcm":
				GenerateGcm (args [1]);
				break;
			default:
				throw new InvalidOperationException ();
			}
		}

		void Work ()
		{
			// Connection ("-server=openssl", "-client=openssl", "-verbose");
			// RunTests ("-include=One", "-server=mono", "-client=mono", "-verbose");
			// Client ("--client=mono", "-verbose");
			// RunTests ("-server=mono", "-client=mono", "-include=Martin");
			RunTests ("-include=Martin");
		}

		void GenerateCbc (string filename)
		{
			using (var writer = new StreamWriter (filename)) {
				var testCbc = new TestCbcBlockCipher (Configuration, new MonoCryptoTest ());
				testCbc.Generate (writer);
			}
		}

		void GenerateGcm (string filename)
		{
			using (var writer = new StreamWriter (filename)) {
				var testGcm = new TestGaloisCounterCipher (Configuration, new MonoCryptoTest ());
				testGcm.Generate (writer);
			}
		}

		#if FIXME
		static void Client (params string[] args)
		{
			ClientFactory factory = Factory.DotNetClient;;
			int repeat = 0;

			var parameters = new ClientParameters ();
			parameters.VerifyPeerCertificate = false;

			var p = new OptionSet {
				{ "client=", v => factory = ConnectionFactoryProvider.GetClientFactory (v) },
				{ "verbose", v => parameters.EnableDebugging = true },
				{ "verify", v => parameters.VerifyPeerCertificate = true }
			};
			var extra = p.Parse (args);
			if (extra.Count != 0)
				throw new InvalidOperationException ();

			if (parameters.VerifyPeerCertificate)
				parameters.TrustedCA = ResourceManager.LocalCACertificate;

			if (repeat < 0)
				repeat = int.MaxValue;
			else if (repeat == 0)
				repeat = 1;

			for (int i = 0; i < repeat; i++) {
				RunClient (factory, parameters).Wait ();
			}
		}

		static void Server (string[] args)
		{
			var newArgs = new ArraySegment<string> (args, 1, args.Length - 1);
			ServerFactory factory = Factory.MonoServer;
			int repeat = 0;

			var parameters = new ServerParameters ();

			var p = new OptionSet {
				{ "server=", v => factory = ConnectionFactoryProvider.GetServerFactory (v) },
				{ "verbose", v => parameters.EnableDebugging = true },
				{ "repeat", (int v) => repeat = v }
			};
			var extra = p.Parse (newArgs);
			if (extra.Count != 0)
				throw new InvalidOperationException ();

			if (repeat < 0)
				repeat = int.MaxValue;
			else if (repeat == 0)
				repeat = 1;

			for (int i = 0; i < repeat; i++) {
				RunServer (factory, parameters).Wait ();
			}
		}

		void Connection (params string[] args)
		{
			int repeat = 0;

			var clientFactory = Factory.OpenSslClient;
			var serverFactory = Factory.OpenSslServer;

			var parameters = new ClientAndServerParameters ();
			parameters.VerifyPeerCertificate = false;
			parameters.TrustedCA = ResourceManager.LocalCACertificate;

			var p = new OptionSet {
				{ "verbose", v => parameters.EnableDebugging = true },
				{ "repeat=", (int v) => repeat = v },
				{ "client=", v => clientFactory = ConnectionFactoryProvider.GetClientFactory (v) },
				{ "server=", v => serverFactory = ConnectionFactoryProvider.GetServerFactory (v) },
				{ "verify", v => parameters.VerifyPeerCertificate = true },
				{ "ask-for-cert", v => parameters.AskForClientCertificate = true },
				{ "require-cert", v => parameters.RequireClientCertificate = true }
			};
			var extra = p.Parse (args);
			if (extra.Count != 0)
				throw new InvalidOperationException ();

			if (repeat < 0)
				repeat = int.MaxValue;
			else if (repeat == 0)
				repeat = 1;

			var factory = new ClientAndServerFactory (serverFactory, clientFactory);

			for (int i = 0; i < repeat; i++) {
				RunWithLocalServer (factory, parameters).Wait ();
			}
		}


		static ClientParameters GetClientParameters ()
		{
			var clientParameters = new ClientParameters ();

			clientParameters.VerifyPeerCertificate = false;
			clientParameters.TrustedCA = ResourceManager.LocalCACertificate;
			return clientParameters;
		}

		static ClientAndServerParameters GetClientAndServerParameters ()
		{
			return new ClientAndServerParameters {
				VerifyPeerCertificate = false, TrustedCA = ResourceManager.LocalCACertificate
			};
		}

		void LocalLoop (ClientAndServerFactory factory)
		{
			while (true) {
				RunWithLocalServer (factory).Wait ();
			}
		}

		Task RunWithLocalServer (ClientAndServerFactory factory)
		{
			var parameters = GetClientAndServerParameters ();
			return RunWithLocalServer (factory, parameters);
		}
		#endif

		protected void PrintError (Exception ex)
		{
			var aggregate = ex as AggregateException;
			if (aggregate == null) {
				PrintSingleError (ex);
				Environment.Exit (255);
			}

			C.WriteLine ("ERROR: {0}", aggregate.Message);
			foreach (var inner in aggregate.InnerExceptions) {
				if (inner is TaskCanceledException)
					continue;
				PrintSingleError (inner);
			}
			Environment.Exit (255);
		}

		protected virtual void PrintSingleError (Exception ex)
		{
			var tlsEx = ex as TLS.TlsException;
			if (tlsEx != null) {
				C.WriteLine ("TLS EXCEPTION: {0}", tlsEx.Alert.Description);
				return;
			}

			C.WriteLine ("ERROR: {0}", ex);
		}

		async Task RunWithLocalServer (ClientAndServerFactory factory, ClientAndServerParameters parameters)
		{
			try {
				var connection = (IClientAndServer)await factory.Start (parameters);
				var handler = ClientAndServerHandlerFactory.WaitForOkAndDone.Create (connection.Server, connection.Client);
				await handler.Run ();
				connection.Dispose ();
			} catch (Exception ex) {
				PrintError (ex);
			}
		}

		static void ServerLoop (ServerFactory factory, ServerParameters parameters)
		{
			while (true) {
				RunServer (factory, parameters).Wait ();
			}
		}

		static async Task RunServer (ServerFactory factory, ServerParameters parameters)
		{
			using (var server = await factory.Start (parameters)) {
				var handler = ConnectionHandlerFactory.Echo.Create (server);
				await handler.Run ();
			}
		}

		static void ClientLoop (ClientFactory factory, ClientParameters parameters)
		{
			for (int i = 0; i < 10; i++) {
				RunClient (factory, parameters).Wait ();
				Thread.Sleep (500);
			}
		}

		static async Task RunClient (ClientFactory factory, ClientParameters parameters)
		{
			using (var client = await factory.Start (parameters)) {
				var handler = ConnectionHandlerFactory.Echo.Create (client);
				await handler.Run ();
			}
		}

		static IPEndPoint ParseEndPoint (string text)
		{
			var pos = text.IndexOf (":");
			if (pos < 0)
				return new IPEndPoint (IPAddress.Parse (text), 4433);
			var address = IPAddress.Parse (text.Substring (0, pos));
			var port = int.Parse (text.Substring (pos + 1));
			return new IPEndPoint (address, port);
		}

		void RunTests (params string[] args)
		{
			string clientArg = null;
			string serverArg = null;

			var p = new OptionSet {
				{ "verbose", v => Configuration.EnableDebugging = true },
				{ "client=", v => clientArg = v },
				{ "server=", v => serverArg = v }
			};
			var extra = p.Parse (args);

			Configuration.RegisterProvider (ConnectionFactoryProvider.GetClientAndServer (clientArg, serverArg));
			Configuration.RegisterProvider (new CryptoTestFactory ("mono"));

			RunTestSuite (extra);
		}

		void RunTestSuite (IList<string> extra)
		{
			var nunitArgs = new List<string> ();
			nunitArgs.Add ("-domain=none");
			nunitArgs.Add ("-nologo");
			nunitArgs.Add ("-noresult");
			nunitArgs.Add (typeof(AddIn).Assembly.Location);
			nunitArgs.AddRange (extra);

			NUnit.ConsoleRunner.Runner.Main (nunitArgs.ToArray ());
		}
	}
}
