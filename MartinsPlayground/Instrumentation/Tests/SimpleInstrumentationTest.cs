using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;
using Mono.Security.NewTls.Negotiation;
using Mono.Security.NewTls.Handshake;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;
	using Resources;

	[Explicit]
	[Category ("NotWorking")]
	[ConnectionFactoryParameters (ConnectionType.MonoClient | ConnectionType.MonoServer)]
	class SimpleInstrumentationTest : ConnectionTest
	{
		public SimpleInstrumentationTest (TestConfiguration config, ClientAndServerFactory factory)
			: base (config, factory)
		{
		}

		[Test]
		[Category ("Work")]
		public async void Hello ()
		{
			RequireMonoServer ();

			var parameters = new MonoClientAndServerParameters {
				RequireClientCertificate = true, ClientCertificate = ResourceManager.MonkeyCertificate,
				TrustedCA = ResourceManager.LocalCACertificate, VerifyPeerCertificate = true
			};

			parameters.ServerInstrumentation.Add (NegotiationState.InitialServerConnection, c => new ServerConnectionHandler (c, false));

			await Run (parameters);
		}

		[Test]
		[Category ("Work2")]
		public async void HelloClient ()
		{
			RequireMonoClient ();

			var certParams = new ClientCertificateParameters ();
			certParams.SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa));
			certParams.EnsureDefaultValues ();

			var parameters = new MonoClientAndServerParameters {
				RequireClientCertificate = true, ClientCertificate = ResourceManager.MonkeyCertificate,
				TrustedCA = ResourceManager.LocalCACertificate, VerifyPeerCertificate = true,
				ClientCertificateParameters = certParams
			};

			parameters.ClientInstrumentation.Add (NegotiationState.ServerHello, c => new ServerHelloHandler (c));

			await Run (parameters);
		}

		void RequireMonoClient ()
		{
			if (!Factory.ClientFactory.IsMono)
				throw new IgnoreException ("Instrumentation requires Mono.");
		}

		void RequireMonoServer ()
		{
			if (!Factory.ServerFactory.IsMono)
				throw new IgnoreException ("Instrumentation requires Mono.");
		}

		class ServerConnectionHandler : ServerConnection
		{
			public ServerConnectionHandler (TlsContext context, bool renegotiating)
				: base (context, renegotiating)
			{
			}

			protected override SignatureAndHashAlgorithm SelectSignatureAlgorithm ()
			{
				var algorithm = base.SelectSignatureAlgorithm ();
				DebugHelper.WriteLine ("SIGNATURE ALGORITHM: {0}", algorithm);
				algorithm = new SignatureAndHashAlgorithm (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa);
				DebugHelper.WriteLine ("NEW SIGNATURE ALGORITHM: {0}", algorithm);
				return algorithm;
			}

			protected override TlsCertificateRequest GenerateCertificateRequest ()
			{
				var parameters = new ClientCertificateParameters ();
				parameters.CertificateTypes.Add (ClientCertificateType.RsaFixedDh);
				DebugHelper.WriteLine ("CERTIFICATE REQUEST");
				parameters.SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Md5, SignatureAlgorithmType.ECDsa));
				parameters.CertificateAuthorities.Add ("CN=NotExisting");
				return new TlsCertificateRequest (parameters);
			}

			protected override MessageStatus HandleMessage (Message message)
			{
				DebugHelper.WriteLine ("TEST HANDLE MESSAGE: {0}", message);
				return base.HandleMessage (message);
			}
		}

		class ServerHelloHandler : ServerHello
		{
			public ServerHelloHandler (TlsContext context)
				: base (context)
			{
			}

			protected override SignatureAndHashAlgorithm SelectSignatureType ()
			{
				var algorithm = base.SelectSignatureType ();
				DebugHelper.WriteLine ("SIGNATURE ALGORITHM: {0}", algorithm);
				algorithm = new SignatureAndHashAlgorithm (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa);
				DebugHelper.WriteLine ("NEW SIGNATURE ALGORITHM: {0}", algorithm);
				return algorithm;
			}
		}

		async Task Run (ClientAndServerParameters parameters)
		{
			if (Configuration.EnableDebugging)
				parameters.EnableDebugging = true;
			var connection = await Factory.Start (parameters);
			connection.Dispose ();
		}
	}
}
