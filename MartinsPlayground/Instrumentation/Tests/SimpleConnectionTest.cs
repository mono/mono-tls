using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using NUnit.Framework;
using NUnit.Core;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using System.Security.Authentication;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;
	using Resources;

	class SimpleConnectionTest : ConnectionTest
	{
		public SimpleConnectionTest (TestConfiguration config, ClientAndServerFactory factory)
			: base (config, factory)
		{
		}

		[Test]
		[Category ("Simple")]
		public async void CheckCipherSuite ()
		{
			if (!Factory.HasConnectionInfo)
				throw new IgnoreException ("Current implementation does not support ConnectionInfo.");

			var expectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;

			await Run (new ClientAndServerParameters {
				VerifyPeerCertificate = false
			}, connection => {
				var connectionInfo = connection.Server.GetConnectionInfo ();
				Assert.That (connectionInfo, Is.Not.Null, "#1");
				Assert.That (connectionInfo.CipherCode, Is.EqualTo (expectedCipher), "#2");
			});
		}

		IEnumerable<CipherSuiteCode> GetAllCipherCodes ()
		{
			// Galois-Counter Cipher Suites.
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;

			// Galois-Counter with Legacy RSA Key Exchange.
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384;

			// Diffie-Hellman Cipher Suites
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;

			// Legacy AES Cipher Suites
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
		}

		[Test]
		[Category ("Simple")]
		[TestCaseSource ("GetAllCipherCodes")]
		public async void TestAllCiphers (CipherSuiteCode code)
		{
			if (!Factory.CanSelectCiphers)
				throw new IgnoreException ("Current implementation does not let us select ciphers.");

			var requestedCiphers = new CipherSuiteCode[] { code };

			await Run (new ClientAndServerParameters {
				VerifyPeerCertificate = false,
				ClientCiphers = requestedCiphers
			}, connection => {
				var connectionInfo = connection.Server.GetConnectionInfo ();
				Assert.That (connectionInfo, Is.Not.Null, "#1");
				Assert.That (connectionInfo.CipherCode, Is.EqualTo (code), "#2");
			});
		}

		[Test]
		[Category ("Martin")]
		public async void TestInvalidCipher ()
		{
			if (!Factory.CanSelectCiphers)
				throw new IgnoreException ("Current implementation does not let us select ciphers.");

			var requestedCipher = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 };
			var supportedCipher = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA };

			await ExpectAlert (new ClientAndServerParameters {
				VerifyPeerCertificate = false, ClientCiphers = requestedCipher, ServerCiphers = supportedCipher
			}, AlertDescription.HandshakeFailure);
		}

		void ExpectAlert (Task t, AlertDescription expectedAlert, string message)
		{
			Assert.That (t.IsFaulted, Is.True, "#1:" + message);
			var baseException = t.Exception.GetBaseException ();
			if (baseException is AggregateException) {
				var aggregate = baseException as AggregateException;
				Assert.That (aggregate.InnerExceptions.Count, Is.EqualTo (2), "#2a:" + message);
				Assert.That (aggregate.InnerExceptions [0], Is.InstanceOf<AuthenticationException> (), "#2b:" + message);
				baseException = aggregate.InnerExceptions [1];
			}
			Assert.That (baseException, Is.InstanceOf<TlsException> (), "#2:" + message);
			var alert = ((TlsException)baseException).Alert;
			Assert.That (alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3:" + message);
			Assert.That (alert.Description, Is.EqualTo (expectedAlert), "#4:" + message);
		}

		async Task ExpectAlert (ClientAndServerParameters parameters, AlertDescription alert)
		{
			if (Configuration.EnableDebugging)
				parameters.EnableDebugging = true;
			using (var connection = (ClientAndServer)Factory.Create (parameters)) {
				await connection.Server.Start ();
				await connection.Client.Start ();

				var serverTask = connection.Server.WaitForConnection ();
				var clientTask = connection.Client.WaitForConnection ();

				var t1 = clientTask.ContinueWith (t => ExpectAlert (t, alert, "client"));
				var t2 = serverTask.ContinueWith (t => ExpectAlert (t, alert, "server"));

				await Task.WhenAll (t1, t2);
			}
		}

		async Task Run (ClientAndServerParameters parameters, Action<ClientAndServer> action = null)
		{
			try {
				if (Configuration.EnableDebugging)
					parameters.EnableDebugging = true;
				using (var connection = (ClientAndServer)await Factory.Start (parameters)) {
					if (action != null)
						action (connection);
					var handler = ConnectionHandlerFactory.HandshakeAndDone.Create (connection);
					await handler.Run ();
				}
			} catch (Exception ex) {
				DebugHelper.WriteLine ("ERROR: {0} {1}", ex.GetType (), ex);
				throw;
			}
		}
	}
}
