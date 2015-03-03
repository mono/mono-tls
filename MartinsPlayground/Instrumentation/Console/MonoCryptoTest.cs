using System;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class MonoCryptoTest : ICryptoTestHost
	{
		System.Threading.Tasks.Task Xamarin.AsyncTests.ITestInstance.Initialize (Xamarin.AsyncTests.TestContext ctx, System.Threading.CancellationToken cancellationToken)
		{
			throw new NotImplementedException ();
		}

		System.Threading.Tasks.Task Xamarin.AsyncTests.ITestInstance.PreRun (Xamarin.AsyncTests.TestContext ctx, System.Threading.CancellationToken cancellationToken)
		{
			throw new NotImplementedException ();
		}

		System.Threading.Tasks.Task Xamarin.AsyncTests.ITestInstance.PostRun (Xamarin.AsyncTests.TestContext ctx, System.Threading.CancellationToken cancellationToken)
		{
			throw new NotImplementedException ();
		}

		System.Threading.Tasks.Task Xamarin.AsyncTests.ITestInstance.Destroy (Xamarin.AsyncTests.TestContext ctx, System.Threading.CancellationToken cancellationToken)
		{
			throw new NotImplementedException ();
		}

		byte[] ICryptoTestHost.GetRandomBytes (int count)
		{
			throw new NotImplementedException ();
		}

		public byte[] TestPRF (HandshakeHashType algorithm, byte[] secret, string seed, byte[] data, int length)
		{
			var prf = new PseudoRandomFunctionTls12 (algorithm);

			var result = prf.PRF (new SecureBuffer (secret), seed, new SecureBuffer (data), length);
			return result.StealBuffer ();
		}

		HashAlgorithm CreateHash (HandshakeHashType algorithm)
		{
			switch (algorithm) {
			case HandshakeHashType.SHA256:
				return SHA256.Create ();
			case HandshakeHashType.SHA384:
				return SHA384.Create ();
			default:
				throw new NotSupportedException ();
			}
		}

		public byte[] TestDigest (HandshakeHashType algorithm, byte[] data)
		{
			var hash = CreateHash (algorithm);
			hash.TransformFinalBlock (data, 0, data.Length);
			return hash.Hash;
		}

		public bool SupportsEncryption {
			get { return true; }
		}

		public ICryptoTestContext CreateContext ()
		{
			return new MonoCryptoContext (TlsProtocolCode.Tls12, true);
		}
	}
}

