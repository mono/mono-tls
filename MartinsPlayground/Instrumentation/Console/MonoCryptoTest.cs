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

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public class MonoCryptoTest : ICryptoTestProvider
	{
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

