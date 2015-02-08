using System;
using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public interface ICryptoTestProvider
	{
		byte[] TestPRF (HandshakeHashType algorithm, byte[] secret, string seed, byte[] data, int length);

		byte[] TestDigest (HandshakeHashType algorithm, byte[] data);

		bool SupportsEncryption {
			get;
		}

		ICryptoTestContext CreateContext ();
	}
}

