using System;

namespace Mono.Security.NewTls.Cipher
{
	[CLSCompliant (false)]
	public static class CipherSuiteFactory
	{
		internal static CipherSuite CreateCipherSuite (TlsProtocolCode protocol, CipherSuiteCode code)
		{
			if (protocol == TlsProtocolCode.Tls12)
				return CreateCipherSuiteTls12 (code);
			else if (protocol == TlsProtocolCode.Tls10)
				return CreateCipherSuiteTls10 (code);
			else
				throw new TlsException (AlertDescription.ProtocolVersion);
		}

		static CipherSuite CreateCipherSuiteTls12 (CipherSuiteCode code)
		{
			// Sanity check.
			if (!IsCipherSupported (TlsProtocolCode.Tls12, code))
				throw new TlsException (AlertDescription.InsuficientSecurity, "Unknown cipher suite: {0}", code);

			switch (code) {
			// Galois-Counter Cipher Suites
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.AesGcm256, HashAlgorithmType.Sha384, ExchangeAlgorithmType.DiffieHellman);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.AesGcm128, HashAlgorithmType.Sha256, ExchangeAlgorithmType.DiffieHellman);

			// Diffie-Hellman Cipher Suites
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha256, ExchangeAlgorithmType.DiffieHellman);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha256, ExchangeAlgorithmType.DiffieHellman);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha1, ExchangeAlgorithmType.DiffieHellman);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha1, ExchangeAlgorithmType.DiffieHellman);

			// Galois-Counter with Legacy RSA Key Exchange
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.AesGcm128, HashAlgorithmType.Sha256, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.AesGcm256, HashAlgorithmType.Sha384, ExchangeAlgorithmType.RsaSign);

			// AES Cipher Suites
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha256, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha256, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA:
				return new TlsCipherSuite12 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaSign);

			default:
				throw new TlsException (AlertDescription.InsuficientSecurity, "Unknown cipher suite: {0}", code);
			}
		}

		static CipherSuite CreateCipherSuiteTls10 (CipherSuiteCode code)
		{
			// Sanity check.
			if (!IsCipherSupported (TlsProtocolCode.Tls10, code))
				throw new TlsException (AlertDescription.InsuficientSecurity, "Unknown cipher suite: {0}", code);

			switch (code) {
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA:
				return new TlsCipherSuite10 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA:
				return new TlsCipherSuite10 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaSign);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
				return new TlsCipherSuite10 (code, CipherAlgorithmType.Aes256, HashAlgorithmType.Sha1, ExchangeAlgorithmType.DiffieHellman);
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
				return new TlsCipherSuite10 (code, CipherAlgorithmType.Aes128, HashAlgorithmType.Sha1, ExchangeAlgorithmType.DiffieHellman);
			default:
				throw new TlsException (AlertDescription.InsuficientSecurity, "Unknown cipher suite: {0}", code);
			}
		}

		public static bool IsCipherSupported (TlsProtocolCode protocol, CipherSuiteCode code)
		{
			var array = GetSupportedCiphersArray (protocol);
			for (int i = 0; i < array.Length; i++)
				if (array [i] == code)
					return true;
			return false;
		}

		public static CipherSuiteCollection GetDefaultCiphers (TlsProtocolCode protocol)
		{
			return new CipherSuiteCollection (protocol, GetDefaultCiphersArray (protocol));
		}

		public static CipherSuiteCollection GetSupportedCiphers (TlsProtocolCode protocol)
		{
			return new CipherSuiteCollection (protocol, GetSupportedCiphersArray (protocol));
		}

		internal static CipherSuiteCode[] GetDefaultCiphersArray (TlsProtocolCode protocol)
		{
			if (protocol == TlsProtocolCode.Tls12)
				return DefaultCiphersTls12;
			else if (protocol == TlsProtocolCode.Tls10)
				return DefaultCiphersTls10;
			else
				throw new TlsException (AlertDescription.ProtocolVersion);
		}

		internal static CipherSuiteCode[] GetSupportedCiphersArray (TlsProtocolCode protocol)
		{
			if (protocol == TlsProtocolCode.Tls12)
				return SupportedCiphersTls12;
			else if (protocol == TlsProtocolCode.Tls10)
				return SupportedCiphersTls10;
			else
				throw new TlsException (AlertDescription.ProtocolVersion);
		}

		static readonly CipherSuiteCode[] SupportedCiphersTls12 = {
			// Galois-Counter Cipher Suites
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,

			// Diffie-Hellman Cipher Suites
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

			//
			// LEGACY CIPHERS with RSA Key Exchange.
			//

			// Legacy RSA Cipher Suites
			CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384,

			// Legacy AES Cipher Suites
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
		};

		static readonly CipherSuiteCode[] SupportedCiphersTls10 = {
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
		};

		// Currently the same as SupportedCiphers12, but we may change this in future.
		static readonly CipherSuiteCode[] DefaultCiphersTls12 = SupportedCiphersTls12;
		static readonly CipherSuiteCode[] DefaultCiphersTls10 = SupportedCiphersTls10;
	}
}

