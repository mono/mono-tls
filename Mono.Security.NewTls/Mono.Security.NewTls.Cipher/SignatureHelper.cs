using System;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using MSC = Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	internal static class SignatureHelper
	{
		public static SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, byte[] hash, AsymmetricAlgorithm key)
		{
			if (type.Signature != SignatureAlgorithmType.Rsa)
				throw new TlsException (AlertDescription.IlegalParameter);
			return CreateSignature (type.Hash, hash, key);
		}

		public static SecureBuffer CreateSignature (HashAlgorithmType type, byte[] hash, AsymmetricAlgorithm key)
		{
			return new SecureBuffer (MSC.PKCS1.Sign_v15 ((RSA)key, type, hash));
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, byte[] hash, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (type.Signature != SignatureAlgorithmType.Rsa)
				throw new TlsException (AlertDescription.IlegalParameter);
			return VerifySignature (type.Hash, hash, key, signature);
 		}

		public static bool VerifySignature (HashAlgorithmType type, byte[] hash, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			return MSC.PKCS1.Verify_v15 ((RSA)key, type, hash, signature.Buffer);
		}

		public static bool IsAlgorithmSupported (SignatureAndHashAlgorithm algorithm)
		{
			if (algorithm.Signature != SignatureAlgorithmType.Rsa)
				return false;
			switch (algorithm.Hash) {
			case HashAlgorithmType.Md5:
			case HashAlgorithmType.Sha512:
			case HashAlgorithmType.Sha384:
			case HashAlgorithmType.Sha256:
			case HashAlgorithmType.Sha224:
			case HashAlgorithmType.Sha1:
				return true;
			default:
				return false;
			}
		}

		public static SignatureAndHashAlgorithm DecodeSignatureAndHashAlgorithm (TlsBuffer buffer)
		{
			var hash = (HashAlgorithmType)buffer.ReadByte ();
			var signature = (SignatureAlgorithmType)buffer.ReadByte ();
			return new SignatureAndHashAlgorithm (hash, signature);
		}

		public static void EncodeSignatureAndHashAlgorithm (SignatureAndHashAlgorithm algorithm, TlsStream stream)
		{
			stream.Write ((byte)algorithm.Hash);
			stream.Write ((byte)algorithm.Signature);
		}

		public static void EncodeSignatureAndHashAlgorithm (SignatureAndHashAlgorithm algorithm, TlsBuffer buffer)
		{
			buffer.Write ((byte)algorithm.Hash);
			buffer.Write ((byte)algorithm.Signature);
		}

	}
}

