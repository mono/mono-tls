using System;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using MSC = Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	using Instrumentation;

	internal static class SignatureHelper
	{
		public static SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, SecureBuffer data, AsymmetricAlgorithm key)
		{
			if (!IsAlgorithmSupported (type))
				throw new TlsException (AlertDescription.IlegalParameter);
			using (var d = new DisposeContext ()) {
				var algorithm = d.Add (MSC.HashAlgorithmProvider.CreateAlgorithm (type.Hash));
				algorithm.TransformBlock (data.Buffer, 0, data.Size);
				return CreateSignature (type, algorithm, d.Add (algorithm.GetRunningHash ()), key);
			}
		}

		public static SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, IHashAlgorithm hash, SecureBuffer hashData, AsymmetricAlgorithm key)
		{
			if (type.Hash != hash.Algorithm)
				throw new TlsException (AlertDescription.IlegalParameter);
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return new SecureBuffer (MSC.PKCS1.Sign_v15 ((RSA)key, hash, hashData.Buffer));
			else
				throw new NotSupportedException ();
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, SecureBuffer data, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (!IsAlgorithmSupported (type))
				throw new TlsException (AlertDescription.IlegalParameter);
			using (var d = new DisposeContext ()) {
				var algorithm = d.Add (MSC.HashAlgorithmProvider.CreateAlgorithm (type.Hash));
				algorithm.TransformBlock (data.Buffer, 0, data.Size);
				return VerifySignature (type, algorithm, d.Add (algorithm.GetRunningHash ()), key, signature);
			}
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, IHashAlgorithm hash, SecureBuffer hashData, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (type.Hash != hash.Algorithm)
				throw new TlsException (AlertDescription.IlegalParameter);
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return MSC.PKCS1.Verify_v15 ((RSA)key, hash, hashData.Buffer, signature.Buffer);
			else
				throw new NotSupportedException ();
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

		public static void VerifySignatureAlgorithm (SignatureAndHashAlgorithm algorithm)
		{
			if (!IsAlgorithmSupported (algorithm))
				throw new TlsException (AlertDescription.IlegalParameter);
		}

		public static void VerifySignatureParameters (SignatureParameters parameters)
		{
			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (!IsAlgorithmSupported (algorithm))
					throw new TlsException (AlertDescription.IlegalParameter);
			}
		}

		public static ISignatureProvider GetSignatureProvider (TlsContext ctx)
		{
			#if INSTRUMENTATION
			if (ctx.Configuration.HasInstrumentation && ctx.Configuration.Instrumentation.HasSignatureInstrument)
				return ctx.Configuration.Instrumentation.SignatureInstrument;
			#endif

			return DefaultSignatureProvider.Instance;
		}
	}
}

