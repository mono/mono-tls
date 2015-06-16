using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	static class SignatureHelper
	{
		static IRunningHash GetAlgorithm (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Sha1:
				return new SHA1CryptoServiceProvider ();
			case HashAlgorithmType.Sha256:
				return new SHA256Managed ();
			case HashAlgorithmType.Sha384:
				return new SHA384Managed ();
			case HashAlgorithmType.Sha512:
				return new SHA512Managed ();
			default:
				throw new NotSupportedException ();
			}
		}

		static bool VerifyHashType (SignatureAndHashAlgorithm type, HashAlgorithm hash)
		{
			if (hash is SHA1)
				return type.Hash == HashAlgorithmType.Sha1;
			else if (hash is SHA256)
				return type.Hash == HashAlgorithmType.Sha256;
			else if (hash is SHA384)
				return type.Hash == HashAlgorithmType.Sha384;
			else if (hash is SHA512)
				return type.Hash == HashAlgorithmType.Sha512;
			else
				return false;
		}

		public static SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, SecureBuffer data, AsymmetricAlgorithm key)
		{
			if (!IsAlgorithmSupported (type))
				throw new TlsException (AlertDescription.IlegalParameter);
			using (var d = new DisposeContext ()) {
				var algorithm = d.Add ((HashAlgorithm)GetAlgorithm (type.Hash));
				algorithm.TransformFinalBlock (data.Buffer, 0, data.Size);
				return CreateSignature (type, algorithm, d.Add (algorithm.Hash), key);
			}
		}

		public static SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, HashAlgorithm hash, SecureBuffer hashData, AsymmetricAlgorithm key)
		{
			if (!VerifyHashType (type, hash))
				throw new TlsException (AlertDescription.IlegalParameter);
			#if INSIDE_MONO_NEWTLS
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return new SecureBuffer (PKCS1.Sign_v15 ((RSA)key, hash, hashData.Buffer));
			else
				throw new NotSupportedException ();
			#else
			throw new NotSupportedException ();
			#endif
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, SecureBuffer data, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (!IsAlgorithmSupported (type))
				throw new TlsException (AlertDescription.IlegalParameter);
			using (var d = new DisposeContext ()) {
				var algorithm = d.Add ((HashAlgorithm)GetAlgorithm (type.Hash));
				algorithm.TransformFinalBlock (data.Buffer, 0, data.Size);
				return VerifySignature (type, algorithm, d.Add (algorithm.Hash), key, signature);
			}
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, HashAlgorithm hash, SecureBuffer hashData, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (!VerifyHashType (type, hash))
				throw new TlsException (AlertDescription.IlegalParameter);
			#if INSIDE_MONO_NEWTLS
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return PKCS1.Verify_v15 ((RSA)key, hash, hashData.Buffer, signature.Buffer);
			else
				throw new NotSupportedException ();
			#else
			throw new NotSupportedException ();
			#endif
		}

		#if INSIDE_MONO_NEWTLS
		public static SignatureAndHashAlgorithm SelectSignatureType (HandshakeParameters handshakeParameters)
		{
			if (handshakeParameters.ClientCertificateParameters != null && handshakeParameters.ClientCertificateParameters.HasSignatureParameters)
				return SelectSignatureType (handshakeParameters.ClientCertificateParameters.SignatureParameters);
			else
				return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa);
		}
		#endif

		public static bool IsAlgorithmSupported (SignatureAndHashAlgorithm algorithm)
		{
			if (algorithm.Signature != SignatureAlgorithmType.Rsa)
				return false;
			switch (algorithm.Hash) {
			case HashAlgorithmType.Sha512:
			case HashAlgorithmType.Sha384:
			case HashAlgorithmType.Sha256:
			case HashAlgorithmType.Sha1:
				return true;
			default:
				return false;
			}
		}

		static SignatureAndHashAlgorithm SelectSignatureType (SignatureParameters parameters)
		{
			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (IsAlgorithmSupported (algorithm))
					return algorithm;
			}

			throw new TlsException (AlertDescription.HandshakeFailure, "Client did not offer any supported signature type.");
		}

		public static void VerifySignatureParameters (SignatureParameters parameters)
		{
			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (!IsAlgorithmSupported (algorithm))
					throw new TlsException (AlertDescription.IlegalParameter);
			}
		}
	}
}

