using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using MSC = Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	public static class SignatureHelper
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
			#if INSIDE_MONO_NEWTLS
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return new SecureBuffer (MSC.PKCS1.Sign_v15 ((RSA)key, hash, hashData.Buffer));
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
				var algorithm = d.Add (MSC.HashAlgorithmProvider.CreateAlgorithm (type.Hash));
				algorithm.TransformBlock (data.Buffer, 0, data.Size);
				return VerifySignature (type, algorithm, d.Add (algorithm.GetRunningHash ()), key, signature);
			}
		}

		public static bool VerifySignature (SignatureAndHashAlgorithm type, IHashAlgorithm hash, SecureBuffer hashData, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			if (type.Hash != hash.Algorithm)
				throw new TlsException (AlertDescription.IlegalParameter);
			#if INSIDE_MONO_NEWTLS
			if (type.Signature == SignatureAlgorithmType.Rsa)
				return MSC.PKCS1.Verify_v15 ((RSA)key, hash, hashData.Buffer, signature.Buffer);
			else
				throw new NotSupportedException ();
			#else
			throw new NotSupportedException ();
			#endif
		}

		#if INSIDE_MONO_NEWTLS
		internal static SignatureAndHashAlgorithm SelectSignatureType (HandshakeParameters handshakeParameters)
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

