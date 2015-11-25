using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	public struct SignatureAndHashAlgorithm
	{
		public readonly HashAlgorithmType Hash;
		public readonly SignatureAlgorithmType Signature;

		public SignatureAndHashAlgorithm (HashAlgorithmType hash, SignatureAlgorithmType signature)
		{
			Hash = hash;
			Signature = signature;
		}

		public SignatureAndHashAlgorithm (HashAlgorithmType hash)
		{
			Hash = hash;
			Signature = SignatureAlgorithmType.Rsa;
		}

		public override int GetHashCode ()
		{
			return Hash.GetHashCode ();
		}

		public override bool Equals (object obj)
		{
			var other = (SignatureAndHashAlgorithm)obj;
			return other.Hash == Hash && other.Signature == Signature;
		}

		public override string ToString ()
		{
			return string.Format ("[SignatureAndHashAlgorithm: {0} {1}]", Hash, Signature);
		}
	}
}

