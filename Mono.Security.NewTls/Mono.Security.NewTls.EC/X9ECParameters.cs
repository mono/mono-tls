using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Mono.Security.NewTls.EC
{
	/*
	 * ASN.1 def for Elliptic-Curve ECParameters structure. See
	 * X9.62, for further details.
	 */
	public class X9ECParameters
	{
		private ECCurve curve;
		private ECPoint g;
		private BigInteger n;
		private BigInteger h;
		private byte[] seed;

		public X9ECParameters (
			ECCurve		curve,
			ECPoint		g,
			BigInteger	n)
			: this (curve, g, n, BigInteger.One, null)
		{
		}

		public X9ECParameters (
			ECCurve		curve,
			ECPoint		g,
			BigInteger	n,
			BigInteger	h)
			: this (curve, g, n, h, null)
		{
		}

		public X9ECParameters (
			ECCurve		curve,
			ECPoint		g,
			BigInteger	n,
			BigInteger	h,
			byte[]		seed)
		{
			this.curve = curve;
			this.g = g;
			this.n = n;
			this.h = h;
			this.seed = seed;
		}

		public ECCurve Curve {
			get { return curve; }
		}

		public ECPoint G {
			get { return g; }
		}

		public BigInteger N {
			get { return n; }
		}

		public BigInteger H {
			get {
				if (h == null) {
					// TODO - this should be calculated, it will cause issues with custom curves.
					return BigInteger.One;
				}

				return h;
			}
		}

		public byte[] GetSeed ()
		{
			return seed;
		}
	}
}
