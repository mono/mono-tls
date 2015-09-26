using System;
using BCA = Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;

namespace Mono.Security.NewTls.EC
{
	internal static class NamedCurveHelper
	{
		internal static ECDomainParameters GetECParameters (NamedCurve namedCurve)
		{
 			if (!Enum.IsDefined (typeof(NamedCurve), namedCurve))
				return null;

			string curveName = namedCurve.ToString ();

			// Lazily created the first time a particular curve is accessed
			X9ECParameters ecP = SecNamedCurves.GetByName (curveName);

			if (ecP == null)
				return null;

			// It's a bit inefficient to do this conversion every time
			return new ECDomainParameters (ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed ());
		}
	}
}
