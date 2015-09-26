using System;

namespace Mono.Security.NewTls.EC
{
	public abstract class SecObjectIdentifiers
	{
		/**
		 *  EllipticCurve OBJECT IDENTIFIER ::= {
		 *        iso(1) identified-organization(3) certicom(132) curve(0)
		 *  }
		 */
		const string OidEllipticCurve = "1.3.132.0";

		public static readonly ASN1 EllipticCurve = ASN1Convert.FromOid (OidEllipticCurve);

		public static readonly ASN1 SecT163k1 = ASN1Convert.FromOid (OidEllipticCurve + ".1");
		public static readonly ASN1 SecT163r1 = ASN1Convert.FromOid (OidEllipticCurve + ".2");
		public static readonly ASN1 SecT239k1 = ASN1Convert.FromOid (OidEllipticCurve + ".3");
		public static readonly ASN1 SecT113r1 = ASN1Convert.FromOid (OidEllipticCurve + ".4");
		public static readonly ASN1 SecT113r2 = ASN1Convert.FromOid (OidEllipticCurve + ".5");
		public static readonly ASN1 SecP112r1 = ASN1Convert.FromOid (OidEllipticCurve + ".6");
		public static readonly ASN1 SecP112r2 = ASN1Convert.FromOid (OidEllipticCurve + ".7");
		public static readonly ASN1 SecP160r1 = ASN1Convert.FromOid (OidEllipticCurve + ".8");
		public static readonly ASN1 SecP160k1 = ASN1Convert.FromOid (OidEllipticCurve + ".9");
		public static readonly ASN1 SecP256k1 = ASN1Convert.FromOid (OidEllipticCurve + ".10");
		public static readonly ASN1 SecT163r2 = ASN1Convert.FromOid (OidEllipticCurve + ".15");
		public static readonly ASN1 SecT283k1 = ASN1Convert.FromOid (OidEllipticCurve + ".16");
		public static readonly ASN1 SecT283r1 = ASN1Convert.FromOid (OidEllipticCurve + ".17");
		public static readonly ASN1 SecT131r1 = ASN1Convert.FromOid (OidEllipticCurve + ".22");
		public static readonly ASN1 SecT131r2 = ASN1Convert.FromOid (OidEllipticCurve + ".23");
		public static readonly ASN1 SecT193r1 = ASN1Convert.FromOid (OidEllipticCurve + ".24");
		public static readonly ASN1 SecT193r2 = ASN1Convert.FromOid (OidEllipticCurve + ".25");
		public static readonly ASN1 SecT233k1 = ASN1Convert.FromOid (OidEllipticCurve + ".26");
		public static readonly ASN1 SecT233r1 = ASN1Convert.FromOid (OidEllipticCurve + ".27");
		public static readonly ASN1 SecP128r1 = ASN1Convert.FromOid (OidEllipticCurve + ".28");
		public static readonly ASN1 SecP128r2 = ASN1Convert.FromOid (OidEllipticCurve + ".29");
		public static readonly ASN1 SecP160r2 = ASN1Convert.FromOid (OidEllipticCurve + ".30");
		public static readonly ASN1 SecP192k1 = ASN1Convert.FromOid (OidEllipticCurve + ".31");
		public static readonly ASN1 SecP224k1 = ASN1Convert.FromOid (OidEllipticCurve + ".32");
		public static readonly ASN1 SecP224r1 = ASN1Convert.FromOid (OidEllipticCurve + ".33");
		public static readonly ASN1 SecP384r1 = ASN1Convert.FromOid (OidEllipticCurve + ".34");
		public static readonly ASN1 SecP521r1 = ASN1Convert.FromOid (OidEllipticCurve + ".35");
		public static readonly ASN1 SecT409k1 = ASN1Convert.FromOid (OidEllipticCurve + ".36");
		public static readonly ASN1 SecT409r1 = ASN1Convert.FromOid (OidEllipticCurve + ".37");
		public static readonly ASN1 SecT571k1 = ASN1Convert.FromOid (OidEllipticCurve + ".38");
		public static readonly ASN1 SecT571r1 = ASN1Convert.FromOid (OidEllipticCurve + ".39");

		public static readonly ASN1 SecP192r1 = X9ObjectIdentifiers.Prime192v1;
		public static readonly ASN1 SecP256r1 = X9ObjectIdentifiers.Prime256v1;
	}
}