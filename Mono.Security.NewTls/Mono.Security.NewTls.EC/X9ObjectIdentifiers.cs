namespace Mono.Security.NewTls.EC
{
	public abstract class X9ObjectIdentifiers
	{
		//
		// X9.62
		//
		// ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
		//            us(840) ansi-x962(10045) }
		//
		internal const string AnsiX962 = "1.2.840.10045";
		internal const string IdFieldType = AnsiX962 + ".1";

		public static readonly ASN1 PrimeField = ASN1Convert.FromOid (IdFieldType + ".1");

		public static readonly ASN1 CharacteristicTwoField = ASN1Convert.FromOid (IdFieldType + ".2");

		public static readonly ASN1 GNBasis = ASN1Convert.FromOid (IdFieldType + ".2.3.1");

		public static readonly ASN1 TPBasis = ASN1Convert.FromOid (IdFieldType + ".2.3.2");

		public static readonly ASN1 PPBasis = ASN1Convert.FromOid (IdFieldType + ".2.3.3");

		public const string IdECSigType = AnsiX962 + ".4";

		public static readonly ASN1 ECDsaWithSha1 = ASN1Convert.FromOid (IdECSigType + ".1");

		public const string IdPublicKeyType = AnsiX962 + ".2";

		public static readonly ASN1 IdECPublicKey = ASN1Convert.FromOid (IdPublicKeyType + ".1");

		internal const string IdECDsaWithSha2 = IdECSigType + ".3";
		public static readonly ASN1 ECDsaWithSha2 = ASN1Convert.FromOid (IdECDsaWithSha2);
		public static readonly ASN1 ECDsaWithSha224 = ASN1Convert.FromOid (IdECDsaWithSha2 + ".1");
		public static readonly ASN1 ECDsaWithSha256 = ASN1Convert.FromOid (IdECDsaWithSha2 + ".2");
		public static readonly ASN1 ECDsaWithSha384 = ASN1Convert.FromOid (IdECDsaWithSha2 + ".3");
		public static readonly ASN1 ECDsaWithSha512 = ASN1Convert.FromOid (IdECDsaWithSha2 + ".4");


		//
		// named curves
		//
		internal const string IdEllipticCurve = AnsiX962 + ".3";
		public static readonly ASN1 EllipticCurve = ASN1Convert.FromOid (IdEllipticCurve);

		//
		// Two Curves
		//
		internal const string IdCTwoCurve = IdEllipticCurve + ".0";
		public static readonly ASN1 CTwoCurve = ASN1Convert.FromOid (IdEllipticCurve + ".0");

		public static readonly ASN1 C2Pnb163v1 = ASN1Convert.FromOid (IdCTwoCurve + ".1");
		public static readonly ASN1 C2Pnb163v2 = ASN1Convert.FromOid (IdCTwoCurve + ".2");
		public static readonly ASN1 C2Pnb163v3 = ASN1Convert.FromOid (IdCTwoCurve + ".3");
		public static readonly ASN1 C2Pnb176w1 = ASN1Convert.FromOid (IdCTwoCurve + ".4");
		public static readonly ASN1 C2Tnb191v1 = ASN1Convert.FromOid (IdCTwoCurve + ".5");
		public static readonly ASN1 C2Tnb191v2 = ASN1Convert.FromOid (IdCTwoCurve + ".6");
		public static readonly ASN1 C2Tnb191v3 = ASN1Convert.FromOid (IdCTwoCurve + ".7");
		public static readonly ASN1 C2Onb191v4 = ASN1Convert.FromOid (IdCTwoCurve + ".8");
		public static readonly ASN1 C2Onb191v5 = ASN1Convert.FromOid (IdCTwoCurve + ".9");
		public static readonly ASN1 C2Pnb208w1 = ASN1Convert.FromOid (IdCTwoCurve + ".10");
		public static readonly ASN1 C2Tnb239v1 = ASN1Convert.FromOid (IdCTwoCurve + ".11");
		public static readonly ASN1 C2Tnb239v2 = ASN1Convert.FromOid (IdCTwoCurve + ".12");
		public static readonly ASN1 C2Tnb239v3 = ASN1Convert.FromOid (IdCTwoCurve + ".13");
		public static readonly ASN1 C2Onb239v4 = ASN1Convert.FromOid (IdCTwoCurve + ".14");
		public static readonly ASN1 C2Onb239v5 = ASN1Convert.FromOid (IdCTwoCurve + ".15");
		public static readonly ASN1 C2Pnb272w1 = ASN1Convert.FromOid (IdCTwoCurve + ".16");
		public static readonly ASN1 C2Pnb304w1 = ASN1Convert.FromOid (IdCTwoCurve + ".17");
		public static readonly ASN1 C2Tnb359v1 = ASN1Convert.FromOid (IdCTwoCurve + ".18");
		public static readonly ASN1 C2Pnb368w1 = ASN1Convert.FromOid (IdCTwoCurve + ".19");
		public static readonly ASN1 C2Tnb431r1 = ASN1Convert.FromOid (IdCTwoCurve + ".20");

		//
		// Prime
		//
		internal const string IdPrimeCurve = IdEllipticCurve + ".1";
		public static readonly ASN1 PrimeCurve = ASN1Convert.FromOid (IdPrimeCurve);

		public static readonly ASN1 Prime192v1 = ASN1Convert.FromOid (IdPrimeCurve + ".1");
		public static readonly ASN1 Prime192v2 = ASN1Convert.FromOid (IdPrimeCurve + ".2");
		public static readonly ASN1 Prime192v3 = ASN1Convert.FromOid (IdPrimeCurve + ".3");
		public static readonly ASN1 Prime239v1 = ASN1Convert.FromOid (IdPrimeCurve + ".4");
		public static readonly ASN1 Prime239v2 = ASN1Convert.FromOid (IdPrimeCurve + ".5");
		public static readonly ASN1 Prime239v3 = ASN1Convert.FromOid (IdPrimeCurve + ".6");
		public static readonly ASN1 Prime256v1 = ASN1Convert.FromOid (IdPrimeCurve + ".7");
	}
}
