using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Mono.Security.X509.Extensions;

namespace Mono.Security.NewTls
{
	using MX = Mono.Security.X509;
	using SSCX = System.Security.Cryptography.X509Certificates;

	public static class CertificateManager
	{
		internal static void CheckRemoteCertificate (TlsConfiguration config, MX.X509CertificateCollection certificates)
		{
			if (certificates == null || certificates.Count < 1)
				throw new TlsException (AlertDescription.CertificateUnknown);

			var helper = CertificateValidationHelper.GetValidator (config.TlsSettings);

			X509Certificate2Collection scerts = null;
			if (certificates != null) {
				scerts = new X509Certificate2Collection ();
				for (int i = 0; i < certificates.Count; i++)
					scerts.Add (new X509Certificate2 (certificates [i].RawData));
			}

			var result = helper.ValidateCertificate (config.TargetHost, false, scerts);
			if (result != null && result.Trusted && !result.UserDenied)
				return;

			// FIXME: check other values to report correct error type.
			throw new TlsException (AlertDescription.CertificateUnknown);
		}

		static SslPolicyErrors GetStatus (MX.X509ChainStatusFlags flags)
		{
			switch (flags) {
			case MX.X509ChainStatusFlags.NoError:
				return SslPolicyErrors.None;
			default:
				return SslPolicyErrors.RemoteCertificateChainErrors;
			}
		}

		internal static void CheckClientCertificate (TlsContext context, MX.X509CertificateCollection certificates)
		{
			if (context.SettingsProvider.HasClientCertificateParameters) {
				var certParams = context.SettingsProvider.ClientCertificateParameters;
				if (certParams.CertificateAuthorities.Count > 0) {
					if (!certParams.CertificateAuthorities.Contains (certificates [0].IssuerName))
						throw new TlsException (AlertDescription.BadCertificate);
				}
			}

			var helper = CertificateValidationHelper.GetValidator (context.Configuration.TlsSettings);

			X509Certificate2Collection scerts = null;
			if (certificates != null) {
				scerts = new X509Certificate2Collection ();
				for (int i = 0; i < certificates.Count; i++)
					scerts.Add (new X509Certificate2 (certificates [i].RawData));
			}

			var result = helper.ValidateCertificate (string.Empty, true, scerts);
			if (result == null || !result.Trusted || result.UserDenied)
				throw new TlsException (AlertDescription.CertificateUnknown);
		}

		internal static bool VerifyServerCertificate (TlsContext context, MX.X509Certificate certificate, ExchangeAlgorithmType algorithm)
		{
			if (context.NegotiatedProtocol == TlsProtocolCode.Tls12 && certificate.Version < 3)
				throw new TlsException (AlertDescription.UnsupportedCertificate, "X.509v3 server certificate required");

			if (certificate.KeyAlgorithm != null && !certificate.KeyAlgorithm.Equals (OidKeyAlgorithmRsa))
				return false;
			if (certificate.SignatureAlgorithm != null && !VerifySignatureAlgorithm (certificate.SignatureAlgorithm))
				return false;

			switch (algorithm) {
			case ExchangeAlgorithmType.Rsa:
				return VerifyKeyUsage (certificate, KeyUsages.keyEncipherment, OidServerAuth);

			case ExchangeAlgorithmType.Dhe:
			case ExchangeAlgorithmType.EcDhe:
				return VerifyKeyUsage (certificate, KeyUsages.digitalSignature, OidServerAuth);

			default:
				throw new TlsException (AlertDescription.InternalError);
			}
		}

		internal static bool VerifyClientCertificate (TlsContext context, MX.X509Certificate certificate, ExchangeAlgorithmType algorithm)
		{
			if (context.NegotiatedProtocol == TlsProtocolCode.Tls12 && certificate.Version < 3)
				throw new TlsException (AlertDescription.UnsupportedCertificate, "X.509v3 client certificate required");

			if (certificate.KeyAlgorithm != null && !certificate.KeyAlgorithm.Equals (OidKeyAlgorithmRsa))
				return false;
			if (certificate.SignatureAlgorithm != null && !VerifySignatureAlgorithm (certificate.SignatureAlgorithm))
				return false;

			switch (algorithm) {
			case ExchangeAlgorithmType.Rsa:
				return VerifyKeyUsage (certificate, KeyUsages.keyEncipherment, OidClientAuth);

			case ExchangeAlgorithmType.Dhe:
			case ExchangeAlgorithmType.EcDhe:
				return VerifyKeyUsage (certificate, KeyUsages.digitalSignature, OidClientAuth);

			default:
				throw new TlsException (AlertDescription.InternalError);
			}
		}

		const string OidKeyUsage = "2.5.29.15";
		const string OidExtendedKeyUsage = "2.5.29.37";

		const string OidServerAuth = "1.3.6.1.5.5.7.3.1";
		const string OidClientAuth = "1.3.6.1.5.5.7.3.2";

		const string OidKeyAlgorithmRsa = "1.2.840.113549.1.1.1";

		static bool VerifySignatureAlgorithm (string algorithm)
		{
			switch (algorithm) {
			case "1.2.840.113549.1.1.4":    // MD5 with RSA encryption
			case "1.2.840.113549.1.1.5":    // SHA-1 with RSA Encryption
			case "1.3.14.3.2.29":           // SHA1 with RSA signature
			case "1.2.840.113549.1.1.11":   // SHA-256 with RSA Encryption
			case "1.2.840.113549.1.1.12":   // SHA-384 with RSA Encryption
			case "1.2.840.113549.1.1.13":   // SHA-512 with RSA Encryption
				return true;

			default:
				return false;
			}
		}

		internal static bool VerifyKeyUsage (MX.X509Certificate certificate, KeyUsages keyUsages, string purpose)
		{
			if (certificate.Extensions == null)
				return true;

			KeyUsageExtension kux = null;
			ExtendedKeyUsageExtension eku = null;

			var xtn = certificate.Extensions [OidKeyUsage];
			if (xtn != null)
				kux = new KeyUsageExtension (xtn);

			xtn = certificate.Extensions [OidExtendedKeyUsage];
			if (xtn != null)
				eku = new ExtendedKeyUsageExtension (xtn);

			if ((kux != null) && (eku != null)) {
				// RFC3280 states that when both KeyUsageExtension and
				// ExtendedKeyUsageExtension are present then BOTH should
				// be valid
				if (!kux.Support (keyUsages))
					return false;
				return eku.KeyPurpose.Contains (purpose);
			} else if (kux != null) {
				return kux.Support (keyUsages);
			} else if (eku != null) {
				return eku.KeyPurpose.Contains (purpose);
			}

			return true;
		}
	}
}

