using System;
using System.Net.Security;
using System.Security.Cryptography;
using Mono.Security.Interface;
using MX = Mono.Security.X509;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.NewTls
{
	public delegate bool RemoteCertValidationCallback (string host, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors);
	public delegate bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors);
	public delegate SSCX.X509Certificate LocalCertSelectionCallback (string targetHost, SSCX.X509CertificateCollection localCertificates, SSCX.X509Certificate remoteCertificate, string[] acceptableIssuers);

	public class TlsConfiguration : SecretParameters
	{
		readonly TlsProtocols supportedProtocols;
		readonly TlsProtocolCode requestedProtocol;

		public TlsProtocols SupportedProtocols {
			get { return supportedProtocols; }
		}

		internal TlsProtocolCode RequestedProtocol {
			get { return requestedProtocol; }
		}

		public TlsSettings TlsSettings {
			get;
			private set;
		}

		internal RenegotiationFlags RenegotiationFlags {
			get;
			private set;
		}

		public bool? AskForClientCertificate {
			get; set;
		}

		internal void ForceDisableRenegotiation ()
		{
			var abortOnHello = RenegotiationFlags & RenegotiationFlags.AbortOnHelloRequest;
			RenegotiationFlags = RenegotiationFlags.DisallowRenegotiation | abortOnHello;
		}

		internal bool EnableSecureRenegotiation {
			get {
				return (RenegotiationFlags & (RenegotiationFlags.DisallowRenegotiation | RenegotiationFlags.SecureRenegotiation)) == RenegotiationFlags.SecureRenegotiation;
			}
		}

		internal const RenegotiationFlags DefaultRenegotiationFlags = RenegotiationFlags.SecureRenegotiation | RenegotiationFlags.SendClientHelloExtension;

		public TlsConfiguration (TlsProtocols protocols, TlsSettings settings, string targetHost)
		{
			supportedProtocols = protocols;
			requestedProtocol = CheckProtocol (ref supportedProtocols, false);
			TlsSettings = settings ?? new TlsSettings ();
			TargetHost = targetHost;

			RenegotiationFlags = DefaultRenegotiationFlags;
		}

		public TlsConfiguration (TlsProtocols protocols, TlsSettings settings, MX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			supportedProtocols = protocols;
			requestedProtocol = CheckProtocol (ref supportedProtocols, true);
			TlsSettings = settings ?? new TlsSettings ();
			Certificate = certificate;
			PrivateKey = privateKey;

			RenegotiationFlags = DefaultRenegotiationFlags;
		}

		#region Protocol Versions

		static TlsProtocolCode CheckProtocol (ref TlsProtocols protocols, bool isServer)
		{
			if (isServer)
				protocols &= TlsProtocols.ServerMask;
			else
				protocols &= TlsProtocols.ClientMask;

			if (protocols == 0)
				throw new TlsException (AlertDescription.ProtocolVersion);

			if ((protocols & TlsProtocols.Tls12) != 0)
				return TlsProtocolCode.Tls12;
			if ((protocols & TlsProtocols.Tls11) != 0)
				return TlsProtocolCode.Tls11;
			if ((protocols & TlsProtocols.Tls10) != 0)
				return TlsProtocolCode.Tls10;

			throw new TlsException (AlertDescription.ProtocolVersion);
		}

		public bool IsSupportedClientProtocol (TlsProtocolCode protocol)
		{
			switch (protocol) {
			case TlsProtocolCode.Tls10:
				return (supportedProtocols & TlsProtocols.Tls10Server) != 0;
			case TlsProtocolCode.Tls11:
				return (supportedProtocols & TlsProtocols.Tls11Server) != 0;
			case TlsProtocolCode.Tls12:
				return (supportedProtocols & TlsProtocols.Tls12Server) != 0;
			default:
				return false;
			}
		}

		public bool IsSupportedServerProtocol (TlsProtocolCode protocol)
		{
			switch (protocol) {
			case TlsProtocolCode.Tls10:
				return (supportedProtocols & TlsProtocols.Tls10Client) != 0;
			case TlsProtocolCode.Tls11:
				return (supportedProtocols & TlsProtocols.Tls11Client) != 0;
			case TlsProtocolCode.Tls12:
				return (supportedProtocols & TlsProtocols.Tls12Client) != 0;
			default:
				return false;
			}
		}

		public static bool IsTls10OrNewer (TlsProtocolCode protocol)
		{
			return IsTls10OrNewer ((short)protocol);
		}

		public static bool IsTls10OrNewer (short code)
		{
			return (code >> 8) == 3 && (code & 0x00ff) > 1;
		}

		public static bool IsTls12OrNewer (TlsProtocolCode protocol)
		{
			return IsTls12OrNewer ((short)protocol);
		}

		public static bool IsTls12OrNewer (short code)
		{
			return (code >> 8) == 3 && (code & 0x00ff) >= 3;
		}

		#endregion

		#region Client Configuration

		public string TargetHost {
			get;
			private set;
		}

		public ICertificateValidator CertificateValidator {
			get; set;
		}

		#endregion

		#region Common Configuration

		internal MX.X509Certificate Certificate {
			get;
			private set;
		}

		internal AsymmetricAlgorithm PrivateKey {
			get;
			private set;
		}

		public bool HasCredentials {
			get { return Certificate != null && PrivateKey != null; }
		}

		public void SetCertificate (MX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			Certificate = certificate;
			#if !BOOTSTRAP_BASIC
			if (PrivateKey != null && PrivateKey != privateKey)
				PrivateKey.Dispose ();
			#endif
			PrivateKey = privateKey;
		}

		#endregion

		protected override void Clear ()
		{
			PrivateKey = null;
			Certificate = null;
		}
	}
}

