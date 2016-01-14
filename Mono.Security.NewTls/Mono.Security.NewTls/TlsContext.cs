extern alias NewSystemSource;

using System;
using System.Net;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using Mono.Security.Interface;

using MNS = NewSystemSource::Mono.Net.Security;

namespace Mono.Security.NewTls
{
	using Mono.Security.X509;
	using Handshake;
	using Negotiation;
	using Extensions;
	using Cipher;

	/*
	 * Please note that the code in this module is not ready yet, it has NOT BEEN SECURITY AUDITED
	 * AND NO GUARANTEE ABOUT SECURITY OR STABILITY can be made!
	 *
	 * You are very welcome to use this module to test the new TLS code, find bugs, problems,
	 * security issues, anything in it - but do not use it in production environment until it is ready.
	 *
	 */
	public class TlsContext : SecretParameters, ITlsContext, MNS.ITlsContext
	{
		readonly bool isServer;
		readonly TlsConfiguration configuration;
		readonly SettingsProvider settingsProvider;
		readonly SignatureProvider signatureProvider;
		#if INSTRUMENTATION
		readonly InstrumentationEventSink instrumentationEventSink;
		readonly ISet<HandshakeInstrumentType> handshakeInstruments;
		#endif
		readonly IMonoTlsEventSink eventSink;

		Session session;
		HandshakeParameters handshakeParameters;

		TlsProtocolCode negotiatedProtocol;

		NegotiationHandler negotiationHandler;

		MonoTlsConnectionInfo connectionInfo;

		TlsBuffer cachedFragment;
		int skipToOffset = -1;

		internal const short MAX_FRAGMENT_SIZE	= 16384; // 2^14

		public bool IsServer {
			get { return isServer; }
		}

		public TlsConfiguration Configuration {
			get { return configuration; }
		}

		public SettingsProvider SettingsProvider {
			get { return settingsProvider; }
		}

		public SignatureProvider SignatureProvider {
			get { return signatureProvider; }
		}

		internal Session Session {
			get { return session; }
		}

		internal HandshakeParameters HandshakeParameters {
			get { return handshakeParameters; }
			set { handshakeParameters = value; }
		}

		internal bool EnableDebugging {
			get;
			private set;
		}

		public bool ReceivedCloseNotify {
			get;
			private set;
		}

		public TlsException LastError {
			get;
			private set;
		}

		byte[] OnError (TlsException error)
		{
			LastError = error;
			if (eventSink != null)
				eventSink.Error (error);

			#if INSTRUMENTATION
			if (HasInstrument (HandshakeInstrumentType.DontSendAlerts))
				return null;
			#endif

			if (negotiationHandler == null || !negotiationHandler.CanSendAlert)
				return null;

			try {
				return CreateAlert (error.Alert);
			} catch {
				return null;
			}
		}

		public TlsContext (TlsConfiguration configuration, bool isServer, IMonoTlsEventSink eventSink)
		{
			this.configuration = configuration;
			this.isServer = isServer;
			this.eventSink = eventSink;

			#if INSTRUMENTATION
			var instrumentation = configuration.UserSettings.Instrumentation;
			if (instrumentation != null) {
				if (instrumentation.HasSignatureInstrument)
					signatureProvider = instrumentation.SignatureInstrument;
				if (instrumentation.HasSettingsInstrument)
					settingsProvider = instrumentation.SettingsInstrument;
				handshakeInstruments = instrumentation.HandshakeInstruments;
				instrumentationEventSink = instrumentation.EventSink;
			}
			#endif

			if (signatureProvider == null)
				signatureProvider = new SignatureProvider ();
			if (settingsProvider == null)
				settingsProvider = new SettingsProvider (configuration.UserSettings);

			session = new Session (configuration);
			Session.RandomNumberGenerator = RandomNumberGenerator.Create ();

			if (IsServer)
				negotiationHandler = CreateNegotiationHandler (NegotiationState.InitialServerConnection);
			else
				negotiationHandler = CreateNegotiationHandler (NegotiationState.InitialClientConnection);

			if (settingsProvider.EnableDebugging)
				EnableDebugging = true;

			settingsProvider.Initialize (this);
		}

		#if INSTRUMENTATION

		internal bool HasInstrument (HandshakeInstrumentType type)
		{
			return handshakeInstruments != null ? handshakeInstruments.Contains (type) : false;
		}

		internal bool HasInstrumentationEventSink {
			get { return instrumentationEventSink != null; }
		}

		internal InstrumentationEventSink InstrumentationEventSink {
			get { return instrumentationEventSink; }
		}

		#endif

		public X509Certificate GetRemoteCertificate (out X509CertificateCollection remoteCertificateStore)
		{
			if (Session.CurrentCrypto == null) {
				remoteCertificateStore = null;
				return null;
			} else {
				remoteCertificateStore = Session.CurrentCrypto.ServerCertificates;
				return remoteCertificateStore [0];
			}
		}

		public bool VerifyRemoteCertificate ()
		{
			if (Session.CurrentCrypto.RemoteCertificateVerified)
				return true;

			if (IsServer) {
				CertificateManager.CheckClientCertificate (this, Session.CurrentCrypto.ClientCertificates);
			} else {
				CertificateManager.CheckRemoteCertificate (Configuration, Session.CurrentCrypto.ServerCertificates);
			}

			return true;
		}

		public bool IsValid {
			get { return session != null && negotiationHandler != null; }
		}

		void CheckValid ()
		{
			if (!IsValid)
				throw new TlsException (AlertDescription.InternalError, "The session is no longer valid.");
		}

		protected override void Clear ()
		{
			negotiationHandler = null;
			if (handshakeParameters != null) {
				handshakeParameters.Dispose ();
				handshakeParameters = null;
			}
			if (session != null) {
				session.Dispose ();
				session = null;
			}
		}

		#region Protocol Versions

		public bool HasNegotiatedProtocol {
			get { return (short)negotiatedProtocol != 0; }
		}

		public TlsProtocolCode NegotiatedProtocol {
			get {
				if (!HasNegotiatedProtocol)
					throw new InvalidOperationException ();
				return negotiatedProtocol;
			}
		}

		bool IsAcceptableServerProtocol (TlsProtocolCode serverProtocol)
		{
			if (serverProtocol == Configuration.RequestedProtocol)
				return true;

			if (Configuration.RequestedProtocol == TlsProtocolCode.Tls12) {
				switch (serverProtocol) {
				case TlsProtocolCode.Tls11:
					return (Configuration.SupportedProtocols & TlsProtocols.Tls11Client) != 0;
				case TlsProtocolCode.Tls10:
					return (Configuration.SupportedProtocols & TlsProtocols.Tls10Client) != 0;
				default:
					return false;
				}
			} else if (Configuration.RequestedProtocol == TlsProtocolCode.Tls11) {
				switch (serverProtocol) {
				case TlsProtocolCode.Tls10:
					return (Configuration.SupportedProtocols & TlsProtocols.Tls10Client) != 0;
				default:
					return false;
				}
			} else {
				return false;
			}
		}

		internal void VerifyServerProtocol (TlsProtocolCode serverProtocol)
		{
			if (!Configuration.IsSupportedServerProtocol (serverProtocol))
				throw new TlsException (AlertDescription.ProtocolVersion);
			if (HasNegotiatedProtocol && serverProtocol != NegotiatedProtocol)
				throw new TlsException (AlertDescription.ProtocolVersion);

			if (!IsAcceptableServerProtocol (serverProtocol))
				throw new TlsException (
					AlertDescription.ProtocolVersion,
					"Incorrect protocol version received from server");

			negotiatedProtocol = serverProtocol;
		}

		internal void VerifyClientProtocol (TlsProtocolCode clientProtocol)
		{
			if (!Configuration.IsSupportedClientProtocol (clientProtocol))
				throw new TlsException (AlertDescription.ProtocolVersion);
			if (HasNegotiatedProtocol && clientProtocol != NegotiatedProtocol)
				throw new TlsException (AlertDescription.ProtocolVersion);

			// FIXME: we're overly strict at the moment
			if (clientProtocol != Configuration.RequestedProtocol)
				throw new TlsException (
					AlertDescription.ProtocolVersion,
					"Incorrect protocol version received from client");

			negotiatedProtocol = clientProtocol;
		}

		#endregion

		#region ITlsContext

		public bool IsAlgorithmSupported (SignatureAndHashAlgorithm algorithm)
		{
			if (HasNegotiatedProtocol && NegotiatedProtocol != TlsProtocolCode.Tls12)
				throw new TlsException (AlertDescription.IlegalParameter);

			return SignatureHelper.IsAlgorithmSupported (algorithm);
		}

		bool? ITlsContext.AskForClientCertificate {
			get { return configuration.AskForClientCertificate; }
		}

		public bool HasCurrentSignatureParameters {
			get { return session != null && session.HasSignatureParameters; }
		}

		public SignatureParameters CurrentSignatureParameters {
			get { return Session.SignatureParameters; }
		}

		public bool HasClientCertificateParameters {
			get { return session != null && session.HasCertificateParameters; }
		}

		public ClientCertificateParameters ClientCertificateParameters {
			get { return Session.ClientCertificateParameters; }
		}

		#endregion

		#region Main Loop

		int MNS.ITlsContext.GenerateNextToken (TlsBuffer incoming, TlsMultiBuffer outgoing)
		{
			return (int)GenerateNextToken (incoming, outgoing);
		}

		public SecurityStatus GenerateNextToken (TlsBuffer incoming, TlsMultiBuffer outgoing)
		{
			try {
				CheckValid ();
				return _GenerateNextToken (incoming, outgoing);
			} catch (TlsException ex) {
				var alert = OnError (ex);
				if (alert != null)
					outgoing.Add (alert);
				Clear ();
				return SecurityStatus.ContextExpired;
			} catch {
				Clear ();
				throw;
			}
		}

		SecurityStatus _GenerateNextToken (TlsBuffer incoming, TlsMultiBuffer outgoing)
		{
			#if DEBUG_FULL
			if (EnableDebugging) {
				DebugHelper.WriteLine ("GenerateNextToken({0}): {1}", IsServer ? "server" : "client", negotiationHandler);
				if (incoming != null)
					DebugHelper.WriteRemaining ("  incoming", incoming);
			}
			#endif

			if (incoming == null) {
				negotiationHandler = negotiationHandler.GenerateReply (outgoing);
				return SecurityStatus.ContinueNeeded;
			}

			var contentType = (ContentType)incoming.ReadByte ();
			#if DEBUG_FULL
			if (EnableDebugging)
				DebugHelper.WriteLine ("  received message type {0}", contentType);
			#endif

			if (skipToOffset >= 0 && contentType != ContentType.Handshake)
				throw new TlsException (AlertDescription.InternalError);

			if (contentType == ContentType.Alert)
				return ProcessAlert (incoming);

			bool decrypted = false;
			if (cachedFragment != null) {
				if (contentType != ContentType.Handshake)
					throw new TlsException (AlertDescription.DecodeError);
				decrypted = ReadStandardBuffer (ContentType.Handshake, ref incoming);
				cachedFragment.Write (incoming.Buffer, incoming.Position, incoming.Remaining);
				if (cachedFragment.Remaining > 0)
					return SecurityStatus.ContinueNeeded;
				incoming.Dispose ();
				incoming = cachedFragment;
				cachedFragment = null;
				incoming.Position = 0;
			} else {
				decrypted = ReadStandardBuffer (contentType, ref incoming);
			}

			if (Session.Read != null && Session.Read.Cipher != null && !decrypted)
				throw new TlsException (AlertDescription.DecryptError, "Expected encrypted message.");

			try {
				if (contentType == ContentType.ChangeCipherSpec)
					return negotiationHandler.ProcessMessage (new TlsChangeCipherSpec ());
				else if (contentType == ContentType.ApplicationData) {
					if (session.Read == null || session.Read.Cipher == null || !session.SecureRenegotiation)
						throw new TlsException (AlertDescription.DecodeError);
					// FIXME
					Console.Error.WriteLine ("FUCK!");
					throw new NotImplementedException ();
				} else if (contentType != ContentType.Handshake) {
					throw new TlsException (AlertDescription.UnexpectedMessage);
				}

				if (skipToOffset >= 0) {
					incoming.Position = skipToOffset;
					skipToOffset = -1;
				}

				SecurityStatus result;
				bool finished;

				while (true) {
					var startOffset = incoming.Position;
					finished = ProcessHandshakeMessage (incoming, out result);
					if (result == SecurityStatus.CredentialsNeeded) {
						// Caller will call us again with the same input.
						skipToOffset = startOffset;
						if (decrypted)
							Session.Read.ReadSequenceNumber--;
						return result;
					}
					if (incoming.Remaining == 0)
						break;
					if (finished || result != SecurityStatus.ContinueNeeded)
						throw new TlsException (AlertDescription.UnexpectedMessage);
				}

				if (finished)
					negotiationHandler = negotiationHandler.GenerateReply (outgoing);

				return result;
			} finally {
				if (decrypted)
					incoming.Dispose ();
			}
		}

		SecurityStatus ProcessAlert (TlsBuffer buffer)
		{
			bool decrypted = false;
			if ((session.Read != null && session.Read.Cipher != null) || (buffer.Remaining != 2))
				decrypted = ReadStandardBuffer (ContentType.Alert, ref buffer);
			if (buffer.Remaining != 2)
				throw new TlsException (AlertDescription.IlegalParameter, "Invalid Alert message size");

			var level = (AlertLevel)buffer.ReadByte ();
			var description = (AlertDescription)buffer.ReadByte ();
			if (decrypted)
				buffer.Dispose ();

			if (level == AlertLevel.Warning) {
				if (description == AlertDescription.CloseNotify) {
					ReceivedCloseNotify = true;
					if (eventSink != null)
						eventSink.ReceivedCloseNotify ();
					return SecurityStatus.ContextExpired;
				}

				DebugHelper.WriteLine ("Received alert: {0}", description);
				return SecurityStatus.ContinueNeeded;
			} else {
				throw new TlsException (description);
			}
		}

		bool ProcessHandshakeMessage (TlsBuffer incoming, out SecurityStatus status)
		{
			var handshakeType = (HandshakeType)incoming.ReadByte ();
			#if DEBUG_FULL
			if (EnableDebugging) {
				DebugHelper.WriteLine (">>>> Processing Handshake record ({0})", handshakeType);
				DebugHelper.WriteRemaining ("HANDSHAKE", incoming);
			}
			#endif

			// Read message length
			int length = incoming.ReadInt24 ();
			if (incoming.Remaining < length) {
				cachedFragment = new TlsBuffer (length + 4);
				cachedFragment.Position = incoming.Remaining + 4;
				Buffer.BlockCopy (incoming.Buffer, incoming.Position - 4, cachedFragment.Buffer, 0, cachedFragment.Position);
				incoming.Position += incoming.Remaining;
				status = SecurityStatus.ContinueNeeded;
				return false;
			}

			var buffer = incoming.ReadBuffer (length);
			return negotiationHandler.ProcessHandshakeMessage (handshakeType, buffer, out status);
		}

		internal NegotiationHandler CreateNegotiationHandler (NegotiationState state)
		{
			switch (state) {
			case NegotiationState.InitialClientConnection:
				return new ClientConnection (this, false);
			case NegotiationState.RenegotiatingClientConnection:
				return new ClientConnection (this, true);
			case NegotiationState.ClientKeyExchange:
				return new ClientKeyExchange (this);
			case NegotiationState.InitialServerConnection:
				return new ServerConnection (this, false);
			case NegotiationState.RenegotiatingServerConnection:
				return new ServerConnection (this, true);
			case NegotiationState.ServerHello:
				return new ServerHello (this);
			case NegotiationState.ServerFinished:
				return new ServerFinished (this);
			default:
				throw new InvalidOperationException ();
			}
		}

		internal void FinishHandshake ()
		{
			HandshakeParameters.Dispose ();
			HandshakeParameters = null;

			if (Session.CurrentCrypto == null || Session.PendingCrypto != null)
				throw new TlsException (AlertDescription.InsuficientSecurity, "No ciper");
			if (Session.CurrentCrypto.Cipher == null)
				throw new TlsException (AlertDescription.InsuficientSecurity, "No ciper");

			TlsProtocols protocol;
			switch (Session.CurrentCrypto.Protocol) {
			case TlsProtocolCode.Tls10:
				protocol = TlsProtocols.Tls10;
				break;
			case TlsProtocolCode.Tls11:
				protocol = TlsProtocols.Tls11;
				break;
			case TlsProtocolCode.Tls12:
				protocol = TlsProtocols.Tls12;
				break;
			default:
				throw new TlsException (AlertDescription.ProtocolVersion);
			}

			var cipher = Session.CurrentCrypto.Cipher;
			connectionInfo = new MonoTlsConnectionInfo {
				CipherSuiteCode = cipher.Code, ProtocolVersion = protocol,
				CipherAlgorithmType = cipher.CipherAlgorithmType,
				HashAlgorithmType = cipher.HashAlgorithmType,
				ExchangeAlgorithmType = cipher.ExchangeAlgorithmType
			};
		}

		public MonoTlsConnectionInfo ConnectionInfo {
			get { return connectionInfo; }
		}

		#endregion

		#region Crypto

		int MNS.ITlsContext.DecryptMessage (ref TlsBuffer incoming)
		{
			return (int)DecryptMessage (ref incoming);
		}

		public SecurityStatus DecryptMessage (ref TlsBuffer incoming)
		{
			try {
				CheckValid ();
				return _DecryptMessage (ref incoming);
			} catch (TlsException ex) {
				var alert = OnError (ex);
				if (alert != null)
					incoming = new TlsBuffer (alert);
				else
					incoming = null;
				Clear ();
				return SecurityStatus.ContextExpired;
			} catch {
				Clear ();
				throw;
			}
		}

		SecurityStatus _DecryptMessage (ref TlsBuffer incoming)
		{
			// Try to read the Record Content Type
			var contentType = (ContentType)incoming.ReadByte ();
			#if DEBUG_FULL
			if (EnableDebugging)
				DebugHelper.WriteLine ("DecryptMessage({0}): {1}", IsServer ? "server" : "client", contentType);
			#endif

			if (contentType == ContentType.Handshake) {
				#if INSTRUMENTATION
				if (HasInstrumentationEventSink)
					InstrumentationEventSink.StartRenegotiation (this);
				#endif
				incoming.Position--;
				return SecurityStatus.Renegotiate;
			}

			ReadStandardBuffer (contentType, ref incoming);

			if (contentType == ContentType.Alert) {
				var level = (AlertLevel)incoming.ReadByte ();
				var description = (AlertDescription)incoming.ReadByte ();
				if (level == AlertLevel.Warning && description == AlertDescription.CloseNotify) {
					ReceivedCloseNotify = true;
					if (eventSink != null)
						eventSink.ReceivedCloseNotify ();
					return SecurityStatus.ContextExpired;
				}
				DebugHelper.WriteLine ("ALERT: {0} {1}", level, description);
				throw new TlsException (level, description);
			} else if (contentType == ContentType.ApplicationData) {
				return SecurityStatus.OK;
			}

			throw new TlsException (AlertDescription.UnexpectedMessage, "Unknown content type {0}", contentType);
		}

		int MNS.ITlsContext.EncryptMessage (ref TlsBuffer incoming)
		{
			return (int)EncryptMessage (ref incoming);
		}

		public SecurityStatus EncryptMessage (ref TlsBuffer incoming)
		{
			try {
				CheckValid ();
				return _EncryptMessage (ref incoming);
			} catch (TlsException ex) {
				var alert = OnError (ex);
				if (alert != null)
					incoming = new TlsBuffer (alert);
				else
					incoming = null;
				Clear ();
				return SecurityStatus.ContextExpired;
			} catch {
				Clear ();
				throw;
			}
		}

		SecurityStatus _EncryptMessage (ref TlsBuffer incoming)
		{
			#if DEBUG_FULL
			if (EnableDebugging)
			DebugHelper.WriteRemaining ("EncryptMessage", incoming);
			#endif

			var buffer = EncodeRecord (ContentType.ApplicationData, incoming.GetRemaining ());

			#if DEBUG_FULL
			if (EnableDebugging)
				DebugHelper.WriteBuffer ("EncryptMessage done", buffer);
			#endif

			incoming = new TlsBuffer (buffer);
			return SecurityStatus.OK;
		}

		#endregion

		#region Encoding

		internal byte[] EncodeHandshakeRecord (HandshakeMessage message)
		{
			var buffer = message.EncodeMessage ();

			int fragmentSize = MAX_FRAGMENT_SIZE;
			#if INSTRUMENTATION
			if (message.Type == HandshakeType.ServerHello && HasInstrument (HandshakeInstrumentType.FragmentServerHello))
				fragmentSize = 30;
			else if (HasInstrument (HandshakeInstrumentType.FragmentHandshakeMessages))
				fragmentSize = 512;
			#endif

			var encoded = EncodeRecord_internal (ContentType.Handshake, buffer, fragmentSize);
			if (message.Type != HandshakeType.HelloRequest)
				HandshakeParameters.HandshakeMessages.Add (message, buffer);
			#if DEBUG_FULL
			if (EnableDebugging) {
				DebugHelper.WriteLine ("EncodeHandshakeRecord: {0}", message.Type);
				DebugHelper.WriteLine ("Encoded", encoded);
			}
			#endif
			return encoded;
		}

		SecurityStatus EncodeHandshakeRecord (HandshakeMessage message, TlsMultiBuffer output)
		{
			var bytes = EncodeHandshakeRecord (message);

			output.Add (bytes);

			return message.Type == HandshakeType.Finished ? SecurityStatus.OK : SecurityStatus.ContinueNeeded;
		}

		internal byte[] EncodeRecord (ContentType contentType, byte[] buffer)
		{
			return EncodeRecord (contentType, new BufferOffsetSize (buffer));
		}

		internal byte[] EncodeRecord (ContentType contentType, IBufferOffsetSize buffer)
		{
			int fragmentSize = MAX_FRAGMENT_SIZE;
			#if INSTRUMENTATION
			if (HasInstrument (HandshakeInstrumentType.FragmentHandshakeMessages))
				fragmentSize = 512;
			#endif

			return EncodeRecord_internal (contentType, buffer, fragmentSize);
		}

		byte[] EncodeRecord_internal (ContentType contentType, IBufferOffsetSize buffer, int fragmentSize = MAX_FRAGMENT_SIZE)
		{
			CheckValid ();
			var protocol = HasNegotiatedProtocol ? NegotiatedProtocol : Configuration.RequestedProtocol;

			var output = new TlsStream ();
			EncodeRecord_internal (protocol, contentType, Session != null ? Session.Write : null, buffer, output, fragmentSize);
			output.Finish ();

			var result = new byte [output.Size];
			Buffer.BlockCopy (output.Buffer, output.Offset, result, 0, output.Size);
			return result;
		}

		public static void EncodeRecord (TlsProtocolCode protocol, ContentType contentType, CryptoParameters crypto, IBufferOffsetSize buffer, TlsStream output)
		{
			EncodeRecord_internal (protocol, contentType, crypto, buffer, output);
		}

		static void EncodeRecord_internal (TlsProtocolCode protocol, ContentType contentType, CryptoParameters crypto, IBufferOffsetSize buffer, TlsStream output,
			int fragmentSize = MAX_FRAGMENT_SIZE)
		{
			var maxExtraBytes = crypto != null ? crypto.MaxExtraEncryptedBytes : 0;

			var offset = buffer.Offset;
			var remaining = buffer.Size;

			#if !INSTRUMENTATION
			fragmentSize = MAX_FRAGMENT_SIZE;
			#endif

			do {
				BufferOffsetSize fragment;

				var encryptedSize = crypto != null ? crypto.GetEncryptedSize (remaining) : remaining;
				if (encryptedSize <= fragmentSize)
					fragment = new BufferOffsetSize (buffer.Buffer, offset, remaining);
				else {
					fragment = new BufferOffsetSize (buffer.Buffer, offset, fragmentSize - maxExtraBytes);
					encryptedSize = crypto != null ? crypto.GetEncryptedSize (fragment.Size) : fragment.Size;
				}

				// Write tls message
				output.Write ((byte)contentType);
				output.Write ((short)protocol);
				output.Write ((short)encryptedSize);

				if (crypto != null) {
					output.MakeRoom (encryptedSize);
					var ret = crypto.Encrypt (contentType, fragment, output.GetRemaining ());
					output.Position += ret;
				} else {
					output.Write (fragment.Buffer, fragment.Offset, fragment.Size);
				}

				offset += fragment.Size;
				remaining -= fragment.Size;
			} while (remaining > 0);
		}

		bool ReadStandardBuffer (ContentType contentType, ref TlsBuffer buffer)
		{
			if (buffer.Remaining < 4)
				throw new TlsException (
					AlertDescription.DecodeError, "buffer underrun");

			short protocolCode = buffer.ReadInt16 ();
			short length = buffer.ReadInt16 ();

			#if DEBUG_FULL
			if (EnableDebugging) {
				DebugHelper.WriteLine ("ReadStandardBuffer: {0:x} {1:x}", protocolCode, length);
				DebugHelper.WriteRemaining ("  Buffer", buffer);
			}
			#endif

			if (HasNegotiatedProtocol) {
				var protocol = (TlsProtocolCode)protocolCode;
				if (protocol != NegotiatedProtocol)
					throw new TlsException (AlertDescription.ProtocolVersion);
			} else {
				if ((protocolCode >> 8 != 3) || ((protocolCode & 0x00ff) < 1))
					throw new TlsException (AlertDescription.ProtocolVersion);
			}

			if (length != buffer.Remaining)
				throw new TlsException (
					AlertDescription.DecodeError, "Invalid buffer size");

			return DecryptRecordFragment (contentType, ref buffer);
		}

		bool DecryptRecordFragment (ContentType contentType, ref TlsBuffer buffer)
		{
			var read = Session.Read;
			if (read == null || read.Cipher == null)
				return false;

			var output = read.Decrypt (contentType, buffer.GetRemaining ());
			buffer = new TlsBuffer (output);
			return true;
		}

		public byte[] CreateAlert (Alert alert)
		{
			try {
				CheckValid ();
				return _CreateAlert (alert);
			} catch {
				Clear ();
				throw;
			}
		}

		byte[] _CreateAlert (Alert alert)
		{
			var buffer = new BufferOffsetSize (2);
			buffer.Buffer [0] = (byte)alert.Level;
			buffer.Buffer [1] = (byte)alert.Description;

			return EncodeRecord (ContentType.Alert, buffer);
		}

		public byte[] CreateHelloRequest ()
		{
			try {
				CheckValid ();
				return _CreateHelloRequest ();
			} catch {
				Clear ();
				throw;
			}
		}

		byte[] _CreateHelloRequest ()
		{
			var message = new TlsHelloRequest ();
			var buffer = message.EncodeMessage ();

			return EncodeRecord (ContentType.Handshake, buffer);
		}

		#endregion
	}
}

