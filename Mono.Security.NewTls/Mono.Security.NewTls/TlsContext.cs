using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	using Mono.Security.X509;
	using Handshake;
	using Negotiation;
	using Extensions;
	using Cipher;
	#if INSTRUMENTATION
	using Instrumentation;
	#endif

	public class TlsContext
	{
		readonly bool isServer;
		readonly TlsConfiguration configuration;

		Session session;
		HandshakeParameters handshakeParameters;

		TlsProtocolCode negotiatedProtocol;

		NegotiationHandler negotiationHandler;

		TlsBuffer cachedFragment;
		int skipToOffset = -1;

		internal const short MAX_FRAGMENT_SIZE	= 16384; // 2^14

		public bool IsServer {
			get { return isServer; }
		}

		public TlsConfiguration Configuration {
			get { return configuration; }
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

		public TlsContext (TlsConfiguration configuration, bool isServer)
		{
			this.configuration = configuration;
			this.isServer = isServer;

			#if INSTRUMENTATION
			SetupInstrumentation ();
			#endif

			session = new Session (configuration);
			Session.RandomNumberGenerator = RandomNumberGenerator.Create ();

			if (IsServer)
				negotiationHandler = CreateNegotiationHandler (NegotiationState.InitialServerConnection);
			else
				negotiationHandler = CreateNegotiationHandler (NegotiationState.InitialClientConnection);

			if (Configuration.UserSettings != null && Configuration.UserSettings.EnableDebugging)
				EnableDebugging = true;
		}

		#if INSTRUMENTATION

		public ContextInstrument Instrument {
			get;
			private set;
		}
		
		void SetupInstrumentation ()
		{
			if (configuration.UserSettings == null || configuration.UserSettings.Instrumentation == null)
				return;
			if (configuration.UserSettings.Instrumentation.IsEmpty)
				return;
			Instrument = configuration.UserSettings.Instrumentation.Context;
			if (Instrument == null)
				throw new InvalidOperationException ();
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
			if (Session.CurrentCrypto.ServerCertificateVerified)
				return true;
			CertificateManager.CheckRemoteCertificate (Configuration, Session.CurrentCrypto.ServerCertificates);
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

		public void Clear ()
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

		TlsProtocolCode ValidateProtocolCode (TlsProtocolCode protocol)
		{
			if (!Configuration.IsSupportedProtocol (protocol))
				throw new TlsException (AlertDescription.ProtocolVersion);
			if (HasNegotiatedProtocol && protocol != NegotiatedProtocol)
				throw new TlsException (AlertDescription.ProtocolVersion);
			return protocol;
		}

		internal void VerifyServerProtocol (TlsProtocolCode code)
		{
			var serverProtocol = ValidateProtocolCode (code);

			// FIXME: we're overly strict at the moment
			if (serverProtocol != Configuration.RequestedProtocol)
				throw new TlsException (
					AlertDescription.ProtocolVersion,
					"Incorrect protocol version received from server");

			negotiatedProtocol = serverProtocol;
		}

		internal void VerifyClientProtocol (TlsProtocolCode code)
		{
			var clientProtocol = ValidateProtocolCode (code);

			// FIXME: we're overly strict at the moment
			if (clientProtocol != Configuration.RequestedProtocol)
				throw new TlsException (
					AlertDescription.ProtocolVersion,
					"Incorrect protocol version received from client");

			negotiatedProtocol = clientProtocol;
		}

		#endregion

		#region Main Loop

		public SecurityStatus GenerateNextToken (TlsBuffer incoming, TlsMultiBuffer outgoing)
		{
			try {
				CheckValid ();
				return _GenerateNextToken (incoming, outgoing);
			} catch (TlsException ex) {
				LastError = ex;
				var alert = CreateAlert (ex.Alert);
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
				DebugHelper.WriteLine ("GenerateNextToken: {0}", negotiationHandler);
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
				cachedFragment.Write (incoming.Buffer, incoming.Position, incoming.Position + incoming.Remaining);
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
				incoming.Dispose ();
				status = SecurityStatus.ContinueNeeded;
				return false;
			}

			var buffer = incoming.ReadBuffer (length);
			return negotiationHandler.ProcessHandshakeMessage (handshakeType, buffer, out status);
		}

		internal NegotiationHandler CreateNegotiationHandler (NegotiationState state)
		{
			#if INSTRUMENTATION
			if (Instrument != null) {
				var handler = Instrument.CreateNegotiationHandler (this, state);
				if (handler != null)
					return handler;
			}
			#endif

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

			if (configuration.UserSettings != null)
				configuration.UserSettings.ConnectionInfo = GetConnectionInfo ();
		}

		TlsConnectionInfo GetConnectionInfo ()
		{
			return new TlsConnectionInfo {
				CipherCode = Session.CurrentCrypto.Cipher.Code
			};
		}

		#endregion

		#region Crypto

		public SecurityStatus DecryptMessage (ref TlsBuffer incoming)
		{
			try {
				CheckValid ();
				return _DecryptMessage (ref incoming);
			} catch (TlsException ex) {
				LastError = ex;
				var alert = CreateAlert (ex.Alert);
				incoming = new TlsBuffer (alert);
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
				DebugHelper.WriteLine ("DecryptMessage: {0}", contentType);
			#endif

			ReadStandardBuffer (contentType, ref incoming);

			if (contentType == ContentType.Alert) {
				var level = (AlertLevel)incoming.ReadByte ();
				var description = (AlertDescription)incoming.ReadByte ();
				if (level == AlertLevel.Warning && description == AlertDescription.CloseNotify) {
					ReceivedCloseNotify = true;
					return SecurityStatus.ContextExpired;
				}
				DebugHelper.WriteLine ("ALERT: {0} {1}", level, description);
				throw new TlsException (level, description);
			} else if (contentType == ContentType.ApplicationData)
				return SecurityStatus.OK;
			else if (contentType != ContentType.Handshake)
				throw new TlsException (AlertDescription.UnexpectedMessage, "Unknown content type {0}", contentType);

			try {
				SecurityStatus status;
				var finished = ProcessHandshakeMessage (incoming, out status);
				DebugHelper.WriteLine ("RENEGOTIATION REQUEST: {0} {1}", finished, status);
				return status;
			} finally {
				incoming.Dispose ();
				incoming = null;
			}
		}

		public SecurityStatus EncryptMessage (ref TlsBuffer incoming)
		{
			try {
				CheckValid ();
				return _EncryptMessage (ref incoming);
			} catch (TlsException ex) {
				LastError = ex;
				var alert = CreateAlert (ex.Alert);
				incoming = new TlsBuffer (alert);
				Clear ();
				return SecurityStatus.ContextExpired;
			} catch {
				Clear ();
				throw;
			}
		}

		SecurityStatus _EncryptMessage (ref TlsBuffer incoming)
		{
			var buffer = EncodeRecord (ContentType.ApplicationData, incoming.GetRemaining ());
			incoming = new TlsBuffer (buffer);
			return SecurityStatus.OK;
		}

		#endregion

		#region Encoding

		internal byte[] EncodeHandshakeRecord (HandshakeMessage message)
		{
			var buffer = message.EncodeMessage ();

			var encoded = EncodeRecord (ContentType.Handshake, buffer);
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

		internal byte[] EncodeRecord (ContentType contentType, IBufferOffsetSize buffer)
		{
			CheckValid ();
			var protocol = HasNegotiatedProtocol ? NegotiatedProtocol : Configuration.RequestedProtocol;

			var output = new TlsStream ();
			EncodeRecord (protocol, contentType, Session != null ? Session.Write : null, buffer, output);
			output.Finish ();

			var result = new byte [output.Size];
			Buffer.BlockCopy (output.Buffer, output.Offset, result, 0, output.Size);
			return result;
		}

		static internal void EncodeRecord (TlsProtocolCode protocol, ContentType contentType, CryptoParameters crypto, IBufferOffsetSize buffer, TlsStream output)
		{
			var maxExtraBytes = crypto != null ? crypto.MaxExtraEncryptedBytes : 0;

			var offset = buffer.Offset;
			var remaining = buffer.Size;

			do {
				BufferOffsetSize fragment;

				var encryptedSize = crypto != null ? crypto.GetEncryptedSize (remaining) : remaining;
				if (encryptedSize <= MAX_FRAGMENT_SIZE)
					fragment = new BufferOffsetSize (buffer.Buffer, offset, remaining);
				else {
					fragment = new BufferOffsetSize (buffer.Buffer, offset, MAX_FRAGMENT_SIZE - maxExtraBytes);
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

		#endregion
	}
}

