//
// TlsContextWrapper.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
extern alias PrebuiltSystem;
using System;
using Mono.Security.NewTls;
using System.Security.Cryptography;
using SSCX = System.Security.Cryptography.X509Certificates;
using PSSCX = PrebuiltSystem::System.Security.Cryptography.X509Certificates;

#if PREBUILT_MSI
using MSI = PrebuiltSystem::Mono.Security.Interface;
#else
using MSI = Mono.Security.Interface;
#endif
using MX = Mono.Security.X509;

namespace Mono.Security.Providers.NewTls
{
	class TlsContextWrapper : SecretParameters, MSI.IMonoTlsContext
	{
		TlsConfiguration config;
		TlsContext context;
		bool serverMode;

		public TlsContextWrapper (TlsConfiguration config, bool serverMode)
		{
			this.config = config;
			this.serverMode = serverMode;
		}

		public bool IsServer {
			get { return serverMode; }
		}

		public bool IsValid {
			get { return context != null && context.IsValid; }
		}

		public void Initialize ()
		{
			if (context != null)
				throw new InvalidOperationException ();
			context = new TlsContext (config, serverMode);
		}

		protected override void Clear ()
		{
			if (context != null) {
				context.Clear ();
				context = null;
			}
		}

		public TlsConfiguration Configuration {
			get {
				if (config == null)
					throw new ObjectDisposedException ("TlsConfiguration");
				return config;
			}
		}

		public TlsContext Context {
			get {
				if (!IsValid)
					throw new ObjectDisposedException ("TlsContext");
				return context;
			}
		}

		public bool HasCredentials {
			get { return Configuration.HasCredentials; }
		}

		public void SetCertificate (SSCX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			var monoCert = new MX.X509Certificate (certificate.GetRawCertData ());
			Configuration.SetCertificate (monoCert, privateKey);
		}

		public int GenerateNextToken (MSI.IBufferOffsetSize incoming, out MSI.IBufferOffsetSize outgoing)
		{
			var input = incoming != null ? new TlsBuffer (BOSWrapper.Wrap (incoming)) : null;
			TlsMultiBuffer output = new TlsMultiBuffer ();
			var retval = Context.GenerateNextToken (input, output);
			if (output.IsEmpty)
				outgoing = null;
			outgoing = BOSWrapper.Wrap (output.StealBuffer ());
			return (int)retval;
		}

		public int EncryptMessage (ref MSI.IBufferOffsetSize incoming)
		{
			var buffer = new TlsBuffer (BOSWrapper.Wrap (incoming));
			var retval = Context.EncryptMessage (ref buffer);
			incoming = BOSWrapper.Wrap (buffer.GetRemaining ());
			return (int)retval;
		}

		public int DecryptMessage (ref MSI.IBufferOffsetSize incoming)
		{
			var buffer = new TlsBuffer (BOSWrapper.Wrap (incoming));
			var retval = Context.DecryptMessage (ref buffer);
			incoming = buffer != null ? BOSWrapper.Wrap (buffer.GetRemaining ()) : null;
			return (int)retval;
		}

		class BOSWrapper : MSI.IBufferOffsetSize, IBufferOffsetSize
		{
			public byte[] Buffer {
				get;
				private set;
			}

			public int Offset {
				get;
				private set;
			}

			public int Size {
				get;
				private set;
			}

			BOSWrapper (byte[] buffer, int offset, int size)
			{
				Buffer = buffer;
				Offset = offset;
				Size = size;
			}

			public static BOSWrapper Wrap (MSI.IBufferOffsetSize bos)
			{
				return bos != null ? new BOSWrapper (bos.Buffer, bos.Offset, bos.Size) : null;
			}

			public static BOSWrapper Wrap (IBufferOffsetSize bos)
			{
				return bos != null ? new BOSWrapper (bos.Buffer, bos.Offset, bos.Size) : null;
			}
		}

		public byte[] CreateCloseNotify ()
		{
			return Context.CreateAlert (new Alert (AlertLevel.Warning, AlertDescription.CloseNotify));
		}

		public SSCX.X509Certificate GetRemoteCertificate (out PSSCX.X509CertificateCollection remoteCertificateStore)
		{
			MX.X509CertificateCollection monoCollection;
			var remoteCert = Context.GetRemoteCertificate (out monoCollection);
			if (remoteCert == null) {
				remoteCertificateStore = null;
				return null;
			}

			remoteCertificateStore = new PSSCX.X509CertificateCollection ();
			foreach (var cert in monoCollection) {
				remoteCertificateStore.Add (new PSSCX.X509Certificate2 (cert.RawData));
			}
			return new PSSCX.X509Certificate2 (remoteCert.RawData);

		}

		public bool VerifyRemoteCertificate ()
		{
			return Context.VerifyRemoteCertificate ();
		}

		public Exception LastError {
			get {
				if (context != null)
					return context.LastError;
				return null;
			}
		}

		public bool ReceivedCloseNotify {
			get {
				return Context.ReceivedCloseNotify;
			}
		}

		public MSI.MonoTlsConnectionInfo GetConnectionInfo ()
		{
			var info = Context.ConnectionInfo;
			if (info == null)
				return null;
			return new MSI.MonoTlsConnectionInfo {
				CipherSuiteCode = (short)info.CipherCode, ProtocolVersion = (MSI.TlsProtocols)info.ProtocolVersion
			};
		}
	}
}

