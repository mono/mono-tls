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
using System;
using Mono.Security.Interface;
using Mono.Security.Protocol.NewTls;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MX = Mono.Security.X509;

namespace Mono.Security.Providers.NewTls
{
	class TlsContextWrapper : SecretParameters, IMonoTlsContext
	{
		TlsConfiguration config;
		TlsContext context;

		public TlsContextWrapper (TlsConfiguration config)
		{
			this.config = config;
		}

		public bool IsValid {
			get { return context != null && context.IsValid; }
		}

		public void Initialize (bool serverMode)
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

		public void SetCertificate (MX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			Configuration.SetCertificate (certificate, privateKey);
		}

		public int GenerateNextToken (IBufferOffsetSize incoming, out IBufferOffsetSize outgoing)
		{
			var input = incoming != null ? new TlsBuffer (incoming) : null;
			TlsMultiBuffer output = new TlsMultiBuffer ();
			var retval = Context.GenerateNextToken (input, output);
			if (output.IsEmpty)
				outgoing = null;
			outgoing = output.StealBuffer ();
			return (int)retval;
		}

		public int EncryptMessage (ref IBufferOffsetSize incoming)
		{
			var buffer = new TlsBuffer (incoming);
			var retval = Context.EncryptMessage (ref buffer);
			incoming = buffer.GetRemaining ();
			return (int)retval;
		}

		public int DecryptMessage (ref IBufferOffsetSize incoming)
		{
			var buffer = new TlsBuffer (incoming);
			var retval = Context.DecryptMessage (ref buffer);
			incoming = buffer.GetRemaining ();
			return (int)retval;
		}

		public byte[] CreateCloseNotify ()
		{
			return Context.CreateAlert (new Alert (AlertLevel.Warning, AlertDescription.CloseNotify));
		}

		public MX.X509Certificate GetRemoteCertificate (out MX.X509CertificateCollection remoteCertificateStore)
		{
			return Context.GetRemoteCertificate (out remoteCertificateStore);
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
	}
}

