//
// MonoNewTlsStreamFactory.cs
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
extern alias NewSystemSource;
using XEncryptionPolicy = NewSystemSource::System.Net.Security.EncryptionPolicy;
using XSslPolicyErrors = NewSystemSource::System.Net.Security.SslPolicyErrors;
using XLocalCertificateSelectionCallback = NewSystemSource::System.Net.Security.LocalCertificateSelectionCallback;
using XRemoteCertificateValidationCallback = NewSystemSource::System.Net.Security.RemoteCertificateValidationCallback;

using System;
using System.IO;
using PrebuiltSystem::System.Net.Security;
using PrebuiltSystem::System.Security.Authentication;
using TlsSettings = Mono.Security.NewTls.TlsSettings;

using PSSCX = PrebuiltSystem::System.Security.Cryptography.X509Certificates;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Providers.NewTls
{
	public static class MonoNewTlsStreamFactory
	{
		public static MonoNewTlsStream CreateServer (
			Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
			LocalCertificateSelectionCallback certSelectionCallback, XEncryptionPolicy encryptionPolicy, TlsSettings settings,
			SSCX.X509Certificate serverCertificate, bool clientCertificateRequired, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
		{
			var stream = new MonoNewTlsStream (
				innerStream, leaveOpen,
				ConvertCallback (certValidationCallback),
				ConvertCallback (certSelectionCallback),
				(XEncryptionPolicy)encryptionPolicy,
				settings);

			try {
				stream.AuthenticateAsServer (serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation);
			} catch (Exception ex) {
				var tlsEx = stream.LastError;
				if (tlsEx != null)
					throw new AggregateException (ex, tlsEx);
				throw;
			}

			return stream;
		}

		public static MonoNewTlsStream CreateClient (
			Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
			LocalCertificateSelectionCallback certSelectionCallback, XEncryptionPolicy encryptionPolicy, TlsSettings settings,
			string targetHost, PSSCX.X509CertificateCollection clientCertificates, SslProtocols enabledSslProtocols, bool checkCertificateRevocation)
		{
			var stream = new MonoNewTlsStream (
				innerStream, leaveOpen,
				ConvertCallback (certValidationCallback),
				ConvertCallback (certSelectionCallback),
				(XEncryptionPolicy)encryptionPolicy,
				settings);

			try {
				stream.AuthenticateAsClient (targetHost, clientCertificates, enabledSslProtocols, checkCertificateRevocation);
			} catch (Exception ex) {
				var tlsEx = stream.LastError;
				if (tlsEx != null)
					throw new AggregateException (ex, tlsEx);
				throw;
			}
			return stream;
		}

		static XLocalCertificateSelectionCallback ConvertCallback (LocalCertificateSelectionCallback callback)
		{
			if (callback == null)
				return null;
			return (s, t, lc, rc, ai) => callback (s, t, lc, rc, ai);
		}

		static XRemoteCertificateValidationCallback ConvertCallback (RemoteCertificateValidationCallback callback)
		{
			if (callback == null)
				return null;
			return (s, c, ch, e) => callback (s, c, ch, (SslPolicyErrors)e);
		}
	}
}
