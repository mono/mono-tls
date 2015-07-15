//
// MonoSslStream.cs
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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.ConnectionFramework;

using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoSslStream : ISslStream, IMonoSslStream
	{
		readonly MSI.MonoSslStream stream;
		readonly MonoNewTlsStream monoNewTlsStream;

		public MonoSslStream (MSI.MonoSslStream stream)
		{
			this.stream = stream;

			if (NewTlsProvider.IsNewTlsStream (stream))
				monoNewTlsStream = NewTlsProvider.GetNewTlsStream (stream);
		}

		public bool IsAuthenticated {
			get { return stream.IsAuthenticated; }
		}

		public bool IsMutuallyAuthenticated {
			get { return stream.IsMutuallyAuthenticated; }
		}

		public bool HasLocalCertificate {
			get { return stream.InternalLocalCertificate != null; }
		}

		public bool HasRemoteCertificate {
			get { return stream.RemoteCertificate != null; }
		}

		public Stream AuthenticatedStream {
			get { return stream.AuthenticatedStream; }
		}

		public bool SupportsCleanShutdown {
			get { return monoNewTlsStream != null; }
		}

		public ProtocolVersions ProtocolVersion {
			get { return (ProtocolVersions)stream.SslProtocol; }
		}

		public Exception LastError {
			get {
				if (monoNewTlsStream != null)
					return monoNewTlsStream.LastError;
				return null;
			}
		}

		public async Task<bool> TryCleanShutdown ()
		{
			if (monoNewTlsStream == null)
				return false;
			await monoNewTlsStream.Shutdown ();
			return true;
		}

		public Task RequestRenegotiation ()
		{
			return monoNewTlsStream.RequestRenegotiation ();
		}
	}
}

