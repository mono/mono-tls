//
// MonoNewTlsStream.cs
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

extern alias NewMonoSource;
using EncryptionPolicy = NewMonoSource::System.Net.Security.EncryptionPolicy;
using LocalCertificateSelectionCallback = NewMonoSource::System.Net.Security.LocalCertificateSelectionCallback;
using RemoteCertificateValidationCallback = NewMonoSource::System.Net.Security.RemoteCertificateValidationCallback;
using SslStream = NewMonoSource::System.Net.Security.SslStream;

using System;
using System.IO;
using System.Threading.Tasks;
using Mono.Security.Interface;
using Mono.Security.Protocol.NewTls;

namespace Mono.Security.Providers.NewTls
{
	public class MonoNewTlsStream : SslStream
	{
		internal MonoNewTlsStream (Stream innerStream, TlsSettings settings)
			: this (innerStream, false, null, null, settings)
		{
		}

		internal MonoNewTlsStream (Stream innerStream, bool leaveOpen, TlsSettings settings)
			: this (innerStream, leaveOpen, null, null, EncryptionPolicy.RequireEncryption, settings)
		{
		}

		internal MonoNewTlsStream (Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, MonoTlsSettings settings)
			: this (innerStream, leaveOpen, certValidationCallback, null, EncryptionPolicy.RequireEncryption, settings)
		{
		}

		internal MonoNewTlsStream (Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
		                                LocalCertificateSelectionCallback certSelectionCallback, MonoTlsSettings settings)
			: this (innerStream, leaveOpen, certValidationCallback, certSelectionCallback, EncryptionPolicy.RequireEncryption, settings)
		{
		}

		internal MonoNewTlsStream (Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
		                                LocalCertificateSelectionCallback certSelectionCallback, EncryptionPolicy encryptionPolicy, MonoTlsSettings settings)
			: base (innerStream, leaveOpen, certValidationCallback, certSelectionCallback, encryptionPolicy, settings)
		{
		}

		new public bool IsClosed {
			get { return base.IsClosed; }
		}

		new public TlsException LastError {
			get { return (TlsException)base.LastError; }
		}

		public Task Shutdown (bool waitForReply)
		{
			return Task.Factory.FromAsync ((state, result) => BeginShutdown (waitForReply, state, result), EndShutdown, null);
		}
	}
}


