//
// ClientParameters.cs
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
using System.Linq;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public sealed class ClientParameters : ConnectionParameters, IClientParameters, ICloneable
	{
		public ClientParameters (string identifier)
			: base (identifier)
		{
		}

		ClientParameters (ClientParameters other)
			: base (other)
		{
			if (other.ClientCiphers != null)
				ClientCiphers = new List<CipherSuiteCode> (other.ClientCiphers);
			ClientCertificate = other.ClientCertificate;
			ExpectedCipher = other.ExpectedCipher;
		}

		object ICloneable.Clone ()
		{
			return DeepClone ();
		}

		public ClientParameters DeepClone ()
		{
			return new ClientParameters (this);
		}

		public ICollection<CipherSuiteCode> ClientCiphers {
			get; set;
		}

		public IClientCertificate ClientCertificate {
			get; set;
		}

		public CipherSuiteCode? ExpectedCipher {
			get; set;
		}
	}
}

