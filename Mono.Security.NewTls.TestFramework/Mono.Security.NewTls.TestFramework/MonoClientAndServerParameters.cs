//
// MonoClientAndServerParameters.cs
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
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFramework
{
	using Instrumentation;

	public class MonoClientAndServerParameters : ClientAndServerParameters
	{
		public MonoClientAndServerParameters (string identifier, IServerCertificate certificate)
			: base (identifier, new MonoClientParameters (identifier), new MonoServerParameters (identifier, certificate))
		{
		}

		protected MonoClientAndServerParameters (string identifier, MonoClientParameters clientParameters, MonoServerParameters serverParameters)
			: base (identifier, clientParameters, serverParameters)
		{
		}

		public MonoClientAndServerParameters (ClientParameters clientParameters, ServerParameters serverParameters)
			: base (clientParameters, serverParameters)
		{
		}

		protected MonoClientAndServerParameters (MonoClientAndServerParameters other)
			: base (other)
		{
			ExpectedCipher = other.ExpectedCipher;
		}

		public override ConnectionParameters DeepClone ()
		{
			return new MonoClientAndServerParameters (this);
		}

		public MonoClientParameters MonoClientParameters {
			get { return (MonoClientParameters)base.ClientParameters; }
		}

		public MonoServerParameters MonoServerParameters {
			get { return (MonoServerParameters)base.ServerParameters; }
		}

		public ICollection<CipherSuiteCode> ClientCiphers {
			get { return MonoClientParameters.ClientCiphers; }
			set { MonoClientParameters.ClientCiphers = value; }
		}

		public ICollection<CipherSuiteCode> ServerCiphers {
			get { return MonoServerParameters.ServerCiphers; }
			set { MonoServerParameters.ServerCiphers = value; }
		}

		public CipherSuiteCode? ExpectedCipher {
			get; set;
		}

		public CipherSuiteCode? ExpectedClientCipher {
			get { return MonoClientParameters.ExpectedCipher; }
			set { MonoClientParameters.ExpectedCipher = value; }
		}

		public CipherSuiteCode? ExpectedServerCipher {
			get { return MonoServerParameters.ExpectedCipher; }
			set { MonoServerParameters.ExpectedCipher = value; }
		}

		public InstrumentCollection ClientInstrumentation {
			get { return MonoClientParameters.Instrumentation; }
			set { MonoClientParameters.Instrumentation = value; }
		}

		public InstrumentCollection ServerInstrumentation {
			get { return MonoServerParameters.Instrumentation; }
			set { MonoServerParameters.Instrumentation = value; }
		}
	}
}

