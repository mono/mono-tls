//
// Instrumentation.cs
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
using System.Text;
using System.Threading;
using System.Collections.Generic;

namespace Mono.Security.NewTls
{
	public class Instrumentation
	{
		HashSet<HandshakeInstrumentType> handshakeInstruments;

		public bool HasEventSink {
			get { return EventSink != null; }
		}

		public InstrumentationEventSink EventSink {
			get; set;
		}

		public bool HasSettingsInstrument {
			get { return SettingsInstrument != null; }
		}

		public SettingsProvider SettingsInstrument {
			get; set;
		}

		public bool HasSignatureInstrument {
			get { return SignatureInstrument != null; }
		}

		public SignatureProvider SignatureInstrument {
			get; set;
		}

		public ISet<HandshakeInstrumentType> HandshakeInstruments {
			get {
				if (handshakeInstruments == null)
					Interlocked.CompareExchange<HashSet<HandshakeInstrumentType>> (ref handshakeInstruments, new HashSet<HandshakeInstrumentType> (), null);
				return handshakeInstruments;
			}
		}

		public const string TheQuickBrownFox = "The quick brown fox jumps over the lazy dog";
		public static readonly byte[] TheQuickBrownFoxBuffer = new byte[] {
			0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20,
			0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67
		};

		public static byte[] GetTextBuffer (HandshakeInstrumentType type)
		{
			var text = string.Format ("@{0}:{1}", type, TheQuickBrownFox);
			return Encoding.UTF8.GetBytes (text);
		}
	}
}

