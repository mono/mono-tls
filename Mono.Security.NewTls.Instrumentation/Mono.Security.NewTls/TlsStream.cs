//
// TlsStream2.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2014 Xamarin Inc. (http://www.xamarin.com)
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

namespace Mono.Security.NewTls
{
	public class TlsStream : TlsBuffer
	{
		const int ChunkSize = 16384;

		bool finished;

		public void MakeRoom (int size)
		{
			MakeRoomInternal (size);
		}

		protected override void MakeRoomInternal (int size)
		{
			if (Position + size <= EndOffset)
				return;
			if (finished)
				throw new InvalidOperationException ();
			var expandBy = ((size + ChunkSize - 1) / ChunkSize) * ChunkSize;
			var newBuffer = new byte [Size + expandBy];
			if (Buffer != null)
				System.Buffer.BlockCopy (Buffer, 0, newBuffer, 0, Position);

			SetBuffer (newBuffer, 0, newBuffer.Length);
		}

		public int Length {
			get { return finished ? Size : Position; }
		}

		public void Finish ()
		{
			finished = true;
			SetBuffer (Buffer, 0, Position);
			Position = 0;
		}
	}
}

