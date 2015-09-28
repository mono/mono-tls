//
// SecureRandomGenerator.cs
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
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class SecureRandomGenerator : Random
	{
		protected RandomNumberGenerator generator;

		public SecureRandomGenerator (RandomNumberGenerator generator)
			: base (0)
		{
			this.generator = generator;
		}

		public override int Next ()
		{
			for (;;) {
				int i = NextInt () & int.MaxValue;

				if (i != int.MaxValue)
					return i;
			}
		}

		public override int Next (int maxValue)
		{
			if (maxValue < 2) {
				if (maxValue < 0)
					throw new ArgumentOutOfRangeException ("maxValue < 0");

				return 0;
			}

			// Test whether maxValue is a power of 2
			if ((maxValue & -maxValue) == maxValue) {
				int val = NextInt () & int.MaxValue;
				long lr = ((long)maxValue * (long)val) >> 31;
				return (int)lr;
			}

			int bits, result;
			do {
				bits = NextInt () & int.MaxValue;
				result = bits % maxValue;
			} while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

			return result;
		}

		public override int Next (int minValue, int maxValue)
		{
			if (maxValue <= minValue) {
				if (maxValue == minValue)
					return minValue;

				throw new ArgumentException ("maxValue cannot be less than minValue");
			}

			int diff = maxValue - minValue;
			if (diff > 0)
				return minValue + Next (diff);

			for (;;) {
				int i = NextInt ();

				if (i >= minValue && i < maxValue)
					return i;
			}
		}

		public override void NextBytes (byte[] buffer)
		{
			generator.GetBytes (buffer);
		}

		private static readonly double DoubleScale = System.Math.Pow (2.0, 64.0);

		public override double NextDouble ()
		{
			return Convert.ToDouble ((ulong)NextLong ()) / DoubleScale;
		}

		public virtual int NextInt ()
		{
			byte[] intBytes = new byte[4];
			NextBytes (intBytes);

			int result = 0;
			for (int i = 0; i < 4; i++) {
				result = (result << 8) + (intBytes [i] & 0xff);
			}

			return result;
		}

		public virtual long NextLong ()
		{
			return ((long)(uint)NextInt () << 32) | (long)(uint)NextInt ();
		}
	}
}

