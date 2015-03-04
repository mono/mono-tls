//
// CipherTest.cs
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
using System.Reflection;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public abstract class CipherTest : ITestHost<IEncryptionTestHost>
	{
		public IEncryptionTestHost CreateInstance (TestContext context)
		{
			var provider = DependencyInjector.Get<ICryptoProvider> ();
			return provider.GetEncryptionTestHost (ProviderType, GetParameters ());
		}

		[NewTlsTestFeatures.SelectCryptoProvider]
		public CryptoTestHostType ProviderType {
			get;
			private set;
		}

		public abstract CryptoTestParameters GetParameters ();

		#region Auto-generated

		protected class OutputGenerator {
			TextWriter output;
			string indent;
			IRandomNumberGenerator rng;
			Dictionary<string,byte[]> fields;

			public OutputGenerator (IRandomNumberGenerator rng, TextWriter output, string indent)
			{
				this.output = output;
				this.indent = indent;
				this.rng = rng;

				fields = new Dictionary<string, byte[]> ();
			}

			public byte[] GetField (string name)
			{
				return fields [name];
			}

			public void WriteRandom (string name, int size)
			{
				var buffer = rng.GetRandomBytes (size);
				WriteOutput (name, buffer);
			}

			public void WriteOutput (string name, IBufferOffsetSize buffer)
			{
				var array = new byte [buffer.Size];
				Buffer.BlockCopy (buffer.Buffer, buffer.Offset, array, 0, buffer.Size);
				WriteOutput (name, array);
			}

			public void WriteOutput (string name, byte[] buffer)
			{
				fields.Add (name, buffer);
				output.WriteLine (DebugHelper.GenerateCSharp (name, indent, buffer));
			}
		}

		OutputGenerator generator;

		protected OutputGenerator Generator {
			get { return generator; }
		}

		protected byte[] GetField (string name)
		{
			if (generator != null)
				return generator.GetField (name);
			var typeInfo = GetType ().GetTypeInfo ();
			var field = typeInfo.GetDeclaredField (name);
			return (byte[])field.GetValue (this);
		}

		protected IBufferOffsetSize GetBuffer (string name)
		{
			return new BufferOffsetSize (GetField (name));
		}

		protected IBufferOffsetSize GetBuffer (string name, int offset, int size)
		{
			var buffer = GetField (name);
			if (offset + size > buffer.Length)
				throw new OverflowException ();
			return new BufferOffsetSize (buffer, offset, size);
		}

		protected void WriteAndCheckOutput (TestContext ctx, string name, IBufferOffsetSize buffer)
		{
			if (generator != null) {
				generator.WriteOutput (name, buffer);
				return;
			}

			CheckOutput (ctx, name, buffer);
		}

		protected void CheckOutput (TestContext ctx, string name, IBufferOffsetSize buffer)
		{
			var array = new byte [buffer.Size];
			Buffer.BlockCopy (buffer.Buffer, buffer.Offset, array, 0, buffer.Size);
			var data = GetField (name);
			ctx.Assert (array, Is.EqualTo (data), "output");
		}

		protected abstract void Generate (TestContext ctx, IEncryptionTestHost host);

		// Call this function to randomly generate these byte arrays.
		public void Generate (TestContext ctx, IRandomNumberGenerator rng, TextWriter output)
		{
			output.WriteLine ("namespace Mono.Security.Instrumentation.Tests");
			output.WriteLine ("{");
			output.WriteLine ("\tpartial class {0}", GetType ().Name);
			output.WriteLine ("\t{");

			generator = new OutputGenerator (rng, output, "\t\t");

			var host = CreateInstance (ctx);

			Generate (ctx, host);

			output.WriteLine ("\t}");
			output.WriteLine ("}");
		}

		#endregion
	}
}

