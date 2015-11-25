//
// TestGaloisCounterGipher.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	[AsyncTestFixture]
	public partial class TestGaloisCounterCipher : CipherTest
	{
		public override CryptoTestParameters GetParameters ()
		{
			return CryptoTestParameters.CreateGCM (
				TlsProtocolCode.Tls12, CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256, GetField (TestKeyName),
				GetField (ImplicitNonce), GetField (ExplicitNonce));
		}

		#region Auto-generated

		const string TestKeyName = "testkey";
		const string ImplicitNonce = "implicitNonce";
		const string ExplicitNonce = "explicitNonce";
		const string TestDataName = "testData";
		const string HelloWorldName = "helloWorld";

		const string HelloWorldResult = "helloWorldResult";
		const string Data0Result = "testData0Result";
		const string DataResult = "testDataResult";

		const int MagicDataSize = 13;
		const int MagicData2Size = 21;

		const string MagicDataName = "magicData";
		const string MagicData2Name = "magicData2";

		protected override void Generate (TestContext ctx, IEncryptionTestHost host)
		{
			Generator.WriteRandom (TestKeyName, 32);
			Generator.WriteRandom (ImplicitNonce, 4);
			Generator.WriteRandom (ExplicitNonce, 8);
			Generator.WriteRandom (TestDataName, 128);

			Generator.WriteRandom (MagicDataName, MagicDataSize);
			Generator.WriteRandom (MagicData2Name, MagicData2Size);

			Generator.WriteOutput (HelloWorldName, Encoding.UTF8.GetBytes ("Hello World!"));

			TestHelloWorld (ctx, host);
			TestData0 (ctx, host);
			TestData (ctx, host);
		}

		#endregion

		[AsyncTest]
		public void Sizes (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			ctx.Assert (host.BlockSize, Is.EqualTo (16), "#1");
			ctx.Assert (host.MinExtraEncryptedBytes, Is.EqualTo (24), "#2");
			ctx.Assert (host.MaxExtraEncryptedBytes, Is.EqualTo (24), "#2");
		}

		[AsyncTest]
		public void TestHelloWorld (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (HelloWorldName);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (buffer.Size + host.MinExtraEncryptedBytes), "#2");
			WriteAndCheckOutput (ctx, HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestData0 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer =  GetBuffer (TestDataName, 0, 0);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (host.MinExtraEncryptedBytes), "#2");
			WriteAndCheckOutput (ctx, Data0Result, output);
		}

		[AsyncTest]
		public void TestData (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (buffer.Size + host.MinExtraEncryptedBytes), "#2");
			WriteAndCheckOutput (ctx, DataResult, output);
		}

		[AsyncTest]
		public void TestInputOffset (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var hello = GetBuffer (HelloWorldName);
			var input = new TlsBuffer (hello.Size + MagicDataSize + MagicData2Size);
			input.Write (GetBuffer (MagicDataName));
			var startPos = input.Position;
			input.Write (hello);
			input.Write (GetBuffer (MagicData2Name));

			var output = host.Encrypt (new BufferOffsetSize (input.Buffer, startPos, hello.Size));
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (hello.Size + host.MinExtraEncryptedBytes), "#2");

			WriteAndCheckOutput (ctx, HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestOutputOffset (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (HelloWorldName);

			var output = new TlsBuffer (input.Size + host.MaxExtraEncryptedBytes + MagicDataSize);
			output.Write (GetBuffer (MagicDataName));

			var startOffset = output.Offset;
			var startPos = output.Position;
			var startSize = output.Size;

			var length = host.Encrypt (input, output.GetRemaining ());

			ctx.Assert (length, Is.GreaterThanOrEqualTo (0), "#1");
			ctx.Assert (length, Is.EqualTo (input.Size + host.MinExtraEncryptedBytes), "#2a");
			ctx.Assert (output.Offset, Is.EqualTo (startOffset), "#2b");
			ctx.Assert (output.Size, Is.EqualTo (startSize), "#2c");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			ctx.Assert (magic, Is.EqualTo (GetField (MagicDataName)), "#3");

			var encrypted = output.ReadBytes (length);
			CheckOutput (ctx, HelloWorldResult, new BufferOffsetSize (encrypted));
		}

		[AsyncTest]
		public void TestDecrypt (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (HelloWorldResult);
			var output = new TlsBuffer (input.Size + MagicDataSize + MagicData2Size);
			output.Write (GetBuffer (MagicDataName));
			output.Write (GetBuffer (MagicData2Name));

			var hello = GetField (HelloWorldName);

			var length = host.Decrypt (input, output.GetRemaining ());
			ctx.Assert (length, Is.EqualTo (hello.Length), "#1");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			ctx.Assert (magic, Is.EqualTo (GetField (MagicDataName)), "#2");

			var magic2 = output.ReadBytes (MagicData2Size);
			ctx.Assert (magic2, Is.EqualTo (GetField (MagicData2Name)), "#3");

			var decrypted = output.ReadBytes (length);
			ctx.Assert (decrypted, Is.EqualTo (hello), "#4");
		}
	}
}

