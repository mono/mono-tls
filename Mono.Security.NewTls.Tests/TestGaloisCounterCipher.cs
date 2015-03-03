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

namespace Mono.Security.NewTls.Tests
{
	public class TestGaloisCounterCipher : CipherTest
	{
		#if FIXME
		protected override void Initialize ()
		{
			Context.InitializeGCM (CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256, GetField (TestKeyName),
				GetField (ImplicitNonce), GetField (ExplicitNonce));
		}

		public TestGaloisCounterCipher (TestConfiguration config, ICryptoTestHost provider)
			: base (config, provider)
		{
		}
		#endif

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

		protected override void Generate ()
		{
			Generator.WriteRandom (TestKeyName, 32);
			Generator.WriteRandom (ImplicitNonce, 4);
			Generator.WriteRandom (ExplicitNonce, 8);
			Generator.WriteRandom (TestDataName, 128);

			Generator.WriteRandom (MagicDataName, MagicDataSize);
			Generator.WriteRandom (MagicData2Name, MagicData2Size);

			Generator.WriteOutput (HelloWorldName, Encoding.UTF8.GetBytes ("Hello World!"));

			#if FIXME
			TestHelloWorld ();
			TestData0 ();
			TestData ();
			#endif
		}

		#endregion

		#if FIXME
		[AsyncTest]
		public void Sizes ()
		{
			Assert.That (Context.BlockSize, Is.EqualTo (16), "#1");
			Assert.That (Context.MinExtraEncryptedBytes, Is.EqualTo (24), "#2");
			Assert.That (Context.MaxExtraEncryptedBytes, Is.EqualTo (24), "#2");
		}

		[AsyncTest]
		public void TestHelloWorld ()
		{
			var buffer = GetBuffer (HelloWorldName);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (buffer.Size + Context.MinExtraEncryptedBytes), "#2");
			WriteOutput (HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestData0 ()
		{
			var buffer =  GetBuffer (TestDataName, 0, 0);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (Context.MinExtraEncryptedBytes), "#2");
			WriteOutput (Data0Result, output);
		}

		[AsyncTest]
		public void TestData ()
		{
			var buffer = GetBuffer (TestDataName);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (buffer.Size + Context.MinExtraEncryptedBytes), "#2");
			WriteOutput (DataResult, output);
		}

		[AsyncTest]
		public void TestInputOffset ()
		{
			var hello = GetBuffer (HelloWorldName);
			var input = new TlsBuffer (hello.Size + MagicDataSize + MagicData2Size);
			input.Write (GetBuffer (MagicDataName));
			var startPos = input.Position;
			input.Write (hello);
			input.Write (GetBuffer (MagicData2Name));

			var output = Context.Encrypt (new BufferOffsetSize (input.Buffer, startPos, hello.Size));
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (hello.Size + Context.MinExtraEncryptedBytes), "#2");

			CheckOutput (HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestOutputOffset ()
		{
			var input = GetBuffer (HelloWorldName);

			var output = new TlsBuffer (input.Size + Context.MaxExtraEncryptedBytes + MagicDataSize);
			output.Write (GetBuffer (MagicDataName));

			var startOffset = output.Offset;
			var startPos = output.Position;
			var startSize = output.Size;

			var length = Context.Encrypt (input, output.GetRemaining ());

			Assert.That (length, Is.GreaterThanOrEqualTo (0), "#1");
			Assert.That (length, Is.EqualTo (input.Size + Context.MinExtraEncryptedBytes), "#2a");
			Assert.That (output.Offset, Is.EqualTo (startOffset), "#2b");
			Assert.That (output.Size, Is.EqualTo (startSize), "#2c");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			Assert.That (magic, Is.EqualTo (GetField (MagicDataName)), "#3");

			var encrypted = output.ReadBytes (length);
			CheckOutput (HelloWorldResult, new BufferOffsetSize (encrypted));
		}

		[AsyncTest]
		public void TestDecrypt ()
		{
			var input = GetBuffer (HelloWorldResult);
			var output = new TlsBuffer (input.Size + MagicDataSize + MagicData2Size);
			output.Write (GetBuffer (MagicDataName));
			output.Write (GetBuffer (MagicData2Name));

			var hello = GetField (HelloWorldName);

			var length = Context.Decrypt (input, output.GetRemaining ());
			Assert.That (length, Is.EqualTo (hello.Length), "#1");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			Assert.That (magic, Is.EqualTo (GetField (MagicDataName)), "#2");

			var magic2 = output.ReadBytes (MagicData2Size);
			Assert.That (magic2, Is.EqualTo (GetField (MagicData2Name)), "#3");

			var decrypted = output.ReadBytes (length);
			Assert.That (decrypted, Is.EqualTo (hello), "#4");
		}
		#endif
	}
}

