using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;

	[Category ("CBC")]
	public partial class TestCbcBlockCipher : CipherTest
	{
		protected override void Initialize ()
		{
			Context.EnableDebugging = true;
			Context.InitializeCBC (CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA, GetField (TestKeyName), GetField (TestMacName), GetField (TestIvName));
		}

		public TestCbcBlockCipher (TestConfiguration config, ICryptoTestProvider provider)
			: base (config, provider)
		{
		}

		#region Auto-generated

		const string TestKeyName = "testKey";
		const string TestMacName = "testMac";
		const string TestIvName = "testIV";
		const string TestDataName = "testData";
		const string HelloWorldName = "helloWorld";
		const string MultiFragmentName = "multiFragment";

		const int MagicDataSize = 13;
		const int MagicData2Size = 21;

		const string MagicDataName = "magicData";
		const string MagicData2Name = "magicData2";

		const string HelloWorldResult = "helloWorldResult";
		const string Data0Result = "testData0Result";
		const string Data11Result = "testData11Result";
		const string Data12Result = "testData12Result";
		const string Data13Result = "testData13Result";
		const string DataResult = "testDataResult";
		const string RecordResult = "recordResult";
		const string MultiFragmentResult = "multiFragmentResult";

		const string ExtraPaddingResult = "testWithExtraPadding";

		protected override void Generate ()
		{
			Generator.WriteRandom (TestKeyName, 32);
			Generator.WriteRandom (TestMacName, 32);
			Generator.WriteRandom (TestIvName, 16);
			Generator.WriteRandom (TestDataName, 128);
			Generator.WriteRandom (MultiFragmentName, TlsContext.MAX_FRAGMENT_SIZE + 32);

			Generator.WriteRandom (MagicDataName, MagicDataSize);
			Generator.WriteRandom (MagicData2Name, MagicData2Size);

			Generator.WriteOutput (HelloWorldName, Encoding.ASCII.GetBytes ("Hello World!"));

			SetUp ();

			TestHelloWorld ();
			TestData ();
			TestData0 ();
			TestData11 ();
			TestData12 ();
			TestData13 ();
			TestRecord ();
			TestMultiFragment ();

			TestEncryptWithExtraPadding ();
		}

		#endregion

		[Test]
		public void Sizes ()
		{
			Assert.That (Context.BlockSize, Is.EqualTo (16), "#1");
			Assert.That (Context.MinExtraEncryptedBytes, Is.EqualTo (37), "#2");
			Assert.That (Context.MaxExtraEncryptedBytes, Is.EqualTo (52), "#2");
		}

		[Test]
		public void TestHelloWorld ()
		{
			var buffer = GetBuffer (HelloWorldName);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + Context.MinExtraEncryptedBytes), "#2");
			Assert.That (output.Size, Is.LessThanOrEqualTo (buffer.Size + Context.MaxExtraEncryptedBytes), "#3");
			WriteOutput (HelloWorldResult, output);
		}

		[Test]
		public void TestData0 ()
		{
			var buffer = GetBuffer (TestDataName, 0, 0);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (48), "#2");
			WriteOutput (Data0Result, output);
		}

		[Test]
		public void TestData11 ()
		{
			// This will use zero padding.
			var buffer = GetBuffer (TestDataName, 0, 11);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (48), "#2");
			WriteOutput (Data11Result, output);
		}

		[Test]
		public void TestData12 ()
		{
			var buffer = GetBuffer (TestDataName, 0, 12);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (64), "#2");
			WriteOutput (Data12Result, output);
		}

		[Test]
		public void TestData13 ()
		{
			var buffer = GetBuffer (TestDataName, 0, 13);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.EqualTo (64), "#2");
			WriteOutput (Data13Result, output);
		}

		[Test]
		public void TestData ()
		{
			var buffer = GetBuffer (TestDataName);
			var output = Context.Encrypt (buffer);
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + Context.MinExtraEncryptedBytes), "#2");
			Assert.That (output.Size, Is.LessThanOrEqualTo (buffer.Size + Context.MaxExtraEncryptedBytes), "#3");
			WriteOutput (DataResult, output);
		}

		[Test]
		public void TestRecord ()
		{
			var buffer = GetBuffer (TestDataName);

			var output = new TlsStream ();
			Context.EncryptRecord (ContentType.ApplicationData, buffer, output);

			Assert.That (output.Position, Is.GreaterThanOrEqualTo (buffer.Size + Context.MinExtraEncryptedBytes + 5), "#2a");
			Assert.That (output.Position, Is.LessThanOrEqualTo (buffer.Size + Context.MaxExtraEncryptedBytes + 5), "#2b");

			var encryptedSize = Context.GetEncryptedSize (buffer.Size);
			Assert.That (output.Position, Is.EqualTo (encryptedSize + 5), "#2c");

			output.Position = 0;
			Assert.That (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#4a");
			Assert.That (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#4b");
			Assert.That (output.ReadInt16 (), Is.EqualTo (encryptedSize), "#4c");
			output.Position += encryptedSize;

			WriteOutput (RecordResult, new BufferOffsetSize (output.Buffer, 0, output.Position));
		}

		[Test]
		public void TestMultiFragment ()
		{
			// Padding will push us above the maximum fragment size.
			var size = TlsContext.MAX_FRAGMENT_SIZE - Context.MinExtraEncryptedBytes + 1;
			var encryptedSize = Context.GetEncryptedSize (size);
			Assert.That (encryptedSize, Is.GreaterThan (TlsContext.MAX_FRAGMENT_SIZE));

			var buffer = GetBuffer (MultiFragmentName, 0, size);
			var output = new TlsStream ();
			Context.EncryptRecord (ContentType.ApplicationData, buffer, output);
			Assert.That (output.Position, Is.GreaterThanOrEqualTo (size + 2 * Context.MinExtraEncryptedBytes + 10), "#2a");
			Assert.That (output.Position, Is.LessThanOrEqualTo (size + 2 * Context.MaxExtraEncryptedBytes + 10), "#2b");
			Assert.That (output.Offset, Is.EqualTo (0), "#3");

			output.Position = 0;
			Assert.That (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#4a");
			Assert.That (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#4b");

			var firstChunkSize = output.ReadInt16 ();
			Assert.That (firstChunkSize, Is.GreaterThanOrEqualTo (TlsContext.MAX_FRAGMENT_SIZE - Context.MaxExtraEncryptedBytes - 1), "#4c");
			Assert.That (firstChunkSize, Is.LessThanOrEqualTo (TlsContext.MAX_FRAGMENT_SIZE), "#4d");

			output.Position += firstChunkSize;

			Assert.That (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#5a");
			Assert.That (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#5b");

			var secondChunkSize = output.ReadInt16 ();
			Assert.That (secondChunkSize, Is.GreaterThanOrEqualTo (encryptedSize - firstChunkSize + Context.MinExtraEncryptedBytes), "#5c");
			Assert.That (secondChunkSize, Is.LessThanOrEqualTo (encryptedSize - firstChunkSize + Context.MaxExtraEncryptedBytes), "#5d");
			output.Position += secondChunkSize;

			WriteOutput (MultiFragmentResult, new BufferOffsetSize (output.Buffer, 0, output.Position));
		}

		[Test]
		public void TestInputOffset ()
		{
			var hello = GetBuffer (HelloWorldName);
			var input = new TlsBuffer (hello.Size + MagicDataSize + MagicData2Size);
			input.Write (GetField (MagicDataName));
			var startPos = input.Position;
			input.Write (hello);
			input.Write (GetBuffer (MagicData2Name));

			var output = Context.Encrypt (new BufferOffsetSize (input.Buffer, startPos, hello.Size));
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.GreaterThanOrEqualTo (hello.Size + Context.MinExtraEncryptedBytes), "#2");
			Assert.That (output.Size, Is.LessThanOrEqualTo (hello.Size + Context.MaxExtraEncryptedBytes), "#2");
			CheckOutput (HelloWorldResult, output);
		}

		[Test]
		public void TestOutputOffset ()
		{
			var input =  GetBuffer (HelloWorldName);

			var output = new TlsBuffer (input.Size + Context.MaxExtraEncryptedBytes + MagicDataSize);
			output.Write (GetBuffer (MagicDataName));

			var startOffset = output.Offset;
			var startPos = output.Position;
			var startSize = output.Size;

			var length = Context.Encrypt (input, output.GetRemaining ());

			Assert.That (length, Is.GreaterThanOrEqualTo (0), "#1");
			Assert.That (length, Is.GreaterThanOrEqualTo (input.Size + Context.MinExtraEncryptedBytes), "#2a");
			Assert.That (length, Is.LessThanOrEqualTo (input.Size + Context.MaxExtraEncryptedBytes), "#2a");
			Assert.That (output.Offset, Is.EqualTo (startOffset), "#2b");
			Assert.That (output.Size, Is.EqualTo (startSize), "#2c");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			Assert.That (magic, Is.EqualTo (GetField (MagicDataName)), "#3");

			var encrypted = output.ReadBytes (length);
			CheckOutput (HelloWorldResult, new BufferOffsetSize (encrypted));
		}


		[Test]
		public void TestDecrypt ()
		{
			var input = GetBuffer (HelloWorldResult);
			var output = new TlsBuffer (input.Size);

			var hello = GetField (HelloWorldName);

			var length = Context.Decrypt (input, output.GetRemaining ());
			Assert.That (length, Is.EqualTo (hello.Length), "#1");

			output.Position = 0;
			var decrypted = output.ReadBytes (length);
			Assert.That (decrypted, Is.EqualTo (hello), "#4");
		}

		[Test]
		public void TestDecryptData0 ()
		{
			var input = GetBuffer (Data0Result);
			var output = Context.Decrypt (input);

			Assert.That (output.Size, Is.EqualTo (0), "#1");
		}

		[Test]
		public void TestDecryptData11 ()
		{
			var input = GetBuffer (Data11Result);
			var output = Context.Decrypt (input);

			Assert.That (output.Size, Is.EqualTo (11), "#1");
			Assert.That (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 11)), "#2");
		}

		[Test]
		public void TestDecryptData12 ()
		{
			var input = GetBuffer (Data12Result);
			var output = Context.Decrypt (input);

			Assert.That (output.Size, Is.EqualTo (12), "#1");
			Assert.That (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 12)), "#2");
		}

		[Test]
		public void TestDecryptData13 ()
		{
			var input = GetBuffer (Data13Result);
			var output = Context.Decrypt (input);

			Assert.That (output.Size, Is.EqualTo (13), "#1");
			Assert.That (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 13)), "#2");
		}

		[Test]
		public void TestDecryptData ()
		{
			var input = GetBuffer (DataResult);
			var output = Context.Decrypt (input);

			var data = GetBuffer (TestDataName);

			Assert.That (output.Size, Is.EqualTo (data.Size), "#1");
			Assert.That (TlsBuffer.Compare (output, data), "#2");
		}

		[Test]
		public void TestEncryptWithExtraPadding ()
		{
			var buffer = GetBuffer (TestDataName);
			IBufferOffsetSize output;
			try {
				Context.ExtraPaddingBlocks = 13;
				output = Context.Encrypt (buffer);
			} finally {
				Context.ExtraPaddingBlocks = 0;
			}

			var extraPadding = 13 * 16;
			Assert.That (output, Is.Not.Null, "#1");
			Assert.That (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + extraPadding + Context.MinExtraEncryptedBytes), "#2");
			Assert.That (output.Size, Is.LessThanOrEqualTo (buffer.Size + extraPadding + Context.MaxExtraEncryptedBytes), "#3");
			WriteOutput (ExtraPaddingResult, output);
		}

		[Test]
		public void TestDecryptWithExtraPadding ()
		{
			var input = GetBuffer (ExtraPaddingResult);
			var output = Context.Decrypt (input);

			var data = GetBuffer (TestDataName);

			Assert.That (output.Size, Is.EqualTo (data.Size), "#1");
			Assert.That (TlsBuffer.Compare (output, data), "#2");
		}

		[Test]
		public void TestDecryptWithInvalidPadding ()
		{
			var input = GetBuffer (ExtraPaddingResult);

			var modified = new TlsBuffer (input.Size);
			modified.Write (input.Buffer);

			var theOffset = modified.Size - (2 * Context.BlockSize) - 5;
			modified.Buffer [theOffset] ^= 0x01;

			input = new BufferOffsetSize (modified.Buffer, 0, modified.Size);

			try {
				Context.Decrypt (input);
				Assert.Fail ("#1");
			} catch (Exception ex) {
				Assert.That (ex, Is.InstanceOf<TlsException> (), "#2");
				var tlsEx = (TlsException)ex;
				Assert.That (tlsEx.Alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3");
				Assert.That (tlsEx.Alert.Description, Is.EqualTo (AlertDescription.BadRecordMAC), "#4");
			}
		}

		[Test]
		public void TestDecryptWithInvalidPadding2 ()
		{
			var input = GetBuffer (Data11Result);

			var modified = new TlsBuffer (input.Size);
			modified.Write (input.Buffer);

			// Flip a bit in the last byte, this will affect the padding size.
			modified.Buffer [modified.Size - 1] ^= 0x01;

			input = new BufferOffsetSize (modified.Buffer, 0, modified.Size);

			try {
				Context.Decrypt (input);
				Assert.Fail ("#1");
			} catch (Exception ex) {
				Assert.That (ex, Is.InstanceOf<TlsException> (), "#2");
				var tlsEx = (TlsException)ex;
				Assert.That (tlsEx.Alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3");
				Assert.That (tlsEx.Alert.Description, Is.EqualTo (AlertDescription.BadRecordMAC), "#4");
			}
		}
	}
}
