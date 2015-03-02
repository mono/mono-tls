// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez

//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Text;
using System.Diagnostics;

namespace Mono.Security.NewTls
{
	public class DebugHelper
	{
		private static bool isInitialized;

		[Conditional("DEBUG")]
		public static void Initialize()
		{
			if (!isInitialized)
			{
#if !PCL
				Debug.Listeners.Add(new TextWriterTraceListener(Console.Out));
				// Debug.Listeners.Add(new TextWriterTraceListener(@"c:\ssl.log"));
				Debug.AutoFlush = true;
				Debug.Indent();
#endif

				isInitialized = true;
			}
		}

		[Conditional("DEBUG")]
		public static void WriteLine(string format, params object[] args)
		{
			Initialize();
			Debug.WriteLine(String.Format(format, args));
		}

		[Conditional("DEBUG")]
		public static void WriteLine(string message)
		{
			Initialize();
			Debug.WriteLine(message);
		}

		[Conditional("DEBUG")]
		public static void WriteLine(string message, byte[] buffer)
		{
			Initialize();
			DebugHelper.WriteLine(String.Format("{0} ({1} bytes)", message, buffer.Length));
			DebugHelper.WriteBuffer(buffer);
		}

		[Conditional("DEBUG")]
		public static void WriteLine(string message, SecureBuffer buffer)
		{
			Initialize();
			DebugHelper.WriteLine(String.Format("{0} ({1} bytes)", message, buffer.Size));
			DebugHelper.WriteBuffer(buffer.Buffer);
		}

		[Conditional("DEBUG")]
		public static void WriteBuffer(byte[] buffer)
		{
			Initialize();
			DebugHelper.WriteBuffer(buffer, 0, buffer.Length);
		}

		[Conditional("DEBUG")]
		public static void WriteBuffer(byte[] buffer, int index, int length)
		{
			Initialize();
			for (int i = index; i < index+length; i += 16)
			{
				int count = (index + length - i) >= 16 ? 16 : (index + length - i);
				string buf = "";
				for (int j = 0; j < count; j++)
				{
					buf += buffer[i + j].ToString("x2") + " ";
				}
				Debug.WriteLine(buf);
			}
		}

		[Obsolete]
		[Conditional ("DEBUG")]
		public static void WriteBuffer(TlsBuffer buffer)
		{
			WriteBuffer(buffer.Buffer, buffer.Position, buffer.Remaining);
		}

		[Conditional ("DEBUG")]
		public static void WriteBuffer(IBufferOffsetSize buffer)
		{
			WriteBuffer(buffer.Buffer, buffer.Offset, buffer.Size);
		}

		[Obsolete]
		[Conditional ("DEBUG")]
		public static void WriteLine(string message, TlsBuffer buffer)
		{
			Initialize ();
			DebugHelper.WriteLine(String.Format("{0} ({1} bytes)", message, buffer.Remaining));
			DebugHelper.WriteBuffer (buffer);
		}

		[Conditional ("DEBUG")]
		public static void WriteLine(string message, IBufferOffsetSize buffer)
		{
			Initialize ();
			DebugHelper.WriteLine(String.Format("{0} ({1} bytes)", message, buffer.Size));
			DebugHelper.WriteBuffer (buffer);
		}

		[Conditional ("DEBUG")]
		public static void WriteBuffer(string message, bool full, TlsBuffer buffer)
		{
			Initialize ();
			var offset = full ? buffer.Offset : buffer.Position;
			var size = full ? buffer.Size : buffer.Remaining;
			DebugHelper.WriteLine ("{0} ({1} bytes)", message, size);
			DebugHelper.WriteBuffer (buffer.Buffer, offset, size);
		}

		[Conditional ("DEBUG")]
		public static void WriteRemaining(string message, TlsBuffer buffer)
		{
			WriteBuffer (message, false, buffer);
		}

		[Conditional ("DEBUG")]
		public static void WriteFull(string message, TlsBuffer buffer)
		{
			WriteBuffer (message, true, buffer);
		}

		[Conditional ("DEBUG")]
		public static void WriteCSharp(string name, string value)
		{
			WriteLine ("const string {0} = \"{1}\";\n", name, value);
		}

		[Conditional ("DEBUG")]
		public static void WriteCSharp(string name, byte[] buffer)
		{
			WriteLine (GenerateCSharp (name, string.Empty, buffer));
		}

		public static string GenerateCSharp(string name, string indent, byte[] buffer)
		{
			return GenerateCSharp (name, indent, buffer, 0, buffer.Length);
		}

		public static string GenerateCSharp(string name, string indent, byte[] buffer, int offset, int size)
		{
			var sb = new StringBuilder ();
			sb.AppendFormat ("{0}internal static readonly byte[] {1} = new byte[] {{\n", indent, name);
			for (int i = 0; i < size; i++) {
				if ((i % 16) == 0)
					sb.Append (indent + "\t");
				sb.AppendFormat ("0x{0:x2}", buffer [offset + i]);
				if (i + 1 >= size)
					break;
				sb.Append (",");
				if (((i + 1) % 16) == 0)
					sb.AppendLine ();
				else
					sb.Append (" ");
			}
			sb.AppendLine ();
			sb.AppendFormat (indent + "}};\n");
			return sb.ToString ();
		}

	}
}
