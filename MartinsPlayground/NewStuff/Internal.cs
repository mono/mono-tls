using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
	public enum BufferType {
		Empty               = 0x00,
		Data                = 0x01,
		Token               = 0x02,
		Parameters          = 0x03,
		Missing             = 0x04,
		Extra               = 0x05,
		Trailer             = 0x06,
		Header              = 0x07,
		Padding             = 0x09,    // non-data padding
		Stream              = 0x0A,
		ChannelBindings     = 0x0E,
		TargetHost          = 0x10,
		ReadOnlyFlag        = unchecked((int)0x80000000),
		ReadOnlyWithChecksum= 0x10000000
	}

	public class SecurityBuffer {
		public int size;
		public BufferType type;
		public byte[] token;
		public SafeHandle unmanagedToken;
		public int offset;

		public SecurityBuffer(byte[] data, int offset, int size, BufferType tokentype) {
			#if INSIDE_SYSTEM
			GlobalLog.Assert(offset >= 0 && offset <= (data == null ? 0 : data.Length), "SecurityBuffer::.ctor", "'offset' out of range.  [" + offset + "]");
			GlobalLog.Assert(size >= 0 && size <= (data == null ? 0 : data.Length - offset), "SecurityBuffer::.ctor", "'size' out of range.  [" + size + "]");
			#endif

			this.offset = data == null || offset < 0 ? 0 : Math.Min(offset, data.Length);
			this.size   = data == null || size < 0 ? 0 : Math.Min(size, data.Length - this.offset);
			this.type   = tokentype;
			this.token  = size == 0 ? null : data;
		}

		public SecurityBuffer(byte[] data, BufferType tokentype) {
			this.size   = data == null ? 0 : data.Length;
			this.type   = tokentype;
			this.token  = size == 0 ? null : data;
		}

		public SecurityBuffer(int size, BufferType tokentype) {
			#if INSIDE_SYSTEM
			GlobalLog.Assert(size >= 0, "SecurityBuffer::.ctor", "'size' out of range.  [" + size.ToString(NumberFormatInfo.InvariantInfo) + "]");
			#endif

			this.size   = size;
			this.type   = tokentype;
			this.token  = size == 0 ? null : new byte[size];
		}

		#if INSIDE_SYSTEM
		public SecurityBuffer(ChannelBinding binding) {
			this.size           = (binding == null ? 0 : binding.Size);
			this.type           = BufferType.ChannelBindings;
			this.unmanagedToken = binding;
		}
		#endif
	}

	internal static class Internal
	{
		public static void HexDump (byte[] buffer)
		{
			var sb = new StringBuilder ();
			var chars = new char [16];
			var length = ((buffer.Length + 15) / 16) * 16;
			for (int i = 0; i < length; i++) {
				if (i < buffer.Length) {
					sb.AppendFormat ("{0:x2} ", buffer [i]);
					if (buffer [i] >= 32 && buffer [i] < 128)
						chars [i % 16] = (char)buffer [i];
					else
						chars [i % 16] = '.';
				} else {
					sb.Append ("   ");
					chars [i % 16] = ' ';
				}

				if (((i + 1) % 16) == 0) {
					sb.Append (" ");
					foreach (var ch in chars) {
						sb.Append (ch);
					}
					sb.AppendLine ();
				} else if (((i + 1) % 8) == 0)
					sb.Append ("- ");
			}
			var text = sb.ToString ();
			Console.WriteLine (text);
			Console.WriteLine ();
		}
	}

}

