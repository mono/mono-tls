using System;
using System.Text;
using System.Net.Sockets;

namespace System.Net
{
    static class Helper
    {
        internal static void InternalShutdown (this Socket socket, SocketShutdown how)
        {
            try {
                socket.Shutdown (how);
            } catch {
            }
        }

        internal static IAsyncResult UnsafeBeginConnect(this Socket socket, EndPoint remoteEP, AsyncCallback callback, object state)
        {
            return socket.BeginConnect(remoteEP, callback, state);
        }

        internal static IAsyncResult UnsafeBeginSend(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            return socket.BeginSend(buffer, offset, size, socketFlags, callback, state);
        }

        internal static IAsyncResult UnsafeBeginReceive(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            return socket.BeginReceive(buffer, offset, size, socketFlags, callback, state);
        }

        internal static IAsyncResult BeginMultipleSend(this Socket socket, BufferOffsetSize[] buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            var segments = new ArraySegment<byte> [buffers.Length];
            for (int i = 0; i < buffers.Length; i++)
                segments[i] = new ArraySegment<byte>(buffers[i].Buffer, buffers[i].Offset, buffers[i].Size);
            return socket.BeginSend(segments, socketFlags, callback, state);
        }

        internal static IAsyncResult UnsafeBeginMultipleSend(this Socket socket, BufferOffsetSize[] buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            return socket.BeginMultipleSend(buffers, socketFlags, callback, state);
        }

        internal static int EndMultipleSend(this Socket socket, IAsyncResult asyncResult)
        {
            return socket.EndSend(asyncResult);
        }

        internal static void MultipleSend(this Socket socket, BufferOffsetSize[] buffers, SocketFlags socketFlags)
        {
            var segments = new ArraySegment<byte> [buffers.Length];
            for (int i = 0; i < buffers.Length; i++)
                segments[i] = new ArraySegment<byte>(buffers[i].Buffer, buffers[i].Offset, buffers[i].Size);
            socket.Send(segments, socketFlags);
        }

        internal static void SetSocketOption(this Socket socket, SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue, bool silent)
        {
            try {
                socket.SetSocketOption(optionLevel, optionName, optionValue);
            } catch {
                if (!silent)
                    throw;
            }
        }

        public static void HexDump (byte[] buffer)
        {
            var sb = new StringBuilder();
            var chars = new char [17];
            for (int i = 0; i < buffer.Length; i++)
            {
                sb.AppendFormat("{0:x2} ", buffer[i]);
                if (buffer[i] >= 32 && buffer[i] < 128)
                    chars[i % 16] = (char)buffer[i];
                else
                    chars[i % 16] = '.';
                if (((i + 1) % 16) == 0)
                {
                    sb.Append(" ");
                    foreach (var ch in chars)
                    {
                        sb.Append(ch);
                    }
                    sb.AppendLine();
                }
                else if (((i+1) % 8) == 0)
                    sb.Append("- ");
            }
            var text = sb.ToString();
            Console.WriteLine(text);
            Console.WriteLine();
        }
    }
}

