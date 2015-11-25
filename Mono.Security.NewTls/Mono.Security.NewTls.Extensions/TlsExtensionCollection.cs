using System;
using System.Collections.Generic;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Extensions
{
	public class TlsExtensionCollection : List<TlsExtension>
	{
		public TlsExtensionCollection ()
		{
		}

		public TlsExtensionCollection (TlsBuffer incoming)
		{
			Read (incoming);
		}

		public TlsExtension Find (ExtensionType type)
		{
			foreach (var extension in this) {
				if (extension.ExtensionType == type)
					return extension;
			}

			return null;
		}

		public bool HasExtension (TlsExtension extension)
		{
			return Find (extension.ExtensionType) != null;
		}

		public RenegotiationExtension AddRenegotiationExtension ()
		{
			RenegotiationExtension renegExt;
			foreach (var extension in this) {
				renegExt = extension as RenegotiationExtension;
				if (renegExt != null)
					return renegExt;
			}

			renegExt = RenegotiationExtension.CreateImplicit ();
			Add (renegExt);
			return renegExt;
		}

		internal static TlsExtension CreateExtension (ExtensionType type, TlsBuffer buffer)
		{
			switch (type) {
			case ExtensionType.ServerName:
				return new ServerNameExtension (buffer);
			case ExtensionType.SignatureAlgorithms:
				return new SignatureAlgorithmsExtension (buffer);
			case ExtensionType.Renegotiation:
				return new RenegotiationExtension (buffer);
			default:
				return null;
			}
		}

		void Read (TlsBuffer incoming)
		{
			if (incoming.Remaining == 0)
				return;

			var length = incoming.ReadInt16 ();
			if (incoming.Remaining != length)
				throw new TlsException (AlertDescription.DecodeError);

			while (incoming.Remaining > 0) {
				var extensionType = (ExtensionType)incoming.ReadInt16 ();
				length = incoming.ReadInt16 ();
				var extensionBuffer = incoming.ReadBuffer (length);

				var extension = CreateExtension (extensionType, extensionBuffer);
				if (extension != null)
					Add (extension);
			}
		}

		internal void Write (TlsStream stream)
		{
			if (Count == 0)
				return;

			var extensionStart = stream.Position;
			stream.Write ((short)0);

			foreach (var extension in this) {
				extension.Encode (stream);
			}

			var endPos = stream.Position;
			stream.Position = extensionStart;
			stream.Write ((short)(endPos - extensionStart - 2));
			stream.Position = endPos;
		}
	}
}

