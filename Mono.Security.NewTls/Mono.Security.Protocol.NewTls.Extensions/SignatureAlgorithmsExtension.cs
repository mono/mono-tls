using System;
using System.Collections.Generic;

namespace Mono.Security.Protocol.NewTls.Extensions
{
	public class SignatureAlgorithmsExtension : TlsExtension
	{
		public override ExtensionType ExtensionType {
			get { return ExtensionType.SignatureAlgorithms; }
		}

		public ICollection<SignatureAndHashAlgorithm> Algorithms {
			get;
			private set;
		}

		public SignatureAlgorithmsExtension (TlsBuffer incoming)
		{
			var length = incoming.ReadInt16 ();
			if ((length % 2) != 0)
				throw new TlsException (AlertDescription.DecodeError);

			var count = length >> 1;
			var algorithms = new List<SignatureAndHashAlgorithm> (count);
			for (int i = 0; i < count; i++) {
				algorithms.Add (new SignatureAndHashAlgorithm (incoming));
			}

			Algorithms = algorithms;
 		}

		public SignatureAlgorithmsExtension (ICollection<SignatureAndHashAlgorithm> algorithms)
		{
			Algorithms = algorithms;
		}

		public override void Encode (TlsBuffer buffer)
		{
			buffer.Write ((short)ExtensionType);
			buffer.Write ((short)(Algorithms.Count * 2 + 2));
			buffer.Write ((short)(Algorithms.Count * 2));
			foreach (var algorithm in Algorithms)
				algorithm.Encode (buffer);
		}

		public override bool ProcessClient (TlsContext context)
		{
			// We must never get this from a server.
			throw new TlsException (AlertDescription.UnsupportedExtension);
		}

		public override TlsExtension ProcessServer (TlsContext context)
		{
			context.HandshakeParameters.SignatureAlgorithms = Algorithms;
			return this;
		}
	}
}

