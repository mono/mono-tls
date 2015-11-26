//
// X509Certificate.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin Inc. (http://www.xamarin.com)
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
using System.Collections;

namespace System.Security.Cryptography.X509Certificates
{
	public class X509CertificateCollection : CollectionBase
	{
		public X509CertificateCollection ()
		{
			throw new NotImplementedException ();
		}

		public X509CertificateCollection (X509Certificate [] value) 
		{
			throw new NotImplementedException ();
		}

		public X509CertificateCollection (X509CertificateCollection value)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate this [int index] {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public int Add (X509Certificate value)
		{
			throw new NotImplementedException ();
		}

		public void AddRange (X509Certificate [] value) 
		{
			throw new NotImplementedException ();
		}

		public void AddRange (X509CertificateCollection value)
		{
			throw new NotImplementedException ();
		}

		public bool Contains (X509Certificate value) 
		{
			throw new NotImplementedException ();
		}

		public void CopyTo (X509Certificate[] array, int index)
		{
			throw new NotImplementedException ();
		}

		public new X509CertificateEnumerator GetEnumerator ()
		{
			throw new NotImplementedException ();
		}

		public int IndexOf (X509Certificate value)
		{
			throw new NotImplementedException ();
		}

		public void Insert (int index, X509Certificate value)
		{
			throw new NotImplementedException ();
		}

		public void Remove (X509Certificate value)
		{
			throw new NotImplementedException ();
		}

		public class X509CertificateEnumerator : IEnumerator
		{
			public X509CertificateEnumerator (X509CertificateCollection mappings)
			{
				throw new NotImplementedException ();
			}

			public X509Certificate Current {
				get { throw new NotImplementedException (); }
			}

			object IEnumerator.Current {
				get { throw new NotImplementedException (); }
			}

 			bool IEnumerator.MoveNext ()
			{
				throw new NotImplementedException ();
			}

			void IEnumerator.Reset () 
			{
				throw new NotImplementedException ();
			}

			public bool MoveNext () 
			{
				throw new NotImplementedException ();
			}

			public void Reset ()
			{
				throw new NotImplementedException ();
			}
		}		
	}
}

