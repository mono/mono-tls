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

namespace System.Security.Cryptography.X509Certificates
{
	public class X509Certificate
	{
		public X509Certificate ()
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (byte[] rawData, string password)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (string fileName)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (string fileName, string password)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (string fileName, string password, X509KeyStorageFlags keyStorageFlags)
		{
			throw new NotImplementedException ();
		}

		public string Issuer {
			get { throw new NotImplementedException (); }
		}

		public string Subject {
			get { throw new NotImplementedException (); }
		}

		public IntPtr Handle {
			get { throw new NotImplementedException (); }
		}

		public virtual byte[] Export (X509ContentType contentType)
		{
			throw new NotImplementedException ();
		}

		public virtual byte[] Export (X509ContentType contentType, string password)
		{
			throw new NotImplementedException ();
		}

		public virtual void Import (byte[] rawData)
		{
			throw new NotImplementedException ();
		}

		public virtual void Import (byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
		{
			throw new NotImplementedException ();
		}

		public virtual void Import (string fileName)
		{
			throw new NotImplementedException ();
		}

		public virtual void Import (string fileName, string password, X509KeyStorageFlags keyStorageFlags)
		{
			throw new NotImplementedException ();
		}

		public virtual void Reset ()
		{
			throw new NotImplementedException ();
		}

		public static X509Certificate CreateFromCertFile (string filename) 
		{
			throw new NotImplementedException ();
		}

		public static X509Certificate CreateFromSignedFile (string filename)
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (byte[] data)
		{
			throw new NotImplementedException ();
		}
	
		public X509Certificate (IntPtr handle) 
		{
			throw new NotImplementedException ();
		}

		public X509Certificate (X509Certificate cert) 
		{
			throw new NotImplementedException ();
		}

		public virtual bool Equals (X509Certificate other)
		{
			throw new NotImplementedException ();
		}
	
		public virtual byte[] GetCertHash () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetCertHashString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetEffectiveDateString ()
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetExpirationDateString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetFormat () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetKeyAlgorithm () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual byte[] GetKeyAlgorithmParameters () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetKeyAlgorithmParametersString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual byte[] GetPublicKey () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetPublicKeyString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual byte[] GetRawCertData () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetRawCertDataString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual byte[] GetSerialNumber () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string GetSerialNumberString () 
		{
			throw new NotImplementedException ();
		}
	
		public virtual string ToString (bool fVerbose) 
		{
			throw new NotImplementedException ();
		}
	}
}
