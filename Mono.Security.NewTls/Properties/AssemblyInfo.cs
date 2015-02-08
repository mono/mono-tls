//
// AssemblyInfo.cs
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
using System.Reflection;
using System.Resources;
using System.Security;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// General Information about the system assembly

[assembly: AssemblyVersion (Consts.FxVersion)]

[assembly: AssemblyCompany ("MONO development team")]
[assembly: AssemblyCopyright ("(c) 2015 Xamarin")]
[assembly: AssemblyDescription ("Mono.Security.NewTls.dll")]
[assembly: AssemblyProduct ("MONO CLI")]
[assembly: AssemblyTitle ("Mono.Security.Providers.dll")]
[assembly: CLSCompliant (true)]
[assembly: ComVisible (false)]
[assembly: NeutralResourcesLanguage ("en-US")]

#if INSTRUMENTATION
	[assembly: InternalsVisibleTo ("Mono.Security.Instrumentation.Framework, PublicKey=0024000004800000940000000602000000240000525341310004000011000000990dad24771188a27bb12112dff736fc75d80d42b0ad009366b859ec62a4b628d65e99bfae957c3907c4e728ba933316727b16ca62ea951b9ce6050ecdc8daf04613befedbc99007f1210fee0f22e8b822a05cd889241bb12324a9907962adf7e2e976bca92702eddee917b440aff54af6f8511f4863379fac442cf72b01e2a8")]
	[assembly: InternalsVisibleTo ("Mono.Security.Instrumentation.Tests, PublicKey=0024000004800000940000000602000000240000525341310004000011000000990dad24771188a27bb12112dff736fc75d80d42b0ad009366b859ec62a4b628d65e99bfae957c3907c4e728ba933316727b16ca62ea951b9ce6050ecdc8daf04613befedbc99007f1210fee0f22e8b822a05cd889241bb12324a9907962adf7e2e976bca92702eddee917b440aff54af6f8511f4863379fac442cf72b01e2a8")]
	[assembly: InternalsVisibleTo ("Mono.Security.Instrumentation.Console, PublicKey=0024000004800000940000000602000000240000525341310004000011000000990dad24771188a27bb12112dff736fc75d80d42b0ad009366b859ec62a4b628d65e99bfae957c3907c4e728ba933316727b16ca62ea951b9ce6050ecdc8daf04613befedbc99007f1210fee0f22e8b822a05cd889241bb12324a9907962adf7e2e976bca92702eddee917b440aff54af6f8511f4863379fac442cf72b01e2a8")]
#endif
